"""Semantic chunking for large diffs with token management.

Splits hunks by file boundaries, maintains context overlap, and tracks token counts.
Ensures per-chunk analysis stays within token budgets (23,400 tokens per detector).
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import tiktoken
from src.core.models import DiffHunk


@dataclass
class Chunk:
    """A logical chunk of code changes (hunks from same/related files).
    
    Attributes:
        id: Unique identifier (e.g., "chunk_1", "chunk_2")
        hunks: List of DiffHunk objects in this chunk
        token_count: Total tokens in hunks (estimated via tiktoken)
        file_paths: Set of files covered by this chunk
        metadata: Additional metadata (e.g., overlap info)
    """
    id: str
    hunks: List[DiffHunk]
    token_count: int
    file_paths: set = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TokenEstimator:
    """Estimates token counts using tiktoken cl100k_base encoder."""
    
    def __init__(self, encoder_name: str = "cl100k_base"):
        """Initialize with specified tiktoken encoder.
        
        Args:
            encoder_name: tiktoken encoder to use (default: cl100k_base for HuggingFace API)
        """
        self.encoder = tiktoken.get_encoding(encoder_name)
        self.encoder_name = encoder_name
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Number of tokens
        """
        return len(self.encoder.encode(text))
    
    def count_hunk_tokens(self, hunks: List[DiffHunk]) -> int:
        """Count total tokens in list of hunks.
        
        Args:
            hunks: List of DiffHunk objects
            
        Returns:
            Total token count
        """
        total = 0
        for hunk in hunks:
            # Each hunk: file path + added lines + removed lines
            hunk_text = f"{hunk.file_path}\n"
            hunk_text += "\n".join(hunk.added_lines)
            hunk_text += "\n"
            hunk_text += "\n".join(hunk.removed_lines)
            total += self.count_tokens(hunk_text)
        return total


class SemanticChunker:
    """Chunks diffs semantically by file boundaries with token-aware splitting.
    
    Strategy:
    1. Group hunks by file path (natural semantic boundaries)
    2. Create chunks that respect max_token_limit
    3. Add overlap between chunks for context preservation (500 tokens)
    4. Tag hunks with chunk IDs for traceability
    """
    
    def __init__(self, max_chunk_tokens: int = 24000, overlap_tokens: int = 500):
        """Initialize chunker.
        
        Args:
            max_chunk_tokens: Maximum tokens per chunk (default 24k for detector safety margin)
            overlap_tokens: Tokens to overlap between chunks (default 500 for context)
        """
        self.max_chunk_tokens = max_chunk_tokens
        self.overlap_tokens = overlap_tokens
        self.estimator = TokenEstimator()
    
    def chunk_diff(self, hunks: List[DiffHunk]) -> List[Chunk]:
        """Split hunks into semantic chunks by file boundaries.
        
        Algorithm:
        1. Group hunks by file_path
        2. Build chunks greedily: add file groups until exceeding max_tokens
        3. Create overlap between chunks for context preservation
        4. Return list of Chunk objects with IDs
        
        Args:
            hunks: Parsed hunks from diff
            
        Returns:
            List of Chunk objects
            
        Raises:
            ValueError: If single file exceeds max_tokens (unrecoverable)
        """
        if not hunks:
            return []
        
        # Group hunks by file path
        hunks_by_file: Dict[str, List[DiffHunk]] = {}
        for hunk in hunks:
            if hunk.file_path not in hunks_by_file:
                hunks_by_file[hunk.file_path] = []
            hunks_by_file[hunk.file_path].append(hunk)
        
        # Check: does any single file exceed limit?
        for file_path, file_hunks in hunks_by_file.items():
            file_tokens = self.estimator.count_hunk_tokens(file_hunks)
            if file_tokens > self.max_chunk_tokens:
                raise ValueError(
                    f"Single file '{file_path}' is {file_tokens} tokens, "
                    f"exceeds max_chunk_tokens ({self.max_chunk_tokens}). "
                    f"Split file into smaller changes."
                )
        
        # Build chunks greedily: add file groups until exceeding limit
        chunks: List[Chunk] = []
        current_chunk_hunks: List[DiffHunk] = []
        current_chunk_tokens = 0
        file_order = sorted(hunks_by_file.keys())  # Deterministic order
        
        for file_path in file_order:
            file_hunks = hunks_by_file[file_path]
            file_tokens = self.estimator.count_hunk_tokens(file_hunks)
            
            # Would adding this file exceed limit?
            if current_chunk_hunks and (current_chunk_tokens + file_tokens) > self.max_chunk_tokens:
                # Yes: finalize current chunk and start new one
                chunk = Chunk(
                    id=f"chunk_{len(chunks) + 1}",
                    hunks=current_chunk_hunks.copy(),
                    token_count=current_chunk_tokens,
                    file_paths=set(h.file_path for h in current_chunk_hunks)
                )
                chunks.append(chunk)
                
                # Add overlap (last N hunks from previous chunk)
                overlap_hunks = self._get_overlap_hunks(
                    current_chunk_hunks,
                    self.overlap_tokens
                )
                current_chunk_hunks = overlap_hunks.copy()
                current_chunk_tokens = self.estimator.count_hunk_tokens(current_chunk_hunks)
            
            # Add this file's hunks to current chunk
            current_chunk_hunks.extend(file_hunks)
            current_chunk_tokens = self.estimator.count_hunk_tokens(current_chunk_hunks)
        
        # Finalize last chunk
        if current_chunk_hunks:
            chunk = Chunk(
                id=f"chunk_{len(chunks) + 1}",
                hunks=current_chunk_hunks,
                token_count=current_chunk_tokens,
                file_paths=set(h.file_path for h in current_chunk_hunks)
            )
            chunks.append(chunk)
        
        return chunks
    
    def _get_overlap_hunks(self, hunks: List[DiffHunk], target_tokens: int) -> List[DiffHunk]:
        """Get last N hunks that total ~target_tokens for overlap.
        
        Args:
            hunks: All hunks from previous chunk
            target_tokens: Target token count for overlap
            
        Returns:
            Last hunks from list totaling ~target_tokens
        """
        if not hunks:
            return []
        
        # Start from end, accumulate until reaching target
        overlap: List[DiffHunk] = []
        tokens = 0
        
        for hunk in reversed(hunks):
            hunk_tokens = self.estimator.count_hunk_tokens([hunk])
            if tokens + hunk_tokens <= target_tokens:
                overlap.insert(0, hunk)
                tokens += hunk_tokens
            else:
                break
        
        return overlap
    
    def should_chunk(self, hunks: List[DiffHunk]) -> bool:
        """Determine if diff should be chunked.
        
        Chunks if:
        - Total tokens > max_chunk_tokens
        - Multiple files involved (semantic chunking improves accuracy)
        
        Args:
            hunks: Parsed hunks from diff
            
        Returns:
            True if chunking should be applied
        """
        total_tokens = self.estimator.count_hunk_tokens(hunks)
        num_files = len(set(h.file_path for h in hunks))
        
        # Chunk if > max_tokens or multiple files AND over 50% of limit
        should = (
            total_tokens > self.max_chunk_tokens or
            (num_files > 1 and total_tokens > self.max_chunk_tokens * 0.5)
        )
        return should
    
    def get_hunks_by_chunk_id(self, chunk_id: str, chunks: List[Chunk]) -> List[DiffHunk]:
        """Fast lookup: get hunks for specific chunk.
        
        Args:
            chunk_id: Chunk identifier (e.g., "chunk_1")
            chunks: List of all chunks
            
        Returns:
            Hunks in specified chunk, or empty list if not found
        """
        for chunk in chunks:
            if chunk.id == chunk_id:
                return chunk.hunks
        return []
    
    def get_chunk_by_id(self, chunk_id: str, chunks: List[Chunk]) -> Optional[Chunk]:
        """Get full Chunk object by ID.
        
        Args:
            chunk_id: Chunk identifier
            chunks: List of all chunks
            
        Returns:
            Chunk object or None if not found
        """
        for chunk in chunks:
            if chunk.id == chunk_id:
                return chunk
        return None


def create_chunker(max_tokens: int = 24000, overlap_tokens: int = 500) -> SemanticChunker:
    """Factory: create configured chunker instance.
    
    Args:
        max_tokens: Max tokens per chunk
        overlap_tokens: Overlap between chunks
        
    Returns:
        Configured SemanticChunker
    """
    return SemanticChunker(max_chunk_tokens=max_tokens, overlap_tokens=overlap_tokens)
