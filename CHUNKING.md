# Semantic Chunking & Token Management System

## Overview

This document describes the implementation of semantic chunking for handling large diffs that exceed HuggingFace API token limits (32,768 tokens per request).

## Problem Statement

- **Large PRs**: Diffs >10,000 tokens exceed API limits
- **Token counting**: HF API has hard 32,768 token limit per request
- **Requirements**: 
  - Support large diffs without losing context
  - Maintain detection accuracy across chunks
  - Aggregate verdicts intelligently (worst-verdict-wins)
  - Preserve full traceability for findings

## Solution: Semantic Chunking

### Strategy

**File-boundary chunking** (not function-level):
- Group hunks by file path
- Build chunks greedily up to max_tokens threshold
- Add overlap between chunks for context preservation
- Tag all findings with chunk_id for traceability

### Why File-Boundary?

1. **Simpler**: Avoid parsing function/class boundaries
2. **Semantic**: Changes to same file should stay together
3. **Safe**: Reduces risk of splitting vulnerability across boundaries
4. **Flexible**: Works with any language (git diff is universal)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Large Diff (40K+ tokens)               │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ TokenEstimator       │
            │ (tiktoken cl100k)    │
            └──────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ should_chunk()?       │
            │ (>max_chunk_tokens)   │
            └──────────────────────┘
                    /        \
                  NO          YES
                  /              \
                 ▼                ▼
            [single           SemanticChunker
             chunk_1]          │
                               ├─ Group hunks by file
                               ├─ Build chunks greedily
                               ├─ Add 500-token overlap
                               └─ Generate chunk_1, chunk_2, ...
                                        │
                                        ▼
                                [chunk_1, chunk_2, ...]
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
                 [A05 detector]    [A02 detector]    [A10 detector]
                    │                   │                   │
                    └───────────────────┴───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ Per-chunk findings (tagged with chunk_id)
                    └───────────────────┬───────────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        │ For each category + chunk:     │                               │
        │ prosecutor → defender → judge  │                               │
        └───────────────────────────────┬───────────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ VerdictAggregator (worst-verdict-wins)
                    │ ├─ Per-category aggregation
                    │ ├─ PR-level verdict
                    │ └─ Filter findings by severity
                    └───────────────────┬───────────────────┘
                                        │
                                        ▼
                          CategoryTriageVerdict[]
                          (with chunk context)
```

## Token Budget

### HuggingFace API Limits

```
┌──────────────────┬──────────────┬─────────────┐
│ Model            │ Max Tokens   │ Budget (90%)│
├──────────────────┼──────────────┼─────────────┤
│ 7B-Instruct      │ 26,000       │ 23,400      │
│ 32B-Instruct     │ 28,000       │ 25,200      │
└──────────────────┴──────────────┴─────────────┘

Hard limit: 32,768 tokens (all models)
Chunking uses: 24,000 tokens per chunk (73% utilization)
Safety margin: 90% (8,768 tokens buffer)
```

### Per-Chunk Allocation

```
Chunk Budget = 24,000 tokens

┌─────────────────────────────────────────────┐
│ Detector Input (formatted hunks)            │
│ ├─ System prompt: ~500 tokens               │
│ ├─ Code hunks: ~18,000 tokens               │
│ └─ Input reserve: ~5,000 tokens             │
│ TOTAL: ~23,400 tokens (safety margin)       │
│                                             │
│ Output: Structured JSON findings (~500)     │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Prosecutor Input (category + findings)      │
│ ├─ System prompt: ~300 tokens               │
│ ├─ Findings summary: ~10,000 tokens         │
│ └─ Input reserve: ~7,700 tokens             │
│ TOTAL: ~18,000 tokens (90% safety margin)   │
│                                             │
│ Output: Structured verdict (~300)           │
└─────────────────────────────────────────────┘

(Similar for Defender, Judge)
```

## Implementation Details

### 1. TokenEstimator (src/agents/chunker.py)

```python
from tiktoken import encoding_for_model

class TokenEstimator:
    def __init__(self):
        # Use cl100k_base (matches HF API token counting)
        self.encoder = encoding_for_model("gpt-3.5-turbo")
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text using tiktoken."""
        return len(self.encoder.encode(text))
    
    def count_hunk_tokens(self, hunks: List[DiffHunk]) -> int:
        """Count total tokens across all hunks."""
        total = 0
        for hunk in hunks:
            text = format_hunk_for_counting(hunk)
            total += self.count_tokens(text)
        return total
```

**Validation**: Startup verifies tiktoken count ≈ HF API count on sample code.

### 2. SemanticChunker (src/agents/chunker.py)

```python
@dataclass
class Chunk:
    id: str                      # chunk_1, chunk_2, ...
    hunks: List[DiffHunk]       # Hunks in this chunk
    token_count: int            # Total tokens

class SemanticChunker:
    def chunk_diff(self, hunks: List[DiffHunk]) -> List[Chunk]:
        """
        Group hunks by file, build chunks up to max_tokens,
        add overlap, return chunks.
        """
        # Step 1: Group hunks by file_path
        hunks_by_file = {}
        for hunk in hunks:
            if hunk.file_path not in hunks_by_file:
                hunks_by_file[hunk.file_path] = []
            hunks_by_file[hunk.file_path].append(hunk)
        
        # Step 2: Validate single file doesn't exceed limit
        for file_path, file_hunks in hunks_by_file.items():
            tokens = self.estimator.count_hunk_tokens(file_hunks)
            if tokens > self.max_chunk_tokens:
                raise ValueError(
                    f"Single file '{file_path}' is {tokens} tokens, "
                    f"exceeds max_chunk_tokens ({self.max_chunk_tokens}). "
                    f"Split file into smaller changes."
                )
        
        # Step 3: Build chunks greedily
        chunks = []
        current_chunk_hunks = []
        current_tokens = 0
        chunk_count = 1
        
        for file_path, file_hunks in sorted(hunks_by_file.items()):
            file_tokens = self.estimator.count_hunk_tokens(file_hunks)
            
            # If adding this file exceeds limit, finalize chunk
            if current_tokens + file_tokens > self.max_chunk_tokens:
                if current_chunk_hunks:
                    chunks.append(Chunk(
                        id=f"chunk_{chunk_count}",
                        hunks=current_chunk_hunks,
                        token_count=current_tokens
                    ))
                    chunk_count += 1
                    
                    # Step 4: Add overlap from end of previous chunk
                    overlap_hunks = get_overlap_hunks(
                        current_chunk_hunks,
                        self.overlap_tokens
                    )
                    current_chunk_hunks = overlap_hunks
                    current_tokens = len(overlap_hunks)
            
            current_chunk_hunks.extend(file_hunks)
            current_tokens += file_tokens
        
        # Finalize last chunk
        if current_chunk_hunks:
            chunks.append(Chunk(
                id=f"chunk_{chunk_count}",
                hunks=current_chunk_hunks,
                token_count=current_tokens
            ))
        
        return chunks
    
    def should_chunk(self, hunks: List[DiffHunk]) -> bool:
        """Detect if diff needs chunking."""
        total_tokens = self.estimator.count_hunk_tokens(hunks)
        return total_tokens > self.max_chunk_tokens
```

### 3. VerdictAggregator (src/agents/triage/aggregator.py)

```python
@dataclass
class AggregatedVerdict:
    category: str               # A05, A02, A10
    final_verdict: str         # CRITICAL, MEDIUM, LOW, FALSE_POSITIVE
    chunk_verdicts: List[JudgeVerdict]  # Per-chunk verdicts
    reasoning: str             # Aggregation explanation
    chunk_sources: List[str]   # Which chunks had final verdict
    confidence: float          # Average across chunks

class VerdictAggregator:
    VERDICT_RANK = {
        "CRITICAL": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "FALSE_POSITIVE": 1
    }
    
    def aggregate_category_verdicts(
        self,
        category: str,
        chunk_verdicts: List[JudgeVerdict]
    ) -> AggregatedVerdict:
        """
        Find worst verdict across chunks.
        CRITICAL > MEDIUM > LOW > FALSE_POSITIVE
        """
        # Find worst verdict
        worst_verdict = "FALSE_POSITIVE"
        worst_rank = 0
        chunk_sources = []
        
        for verdict in chunk_verdicts:
            rank = self.VERDICT_RANK.get(verdict.verdict, 0)
            if rank > worst_rank:
                worst_rank = rank
                worst_verdict = verdict.verdict
                chunk_sources = [verdict.chunk_id]
            elif rank == worst_rank and verdict.verdict == worst_verdict:
                chunk_sources.append(verdict.chunk_id)
        
        # Average confidence
        avg_confidence = sum(v.confidence_score for v in chunk_verdicts) / len(chunk_verdicts)
        
        # Build reasoning
        if len(chunk_verdicts) == 1:
            reasoning = f"Single chunk: {worst_verdict}"
        else:
            reasoning = f"Worst verdict: {worst_verdict} from chunks {chunk_sources}"
        
        return AggregatedVerdict(
            category=category,
            final_verdict=worst_verdict,
            chunk_verdicts=chunk_verdicts,
            reasoning=reasoning,
            chunk_sources=chunk_sources,
            confidence=avg_confidence
        )
    
    def aggregate_all_categories(
        self,
        verdicts_by_category: Dict[str, List[JudgeVerdict]]
    ) -> Dict[str, AggregatedVerdict]:
        """Aggregate all categories."""
        aggregated = {}
        for category, verdicts in verdicts_by_category.items():
            aggregated[category] = self.aggregate_category_verdicts(
                category, verdicts
            )
        return aggregated
    
    def get_pr_level_verdict(self, aggregated: Dict[str, AggregatedVerdict]) -> str:
        """PR-level verdict is worst across all categories."""
        worst = "FALSE_POSITIVE"
        worst_rank = 0
        
        for agg in aggregated.values():
            rank = self.VERDICT_RANK.get(agg.final_verdict, 0)
            if rank > worst_rank:
                worst_rank = rank
                worst = agg.final_verdict
        
        return worst
    
    def filter_findings_by_severity(
        self,
        aggregated: Dict[str, AggregatedVerdict],
        include_low: bool = False,
        include_false_positive: bool = False
    ) -> Dict[str, AggregatedVerdict]:
        """Filter findings for report."""
        filtered = {}
        for category, verdict in aggregated.items():
            if verdict.final_verdict == "CRITICAL" or verdict.final_verdict == "MEDIUM":
                filtered[category] = verdict
            elif include_low and verdict.final_verdict == "LOW":
                filtered[category] = verdict
            elif include_false_positive and verdict.final_verdict == "FALSE_POSITIVE":
                filtered[category] = verdict
        return filtered
```

### 4. Integration in _analyze_diff (src/main.py)

```python
def _analyze_diff(raw_diff: str) -> Tuple[List[DiffHunk], List[VulnerabilityFinding], List[CategoryTriageVerdict]]:
    """Analyze diff with chunking support."""
    
    # Parse diff
    hunks = parse_diff_to_hunks(raw_diff)
    
    # Create chunker with config
    config = Config.load()
    chunker = create_chunker(
        max_tokens=24000,
        overlap_tokens=500
    )
    
    # Determine if chunking needed
    if chunker.should_chunk(hunks):
        chunks = chunker.chunk_diff(hunks)
        print(f"Large diff: {len(hunks)} hunks → {len(chunks)} chunks")
    else:
        from src.core.models import Chunk
        chunks = [Chunk(
            id="chunk_1",
            hunks=hunks,
            token_count=chunker.estimator.count_hunk_tokens(hunks)
        )]
    
    # Run all 3 detectors on each chunk
    findings = []
    verdicts_by_category = {}
    
    for chunk in chunks:
        print(f"Analyzing {chunk.id}...")
        
        # Detect
        chunk_findings = []
        for detector_func in [detect_injection, detect_config, detect_error_handling]:
            findings_list = detector_func(chunk.hunks)
            for f in findings_list:
                f.chunk_id = chunk.id  # Tag with chunk
            chunk_findings.extend(findings_list)
        
        findings.extend(chunk_findings)
        
        # Triage per category
        by_category = {}
        for f in chunk_findings:
            if f.category not in by_category:
                by_category[f.category] = []
            by_category[f.category].append(f)
        
        for category, findings_list in by_category.items():
            # Prosecutor → Defender → Judge
            prosecutor = prosecutor_agent(category, findings_list, chunk.hunks)
            defender = defender_agent(category, prosecutor, chunk.hunks)
            judge = judge_agent(category, prosecutor, defender)
            
            if category not in verdicts_by_category:
                verdicts_by_category[category] = []
            verdicts_by_category[category].append(judge)
    
    # Aggregate verdicts
    aggregator = create_aggregator()
    aggregated = aggregator.aggregate_all_categories(verdicts_by_category)
    
    # Build final verdicts
    final_verdicts = []
    for category, agg in aggregated.items():
        # Collect findings for this category
        category_findings = [f for f in findings if f.category == category]
        
        # Get hunks for this category
        category_hunks = []
        for f in category_findings:
            # Find hunks that contributed to this finding
            pass  # (simplified)
        
        final_verdicts.append(CategoryTriageVerdict(
            category=category,
            findings=category_findings,
            diff_hunks=category_hunks,
            prosecutor=agg.chunk_verdicts[0].prosecutor if agg.chunk_verdicts else None,
            defender=agg.chunk_verdicts[0].defender if agg.chunk_verdicts else None,
            judge=agg.chunk_verdicts[0].judge if agg.chunk_verdicts else None,
        ))
    
    # Sort by severity
    severity_rank = {"CRITICAL": 0, "MEDIUM": 1, "LOW": 2, "FALSE_POSITIVE": 3}
    final_verdicts.sort(
        key=lambda v: severity_rank.get(v.judge.verdict, 4)
    )
    
    return hunks, findings, final_verdicts
```

## Testing

### Unit Tests (tests/test_chunking.py)

```
TokenEstimator:
  ✓ test_count_tokens_simple_text
  ✓ test_count_tokens_code_snippet
  ✓ test_count_hunk_tokens

SemanticChunker:
  ✓ test_chunk_diff_single_file
  ✓ test_chunk_diff_multiple_files
  ✓ test_chunk_overlap
  ✓ test_single_file_exceeds_limit_raises
  ✓ test_should_chunk_small_diff
  ✓ test_should_chunk_large_diff
  ✓ test_get_hunks_by_chunk_id
  ✓ test_get_chunk_by_id

VerdictAggregator:
  ✓ test_aggregate_single_verdict
  ✓ test_aggregate_multiple_verdicts_worst_wins
  ✓ test_aggregate_all_categories
  ✓ test_get_pr_level_verdict
  ✓ test_should_report_finding
  ✓ test_filter_findings_by_severity

Factory functions:
  ✓ test_create_chunker
  ✓ test_create_aggregator

End-to-end:
  ✓ test_chunking_preserves_all_hunks
  ✓ test_chunk_ids_unique_and_ordered
```

### Integration Tests (tests/test_phase3_per_chunk_detection.py)

- Multi-chunk diff detection
- SQL injection across chunks
- Multiple vulnerabilities in different chunks
- Chunk boundary handling
- Detector isolation between chunks

### End-to-End Tests (tests/test_phase5_integration.py)

- Large diff (40K+ tokens) chunking
- 10K token boundary handling
- Real-world scenarios (auth bypass, data exposure)
- System consistency and verdict stability
- Error handling (empty, malformed, Unicode)
- Performance metrics

## Configuration

### YAML Configuration (config/model_config.yaml)

```yaml
models:
  detector:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 26000
    output_reserve: 500
    safety_margin: 0.90
    temperature: 0.3

  prosecutor:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 20000
    output_reserve: 300
    safety_margin: 0.90
    temperature: 0.5

  defender:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 20000
    output_reserve: 300
    safety_margin: 0.90
    temperature: 0.5

  judge:
    model_name: "Qwen/Qwen2.5-Coder-32B-Instruct"
    max_tokens: 28000
    output_reserve: 500
    safety_margin: 0.90
    temperature: 0.3

tokenization:
  encoder: "cl100k_base"  # tiktoken encoder
  validation_samples: 5

retry_policy:
  max_retries: 3
  backoff_factor: 2.0

chunking:
  enabled: true
  max_chunk_tokens: 24000
  overlap_tokens: 500
  strategy: "semantic_file_boundary"

constants:
  hf_api_limit: 32768
```

### Environment Variable Overrides

```bash
# Token limits
SECURITY_AGENT_DETECTOR_TOKENS=23000
SECURITY_AGENT_PROSECUTOR_TOKENS=18000
SECURITY_AGENT_DEFENDER_TOKENS=18000
SECURITY_AGENT_JUDGE_TOKENS=25000

# Temperatures
SECURITY_AGENT_DETECTOR_TEMP=0.3
SECURITY_AGENT_PROSECUTOR_TEMP=0.5
SECURITY_AGENT_JUDGE_TEMP=0.3

# Chunking
SECURITY_AGENT_CHUNKING_ENABLED=true
SECURITY_AGENT_CHUNKING_MAX_TOKENS=24000
SECURITY_AGENT_CHUNKING_OVERLAP=500
```

## Troubleshooting

### "Single file X exceeds max_chunk_tokens"

**Cause**: File is too large for a single chunk.

**Solutions**:
1. Split file into smaller logical pieces
2. Increase `max_chunk_tokens` (not recommended without increasing `safety_margin`)
3. Disable chunking: `SECURITY_AGENT_CHUNKING_ENABLED=false` (risk of token overflow)

### Token count mismatch (tiktoken vs HF API)

**Cause**: Tiktoken and HF API count tokens differently.

**Solution**: Validation runs at startup. If mismatch >5%, token counts are re-calibrated using `HF_API_CALIBRATION_SAMPLES`.

### Slow analysis with many chunks

**Cause**: Large PR creates many chunks (e.g., 50+ API calls).

**Solutions**:
1. Review the PR size (consider splitting into smaller PRs)
2. Check rate limits: `1,000 requests / 5 min`
3. Increase `overlap_tokens` if findings are being missed at boundaries

### Missing findings in later chunks

**Cause**: Insufficient overlap or context loss.

**Solution**: Increase `overlap_tokens` (default 500) to preserve more context.

## Performance

| Scenario | Chunks | API Calls | Est. Time | Cost |
|----------|--------|-----------|-----------|------|
| Small diff (2K) | 1 | 3 | ~30s | $0.01 |
| Medium diff (15K) | 1 | 3 | ~45s | $0.01 |
| Large diff (40K) | 2 | 6 | ~90s | $0.02 |
| Huge diff (100K) | 4+ | 12+ | ~3m | $0.05+ |

*Estimates based on HF API Inference endpoint pricing*

## Future Enhancements

1. **Adaptive chunking**: Adjust chunk size based on diff complexity
2. **Caching**: Cache verdicts for unchanged files
3. **Parallel processing**: Run chunks in parallel (respecting rate limits)
4. **Hybrid strategy**: Mix semantic (file) and syntactic (function) chunking
5. **Streaming**: Stream verdicts as chunks complete
