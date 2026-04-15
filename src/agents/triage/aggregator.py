"""Verdict aggregation for multi-chunk analysis.

Combines per-chunk verdicts using worst-verdict-wins logic:
- If any chunk returns CRITICAL → PR is CRITICAL
- If any chunk returns MEDIUM → PR is MEDIUM (unless CRITICAL exists)
- All LOW and FALSE_POSITIVE → PR is LOW/FALSE_POSITIVE
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field
from src.core.models import JudgeVerdict, CategoryTriageVerdict


@dataclass
class AggregatedVerdict:
    """Aggregated verdict across all chunks for one category.
    
    Attributes:
        category: Vulnerability category (A05, A02, A10)
        final_verdict: Worst verdict across chunks (CRITICAL > MEDIUM > LOW > FALSE_POSITIVE)
        chunk_verdicts: Original per-chunk verdicts for traceability
        reasoning: Explanation of aggregation decision
        chunk_sources: Which chunks contributed to final verdict
    """
    category: str
    final_verdict: str  # CRITICAL, MEDIUM, LOW, FALSE_POSITIVE
    chunk_verdicts: List[JudgeVerdict] = field(default_factory=list)
    reasoning: str = ""
    chunk_sources: List[str] = field(default_factory=list)
    confidence: float = 0.0


class VerdictAggregator:
    """Aggregates per-chunk verdicts to PR-level verdict.
    
    Strategy: Worst verdict wins (security-conservative)
    - CRITICAL > MEDIUM > LOW > FALSE_POSITIVE
    
    All chunks analyzed for same category must agree on verdict,
    or worst case wins to be safe.
    """
    
    # Verdict ranking (higher = more severe)
    VERDICT_RANK = {
        "CRITICAL": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "FALSE_POSITIVE": 1,
    }
    
    # Reverse map for lookup
    RANK_TO_VERDICT = {v: k for k, v in VERDICT_RANK.items()}
    
    def aggregate_category_verdicts(
        self,
        category: str,
        chunk_verdicts: List[JudgeVerdict]
    ) -> AggregatedVerdict:
        """Aggregate verdicts for single category across all chunks.
        
        Args:
            category: Vulnerability category (A05, A02, A10)
            chunk_verdicts: JudgeVerdict from each chunk for this category
            
        Returns:
            AggregatedVerdict with final verdict and reasoning
        """
        if not chunk_verdicts:
            return AggregatedVerdict(
                category=category,
                final_verdict="FALSE_POSITIVE",
                reasoning="No findings in any chunk",
                chunk_verdicts=[]
            )
        
        # Find worst verdict
        worst_rank = 0
        worst_verdict = "FALSE_POSITIVE"
        critical_chunks = []
        medium_chunks = []
        
        for verdict in chunk_verdicts:
            rank = self.VERDICT_RANK.get(verdict.verdict, 0)
            if rank > worst_rank:
                worst_rank = rank
                worst_verdict = verdict.verdict
            
            if verdict.verdict == "CRITICAL":
                critical_chunks.append(verdict.chunk_id or "unknown")
            elif verdict.verdict == "MEDIUM":
                medium_chunks.append(verdict.chunk_id or "unknown")
        
        # Build reasoning
        if worst_verdict == "CRITICAL":
            reasoning = f"CRITICAL verdict found in {len(critical_chunks)} chunk(s): {', '.join(critical_chunks)}"
            chunk_sources = critical_chunks
        elif worst_verdict == "MEDIUM":
            reasoning = f"MEDIUM verdict found in {len(medium_chunks)} chunk(s): {', '.join(medium_chunks)}"
            chunk_sources = medium_chunks
        else:
            reasoning = "All chunks: LOW or FALSE_POSITIVE"
            chunk_sources = []
        
        # Calculate average confidence
        avg_confidence = sum(v.confidence_score for v in chunk_verdicts) / len(chunk_verdicts)
        
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
        """Aggregate verdicts for all categories.
        
        Args:
            verdicts_by_category: Dict mapping category → list of JudgeVerdicts
            
        Returns:
            Dict mapping category → AggregatedVerdict
        """
        aggregated = {}
        for category, verdicts in verdicts_by_category.items():
            aggregated[category] = self.aggregate_category_verdicts(category, verdicts)
        return aggregated
    
    def get_pr_level_verdict(
        self,
        aggregated: Dict[str, AggregatedVerdict]
    ) -> str:
        """Get overall PR verdict (worst across all categories).
        
        Args:
            aggregated: Dict of AggregatedVerdict by category
            
        Returns:
            Worst verdict (CRITICAL > MEDIUM > LOW > FALSE_POSITIVE)
        """
        worst_rank = 0
        worst_verdict = "FALSE_POSITIVE"
        
        for agg_verdict in aggregated.values():
            rank = self.VERDICT_RANK.get(agg_verdict.final_verdict, 0)
            if rank > worst_rank:
                worst_rank = rank
                worst_verdict = agg_verdict.final_verdict
        
        return worst_verdict
    
    def should_report_finding(self, verdict: str) -> bool:
        """Determine if finding should be reported to user.
        
        Strategy: Report CRITICAL and MEDIUM only (hide LOW and FALSE_POSITIVE)
        
        Args:
            verdict: Verdict string (CRITICAL, MEDIUM, LOW, FALSE_POSITIVE)
            
        Returns:
            True if finding should be reported
        """
        return verdict in ["CRITICAL", "MEDIUM"]
    
    def filter_findings_by_severity(
        self,
        aggregated: Dict[str, AggregatedVerdict],
        include_low: bool = False,
        include_false_positive: bool = False
    ) -> Dict[str, AggregatedVerdict]:
        """Filter findings based on severity threshold.
        
        Args:
            aggregated: Dict of AggregatedVerdict by category
            include_low: Include LOW severity (default: False)
            include_false_positive: Include FALSE_POSITIVE (default: False)
            
        Returns:
            Filtered dict with only relevant verdicts
        """
        filtered = {}
        for category, agg_verdict in aggregated.items():
            should_include = True
            
            if agg_verdict.final_verdict == "LOW" and not include_low:
                should_include = False
            elif agg_verdict.final_verdict == "FALSE_POSITIVE" and not include_false_positive:
                should_include = False
            
            if should_include:
                filtered[category] = agg_verdict
        
        return filtered


def create_aggregator() -> VerdictAggregator:
    """Factory: create aggregator instance.
    
    Returns:
        VerdictAggregator
    """
    return VerdictAggregator()
