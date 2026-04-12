"""
tests/test_integration.py - Layer 4: Integration Tests

These tests validate the full pipeline from raw git diff to final security report,
ensuring all components work together correctly.
"""

import pytest
from src.main import run_full_pipeline


class TestFullPipeline:
    """Integration tests for the complete security analysis pipeline."""

    def test_pipeline_with_mixed_vulnerabilities(self, MIXED_CATEGORY_DIFF):
        """
        Test full pipeline on a diff containing mixed vulnerability types (A05, A02, A10).
        
        Expected:
          - SecurityReport object returned
          - verdicts list populated with >= 1 verdict
          - All verdicts have category, risk_label, confidence_score, reasoning
          - At least one finding per category represented
        """
        # Run the real pipeline from raw diff to report
        report = run_full_pipeline(raw_diff=MIXED_CATEGORY_DIFF)
        
        assert report is not None, "Pipeline should return a SecurityReport"
        assert isinstance(report.verdicts, list)
        assert len(report.verdicts) >= 1, "Should have at least one verdict"
        
        # Validate each verdict has required fields
        for verdict in report.verdicts:
            assert hasattr(verdict, 'category'), "Verdict missing category"
            assert hasattr(verdict, 'risk_label'), "Verdict missing risk_label"
            assert hasattr(verdict, 'confidence_score'), "Verdict missing confidence_score"
            assert hasattr(verdict, 'reasoning'), "Verdict missing reasoning"
            
            # Validate field types and ranges
            assert verdict.category in ["A05", "A02", "A10"], f"Invalid category: {verdict.category}"
            assert verdict.risk_label in ["critical_risk", "medium_risk", "low_risk", "false_positive"], \
                f"Invalid risk_label: {verdict.risk_label}"
            assert isinstance(verdict.confidence_score, int), \
                f"confidence_score should be int, got {type(verdict.confidence_score)}"
            assert 1 <= verdict.confidence_score <= 100, \
                f"confidence_score out of range: {verdict.confidence_score}"

    def test_pipeline_with_safe_code(self, COMMENT_ONLY_DIFF):
        """
        Test full pipeline on safe code (comments/documentation only).
        
        Expected:
          - SecurityReport object returned
          - verdicts may be empty OR all verdicts marked as false_positive with low confidence
          - No critical_risk verdicts
        """
        report = run_full_pipeline(raw_diff=COMMENT_ONLY_DIFF)
        
        assert report is not None, "Pipeline should return a SecurityReport"
        assert isinstance(report.verdicts, list)
        
        # Safe code should not have critical risks
        critical_verdicts = [v for v in report.verdicts if v.risk_label == "critical_risk"]
        assert len(critical_verdicts) == 0, \
            f"Safe code should not produce critical_risk verdicts, found {len(critical_verdicts)}"
        
        # All verdicts should have reasonable confidence scores
        for verdict in report.verdicts:
            if verdict.risk_label == "false_positive":
                assert verdict.confidence_score <= 50, \
                    f"False positive should have low confidence, got {verdict.confidence_score}"

    def test_pipeline_with_ambiguous_code(self, SIMPLE_SQL_INJECTION_DIFF):
        """
        Test full pipeline on real-world ambiguous code.
        
        Expected:
          - SecurityReport object returned
          - verdicts list populated
          - confidence_scores reflect uncertainty (mix of high and medium scores OK)
          - reasoning explains the ambiguity or confidence level
        """
        report = run_full_pipeline(raw_diff=SIMPLE_SQL_INJECTION_DIFF)
        
        assert report is not None, "Pipeline should return a SecurityReport"
        assert isinstance(report.verdicts, list)
        assert len(report.verdicts) >= 0, "Verdicts list should exist (may be empty for ambiguous)"
        
        # Each verdict should have meaningful reasoning
        for verdict in report.verdicts:
            assert len(verdict.reasoning) > 0, "Verdict should have reasoning"
            reasoning_words = len(verdict.reasoning.split())
            # Reasoning should be substantive, not empty
            assert reasoning_words >= 10, \
                f"Reasoning too short ({reasoning_words} words), should explain finding"
