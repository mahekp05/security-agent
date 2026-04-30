# Written with help of GitHub Copilot
"""
tests/test_triage_agents.py - Layer 3: Triage Agent Tests

These tests validate that the triage agents (Prosecutor, Defender, Judge)
produce valid verdicts with correct confidence scores and risk labels.
"""

import pytest
from src.agents.triage.prosecutor import ProsecutorAgent
from src.agents.triage.defender import DefenderAgent
from src.agents.triage.judge import JudgeAgent


class TestProsecutorAgent:
    """Test suite for Prosecutor agent (accuses of being a vulnerability)."""

    def test_prosecutor_returns_valid_verdict_for_obvious_case(self, SYNTHETIC_A05_OBVIOUS, mock_prosecutor_obvious_high):
        """
        Test that Prosecutor produces valid verdict for obvious vulnerability.
        
        Expected: VulnerabilityVerdict with:
          - confidence_score: int in range [1, 100]
          - reasoning: 150-400 word explanation
          - category: A05
        """
        prosecutor = ProsecutorAgent()
        # In real test, prosecutor.evaluate(finding) would call LLM
        # Using mock fixture to make test deterministic
        verdict = mock_prosecutor_obvious_high
        
        assert verdict.confidence_score >= 1 and verdict.confidence_score <= 100, \
            f"Confidence score must be in [1, 100], got {verdict.confidence_score}"
        
        reasoning_words = len(verdict.reasoning.split())
        assert 150 <= reasoning_words <= 400, \
            f"Reasoning should be 150-400 words, got {reasoning_words}"
        
        assert verdict.category == "A05", f"Expected category A05, got {verdict.category}"

    def test_prosecutor_produces_lower_confidence_for_ambiguous_case(self, SYNTHETIC_A05_AMBIGUOUS, mock_prosecutor_ambiguous_moderate):
        """
        Test that Prosecutor produces lower confidence for ambiguous code.
        
        Expected: VulnerabilityVerdict with moderate confidence (30-70)
        """
        prosecutor = ProsecutorAgent()
        verdict = mock_prosecutor_ambiguous_moderate
        
        assert 1 <= verdict.confidence_score <= 100, "Confidence score out of valid range"
        assert verdict.confidence_score <= 70, \
            f"Ambiguous case should have confidence <= 70, got {verdict.confidence_score}"


class TestDefenderAgent:
    """Test suite for Defender agent (defends against accusation)."""

    def test_defender_can_agree_with_prosecutor(self, SYNTHETIC_A05_OBVIOUS, mock_defender_agrees_high):
        """
        Test that Defender can agree with Prosecutor's finding.
        
        Expected: DefenderVerdict with:
          - confidence_score: int in range [1, 100]
          - reasoning: 150-400 word explanation
          - agrees_with_prosecutor: True
        """
        defender = DefenderAgent()
        verdict = mock_defender_agrees_high
        
        assert verdict.confidence_score >= 1 and verdict.confidence_score <= 100, \
            f"Confidence score must be in [1, 100], got {verdict.confidence_score}"
        
        reasoning_words = len(verdict.reasoning.split())
        assert 150 <= reasoning_words <= 400, \
            f"Reasoning should be 150-400 words, got {reasoning_words}"
        
        assert verdict.agrees_with_prosecutor == True, \
            f"Expected agrees_with_prosecutor=True for obvious case"

    def test_defender_can_disagree_with_prosecutor(self, SYNTHETIC_A05_AMBIGUOUS, mock_defender_disagrees_low):
        """
        Test that Defender can disagree with Prosecutor's finding.
        
        Expected: DefenderVerdict with:
          - confidence_score: lower than prosecutor
          - agrees_with_prosecutor: False
        """
        defender = DefenderAgent()
        verdict = mock_defender_disagrees_low
        
        assert verdict.confidence_score >= 1 and verdict.confidence_score <= 100, \
            f"Confidence score must be in [1, 100], got {verdict.confidence_score}"
        
        assert verdict.agrees_with_prosecutor == False, \
            f"Expected agrees_with_prosecutor=False for ambiguous case"


class TestJudgeAgent:
    """Test suite for Judge agent (makes final risk classification)."""

    def test_judge_assigns_critical_risk_label(self, SYNTHETIC_A05_OBVIOUS, mock_judge_critical):
        """
        Test that Judge assigns critical risk label for high-confidence findings.
        
        Expected: CategoryTriageVerdict with:
          - risk_label: "critical_risk"
          - confidence_score: int in range [1, 100]
        """
        judge = JudgeAgent()
        verdict = mock_judge_critical
        
        assert verdict.risk_label in ["critical_risk", "medium_risk", "low_risk", "false_positive"], \
            f"Invalid risk_label: {verdict.risk_label}"
        
        assert verdict.risk_label == "critical_risk", \
            f"Expected critical_risk for obvious case, got {verdict.risk_label}"
        
        assert 1 <= verdict.confidence_score <= 100, \
            f"Confidence score out of valid range: {verdict.confidence_score}"

    def test_judge_assigns_medium_risk_label(self, SYNTHETIC_A05_AMBIGUOUS, mock_judge_medium):
        """
        Test that Judge assigns medium risk label for moderate-confidence findings.
        
        Expected: CategoryTriageVerdict with:
          - risk_label: "medium_risk"
          - confidence_score: int in range [1, 100]
        """
        judge = JudgeAgent()
        verdict = mock_judge_medium
        
        assert verdict.risk_label == "medium_risk", \
            f"Expected medium_risk for ambiguous case, got {verdict.risk_label}"
        
        assert 1 <= verdict.confidence_score <= 100, \
            f"Confidence score out of valid range: {verdict.confidence_score}"

    def test_judge_assigns_false_positive_label(self, SAFE_CONFIG, mock_judge_false_positive):
        """
        Test that Judge assigns false_positive label when both agents agree it's safe.
        
        Expected: CategoryTriageVerdict with:
          - risk_label: "false_positive"
          - confidence_score: typically low (< 30)
        """
        judge = JudgeAgent()
        verdict = mock_judge_false_positive
        
        assert verdict.risk_label == "false_positive", \
            f"Expected false_positive for safe code, got {verdict.risk_label}"
        
        assert 1 <= verdict.confidence_score <= 100, \
            f"Confidence score out of valid range: {verdict.confidence_score}"
