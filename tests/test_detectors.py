"""
tests/test_detectors.py - Layer 2: Detector Tests

These tests validate that each detector (A05 Injection, A02 Configuration, A10 Error Handling)
correctly identifies vulnerabilities in DiffHunk objects.
"""

import pytest
from src.agents.detectors.injection_detector import detect_injection
from src.agents.detectors.configuration_detector import detect_configuration
from src.agents.detectors.errorHandling_detector import detect_error_handling


class TestA05InjectionDetector:
    """Test suite for A05 (Injection) detector."""

    def test_injection_detector_finds_obvious_sql_injection(self, OBVIOUS_SQL_INJECTION):
        """
        Test that detector identifies obvious SQL injection (f-string query).
        
        Expected: >= 1 finding with category A05, high confidence
        """
        findings = detect_injection([OBVIOUS_SQL_INJECTION])
        
        assert isinstance(findings, list)
        assert len(findings) >= 1, "Should find SQL injection vulnerability"
        
        finding = findings[0]
        assert finding.category == "A05", f"Expected category A05, got {finding.category}"
        assert finding.confidence in ["High", "Medium"], f"Expected High or Medium confidence, got {finding.confidence}"

    def test_injection_detector_skips_safe_parameterized_query(self, SAFE_SQL_QUERY):
        """
        Test that detector does not flag safe parameterized queries.
        
        Expected: Empty findings OR Low confidence
        """
        findings = detect_injection([SAFE_SQL_QUERY])
        
        assert isinstance(findings, list)
        # Safe query should produce no findings or only Low confidence findings
        if len(findings) > 0:
            assert all(f.confidence == "Low" for f in findings), "Safe query should only produce Low confidence"

    def test_injection_detector_references_specific_code(self, OBVIOUS_SQL_INJECTION):
        """
        Test that detector references specific vulnerable code in description.
        
        Expected: Description mentions f-string, format, query, or injection
        """
        findings = detect_injection([OBVIOUS_SQL_INJECTION])
        
        assert len(findings) >= 1
        finding = findings[0]
        
        description_lower = finding.description.lower()
        relevant_keywords = ["f-string", "f\"", "format", "injection", "query", "sql"]
        keyword_found = any(keyword in description_lower for keyword in relevant_keywords)
        assert keyword_found, f"Description should mention vulnerable pattern. Got: {finding.description}"

    def test_injection_detector_handles_empty_hunks(self):
        """
        Test that detector gracefully handles empty DiffHunk lists.
        
        Expected: Empty findings list (no crash)
        """
        from src.core.models import DiffHunk
        empty_hunk = DiffHunk(file_path="empty.py", added_lines=[], removed_lines=[])
        
        findings = detect_injection([empty_hunk])
        
        assert isinstance(findings, list)
        assert len(findings) == 0, "Empty hunk should produce no findings"


class TestA02ConfigurationDetector:
    """Test suite for A02 (Configuration) detector."""

    def test_config_detector_finds_exposed_api_key(self, EXPOSED_API_KEY):
        """
        Test that detector identifies exposed API keys.
        
        Expected: >= 1 finding with category A02, high confidence
        """
        findings = detect_configuration([EXPOSED_API_KEY])
        
        assert isinstance(findings, list)
        assert len(findings) >= 1, "Should find exposed API key"
        
        finding = findings[0]
        assert finding.category == "A02", f"Expected category A02, got {finding.category}"
        assert finding.confidence in ["High", "Medium"], f"Expected High or Medium confidence, got {finding.confidence}"

    def test_config_detector_skips_safe_config(self, SAFE_CONFIG):
        """
        Test that detector does not flag safe configuration.
        
        Expected: Empty findings OR Low confidence
        """
        findings = detect_configuration([SAFE_CONFIG])
        
        assert isinstance(findings, list)
        # Safe config should produce no findings or only Low confidence findings
        if len(findings) > 0:
            assert all(f.confidence == "Low" for f in findings), "Safe config should only produce Low confidence"

    def test_config_detector_references_specific_config(self, EXPOSED_API_KEY):
        """
        Test that detector references the exposed configuration in description.
        
        Expected: Description mentions key, secret, exposed, or hardcoded
        """
        findings = detect_configuration([EXPOSED_API_KEY])
        
        assert len(findings) >= 1
        finding = findings[0]
        
        description_lower = finding.description.lower()
        relevant_keywords = ["key", "secret", "exposed", "hardcoded", "api", "credential"]
        keyword_found = any(keyword in description_lower for keyword in relevant_keywords)
        assert keyword_found, f"Description should mention exposed pattern. Got: {finding.description}"

    def test_config_detector_handles_empty_hunks(self):
        """
        Test that detector gracefully handles empty DiffHunk lists.
        
        Expected: Empty findings list (no crash)
        """
        from src.core.models import DiffHunk
        empty_hunk = DiffHunk(file_path="empty.py", added_lines=[], removed_lines=[])
        
        findings = detect_configuration([empty_hunk])
        
        assert isinstance(findings, list)
        assert len(findings) == 0, "Empty hunk should produce no findings"


class TestA10ErrorHandlingDetector:
    """Test suite for A10 (Error Handling) detector."""

    def test_error_detector_finds_uncaught_exception(self, UNCAUGHT_EXCEPTION):
        """
        Test that detector identifies uncaught exceptions.
        
        Expected: >= 1 finding with category A10, high confidence
        """
        findings = detect_error_handling([UNCAUGHT_EXCEPTION])
        
        assert isinstance(findings, list)
        assert len(findings) >= 1, "Should find uncaught exception"
        
        finding = findings[0]
        assert finding.category == "A10", f"Expected category A10, got {finding.category}"
        assert finding.confidence in ["High", "Medium"], f"Expected High or Medium confidence, got {finding.confidence}"

    def test_error_detector_skips_safe_error_handling(self, SAFE_ERROR_HANDLING):
        """
        Test that detector does not flag safe error handling.
        
        Expected: Empty findings OR Low confidence
        """
        findings = detect_error_handling([SAFE_ERROR_HANDLING])
        
        assert isinstance(findings, list)
        # Safe error handling should produce no findings or only Low confidence findings
        if len(findings) > 0:
            assert all(f.confidence == "Low" for f in findings), "Safe error handling should only produce Low confidence"

    def test_error_detector_references_specific_error_pattern(self, UNCAUGHT_EXCEPTION):
        """
        Test that detector references the error handling issue in description.
        
        Expected: Description mentions exception, error, uncaught, or missing handler
        """
        findings = detect_error_handling([UNCAUGHT_EXCEPTION])
        
        assert len(findings) >= 1
        finding = findings[0]
        
        description_lower = finding.description.lower()
        relevant_keywords = ["exception", "error", "uncaught", "missing", "handler", "try", "catch"]
        keyword_found = any(keyword in description_lower for keyword in relevant_keywords)
        assert keyword_found, f"Description should mention error handling issue. Got: {finding.description}"

    def test_error_detector_handles_empty_hunks(self):
        """
        Test that detector gracefully handles empty DiffHunk lists.
        
        Expected: Empty findings list (no crash)
        """
        from src.core.models import DiffHunk
        empty_hunk = DiffHunk(file_path="empty.py", added_lines=[], removed_lines=[])
        
        findings = detect_error_handling([empty_hunk])
        
        assert isinstance(findings, list)
        assert len(findings) == 0, "Empty hunk should produce no findings"
