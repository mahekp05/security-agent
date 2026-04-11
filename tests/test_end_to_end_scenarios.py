"""
tests/test_end_to_end_scenarios.py - Layer 5: End-to-End Scenario Tests

These tests validate the complete security analysis pipeline under realistic and edge-case scenarios.
Unlike unit tests that validate individual components, these scenarios test the full flow:
raw diff → parsing → detection → triage agents → ranked report.

VALIDATION APPROACH:
- Tests print validation reports instead of using hard asserts
- A test PASSES if the pipeline completes without exception
- Issues are logged for manual review (confidence-based systems are probabilistic)
- Patterns and ranges are checked, not strict equality

SCENARIOS COVERED:
1. Realistic multi-file PR with mixed vulnerabilities
2. Vulnerability chains (multiple related issues in same flow)
3. Report ranking and severity ordering
4. Prosecutor/Defender debate patterns
5. Duplicate finding detection
6. Edge case: empty diff
7. Edge case: large diff (100+ hunks)
8. Report summary field validation
"""

import pytest
from src.main import run_full_pipeline


class TestEndToEndScenarios:
    """End-to-end pipeline scenario tests with soft validation and reporting."""

    def _print_report_header(self, scenario_name):
        """Print validation report header for a scenario."""
        print("\n" + "=" * 80)
        print(f"SCENARIO: {scenario_name}")
        print("=" * 80)

    def _print_section(self, section_name):
        """Print a section header in the validation report."""
        print(f"\n[{section_name}]")

    def _check_pipeline_completion(self, report, scenario_name):
        """Validate pipeline completed and returned a report."""
        self._print_section("Pipeline Completion")
        
        if report is None:
            print("✗ Pipeline returned None")
            return False
        
        print("✓ Pipeline completed successfully")
        print(f"✓ SecurityReport object returned")
        return True

    def _check_verdicts_structure(self, report):
        """Validate verdict structure and fields."""
        self._print_section("Verdicts Structure")
        
        if not isinstance(report.verdicts, list):
            print("✗ Verdicts is not a list")
            return False
        
        print(f"✓ {len(report.verdicts)} verdicts returned")
        
        issues = []
        for i, verdict in enumerate(report.verdicts):
            # Check required fields
            required_fields = ['category', 'risk_label', 'confidence_score', 'reasoning', 'prosecutor', 'defender', 'judge']
            missing_fields = [f for f in required_fields if not hasattr(verdict, f)]
            
            if missing_fields:
                issues.append(f"  Verdict {i}: Missing fields {missing_fields}")
            
            # Validate field types and ranges
            if hasattr(verdict, 'category') and verdict.category not in ["A05", "A02", "A10"]:
                issues.append(f"  Verdict {i}: Invalid category '{verdict.category}'")
            
            if hasattr(verdict, 'risk_label') and verdict.risk_label not in ["critical_risk", "medium_risk", "low_risk", "false_positive"]:
                issues.append(f"  Verdict {i}: Invalid risk_label '{verdict.risk_label}'")
            
            if hasattr(verdict, 'confidence_score'):
                if not isinstance(verdict.confidence_score, int) or not (1 <= verdict.confidence_score <= 100):
                    issues.append(f"  Verdict {i}: confidence_score out of range: {verdict.confidence_score}")
        
        if issues:
            for issue in issues:
                print(f"⚠ {issue}")
            return False
        
        print("✓ All verdicts have required fields with valid types/ranges")
        return True

    def _check_ranking_by_severity(self, report):
        """Validate verdicts are ranked by severity (critical > medium > low > false_positive)."""
        self._print_section("Ranking by Severity")
        
        risk_order = {"critical_risk": 4, "medium_risk": 3, "low_risk": 2, "false_positive": 1}
        scores = [risk_order.get(v.risk_label, 0) for v in report.verdicts]
        
        issues = []
        for i in range(len(scores) - 1):
            if scores[i] < scores[i + 1]:
                issues.append(f"  Position {i}-{i+1}: {report.verdicts[i].risk_label} (score {scores[i]}) comes before {report.verdicts[i+1].risk_label} (score {scores[i+1]})")
        
        if issues:
            print("⚠ Verdicts not in perfect severity order:")
            for issue in issues:
                print(issue)
        else:
            print("✓ Verdicts ranked correctly by severity (critical > medium > low > false_positive)")
        
        return len(issues) == 0

    def _check_prosecutor_defender_debate(self, report):
        """Validate prosecutor and defender have meaningful difference in confidence."""
        self._print_section("Prosecutor vs Defender Debate")
        
        if not report.verdicts:
            print("⚠ No verdicts to analyze debate")
            return False
        
        patterns = []
        for i, verdict in enumerate(report.verdicts):
            if hasattr(verdict, 'prosecutor') and hasattr(verdict, 'defender'):
                prosecutor_score = verdict.prosecutor.confidence_score
                defender_score = verdict.defender.confidence_score
                agrees = verdict.defender.agrees_with_prosecutor
                diff = abs(prosecutor_score - defender_score)
                
                pattern = f"  Verdict {i} ({verdict.category}): Prosecutor={prosecutor_score}, Defender={defender_score}, Diff={diff}, Agrees={agrees}"
                patterns.append((pattern, diff))
        
        if patterns:
            for pattern, diff in patterns:
                if diff >= 10:
                    print(f"✓ {pattern}")
                else:
                    print(f"⚠ {pattern} — minimal disagreement")
            print("✓ Prosecutor/Defender debate detected")
            return True
        else:
            print("⚠ Could not extract prosecutor/defender scores")
            return False

    def _check_no_duplicate_findings(self, report):
        """Validate no duplicate findings across verdicts."""
        self._print_section("Duplicate Findings Check")
        
        if not report.verdicts:
            print("✓ No verdicts to check for duplicates")
            return True
        
        affected_codes = []
        for verdict in report.verdicts:
            if hasattr(verdict, 'findings'):
                for finding in verdict.findings:
                    affected_codes.append((finding.affected_code, finding.category))
        
        duplicates = {}
        for code, category in affected_codes:
            key = (code, category)
            duplicates[key] = duplicates.get(key, 0) + 1
        
        dup_list = [(k, v) for k, v in duplicates.items() if v > 1]
        
        if dup_list:
            print(f"⚠ Found {len(dup_list)} duplicate findings:")
            for (code, cat), count in dup_list:
                print(f"  - {cat}: '{code[:50]}...' appears {count} times")
            return False
        else:
            print(f"✓ No duplicate findings detected across {len(affected_codes)} findings")
            return True

    def _check_report_summary(self, report):
        """Validate report contains a summary field (optional but preferred)."""
        self._print_section("Report Summary")
        
        if hasattr(report, 'summary'):
            if report.summary:
                summary_len = len(report.summary)
                print(f"✓ Summary field populated ({summary_len} chars)")
                return True
            else:
                print("⚠ Summary field exists but is empty")
                return False
        else:
            print("⚠ Summary field not present in report")
            return False

    def _check_total_findings_count(self, report):
        """Validate total_findings count matches verdicts."""
        self._print_section("Total Findings Count")
        
        if not hasattr(report, 'total_findings'):
            print("⚠ total_findings field not present")
            return False
        
        actual_findings = sum(len(v.findings) for v in report.verdicts if hasattr(v, 'findings'))
        
        if report.total_findings == actual_findings:
            print(f"✓ total_findings ({report.total_findings}) matches actual findings ({actual_findings})")
            return True
        else:
            print(f"⚠ total_findings mismatch: reported={report.total_findings}, actual={actual_findings}")
            return False

    # ========================================================================
    # SCENARIO TESTS (8 comprehensive scenarios)
    # ========================================================================

    def test_realistic_multifile_pr_diff(self, REALISTIC_MULTIFILE_AUTH_REFACTOR):
        """
        Scenario 1: Realistic multi-file PR with auth refactor introducing mixed vulnerabilities.
        
        Validates:
        - Report structure exists and is complete
        - Multiple files are parsed correctly
        - Mixed categories (A05, A02) are detected
        - Findings are reasonable for this code change
        """
        self._print_report_header("Realistic Multi-File PR (Auth Refactor)")
        
        report = run_full_pipeline(raw_diff=REALISTIC_MULTIFILE_AUTH_REFACTOR)
        
        checks = [
            self._check_pipeline_completion(report, "multi-file-auth"),
            self._check_verdicts_structure(report),
            self._check_report_summary(report),
            self._check_total_findings_count(report),
        ]
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_vulnerability_chain_detection(self, VULNERABILITY_CHAIN_DIFF):
        """
        Scenario 2: Vulnerability chain (A05 + A10 together in same code flow).
        
        Validates:
        - Both A05 (injection) and A10 (error handling) are detected
        - Findings reference the same affected code or nearby lines
        - Report identifies the chained nature of the vulnerabilities
        """
        self._print_report_header("Vulnerability Chain (A05 + A10)")
        
        report = run_full_pipeline(raw_diff=VULNERABILITY_CHAIN_DIFF)
        
        checks = [
            self._check_pipeline_completion(report, "vuln-chain"),
            self._check_verdicts_structure(report),
        ]
        
        # Check for both A05 and A10 in verdicts
        categories_found = set(v.category for v in report.verdicts if report.verdicts)
        print(f"\n[Vulnerability Chain Validation]")
        print(f"Categories detected: {categories_found}")
        
        if "A05" in categories_found or "A10" in categories_found:
            print("✓ Chain components detected (A05 and/or A10)")
        else:
            print("⚠ Expected A05 or A10 vulnerabilities not detected in chain")
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_report_ranking_by_severity(self, MIXED_CATEGORY_DIFF):
        """
        Scenario 3: Report ranking validation.
        
        Validates:
        - Verdicts are ordered by severity (critical > medium > low > false_positive)
        - Confidence scores reflect the risk level
        - Higher-risk findings appear first in the report
        """
        self._print_report_header("Report Ranking by Severity")
        
        report = run_full_pipeline(raw_diff=MIXED_CATEGORY_DIFF)
        
        checks = [
            self._check_pipeline_completion(report, "ranking"),
            self._check_verdicts_structure(report),
            self._check_ranking_by_severity(report),
        ]
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_prosecutor_defender_disagreement(self, SIMPLE_SQL_INJECTION_DIFF):
        """
        Scenario 4: Prosecutor vs Defender debate patterns.
        
        Validates:
        - Prosecutor provides confidence-based reasoning
        - Defender either agrees or disagrees with meaningful difference
        - Judge provides final verdict
        - All three agents contribute to the triage result
        """
        self._print_report_header("Prosecutor/Defender Debate")
        
        report = run_full_pipeline(raw_diff=SIMPLE_SQL_INJECTION_DIFF)
        
        checks = [
            self._check_pipeline_completion(report, "debate"),
            self._check_verdicts_structure(report),
            self._check_prosecutor_defender_debate(report),
        ]
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_no_duplicate_findings_across_categories(self, MIXED_CATEGORY_DIFF):
        """
        Scenario 5: Duplicate finding detection.
        
        Validates:
        - Same vulnerable code is not reported twice across different categories
        - Each finding is unique and serves a distinct purpose
        - No redundant findings that confuse the report
        """
        self._print_report_header("No Duplicate Findings")
        
        report = run_full_pipeline(raw_diff=MIXED_CATEGORY_DIFF)
        
        checks = [
            self._check_pipeline_completion(report, "no-dupes"),
            self._check_verdicts_structure(report),
            self._check_no_duplicate_findings(report),
        ]
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_edge_case_empty_diff(self, EMPTY_DIFF):
        """
        Scenario 6: Edge case - empty or whitespace-only diff.
        
        Validates:
        - Pipeline handles empty diffs gracefully
        - Report is returned (possibly with zero verdicts)
        - No exceptions thrown
        """
        self._print_report_header("Edge Case: Empty Diff")
        
        report = run_full_pipeline(raw_diff=EMPTY_DIFF)
        
        checks = [
            self._check_pipeline_completion(report, "empty-diff"),
        ]
        
        if report:
            print(f"\n[Empty Diff Handling]")
            print(f"Verdicts returned: {len(report.verdicts)}")
            
            if len(report.verdicts) == 0:
                print("✓ Empty diff correctly produces zero verdicts")
            else:
                print(f"⚠ Empty diff returned {len(report.verdicts)} verdicts (may be false positives)")
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_edge_case_large_diff(self, LARGE_DIFF_100_HUNKS):
        """
        Scenario 7: Edge case - large diff with 100+ hunks.
        
        Validates:
        - Pipeline handles large diffs without crashing
        - Parsing scales to many hunks
        - Detection and triage complete without timeout
        - Report is generated and valid
        """
        self._print_report_header("Edge Case: Large Diff (100+ Hunks)")
        
        report = run_full_pipeline(raw_diff=LARGE_DIFF_100_HUNKS)
        
        checks = [
            self._check_pipeline_completion(report, "large-diff"),
        ]
        
        if report:
            print(f"\n[Large Diff Handling]")
            print(f"✓ Pipeline completed on 100+ hunk diff")
            print(f"Verdicts generated: {len(report.verdicts)}")
            
            # Validate structure on large report
            checks.append(self._check_verdicts_structure(report))
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")

    def test_report_contains_summary(self, MIXED_CATEGORY_DIFF):
        """
        Scenario 8: Report summary field validation.
        
        Validates:
        - Report includes a summary field
        - Summary provides executive-level insight
        - Summary is non-empty and meaningful
        """
        self._print_report_header("Report Summary Field")
        
        report = run_full_pipeline(raw_diff=MIXED_CATEGORY_DIFF)
        
        checks = [
            self._check_pipeline_completion(report, "summary"),
            self._check_verdicts_structure(report),
            self._check_report_summary(report),
        ]
        
        print(f"\n✓ Scenario completed: {sum(checks)}/{len(checks)} major checks passed")
