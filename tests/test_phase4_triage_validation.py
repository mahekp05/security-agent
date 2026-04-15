"""Phase 4: Per-chunk triage validation.

Tests that verdicts are correctly aggregated across chunks using
worst-verdict-wins logic to produce final security assessments.
"""

import pytest
from src.main import _analyze_diff, run_full_pipeline
from src.agents.triage.aggregator import VerdictAggregator, create_aggregator
from src.core.models import JudgeVerdict, CategoryTriageVerdict


class TestVerdictAggregationLogic:
    """Test verdict aggregation across chunks."""
    
    def test_worst_verdict_wins_critical_beats_medium(self):
        """Test that CRITICAL verdict overrides MEDIUM from other chunks."""
        aggregator = create_aggregator()
        
        # Chunk 1: MEDIUM risk
        chunk1_verdict = JudgeVerdict(
            risk_label="medium_risk",
            reasoning="Possible SQL injection",
            confidence_score=70,
            chunk_id="chunk_1",
            verdict="MEDIUM"
        )
        
        # Chunk 2: CRITICAL risk
        chunk2_verdict = JudgeVerdict(
            risk_label="critical_risk",
            reasoning="Definite SQL injection with UNION",
            confidence_score=95,
            chunk_id="chunk_2",
            verdict="CRITICAL"
        )
        
        agg = aggregator.aggregate_category_verdicts("A05", [chunk1_verdict, chunk2_verdict])
        
        # Should take CRITICAL from chunk_2
        assert agg.final_verdict == "CRITICAL"
        assert "chunk_2" in agg.reasoning.lower() or agg.chunk_sources
    
    def test_worst_verdict_wins_medium_beats_low(self):
        """Test that MEDIUM verdict overrides LOW from other chunks."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(risk_label="low_risk", reasoning="Low", confidence_score=30, chunk_id="chunk_1", verdict="LOW"),
            JudgeVerdict(risk_label="medium_risk", reasoning="Medium", confidence_score=65, chunk_id="chunk_2", verdict="MEDIUM"),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A02", verdicts)
        
        assert agg.final_verdict == "MEDIUM"
    
    def test_worst_verdict_wins_false_positive_ignored(self):
        """Test that FALSE_POSITIVE is overridden by any real verdict."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(risk_label="false_positive", reasoning="Looks suspicious but safe", confidence_score=40, chunk_id="chunk_1", verdict="FALSE_POSITIVE"),
            JudgeVerdict(risk_label="low_risk", reasoning="Actually risky", confidence_score=50, chunk_id="chunk_2", verdict="LOW"),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A05", verdicts)
        
        assert agg.final_verdict == "LOW"
    
    def test_all_false_positives_stays_false_positive(self):
        """Test that all FALSE_POSITIVE verdicts result in FALSE_POSITIVE."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(risk_label="false_positive", reasoning="Not risky", confidence_score=20, chunk_id="chunk_1", verdict="FALSE_POSITIVE"),
            JudgeVerdict(risk_label="false_positive", reasoning="Safe code", confidence_score=25, chunk_id="chunk_2", verdict="FALSE_POSITIVE"),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A05", verdicts)
        
        assert agg.final_verdict == "FALSE_POSITIVE"


class TestMultiCategoryAggregation:
    """Test aggregation across multiple vulnerability categories."""
    
    def test_aggregate_multiple_categories(self):
        """Test aggregating verdicts from multiple categories."""
        aggregator = create_aggregator()
        
        verdicts_by_category = {
            "A05": [
                JudgeVerdict(risk_label="critical_risk", reasoning="SQL injection", confidence_score=90, chunk_id="chunk_1", verdict="CRITICAL"),
            ],
            "A02": [
                JudgeVerdict(risk_label="low_risk", reasoning="API key in comment", confidence_score=40, chunk_id="chunk_1", verdict="LOW"),
            ],
            "A10": [
                JudgeVerdict(risk_label="medium_risk", reasoning="Bare except", confidence_score=65, chunk_id="chunk_2", verdict="MEDIUM"),
            ],
        }
        
        agg_all = aggregator.aggregate_all_categories(verdicts_by_category)
        
        assert len(agg_all) == 3
        assert agg_all["A05"].final_verdict == "CRITICAL"
        assert agg_all["A02"].final_verdict == "LOW"
        assert agg_all["A10"].final_verdict == "MEDIUM"
    
    def test_pr_level_verdict_is_worst_verdict(self):
        """Test that PR-level verdict is the worst across all categories."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'CRITICAL'})(),
            "A02": type('AggVerd', (), {'final_verdict': 'MEDIUM'})(),
            "A10": type('AggVerd', (), {'final_verdict': 'LOW'})(),
        }
        
        pr_verdict = aggregator.get_pr_level_verdict(aggregated)
        
        # Should return CRITICAL (worst)
        assert pr_verdict == "CRITICAL"
    
    def test_pr_level_verdict_all_low(self):
        """Test PR verdict when all categories are LOW."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'LOW'})(),
            "A02": type('AggVerd', (), {'final_verdict': 'LOW'})(),
            "A10": type('AggVerd', (), {'final_verdict': 'FALSE_POSITIVE'})(),
        }
        
        pr_verdict = aggregator.get_pr_level_verdict(aggregated)
        
        # Should return LOW (worst real verdict)
        assert pr_verdict == "LOW"
    
    def test_pr_level_verdict_all_false_positive(self):
        """Test PR verdict when all categories are FALSE_POSITIVE."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'FALSE_POSITIVE'})(),
            "A02": type('AggVerd', (), {'final_verdict': 'FALSE_POSITIVE'})(),
        }
        
        pr_verdict = aggregator.get_pr_level_verdict(aggregated)
        
        # Should return FALSE_POSITIVE
        assert pr_verdict == "FALSE_POSITIVE"


class TestVerdictSeverityFiltering:
    """Test filtering verdicts by severity level."""
    
    def test_should_report_critical(self):
        """Test that CRITICAL findings are always reported."""
        aggregator = create_aggregator()
        
        assert aggregator.should_report_finding("CRITICAL") is True
    
    def test_should_report_medium(self):
        """Test that MEDIUM findings are reported by default."""
        aggregator = create_aggregator()
        
        assert aggregator.should_report_finding("MEDIUM") is True
    
    def test_should_not_report_low_by_default(self):
        """Test that LOW findings are not reported by default."""
        aggregator = create_aggregator()
        
        assert aggregator.should_report_finding("LOW") is False
    
    def test_should_not_report_false_positive_by_default(self):
        """Test that FALSE_POSITIVE is not reported by default."""
        aggregator = create_aggregator()
        
        assert aggregator.should_report_finding("FALSE_POSITIVE") is False
    
    def test_filter_findings_excludes_low(self):
        """Test that LOW findings are filtered out by default."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'CRITICAL'})(),
            "A02": type('AggVerd', (), {'final_verdict': 'LOW'})(),
            "A10": type('AggVerd', (), {'final_verdict': 'MEDIUM'})(),
        }
        
        filtered = aggregator.filter_findings_by_severity(aggregated)
        
        # Should only include CRITICAL and MEDIUM
        assert "A05" in filtered
        assert "A10" in filtered
        assert "A02" not in filtered
    
    def test_filter_findings_includes_low_when_requested(self):
        """Test that LOW findings are included when explicitly requested."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'CRITICAL'})(),
            "A02": type('AggVerd', (), {'final_verdict': 'LOW'})(),
        }
        
        filtered = aggregator.filter_findings_by_severity(aggregated, include_low=True)
        
        assert "A05" in filtered
        assert "A02" in filtered
    
    def test_filter_findings_includes_false_positive_when_requested(self):
        """Test that FALSE_POSITIVE is included when explicitly requested."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'FALSE_POSITIVE'})(),
            "A02": type('AggVerd', (), {'final_verdict': 'CRITICAL'})(),
        }
        
        filtered = aggregator.filter_findings_by_severity(aggregated, include_false_positive=True)
        
        assert "A05" in filtered
        assert "A02" in filtered


class TestChunkVerdictIntegration:
    """Test verdicts properly include chunk information."""
    
    def test_aggregated_verdict_tracks_chunk_sources(self):
        """Test that aggregated verdict tracks which chunks contributed."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(risk_label="low_risk", reasoning="Chunk 1", confidence_score=30, chunk_id="chunk_1", verdict="LOW"),
            JudgeVerdict(risk_label="critical_risk", reasoning="Chunk 2", confidence_score=95, chunk_id="chunk_2", verdict="CRITICAL"),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A05", verdicts)
        
        # Should track that chunk_2 had the critical verdict
        assert agg.chunk_sources
        assert any("chunk_2" in str(source).lower() for source in agg.chunk_sources)
    
    def test_aggregated_verdict_confidence_averaging(self):
        """Test that confidence score is averaged across chunks."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(risk_label="medium_risk", reasoning="C1", confidence_score=60, chunk_id="chunk_1", verdict="MEDIUM"),
            JudgeVerdict(risk_label="medium_risk", reasoning="C2", confidence_score=80, chunk_id="chunk_2", verdict="MEDIUM"),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A05", verdicts)
        
        # Average should be (60 + 80) / 2 = 70
        assert agg.confidence == 70.0


class TestPhase4EndToEnd:
    """End-to-end tests for Phase 4 triage validation."""
    
    def test_multi_chunk_diff_produces_aggregated_verdict(self):
        """Test that multi-chunk diff produces correctly aggregated verdicts."""
        diff = """
diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1,50 +1,70 @@
+def search(query):
+    sql = "SELECT * FROM users WHERE id=" + query
+    return db.execute(sql)

diff --git a/file2.py b/file2.py
--- a/file2.py
+++ b/file2.py
@@ -1,20 +1,30 @@
+DATABASE_PASSWORD = "admin123"
+API_KEY = "sk_prod_xyz"
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should have verdicts
        if verdicts:
            # All verdicts should have category
            for verdict in verdicts:
                assert verdict.category, "Verdict should have category"
                assert verdict.judge.verdict is not None, "Verdict should have judge verdict"
    
    def test_verdicts_correctly_ordered_by_severity(self):
        """Test that verdicts are ordered from most to least severe."""
        diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,100 +1,150 @@
+# Multiple vulnerabilities
+PASSWORD = "hardcoded"
+def run(cmd): os.system(cmd)
+try: data = process()
+except: pass
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        if verdicts and len(verdicts) > 1:
            # Verdicts should be sorted (CRITICAL first if present)
            verdict_values = [v.judge.verdict for v in verdicts if v.judge and v.judge.verdict]
            
            # Build rank dict for comparison
            rank = {"CRITICAL": 4, "MEDIUM": 3, "LOW": 2, "FALSE_POSITIVE": 1}
            
            # Check descending order
            for i in range(len(verdict_values) - 1):
                curr = verdict_values[i]
                next_v = verdict_values[i + 1]
                if curr and next_v:
                    assert rank.get(curr, 0) >= rank.get(next_v, 0), \
                        f"Verdicts not ordered: {curr} should come before {next_v}"
    
    def test_phase4_full_pipeline_with_aggregation(self):
        """Test full pipeline with aggregation from end to end."""
        diff = """
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,30 +1,50 @@
+SECRET_KEY = "my_secret_key_123"
+ADMIN_PASSWORD = "admin123"
+DATABASE_CONNECTION = "postgresql://user:pass@host"

diff --git a/handlers.py b/handlers.py
--- a/handlers.py
+++ b/handlers.py
@@ -1,50 +1,80 @@
+def query_db(user_id):
+    sql = "SELECT * FROM users WHERE id=" + str(user_id)
+    return db.execute(sql)
+
+def handle_request():
+    try:
+        process_data()
+    except:
+        pass
"""
        
        report = run_full_pipeline(raw_diff=diff)
        
        # Should have findings in the report
        assert report, "Should produce a report"
        assert report.total_findings > 0, "Report should have findings"
        assert len(report.verdicts) > 0, "Report should have verdicts"
    
    def test_single_critical_in_chunk1_verdict(self):
        """Test that single CRITICAL in chunk becomes verdict."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(
                risk_label="critical_risk",
                reasoning="Definite vulnerability",
                confidence_score=95,
                chunk_id="chunk_1",
                verdict="CRITICAL"
            ),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A05", verdicts)
        
        assert agg.final_verdict == "CRITICAL"
        assert agg.average_confidence == 95.0
    
    def test_chunk_summary_in_aggregated_verdict(self):
        """Test that aggregated verdict includes chunk summary."""
        aggregator = create_aggregator()
        
        verdicts = [
            JudgeVerdict(risk_label="low_risk", reasoning="Chunk 1", confidence_score=40, chunk_id="chunk_1", verdict="LOW"),
            JudgeVerdict(risk_label="critical_risk", reasoning="Chunk 2", confidence_score=90, chunk_id="chunk_2", verdict="CRITICAL"),
            JudgeVerdict(risk_label="medium_risk", reasoning="Chunk 3", confidence_score=65, chunk_id="chunk_3", verdict="MEDIUM"),
        ]
        
        agg = aggregator.aggregate_category_verdicts("A05", verdicts)
        
        # Aggregated verdict should reference worst verdict source
        assert agg.final_verdict == "CRITICAL"
        # Should have processed all 3 verdicts
        assert len(agg.chunk_verdicts) == 3


class TestVerdictReporting:
    """Test verdict reporting and filtering for output."""
    
    def test_critical_always_reportable(self):
        """Test that CRITICAL verdicts are always included in reports."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A05": type('AggVerd', (), {'final_verdict': 'CRITICAL'})(),
        }
        
        filtered = aggregator.filter_findings_by_severity(aggregated)
        
        assert "A05" in filtered, "CRITICAL should always be reported"
    
    def test_medium_always_reportable(self):
        """Test that MEDIUM verdicts are always included in reports."""
        aggregator = create_aggregator()
        
        aggregated = {
            "A02": type('AggVerd', (), {'final_verdict': 'MEDIUM'})(),
        }
        
        filtered = aggregator.filter_findings_by_severity(aggregated)
        
        assert "A02" in filtered, "MEDIUM should be reported by default"
    
    def test_report_structure_with_aggregated_verdicts(self):
        """Test that report properly structures aggregated verdicts."""
        diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,20 +1,30 @@
+import os
+api_key = "sk_live_123"
+def run(x): os.system(x)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        if verdicts:
            # Each verdict should be properly structured
            for verdict in verdicts:
                assert hasattr(verdict, 'category'), "Verdict missing category"
                assert hasattr(verdict, 'judge'), "Verdict missing judge"
                assert hasattr(verdict.judge, 'verdict'), "Judge missing verdict field"
                # verdict.judge.verdict should be one of the valid values
                valid = ["CRITICAL", "MEDIUM", "LOW", "FALSE_POSITIVE"]
                assert verdict.judge.verdict in valid, f"Invalid verdict: {verdict.judge.verdict}"
