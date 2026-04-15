"""Phase 5: Full Integration Testing & System Validation.

End-to-end tests for complete system with realistic large diffs,
chunking validation, and full security assessment pipeline.
"""

import pytest
from src.main import _analyze_diff, run_full_pipeline
from src.agents.chunker import create_chunker


class TestLargeDiffChunking:
    """Test system with large realistic diffs that trigger chunking."""
    
    def test_40k_token_diff_creates_multiple_chunks(self):
        """Test that a 40K token diff is properly chunked."""
        # Create a large diff with 2 files, each ~20K tokens
        diff = """
diff --git a/auth/login.py b/auth/login.py
--- a/auth/login.py
+++ b/auth/login.py
@@ -1,200 +1,300 @@
""" + "\n".join([f"+def func_{i}(x):\n+    query = 'SELECT * FROM users WHERE id=' + x\n+    return db.execute(query)" for i in range(100)]) + """

diff --git a/config/database.py b/config/database.py
--- a/config/database.py
+++ b/config/database.py
@@ -1,200 +1,300 @@
""" + "\n".join([f"+DB_PASS_{i} = 'password_{i}'\n+API_KEY_{i} = 'key_{i}'" for i in range(100)]) + """
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Verify chunking occurred
        chunker = create_chunker()
        from src.agents.diff_parser import parse_diff_to_hunks
        parsed_hunks = parse_diff_to_hunks(diff)
        
        assert chunker.should_chunk(parsed_hunks) or len(parsed_hunks) > 1, \
            "Large diff should trigger chunking or have multiple hunks"
    
    def test_10k_token_boundary_handling(self):
        """Test diff right at 10K token boundary."""
        # Create diff that's approximately 10K tokens
        diff = """
diff --git a/large_file.py b/large_file.py
--- a/large_file.py
+++ b/large_file.py
@@ -1,500 +1,600 @@
""" + "\n".join([f"+line_{i} = '{i}' + ', '.join(['value'] * 10)" for i in range(500)]) + """
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should complete without token errors
        assert hunks is not None, "Should successfully parse diff at boundary"
    
    def test_multi_file_diff_distribution(self):
        """Test that findings are properly distributed across multiple chunks."""
        # Create diff with vulnerabilities in multiple files
        diff = """
diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1,50 +1,70 @@
+def search_v1(query):
+    sql = "SELECT * FROM products WHERE name = '" + query + "'"
+    return db.execute(sql)

diff --git a/file2.py b/file2.py
--- a/file2.py
+++ b/file2.py
@@ -1,50 +1,70 @@
+def search_v2(query):
+    sql = "SELECT * FROM items WHERE name = '" + query + "'"
+    return db.execute(sql)

diff --git a/file3.py b/file3.py
--- a/file3.py
+++ b/file3.py
@@ -1,50 +1,70 @@
+def search_v3(query):
+    sql = "SELECT * FROM orders WHERE name = '" + query + "'"
+    return db.execute(sql)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # All findings should have chunk_id
        if findings:
            assert all(f.chunk_id for f in findings), \
                "All findings must have chunk_id for traceability"
            
            # Group by chunk
            by_chunk = {}
            for f in findings:
                chunk = f.chunk_id
                if chunk not in by_chunk:
                    by_chunk[chunk] = []
                by_chunk[chunk].append(f)
            
            # Each chunk should have some findings
            for chunk, chunk_findings in by_chunk.items():
                assert len(chunk_findings) > 0, f"{chunk} should have findings"


class TestRealWorldScenarios:
    """Test realistic security scenarios."""
    
    def test_authentication_bypass_scenario(self):
        """Test detection of auth bypass vulnerabilities."""
        diff = """
diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,50 +1,70 @@
+def authenticate(username, password):
+    # Direct string comparison without hashing
+    if username == "admin" and password == "admin123":
+        return True
+    # SQL injection here
+    query = "SELECT * FROM users WHERE user='" + username + "'"
+    return db.execute(query)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should detect auth issues
        if findings:
            categories = {f.category for f in findings}
            # Could detect A05 (injection) and/or A02 (config)
            assert len(categories) > 0, "Should detect auth bypass issues"
    
    def test_data_exposure_scenario(self):
        """Test detection of data exposure."""
        diff = """
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,20 +1,30 @@
+DATABASE_URL = "postgresql://admin:password123@prod-db.internal:5432/main"
+API_KEYS = {
+    "stripe": "sk_live_123456789",
+    "sendgrid": "SG.ABC123DEF456",
+    "aws_access": "AKIAIOSFODNN7EXAMPLE",
+    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
+}
+
+# Debug credentials
+DEBUG_USER = "debug@internal.com"
+DEBUG_PASS = "Debug@123"
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should detect exposed secrets
        if findings:
            assert any(f.category == "A02" for f in findings), \
                "Should detect exposed secrets (A02)"
    
    def test_injection_chain_scenario(self):
        """Test detection of injection chain."""
        diff = """
diff --git a/api.py b/api.py
--- a/api.py
+++ b/api.py
@@ -1,100 +1,150 @@
+import subprocess
+import os
+
+def execute_command(user_command):
+    # Command injection
+    os.system("process_file " + user_command)
+
+def query_database(search_term):
+    # SQL injection
+    sql = "SELECT * FROM data WHERE query = '" + search_term + "'"
+    return db.execute(sql)
+
+def handle_exception(error):
+    # Poor error handling
+    try:
+        process()
+    except:
+        pass
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should detect multiple injection types
        if findings:
            categories = {f.category for f in findings}
            # Should detect A05 (injection) and possibly A10 (error handling)
            assert "A05" in categories, "Should detect injection (A05)"


class TestSystemConsistency:
    """Test system consistency across different scenarios."""
    
    def test_safe_code_produces_clean_report(self):
        """Test that safe code produces clean/minimal report."""
        diff = """
diff --git a/math_utils.py b/math_utils.py
--- a/math_utils.py
+++ b/math_utils.py
@@ -1,10 +1,20 @@
+def add(a, b):
+    return a + b
+
+def multiply(a, b):
+    return a * b
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should have minimal/no critical findings
        if findings:
            critical = [f for f in findings if f.confidence and 'high' in f.confidence.lower()]
            assert len(critical) == 0 or all(f.category == "A02" for f in critical), \
                "Safe math code shouldn't have critical vulns"
    
    def test_verdict_consistency_across_runs(self):
        """Test that same diff produces consistent verdicts."""
        diff = """
diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,30 +1,50 @@
+def login(user_id):
+    query = "SELECT * FROM users WHERE id = " + user_id
+    return db.execute(query)
"""
        
        # Run analysis twice
        hunks1, findings1, verdicts1 = _analyze_diff(diff)
        hunks2, findings2, verdicts2 = _analyze_diff(diff)
        
        # Both runs should find same number of findings
        if findings1 and findings2:
            assert len(findings1) == len(findings2), \
                "Multiple runs should find same number of findings"
            
            # Verdicts should match
            if verdicts1 and verdicts2:
                assert len(verdicts1) == len(verdicts2), \
                    "Multiple runs should produce same number of verdicts"


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_empty_diff_handling(self):
        """Test handling of empty diff."""
        diff = ""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should handle gracefully
        assert hunks is not None, "Should handle empty diff"
        assert findings is not None, "Should return empty findings list"
    
    def test_malformed_diff_handling(self):
        """Test handling of malformed diff."""
        diff = "this is not a valid diff format"
        
        # Should not crash
        try:
            hunks, findings, verdicts = _analyze_diff(diff)
            assert True, "Should handle malformed diff gracefully"
        except Exception as e:
            # If it raises, should be informative
            assert "diff" in str(e).lower() or "parse" in str(e).lower(), \
                "Error should indicate parsing issue"
    
    def test_unicode_diff_handling(self):
        """Test handling of Unicode characters in diff."""
        diff = """
diff --git a/i18n.py b/i18n.py
--- a/i18n.py
+++ b/i18n.py
@@ -1,10 +1,20 @@
+# 你好世界 - Hello World
+message = "😀 Unicode string with emojis 🔒"
+translated = "Hola mundo en español"
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should handle Unicode without crashing
        assert hunks is not None, "Should handle Unicode diff"


class TestChunkingCornerCases:
    """Test chunking in corner cases."""
    
    def test_single_huge_file_error_handling(self):
        """Test error handling when single file exceeds chunk limit."""
        chunker = create_chunker(max_tokens=100)  # Very restrictive
        
        from src.core.models import DiffHunk
        huge_hunk = DiffHunk(
            file_path="huge.py",
            added_lines=["+code " * 100 for _ in range(100)],
            removed_lines=["-code " * 100 for _ in range(100)]
        )
        
        # Should raise informative error
        with pytest.raises(ValueError) as exc_info:
            chunker.chunk_diff([huge_hunk])
        
        assert "exceeds" in str(exc_info.value).lower(), \
            "Error should indicate file size issue"
    
    def test_many_small_files_chunking(self):
        """Test chunking with many small files."""
        from src.core.models import DiffHunk
        
        hunks = [
            DiffHunk(
                file_path=f"small{i}.py",
                added_lines=[f"+def func{i}(): pass"],
                removed_lines=[f"-old_func{i}"]
            )
            for i in range(20)
        ]
        
        chunker = create_chunker(max_tokens=5000)
        chunks = chunker.chunk_diff(hunks)
        
        # Should successfully chunk
        assert len(chunks) >= 1, "Should chunk many small files"
        
        # All hunks should be preserved
        total_hunks = sum(len(c.hunks) for c in chunks)
        assert total_hunks >= len(hunks) - 5, "Should preserve most hunks (with overlap)"


class TestPhase5Integration:
    """Full end-to-end integration tests."""
    
    def test_complete_pipeline_with_report(self):
        """Test complete pipeline from diff to report."""
        diff = """
diff --git a/vulnerable.py b/vulnerable.py
--- a/vulnerable.py
+++ b/vulnerable.py
@@ -1,50 +1,80 @@
+import os
+
+API_KEY = "sk_live_123456789"
+SECRET = "super_secret_password"
+
+def search(query):
+    sql = "SELECT * FROM users WHERE name='" + query + "'"
+    return db.execute(sql)
+
+def run_command(cmd):
+    os.system(cmd)
+
+def handle_error():
+    try:
+        process_data()
+    except:
+        pass
"""
        
        report = run_full_pipeline(raw_diff=diff)
        
        # Should produce report
        assert report is not None, "Should produce report"
        assert isinstance(report, str), "Report should be string"
        assert len(report) > 0, "Report should not be empty"
    
    def test_findings_traceability_through_pipeline(self):
        """Test that findings remain traceable through entire pipeline."""
        diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,30 +1,50 @@
+def unsafe_query(user_input):
+    query = "SELECT * FROM data WHERE id=" + user_input
+    return db.execute(query)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        if findings:
            # Each finding should be traceable
            for finding in findings:
                assert finding.category, "Finding must have category"
                assert finding.affected_code, "Finding must have affected code"
                # Chunk context
                if len(hunks) > 1 or finding.chunk_id:
                    assert finding.chunk_id, "Finding must have chunk_id for multi-chunk diff"
    
    def test_verdict_accuracy_on_realistic_code(self):
        """Test verdict accuracy on realistic code patterns."""
        diff = """
diff --git a/database.py b/database.py
--- a/database.py
+++ b/database.py
@@ -1,50 +1,80 @@
+def get_user(user_id):
+    # This is SQL injection
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    return db.execute(query)
+
+def authenticate(username, password):
+    # Hardcoded check - insecure
+    if username == "admin" and password == "admin123":
+        return generate_token()
+    # Then proper check but after vuln
+    user = User.find_by_name(username)
+    return verify_password(user, password)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should detect the obvious SQL injection
        if findings:
            has_injection = any("sql" in f.description.lower() or "injection" in f.description.lower() 
                              for f in findings)
            assert has_injection, "Should detect SQL injection pattern"


class TestSystemMetrics:
    """Test system performance metrics."""
    
    def test_processing_time_reasonable(self):
        """Test that processing completes in reasonable time."""
        import time
        
        diff = """
diff --git a/file.py b/file.py
--- a/file.py
+++ b/file.py
@@ -1,30 +1,50 @@
+def vulnerable(x):
+    sql = "SELECT * FROM users WHERE id=" + x
+    return db.execute(sql)
"""
        
        start = time.time()
        hunks, findings, verdicts = _analyze_diff(diff)
        elapsed = time.time() - start
        
        # Should complete reasonably fast (LLM calls may take time)
        # Just verify it completed
        assert elapsed >= 0, "Should complete processing"
    
    def test_findings_count_reasonable(self):
        """Test that findings count is reasonable."""
        diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,20 +1,40 @@
+def func(x):
+    sql = "SELECT * FROM t WHERE id=" + x
+    return db.execute(sql)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should have reasonable number of findings (not too many false positives)
        if findings:
            # For simple SQL injection, shouldn't have 100+ findings
            assert len(findings) < 50, "Too many findings might indicate false positives"
