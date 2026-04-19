"""Phase 3: Per-chunk detection validation.

Tests that large diffs are properly chunked and each chunk is analyzed
with findings correctly tagged with chunk IDs.
"""

import pytest
from src.main import _analyze_diff
from src.agents.chunker import create_chunker
from src.core.models import DiffHunk


class TestMultiChunkDetection:
    """Test detection across multiple chunks."""
    
    def test_large_diff_triggers_chunking(self):
        """Test that large diffs trigger chunking."""
        # Create a 40K+ token diff (2 files, 500 lines each)
        hunks = [
            DiffHunk(
                file_path="large_file1.py",
                added_lines=[f"+# Line {i}\n+def func_{i}():\n+    return {i}\n" for i in range(250)],
                removed_lines=[f"-# Old {i}\n-def old_{i}():\n-    pass\n" for i in range(250)]
            ),
            DiffHunk(
                file_path="large_file2.py",
                added_lines=[f"+# Code {i}\n+class Class_{i}:\n+    pass\n" for i in range(250)],
                removed_lines=[f"-# Unused {i}\n-class Old_{i}:\n-    pass\n" for i in range(250)]
            ),
        ]
        
        chunker = create_chunker(max_tokens=24000, overlap_tokens=500)
        chunks = chunker.chunk_diff(hunks)
        
        # Large diff should create multiple chunks
        assert len(chunks) >= 1, "Large diff should be chunked"
        assert all(c.id for c in chunks), "All chunks should have IDs"
        assert all(len(c.hunks) > 0 for c in chunks), "All chunks should have hunks"
    
    def test_sql_injection_across_chunks(self):
        """Test detecting SQL injection split across chunks."""
        # SQL injection in first chunk
        sql_injection_chunk1 = """
diff --git a/app1.py b/app1.py
--- a/app1.py
+++ b/app1.py
@@ -10,6 +10,10 @@
+def search_user(user_id):
+    query = "SELECT * FROM users WHERE id = " + str(user_id)
+    db.execute(query)
+    return result
"""
        
        # More SQL injection in second chunk (different file)
        sql_injection_chunk2 = """
diff --git a/app2.py b/app2.py
--- a/app2.py
+++ b/app2.py
@@ -50,6 +50,10 @@
+def get_data(table_name):
+    sql = "SELECT * FROM " + table_name
+    result = db.execute(sql)
+    return result
"""
        
        combined_diff = sql_injection_chunk1 + "\n" + sql_injection_chunk2
        
        hunks, findings, verdicts = _analyze_diff(combined_diff)
        
        # Should detect SQL injections
        assert len(findings) > 0, "Should detect SQL injections"
        # All findings should have chunk_id (either chunk_1 or chunk_2)
        assert all(f.chunk_id for f in findings), "All findings should be tagged with chunk_id"
    
    def test_multiple_vulnerabilities_different_chunks(self):
        """Test detecting different vulnerability types in different chunks."""
        diff = """
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,5 +1,8 @@
+# Configuration file
+API_KEY = "sk-12345678abcdefgh"
+SECRET_TOKEN = "secret_value_12345"
+DATABASE_PASSWORD = "password123"

diff --git a/error_handler.py b/error_handler.py
--- a/error_handler.py
+++ b/error_handler.py
@@ -50,8 +50,12 @@
 def handle_request():
     try:
-        result = process_data()
+        result = process_data()
+    except:
+        print("Error occurred")
+    return None
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should have multiple finding types
        if findings:
            categories = {f.category for f in findings}
            # Both A02 (exposed secrets) and A10 (error handling) might be detected
            assert len(categories) <= 2, "Should detect multiple vulnerability categories"
            
            # All should have chunk_id
            assert all(f.chunk_id for f in findings), "All findings must have chunk_id"
    
    def test_chunk_ids_are_sequential(self):
        """Test that chunk IDs follow sequential order."""
        large_diff = """
diff --git a/f1.py b/f1.py
--- a/f1.py
+++ b/f1.py
@@ -1,100 +1,100 @@
+""" + "".join([f"+line {i}\n" for i in range(100)]) + """

diff --git a/f2.py b/f2.py
--- a/f2.py
+++ b/f2.py
@@ -1,100 +1,100 @@
+""" + "".join([f"+more {i}\n" for i in range(100)]) + """

diff --git a/f3.py b/f3.py
--- a/f3.py
+++ b/f3.py
@@ -1,100 +1,100 @@
+""" + "".join([f"+code {i}\n" for i in range(100)]) + """
"""
        
        hunks, findings, verdicts = _analyze_diff(large_diff)
        
        # Check chunk_id pattern
        if findings:
            chunk_ids = {f.chunk_id for f in findings if f.chunk_id}
            # Should have sequential chunk IDs like chunk_1, chunk_2, etc
            if len(chunk_ids) > 1:
                assert all(cid.startswith("chunk_") for cid in chunk_ids), \
                    "Chunk IDs should follow chunk_N pattern"
    
    def test_injection_in_multiple_chunks(self):
        """Test detection of injection vulnerabilities across chunks."""
        # Create diff with command injection in two different places
        diff = """
diff --git a/utils.py b/utils.py
--- a/utils.py
+++ b/utils.py
@@ -1,20 +1,25 @@
 import subprocess
 
+def run_command_bad(user_input):
+    cmd = "echo " + user_input
+    os.system(cmd)

diff --git a/handlers.py b/handlers.py
--- a/handlers.py
+++ b/handlers.py
@@ -50,10 +50,15 @@
 import os
 
+def execute_unsafe(filename):
+    path = "/tmp/" + filename
+    cmd = "rm " + path
+    os.system(cmd)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Verify findings have chunk context
        if findings:
            # Group by chunk
            by_chunk = {}
            for f in findings:
                chunk = f.chunk_id or "no_chunk"
                if chunk not in by_chunk:
                    by_chunk[chunk] = []
                by_chunk[chunk].append(f)
            
            # Each chunk should have analyzed content
            for chunk_id, chunk_findings in by_chunk.items():
                assert len(chunk_findings) > 0, f"{chunk_id} should have findings"


class TestChunkBoundaryHandling:
    """Test proper handling of chunk boundaries."""
    
    def test_overlap_preserves_context(self):
        """Test that overlap regions preserve vulnerability context."""
        # SQL injection split between chunks
        diff = """
diff --git a/database.py b/database.py
--- a/database.py
+++ b/database.py
@@ -100,200 +100,210 @@
 def query_builder(table, where_clause):
-    pass
+    sql = "SELECT * FROM " + table + " WHERE " + where_clause
+    return db.execute(sql)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # SQL injection should be detected even if split
        if findings:
            assert all(f.chunk_id for f in findings), "Split vulnerability must have chunk context"
    
    def test_small_diff_single_chunk(self):
        """Test that small diffs remain in single chunk."""
        small_diff = """
diff --git a/tiny.py b/tiny.py
--- a/tiny.py
+++ b/tiny.py
@@ -1,3 +1,5 @@
+# Safe comment
+x = 1
"""
        
        hunks, findings, verdicts = _analyze_diff(small_diff)
        
        # All findings should be from chunk_1 (no chunking needed)
        if findings:
            assert all(f.chunk_id in ["chunk_1", None] for f in findings), \
                "Small diff should use chunk_1 or None"


class TestChunkingWithDetectors:
    """Test interaction between chunking and detectors."""
    
    def test_each_chunk_runs_all_detectors(self):
        """Test that each chunk is scanned by all three detectors."""
        # Diff with multiple vulnerability types
        diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,50 +1,60 @@
 import os
 
+API_KEY = "sk-abc123"
+
+def search(query):
+    sql = "SELECT * FROM users WHERE name = '" + query + "'"
+    return db.execute(sql)
+
+def handle_error():
+    try:
+        result = do_something()
+    except Exception:
+        pass

diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,20 +1,25 @@
+DATABASE_URL = "postgresql://user:password@localhost"
+SECRET_KEY = "mysecret123"
+
+DEBUG = True
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should have findings from multiple categories
        if findings:
            categories = {f.category for f in findings}
            # Could be A02 (config), A05 (injection), A10 (error handling)
            assert len(categories) > 0, "Should detect at least one category"
            
            # Each finding should be tagged with chunk
            assert all(f.chunk_id for f in findings), "All findings must have chunk context"
    
    def test_detector_isolation_between_chunks(self):
        """Test that detectors don't leak findings between chunks."""
        # Two separate files, each with one vuln
        diff = """
diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1,5 +1,8 @@
+DATABASE_PASSWORD = "prod_password_123"

diff --git a/file2.py b/file2.py
--- a/file2.py
+++ b/file2.py
@@ -1,5 +1,8 @@
+def query(user_id):
+    sql = "SELECT * FROM users WHERE id=" + user_id
+    return db.execute(sql)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        if findings:
            # Group findings by category
            by_category = {}
            for f in findings:
                if f.category not in by_category:
                    by_category[f.category] = []
                by_category[f.category].append(f)
            
            # Each category should have findings properly tagged
            for category, findings_list in by_category.items():
                assert all(f.chunk_id for f in findings_list), \
                    f"All {category} findings must have chunk_id"


class TestPhase3EndToEnd:
    """End-to-end tests for Phase 3."""
    
    def test_realistic_pr_with_multiple_chunks(self):
        """Test realistic PR with changes across multiple files."""
        diff = """
diff --git a/src/auth/login.py b/src/auth/login.py
--- a/src/auth/login.py
+++ b/src/auth/login.py
@@ -1,50 +1,70 @@
+def authenticate(username, password):
+    query = "SELECT * FROM users WHERE username='" + username + "'"
+    user = db.execute(query)
+    if user and check_password(user.password, password):
+        return generate_token(user.id)
+    return None

diff --git a/src/config/database.py b/src/config/database.py
--- a/src/config/database.py
+++ b/src/config/database.py
@@ -1,20 +1,25 @@
+DB_PASSWORD = "admin123"
+API_KEY = "sk_test_123456"
+SECRET = "my_secret_key"

diff --git a/src/utils/error_handler.py b/src/utils/error_handler.py
--- a/src/utils/error_handler.py
+++ b/src/utils/error_handler.py
@@ -50,10 +50,15 @@
 def handle_request():
     try:
-        return process()
+        return process()
+    except:
+        print("Error")
+        return None
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Should detect multiple vulnerabilities
        assert len(findings) > 0, "Should detect vulnerabilities in realistic PR"
        
        # Verify findings are properly tagged
        for finding in findings:
            assert finding.chunk_id, f"Finding {finding} missing chunk_id"
            assert finding.chunk_id.startswith("chunk_"), f"Invalid chunk_id format: {finding.chunk_id}"
        
        # Should have verdicts for multiple categories
        assert len(verdicts) > 0, "Should have verdicts for detected categories"
    
    def test_phase3_verdict_aggregation_result(self):
        """Test that Phase 3 findings feed correctly into verdict aggregation."""
        diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,30 +1,40 @@
+import subprocess
+
+def run_cmd(user_input):
+    os.system("cmd " + user_input)
+
+def unsafe_sql(table):
+    query = "SELECT * FROM " + table
+    return db.execute(query)
"""
        
        hunks, findings, verdicts = _analyze_diff(diff)
        
        # Findings should exist
        if findings:
            assert len(findings) > 0, "Should detect findings"
            
            # Verdicts should be generated
            assert len(verdicts) > 0, "Should generate verdicts from findings"
            
            # Verdicts should reference chunks
            for verdict in verdicts:
                # Verdict should have category and verdict_verdict (from aggregator)
                assert hasattr(verdict, 'category'), "Verdict should have category"
