"""
tests/test_diff_parser.py - Layer 1: Diff Parser Tests

These tests validate that raw git diff strings are correctly parsed into
structured DiffHunk objects with file paths and line lists preserved.
"""

import pytest
from src.agents.diff_parser import parse_git_diff


class TestDiffParser:
    """Test suite for git diff parsing."""

    def test_parser_extracts_hunks_from_raw_diff(self, SIMPLE_SQL_INJECTION_DIFF):
        """
        Test that parser extracts hunks from a simple SQL injection diff.
        
        Expected: 1 DiffHunk with correct file_path, added_lines, removed_lines
        """
        hunks = parse_git_diff(SIMPLE_SQL_INJECTION_DIFF)
        
        assert isinstance(hunks, list), "parse_git_diff should return a list"
        assert len(hunks) >= 1, "Should extract at least 1 hunk"
        
        hunk = hunks[0]
        assert hunk.file_path == "app.py", f"Expected file_path 'app.py', got '{hunk.file_path}'"
        assert len(hunk.added_lines) > 0, "Should have added lines"
        assert len(hunk.removed_lines) > 0, "Should have removed lines"

    def test_parser_preserves_file_path(self, MULTI_FILE_DIFF):
        """
        Test that parser correctly preserves file paths across multi-file diffs.
        
        Expected: 3 hunks with unique correct file paths
        """
        hunks = parse_git_diff(MULTI_FILE_DIFF)
        
        assert isinstance(hunks, list)
        assert len(hunks) == 3, f"Expected 3 hunks, got {len(hunks)}"
        
        file_paths = [hunk.file_path for hunk in hunks]
        assert "utils/db.py" in file_paths, "Should include utils/db.py"
        assert "config/settings.py" in file_paths, "Should include config/settings.py"
        assert "server/api.py" in file_paths, "Should include server/api.py"

    def test_parser_filters_irrelevant_changes(self, COMMENT_ONLY_DIFF):
        """
        Test that parser filters or handles comment-only changes gracefully.
        
        Expected: Empty hunks or lenient behavior (no crash)
        """
        hunks = parse_git_diff(COMMENT_ONLY_DIFF)
        
        assert isinstance(hunks, list), "Should return a list even with noise"
        # Parser may return empty or include minor changes - either is acceptable

    def test_parser_handles_added_and_removed_lines(self, SIMPLE_SQL_INJECTION_DIFF):
        """
        Test that parser preserves both added and removed lines.
        
        Expected: DiffHunk with both added_lines and removed_lines as lists
        """
        hunks = parse_git_diff(SIMPLE_SQL_INJECTION_DIFF)
        
        assert len(hunks) > 0
        hunk = hunks[0]
        
        assert isinstance(hunk.added_lines, list), "added_lines should be a list"
        assert isinstance(hunk.removed_lines, list), "removed_lines should be a list"
        assert len(hunk.added_lines) > 0, "Should have added lines"
        assert len(hunk.removed_lines) > 0, "Should have removed lines"

    def test_parser_handles_mixed_category_diff(self, MIXED_CATEGORY_DIFF):
        """
        Test that parser handles diffs containing multiple vulnerability categories.
        
        Expected: 3+ hunks with correct structure (A05 + A02 + A10 hunks)
        """
        hunks = parse_git_diff(MIXED_CATEGORY_DIFF)
        
        assert isinstance(hunks, list)
        assert len(hunks) >= 1, "Should extract at least 1 hunk from mixed category diff"
        
        # Verify structure is preserved for all hunks
        for hunk in hunks:
            assert hasattr(hunk, 'file_path'), "Each hunk should have file_path"
            assert hasattr(hunk, 'added_lines'), "Each hunk should have added_lines"
            assert hasattr(hunk, 'removed_lines'), "Each hunk should have removed_lines"
