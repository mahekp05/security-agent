# Written with help of GitHub Copilot
import re
from typing import List
from src.core.models import DiffHunk

def parse_git_diff(raw_diff: str) -> List[DiffHunk]:
    """
    Pure string parser: extracts code hunks from raw git diff.
    No LLM—just regex pattern matching on diff structure.
    
    Returns all hunks (added/removed lines). Detectors decide what's security-relevant.
    """
    hunks = []
    current_file = None
    current_added = []
    current_removed = []
    
    lines = raw_diff.split('\n')
    
    for line in lines:
        # Extract file path from "diff --git a/file.py b/file.py"
        if line.startswith('diff --git'):
            # Save previous hunk if exists
            if current_file and (current_added or current_removed):
                hunks.append(DiffHunk(
                    file_path=current_file,
                    added_lines=current_added,
                    removed_lines=current_removed
                ))
            
            # Extract new file path: "diff --git a/path b/path" → extract path
            match = re.search(r'b/(.+?)(?:\s|$)', line)
            if match:
                current_file = match.group(1)
                current_added = []
                current_removed = []
        
        # Skip hunk markers (@@...@@), file mode lines, index lines, etc.
        elif line.startswith('@@') or line.startswith('---') or line.startswith('+++') or \
             line.startswith('index ') or line.startswith('new file') or line.startswith('deleted file'):
            continue
        
        # Capture added lines (start with +, but not +++ header)
        elif line.startswith('+') and not line.startswith('+++'):
            current_added.append(line)
        
        # Capture removed lines (start with -, but not --- header)
        elif line.startswith('-') and not line.startswith('---'):
            current_removed.append(line)
    
    # Save last hunk if exists
    if current_file and (current_added or current_removed):
        hunks.append(DiffHunk(
            file_path=current_file,
            added_lines=current_added,
            removed_lines=current_removed
        ))
    
    print(f"Agent: Parsing diff... extracted {len(hunks)} hunks")
    return hunks


if __name__ == "__main__":
    # A mock diff containing a potential SQL injection vulnerability (A05)
    mock_raw_diff = """diff --git a/app/database.py b/app/database.py
index 8329b34..943ab91 100644
--- a/app/database.py
+++ b/app/database.py
@@ -10,6 +10,6 @@ def get_user(db_connection, username):
-    query = "SELECT * FROM users WHERE username = %s"
-    cursor.execute(query, (username,))
+    query = f"SELECT * FROM users WHERE username = '{username}'"
+    cursor.execute(query)
     return cursor.fetchone()
"""

    print("Parsing git diff (pure string parsing, no LLM)...")
    extracted_hunks = parse_git_diff(mock_raw_diff)
    
    for i, hunk in enumerate(extracted_hunks):
        print(f"\n--- Hunk {i+1} ---")
        print(f"File: {hunk.file_path}")
        print(f"Added ({len(hunk.added_lines)}): {hunk.added_lines}")
        print(f"Removed ({len(hunk.removed_lines)}): {hunk.removed_lines}")