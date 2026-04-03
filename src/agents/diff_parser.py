from src.core.llm import get_llm
from src.core.models import DiffHunk, ParsedDiff
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from typing import List

def parse_git_diff(raw_diff: str) -> List[DiffHunk]:
    """
    Takes a raw git diff string and uses the LLM to extract relevant hunks.
    """
    # 1. We use temperature 0.0 because extraction should be deterministic and strict
    llm = get_llm(temperature=0.0)
    
    # 2. Set up the LangChain parser to enforce our Pydantic schema
    parser = PydanticOutputParser(pydantic_object=ParsedDiff)
    
    # 3. Create the prompt instruction
    prompt = PromptTemplate(
        template=(
            "You are an expert DevSecOps engineer. "
            "Analyze the following raw git diff and extract the added and removed lines of code.\n"
            "Filter out irrelevant noise like import changes, whitespace formatting, or comments if they aren't security-relevant.\n\n"
            "{format_instructions}\n\n"
            "RAW GIT DIFF:\n"
            "```diff\n"
            "{raw_diff}\n"
            "```\n"
        ),
        input_variables=["raw_diff"],
        partial_variables={"format_instructions": parser.get_format_instructions()}
    )
    
    # 4. Chain the prompt, model, and parser together
    chain = prompt | llm | parser
    
    print("Agent: Parsing diff...")
    try:
        # Run the API call
        parsed_result: ParsedDiff = chain.invoke({"raw_diff": raw_diff})
        return parsed_result.hunks
    except Exception as e:
        print(f"Error parsing diff: {e}")
        return []
    

if __name__ == "__main__":
    # A mock diff containing a potential SQL injection vulnerability (A05)
    mock_raw_diff = """
diff --git a/app/database.py b/app/database.py
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

    print("Sending mock diff to Qwen-2.5-Coder...")
    extracted_hunks = parse_git_diff(mock_raw_diff)
    
    for i, hunk in enumerate(extracted_hunks):
        print(f"\n--- Hunk {i+1} ---")
        print(f"File: {hunk.file_path}")
        print(f"Added: {hunk.added_lines}")
        print(f"Removed: {hunk.removed_lines}")