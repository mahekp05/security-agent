# Written with help of GitHub Copilot
from src.core.llm import get_llm
from src.core.models import DiffHunk, VulnerabilityFinding
from langchain_core.prompts import PromptTemplate
from typing import List
from pydantic import BaseModel, Field
import json
import re

# Define the output schema for this detector
class InjectionFindings(BaseModel):
    findings: List[VulnerabilityFinding] = Field(description="List of injection vulnerabilities found")

def _parse_injection_response(raw_response) -> InjectionFindings:
    """
    Robustly parse LLM response which may be: bare list, JSON with findings key, or text with JSON.
    Handles various LLM output formats including LangChain message objects.
    """
    # Convert LLM message object to string if needed
    if hasattr(raw_response, 'content'):
        response_text = raw_response.content
    else:
        response_text = str(raw_response)
    
    try:
        # Try to extract JSON from the response (handles markdown code blocks)
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            parsed = json.loads(json_str)
            
            # Handle different JSON formats
            if isinstance(parsed, list):
                # Bare list of findings
                return InjectionFindings(findings=[
                    VulnerabilityFinding(**f) if isinstance(f, dict) else f 
                    for f in parsed
                ])
            elif isinstance(parsed, dict):
                if "findings" in parsed:
                    findings_list = parsed["findings"]
                    if isinstance(findings_list, list):
                        return InjectionFindings(findings=[
                            VulnerabilityFinding(**f) if isinstance(f, dict) else f 
                            for f in findings_list
                        ])
                # If dict but no findings key, treat it as a single finding
                return InjectionFindings(findings=[VulnerabilityFinding(**parsed)])
    except (json.JSONDecodeError, ValueError, KeyError, TypeError) as e:
        pass
    
    # Fallback: no valid JSON found or parsing failed
    return InjectionFindings(findings=[])

def detect_injection(hunks: List[DiffHunk]) -> List[VulnerabilityFinding]:
    """
    Red team approach: analyze code changes for A05 (Injection) vulnerabilities.
    Acts as a penetration tester to find exploitable injection points.
    """
    # 1. Initialize LLM with deterministic temperature
    llm = get_llm(temperature=0.1)
    
    # 2. Create red team prompt
    prompt = PromptTemplate(
        template=(
            "You are a penetration tester analyzing code changes for A05 (Injection) vulnerabilities.\n"
            "Respond in English only.\n\n"
            "Attack types to look for:\n"
            "- SQL Injection: unparameterized queries with user input\n"
            "  Example: query = f\"SELECT * FROM users WHERE id = {{user_id}}\" (vulnerable)\n"
            "  Safe: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\n"
            "- Command Injection: OS commands with unsanitized input\n"
            "  Example: os.system(f\"ping {{hostname}}\") (vulnerable)\n"
            "  Safe: subprocess.run([\"ping\", hostname], shell=False)\n\n"
            "- LDAP Injection: unvalidated LDAP queries\n"
            "  Example: ldap_query = f\"(uid={{username}})\" (vulnerable)\n"
            "  Safe: Use parameterized LDAP libraries\n\n"
            "- Template Injection: unsafe template rendering\n"
            "  Example: template.render(user_input) (vulnerable)\n"
            "  Safe: Use auto-escaping, parameterized templates\n\n"
            "- Code Injection/Eval: dynamic code execution\n"
            "  Example: eval(user_input), exec(code_str) (vulnerable)\n"
            "  Safe: Use safe alternatives like AST parsing or restricted execution\n\n"
            "For each vulnerability found, explain:\n"
            "1. Attack vector: what can be injected\n"
            "2. Impact: what damage is possible\n"
            "3. Why it's exploitable: what defenses are missing\n\n"
            "Return ONLY a JSON object with this structure:\n"
            "{{\n"
            "  \"findings\": [\n"
            "    {{\n"
            "      \"category\": \"A05\",\n"
            "      \"description\": \"vulnerability description\",\n"
            "      \"affected_code\": \"the vulnerable code line\",\n"
            "      \"confidence\": \"High|Medium|Low\"\n"
            "    }}\n"
            "  ]\n"
            "}}\n\n"
            "If no vulnerabilities found, return: {{\"findings\": []}}\n\n"
            "CODE CHANGES:\n"
            "File: {file_path}\n"
            "Added:\n{added_lines}\n"
            "Removed:\n{removed_lines}\n"
        ),
        input_variables=["file_path", "added_lines", "removed_lines"],
    )
    
    # 3. Chain (without parser - we'll parse manually for robustness)
    chain = prompt | llm
    
    all_findings = []
    
    print("Agent: Running A05 (Injection) detector...")
    for hunk in hunks:
        try:
            added_str = "\n".join(hunk.added_lines) if hunk.added_lines else "(none)"
            removed_str = "\n".join(hunk.removed_lines) if hunk.removed_lines else "(none)"
            
            raw_output = chain.invoke({
                "file_path": hunk.file_path,
                "added_lines": added_str,
                "removed_lines": removed_str
            })
            
            # Parse the raw LLM output robustly
            result = _parse_injection_response(raw_output)
            all_findings.extend(result.findings)
        except Exception as e:
            print(f"Error analyzing {hunk.file_path}: {e}")
            continue
    
    return all_findings


if __name__ == "__main__":
    print("=" * 80)
    print("COMPREHENSIVE A05 INJECTION DETECTOR TEST SUITE")
    print("=" * 80)
    
    # ========== POSITIVE TEST CASES (Should detect vulnerabilities) ==========
    print("\n" + "=" * 80)
    print("POSITIVE CASES (Vulnerabilities SHOULD be detected)")
    print("=" * 80)
    
    positive_cases = [
        # SQL Injection - String concatenation
        {
            "name": "SQL Injection: String Concatenation",
            "file": "app/database.py",
            "added": [
                '+    query = "SELECT * FROM users WHERE username = \'" + username + "\'"',
                '+    cursor.execute(query)'
            ],
            "removed": [
                '-    query = "SELECT * FROM users WHERE username = %s"',
                '-    cursor.execute(query, (username,))'
            ]
        },
        # SQL Injection - f-string
        {
            "name": "SQL Injection: f-string",
            "file": "app/models.py",
            "added": [
                '+    query = f"DELETE FROM users WHERE id = {user_id}"',
                '+    db.execute(query)'
            ],
            "removed": [
                '-    db.execute("DELETE FROM users WHERE id = ?", (user_id,))'
            ]
        },
        # Command Injection
        {
            "name": "Command Injection: os.system",
            "file": "utils/shell.py",
            "added": [
                '+    cmd = f"ping -c 1 {hostname}"',
                '+    os.system(cmd)'
            ],
            "removed": [
                '-    subprocess.run(["ping", "-c", "1", hostname], shell=False)'
            ]
        },
        # LDAP Injection
        {
            "name": "LDAP Injection",
            "file": "auth/ldap.py",
            "added": [
                '+    ldap_query = f"(uid={username})(objectClass=*)"',
                '+    results = ldap_conn.search(ldap_query)'
            ],
            "removed": [
                '-    results = ldap_conn.search_st("(uid=*)(objectClass=*)", search_filter=username)'
            ]
        },
        # Code Injection - eval
        {
            "name": "Code Injection: eval()",
            "file": "utils/parser.py",
            "added": [
                '+    result = eval(user_expression)',
                '+    return result'
            ],
            "removed": [
                '-    parser = ast.parse(user_expression, mode="eval")'
            ]
        },
        # Template Injection
        {
            "name": "Template Injection",
            "file": "templates/renderer.py",
            "added": [
                '+    html = f"<div>{user_content}</div>"',
                '+    return html'
            ],
            "removed": [
                '-    return render_template("safe.html", content=escape(user_content))'
            ]
        },
        # SQL Injection with format()
        {
            "name": "SQL Injection: format()",
            "file": "db/queries.py",
            "added": [
                '+    query = "SELECT * FROM accounts WHERE email = \'{}\'".format(email)',
                '+    cursor.execute(query)'
            ],
            "removed": [
                '-    cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))'
            ]
        },
    ]
    
    # ========== NEGATIVE TEST CASES (Should NOT detect vulnerabilities) ==========
    print("\n" + "=" * 80)
    print("NEGATIVE CASES (Safe code - NO vulnerabilities should be detected)")
    print("=" * 80)
    
    negative_cases = [
        # Safe SQL - parameterized
        {
            "name": "Safe SQL: Parameterized query",
            "file": "app/database.py",
            "added": [
                '+    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))',
                '+    return cursor.fetchall()'
            ],
            "removed": []
        },
        # Safe subprocess
        {
            "name": "Safe Command: subprocess with list",
            "file": "utils/shell.py",
            "added": [
                '+    result = subprocess.run(["ping", "-c", "1", hostname], shell=False)',
                '+    return result.returncode'
            ],
            "removed": []
        },
        # Safe ORM usage
        {
            "name": "Safe SQL: ORM with bind params",
            "file": "models/user.py",
            "added": [
                '+    user = User.query.filter_by(username=username).first()',
                '+    return user'
            ],
            "removed": []
        },
        # Safe template rendering
        {
            "name": "Safe Template: with escaping",
            "file": "views/profile.py",
            "added": [
                '+    return render_template("profile.html", user_name=escape(user_input))',
            ],
            "removed": []
        },
    ]
    
    # ========== EDGE CASES ==========
    print("\n" + "=" * 80)
    print("EDGE CASES (Borderline/Complex scenarios)")
    print("=" * 80)
    
    edge_cases = [
        # Concatenation with some validation
        {
            "name": "Edge: String concat with basic validation",
            "file": "app/search.py",
            "added": [
                '+    if len(query) > 255: raise ValueError("too long")',
                '+    sql = "SELECT * FROM items WHERE title = \'" + query + "\'"',
                '+    cursor.execute(sql)'
            ],
            "removed": []
        },
        # Comment suggests intent but still vulnerable
        {
            "name": "Edge: Vulnerable with misleading comment",
            "file": "utils/query.py",
            "added": [
                '+    # Sanitized input - VULNERABLE COMMENT',
                '+    query = f"SELECT * FROM users WHERE id = {user_id}"',
                '+    db.execute(query)'
            ],
            "removed": []
        },
        # Multiple parameters
        {
            "name": "Edge: Multiple injected params",
            "file": "reports/generator.py",
            "added": [
                '+    query = f"SELECT {columns} FROM {table} WHERE {condition}"',
                '+    cursor.execute(query)'
            ],
            "removed": []
        },
    ]
    
    # Helper function to run tests
    def run_test_suite(test_cases: List[dict], suite_name: str):
        print(f"\n### {suite_name} ###")
        results = {"passed": 0, "failed": 0, "errors": 0}
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n[{i}] {test_case['name']}")
            print("-" * 60)
            
            mock_hunk = DiffHunk(
                file_path=test_case["file"],
                added_lines=test_case["added"],
                removed_lines=test_case.get("removed", [])
            )
            
            try:
                findings = detect_injection([mock_hunk])
                
                if findings:
                    print(f"✓ Found {len(findings)} vulnerability(ies):")
                    for finding in findings:
                        print(f"  - {finding.category}: {finding.description}")
                        print(f"    Code: {finding.affected_code[:60]}...")
                        print(f"    Confidence: {finding.confidence}")
                    results["passed"] += 1
                else:
                    print("✗ NO vulnerabilities detected")
                    results["failed"] += 1
            except Exception as e:
                print(f"✗ ERROR: {str(e)[:100]}")
                results["errors"] += 1
        
        return results
    
    # Run all test suites
    pos_results = run_test_suite(positive_cases, "POSITIVE CASES")
    neg_results = run_test_suite(negative_cases, "NEGATIVE CASES")
    edge_results = run_test_suite(edge_cases, "EDGE CASES")
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Positive Cases: {pos_results['passed']}/{len(positive_cases)} passed")
    print(f"Negative Cases: {neg_results['failed']}/{len(negative_cases)} correctly rejected")
    print(f"Edge Cases: {edge_results['passed']}/{len(edge_cases)} detected")
    print(f"Total Errors: {pos_results['errors'] + neg_results['errors'] + edge_results['errors']}")
    print("\nNOTE: Model temperature is set to 0.1 for improved detection accuracy.")