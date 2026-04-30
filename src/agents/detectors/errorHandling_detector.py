# Written with help of GitHub Copilot
from src.core.llm import get_llm
from src.core.models import DiffHunk, VulnerabilityFinding
from langchain_core.prompts import PromptTemplate
from typing import List
from pydantic import BaseModel, Field
import json
import re

# Define the output schema for this detector
class ErrorHandlingFindings(BaseModel):
    findings: List[VulnerabilityFinding] = Field(description="List of error handling vulnerabilities found")

def _parse_error_handling_response(raw_response) -> ErrorHandlingFindings:
    """
    Robustly parse LLM response for error handling issues.
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
                return ErrorHandlingFindings(findings=[
                    VulnerabilityFinding(**f) if isinstance(f, dict) else f 
                    for f in parsed
                ])
            elif isinstance(parsed, dict):
                if "findings" in parsed:
                    findings_list = parsed["findings"]
                    if isinstance(findings_list, list):
                        return ErrorHandlingFindings(findings=[
                            VulnerabilityFinding(**f) if isinstance(f, dict) else f 
                            for f in findings_list
                        ])
                # If dict but no findings key, treat it as a single finding
                return ErrorHandlingFindings(findings=[VulnerabilityFinding(**parsed)])
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        pass
    
    # Fallback: no valid JSON found or parsing failed
    return ErrorHandlingFindings(findings=[])

def detect_error_handling(hunks: List[DiffHunk]) -> List[VulnerabilityFinding]:
    """
    Code quality and security reviewer analyzing code changes for A10 (Mishandling of Exceptional Conditions).
    Focuses on improper error handling, sensitive data in error messages, uncaught exceptions, and fail-open issues.
    """
    # 1. Initialize LLM with temperature for nuanced error handling analysis
    llm = get_llm(temperature=0.1)
    
    # 2. Create prompt for error handling vulnerabilities
    prompt = PromptTemplate(
        template=(
            "You are a code quality and security reviewer analyzing code changes for A10:2025 (Mishandling of Exceptional Conditions) vulnerabilities.\n"
            "Respond in English only.\n\n"
            "Error handling vulnerability categories to analyze:\n\n"
            "1. SENSITIVE DATA IN ERROR MESSAGES (CWE-209, CWE-550, CWE-215):\n"
            "  - Error messages containing passwords, API keys, tokens (vulnerable)\n"
            "  - Stack traces exposed to users showing file paths, database info (vulnerable)\n"
            "  - Debug info containing secrets in production (vulnerable)\n"
            "  - Safe: Log detailed errors internally, show generic user messages\n\n"
            "2. UNCAUGHT & UNCHECKED EXCEPTIONS (CWE-248, CWE-252, CWE-391):\n"
            "  - Function calls without try-catch blocks (vulnerable)\n"
            "  - Ignored return values indicating success/failure (vulnerable)\n"
            "  - No validation of function results before use (vulnerable)\n"
            "  - Safe: Catch all exceptions, check return codes, validate results\n\n"
            "3. NULL POINTER DEREFERENCE (CWE-476):\n"
            "  - Usage of object/result without null checks (vulnerable)\n"
            "  - Assuming query results exist without validation (vulnerable)\n"
            "  - Missing guards for optional values (vulnerable)\n"
            "  - Safe: Always null-check before dereferencing\n\n"
            "4. FAILING OPEN & INSECURE DEFAULTS (CWE-636):\n"
            "  - Exception caught but system grants access anyway (vulnerable)\n"
            "  - Authentication failure continues execution (vulnerable)\n"
            "  - Missing error should skip, not proceed (vulnerable)\n"
            "  - Safe: Fail closed - deny access on errors, require explicit success\n\n"
            "5. MISSING ERROR HANDLING (CWE-390, CWE-703, CWE-754, CWE-755):\n"
            "  - Missing null/empty checks before operations (vulnerable)\n"
            "  - No validation of input parameters (vulnerable)\n"
            "  - Arithmetic without bounds checking (e.g., divide by zero) (vulnerable)\n"
            "  - Safe: Validate all inputs, check all conditions\n\n"
            "6. INCOMPLETE EXCEPTION HANDLING (CWE-460, CWE-396):\n"
            "  - Resource leaks when exception thrown (file not closed) (vulnerable)\n"
            "  - Catching generic Exception instead of specific ones (vulnerable)\n"
            "  - Finally block missing for resource cleanup (vulnerable)\n"
            "  - Safe: Use try-finally or context managers, specific exceptions\n\n"
            "7. MISSING DEFAULT CASES (CWE-478, CWE-484):\n"
            "  - If-else chain without final else handling unknown cases (vulnerable)\n"
            "  - Switch statement without default case (vulnerable)\n"
            "  - Omitted break statement causing fall-through (vulnerable)\n"
            "  - Safe: Always have default case, explicit breaks\n\n"
            "8. MISSING PARAMETER HANDLING (CWE-234, CWE-235):\n"
            "  - Required parameters not validated as present (vulnerable)\n"
            "  - Extra parameters accepted without validation (vulnerable)\n"
            "  - No length/size validation on arguments (vulnerable)\n"
            "  - Safe: Validate parameter presence and values\n\n"
            "9. PRIVILEGE HANDLING FAILURES (CWE-274, CWE-280):\n"
            "  - Permission denied exceptions not caught/handled (vulnerable)\n"
            "  - Operations proceed despite privilege check failure (vulnerable)\n"
            "  - No fallback when elevated privileges unavailable (vulnerable)\n"
            "  - Safe: Check privileges explicitly, handle denial gracefully\n\n"
            "For each vulnerability found, explain:\n"
            "1. Exception handling issue: what is not being handled properly\n"
            "2. Security impact: how this could be exploited\n"
            "3. Severity: whether this allows fail-open, resource leak, or DoS\n\n"
            "Return ONLY a JSON object with this structure:\n"
            "{{\n"
            "  \"findings\": [\n"
            "    {{\n"
            "      \"category\": \"A10\",\n"
            "      \"description\": \"vulnerability description\",\n"
            "      \"affected_code\": \"the problematic code\",\n"
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
    
    print("Agent: Running A10 (Error Handling) detector...")
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
            result = _parse_error_handling_response(raw_output)
            all_findings.extend(result.findings)
        except Exception as e:
            print(f"Error analyzing {hunk.file_path}: {e}")
            continue
    
    return all_findings


if __name__ == "__main__":
    print("=" * 80)
    print("COMPREHENSIVE A10 ERROR HANDLING DETECTOR TEST SUITE")
    print("=" * 80)
    
    # ========== POSITIVE TEST CASES (Should detect vulnerabilities) ==========
    print("\n" + "=" * 80)
    print("POSITIVE CASES (Error handling issues SHOULD be detected)")
    print("=" * 80)
    
    positive_cases = [
        # Sensitive data in error messages
        {
            "name": "Sensitive data in error message",
            "file": "app/auth.py",
            "added": [
                "+except Exception as e:",
                "+    return {'error': f'Database connection failed: {e}', 'db_url': DB_URL}",
            ],
            "removed": [
                "-except Exception as e:",
                "-    log.error(f'Database connection failed: {e}')",
                "-    return {'error': 'Service temporarily unavailable'}"
            ]
        },
        # Stack trace exposed to user
        {
            "name": "Stack trace exposed in production",
            "file": "app/api.py",
            "added": [
                "+@app.errorhandler(Exception)",
                "+def handle_error(e):",
                "+    return {'error': str(e), 'traceback': traceback.format_exc()}, 500"
            ],
            "removed": []
        },
        # Uncaught exception - no try-catch
        {
            "name": "Uncaught exception - missing try-catch",
            "file": "utils/parser.py",
            "added": [
                "+def parse_json(data):",
                "+    return json.loads(data)  # No try-except!"
            ],
            "removed": [
                "-def parse_json(data):",
                "-    try:",
                "-        return json.loads(data)",
                "-    except json.JSONDecodeError as e:"
            ]
        },
        # NULL pointer dereference
        {
            "name": "NULL pointer dereference - no null check",
            "file": "app/models.py",
            "added": [
                "+user = User.query.filter_by(id=user_id).first()",
                "+return user.email  # user could be None!"
            ],
            "removed": [
                "-user = User.query.filter_by(id=user_id).first()",
                "-if user:",
                "-    return user.email"
            ]
        },
        # Unchecked return value
        {
            "name": "Unchecked return value",
            "file": "src/file_ops.py",
            "added": [
                "+def save_file(filename, data):",
                "+    f = open(filename, 'w')",
                "+    f.write(data)",
                "+    f.close()  # No check if write succeeded!"
            ],
            "removed": []
        },
        # Failing open - access granted on auth error
        {
            "name": "Failing open - authentication bypass",
            "file": "middleware/auth.py",
            "added": [
                "+try:",
                "+    verify_token(token)",
                "+except TokenExpired:",
                "+    pass  # Continue anyway - FAIL OPEN!"
            ],
            "removed": [
                "-try:",
                "-    verify_token(token)",
                "-except TokenExpired:",
                "-    abort(401)"
            ]
        },
        # Resource leak on exception
        {
            "name": "Resource leak - file not closed on error",
            "file": "utils/processing.py",
            "added": [
                "+def process_file(filepath):",
                "+    f = open(filepath, 'r')",
                "+    data = json.load(f)  # Exception here, f never closed!",
                "+    return data"
            ],
            "removed": [
                "-def process_file(filepath):",
                "-    with open(filepath, 'r') as f:",
                "-        return json.load(f)"
            ]
        },
    ]
    
    # ========== NEGATIVE TEST CASES (Should NOT detect vulnerabilities) ==========
    print("\n" + "=" * 80)
    print("NEGATIVE CASES (Proper error handling - NO vulnerabilities should be detected)")
    print("=" * 80)
    
    negative_cases = [
        # Proper error handling with generic message
        {
            "name": "Proper error handling - generic user message",
            "file": "app/auth.py",
            "added": [
                "+try:",
                "+    verify_credentials(username, password)",
                "+except Exception as e:",
                "+    log.error(f'Auth failed: {e}')",
                "+    return {'error': 'Invalid credentials'}, 401"
            ],
            "removed": []
        },
        # Null check before dereferencing
        {
            "name": "Proper NULL checking",
            "file": "app/models.py",
            "added": [
                "+user = User.query.filter_by(id=user_id).first()",
                "+if user:",
                "+    return user.email",
                "+return None"
            ],
            "removed": []
        },
        # Resource cleanup with try-finally
        {
            "name": "Proper resource cleanup",
            "file": "utils/processing.py",
            "added": [
                "+def process_file(filepath):",
                "+    try:",
                "+        f = open(filepath, 'r')",
                "+        data = json.load(f)",
                "+    finally:",
                "+        f.close()",
                "+    return data"
            ],
            "removed": []
        },
        # Fail-closed authentication
        {
            "name": "Fail-closed authentication",
            "file": "middleware/auth.py",
            "added": [
                "+try:",
                "+    verify_token(token)",
                "+except TokenExpired:",
                "+    abort(401)  # Fail closed"
            ],
            "removed": []
        },
    ]
    
    # ========== EDGE CASES ==========
    print("\n" + "=" * 80)
    print("EDGE CASES (Borderline exception handling scenarios)")
    print("=" * 80)
    
    edge_cases = [
        # Generic exception catching
        {
            "name": "Edge: Catching generic Exception instead of specific",
            "file": "app/handlers.py",
            "added": [
                "+try:",
                "+    process_data(user_input)",
                "+except Exception:",
                "+    log.error('Processing failed')"
            ],
            "removed": []
        },
        # Missing default case in if-else
        {
            "name": "Edge: Missing default case in decision logic",
            "file": "app/router.py",
            "added": [
                "+if method == 'GET':",
                "+    handle_get()",
                "+elif method == 'POST':",
                "+    handle_post()",
                "+# No else - what if method is DELETE?"
            ],
            "removed": []
        },
        # Division by zero not checked
        {
            "name": "Edge: Division without bounds checking",
            "file": "utils/math.py",
            "added": [
                "+def calculate_average(total, count):",
                "+    return total / count  # What if count is 0?"
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
                findings = detect_error_handling([mock_hunk])
                
                if findings:
                    print(f"✓ Found {len(findings)} issue(s):")
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
    print("\nNOTE: Model temperature is set to 0.1 for nuanced error handling analysis.")
