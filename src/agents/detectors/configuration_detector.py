from src.core.llm import get_llm
from src.core.models import DiffHunk, VulnerabilityFinding
from langchain_core.prompts import PromptTemplate
from typing import List
from pydantic import BaseModel, Field
import json
import re

# Define the output schema for this detector
class ConfigurationFindings(BaseModel):
    findings: List[VulnerabilityFinding] = Field(description="List of configuration vulnerabilities found")

def _parse_configuration_response(raw_response) -> ConfigurationFindings:
    """
    Robustly parse LLM response for configuration issues.
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
                return ConfigurationFindings(findings=[
                    VulnerabilityFinding(**f) if isinstance(f, dict) else f 
                    for f in parsed
                ])
            elif isinstance(parsed, dict):
                if "findings" in parsed:
                    findings_list = parsed["findings"]
                    if isinstance(findings_list, list):
                        return ConfigurationFindings(findings=[
                            VulnerabilityFinding(**f) if isinstance(f, dict) else f 
                            for f in findings_list
                        ])
                # If dict but no findings key, treat it as a single finding
                return ConfigurationFindings(findings=[VulnerabilityFinding(**parsed)])
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        pass
    
    # Fallback: no valid JSON found or parsing failed
    return ConfigurationFindings(findings=[])

def detect_configuration(hunks: List[DiffHunk]) -> List[VulnerabilityFinding]:
    """
    Red team approach: analyze code changes for A02 (Configuration & Deployment) vulnerabilities.
    Focuses on insecure configurations, exposed secrets, and deployment misconfigurations.
    """
    # 1. Initialize LLM with slightly higher temperature for nuanced config analysis
    llm = get_llm(temperature=0.1)
    
    # 2. Create prompt for configuration vulnerabilities
    prompt = PromptTemplate(
        template=(
            "You are a DevSecOps security auditor analyzing code changes for A02 (Configuration & Deployment) vulnerabilities.\n"
            "Respond in English only.\n\n"
            "Configuration vulnerability categories to analyze:\n\n"
            "1. SENSITIVE FILE EXPOSURE:\n"
            "  - .env files committed to repo (vulnerable)\n"
            "  - secrets.yaml, credentials.json in source (vulnerable)\n"
            "  - Private keys (.pem, .key) in repo (vulnerable)\n"
            "  - Safe: Use .gitignore, secret management tools\n\n"
            "2. MISSING SECURITY HEADERS:\n"
            "  - Missing Strict-Transport-Security (HSTS) (vulnerable)\n"
            "  - Missing Content-Security-Policy header (vulnerable)\n"
            "  - Missing X-Frame-Options header (vulnerable)\n"
            "  - Safe: Add security headers in middleware/config\n\n"
            "3. INSECURE DEFAULTS:\n"
            "  - Debug mode enabled in production (vulnerable)\n"
            "  - CORS allowing '*' origin (vulnerable)\n"
            "  - API endpoint without authentication (vulnerable)\n"
            "  - Safe: Disable debug, restrict CORS, enforce auth\n\n"
            "4. CLOUD STORAGE MISCONFIGURATION:\n"
            "  - S3 bucket public read access (vulnerable)\n"
            "  - GCS bucket public access (vulnerable)\n"
            "  - Unencrypted sensitive data storage (vulnerable)\n"
            "  - Safe: Use bucket policies, encryption, IAM\n\n"
            "5. FILE PERMISSIONS & EXPOSURE:\n"
            "  - World-readable sensitive files (vulnerable)\n"
            "  - Backup files (.bak, .old) with credentials (vulnerable)\n"
            "  - Exposed admin interfaces (/admin, /management) (vulnerable)\n"
            "  - Safe: Restrict permissions, remove backups, protect admin paths\n\n"
            "6. HTTP CONFIGURATION ISSUES:\n"
            "  - HTTP protocol allowed instead of HTTPS only (vulnerable)\n"
            "  - Missing certificate pinning (vulnerable)\n"
            "  - Insecure SSL/TLS configuration (vulnerable)\n"
            "  - Safe: Enforce HTTPS, configure modern TLS\n\n"
            "7. INFRASTRUCTURE MISCONFIGURATIONS:\n"
            "  - Database exposed without authentication (vulnerable)\n"
            "  - Open ports exposing services (vulnerable)\n"
            "  - Missing rate limiting (vulnerable)\n"
            "  - Safe: Use VPC, firewalls, rate limiting\n\n"
            "For each vulnerability found, explain:\n"
            "1. Configuration issue: what is misconfigured\n"
            "2. Attack impact: potential compromise\n"
            "3. Risk: how serious is this exposure\n\n"
            "Return ONLY a JSON object with this structure:\n"
            "{{\n"
            "  \"findings\": [\n"
            "    {{\n"
            "      \"category\": \"A02\",\n"
            "      \"description\": \"vulnerability description\",\n"
            "      \"affected_code\": \"the misconfigured code\",\n"
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
    
    print("Agent: Running A02 (Configuration) detector...")
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
            result = _parse_configuration_response(raw_output)
            all_findings.extend(result.findings)
        except Exception as e:
            print(f"Error analyzing {hunk.file_path}: {e}")
            continue
    
    return all_findings


if __name__ == "__main__":
    print("=" * 80)
    print("COMPREHENSIVE A02 CONFIGURATION DETECTOR TEST SUITE")
    print("=" * 80)
    
    # ========== POSITIVE TEST CASES (Should detect vulnerabilities) ==========
    print("\n" + "=" * 80)
    print("POSITIVE CASES (Configuration vulnerabilities SHOULD be detected)")
    print("=" * 80)
    
    positive_cases = [
        # Exposed .env file
        {
            "name": "Exposed .env file with secrets",
            "file": ".env",
            "added": [
                "+DATABASE_URL=postgresql://user:password123@prod-db.example.com:5432/mydb",
                "+API_KEY=sk_live_51234567890abcdefghijklmn",
                "+JWT_SECRET=super_secret_key_never_share"
            ],
            "removed": []
        },
        # Debug mode enabled in production
        {
            "name": "Debug mode enabled in production",
            "file": "config/settings.py",
            "added": [
                "+# Production configuration",
                "+DEBUG = True",
                "+VERBOSE_LOGGING = True",
                "+EXPOSE_ERROR_DETAILS = True"
            ],
            "removed": [
                "-DEBUG = False"
            ]
        },
        # CORS allowing all origins
        {
            "name": "CORS configured to allow all origins",
            "file": "app/middleware.py",
            "added": [
                "+app.add_middleware(CORSMiddleware,",
                "+    allow_origins=['*'],",
                "+    allow_credentials=True,"
            ],
            "removed": [
                "-app.add_middleware(CORSMiddleware,",
                "-    allow_origins=['https://trusted.com'],"
            ]
        },
        # Missing security headers
        {
            "name": "Missing HTTP security headers",
            "file": "app/middleware.py",
            "added": [
                "+response = await call_next(request)",
                "+return response"
            ],
            "removed": [
                "-response.headers['Strict-Transport-Security'] = 'max-age=31536000'",
                "-response.headers['Content-Security-Policy'] = \"default-src 'self'\"",
                "-response.headers['X-Frame-Options'] = 'DENY'"
            ]
        },
        # S3 bucket public access
        {
            "name": "S3 bucket configured for public read access",
            "file": "infra/s3_config.py",
            "added": [
                "+bucket_policy = {",
                "+    'Statement': [{",
                "+        'Effect': 'Allow',",
                "+        'Principal': '*',",
                "+        'Action': 's3:GetObject',",
                "+        'Resource': 'arn:aws:s3:::my-bucket/*'"
            ],
            "removed": []
        },
        # Private key committed to repo
        {
            "name": "Private key committed to repository",
            "file": "config/private.pem",
            "added": [
                "+-----BEGIN RSA PRIVATE KEY-----",
                "+MIIEpAIBAAKCAQEA2Z3qX2BTLS7ZAAAA...[truncated]",
                "+-----END RSA PRIVATE KEY-----"
            ],
            "removed": []
        },
        # Unencrypted database connection in code
        {
            "name": "Unencrypted database credentials in source",
            "file": "src/db.py",
            "added": [
                "+connection_string = 'mongodb://admin:password@mongo-prod.com:27017/production'",
                "+client = MongoClient(connection_string)"
            ],
            "removed": [
                "-connection_string = os.getenv('MONGO_URI')"
            ]
        },
    ]
    
    # ========== NEGATIVE TEST CASES (Should NOT detect vulnerabilities) ==========
    print("\n" + "=" * 80)
    print("NEGATIVE CASES (Secure config - NO vulnerabilities should be detected)")
    print("=" * 80)
    
    negative_cases = [
        # .env in gitignore
        {
            "name": "Environment file properly ignored",
            "file": ".gitignore",
            "added": [
                "+.env",
                "+.env.local",
                "+.env.*.local",
                "+secrets.yaml"
            ],
            "removed": []
        },
        # Proper security headers configured
        {
            "name": "Security headers properly configured",
            "file": "app/middleware.py",
            "added": [
                "+response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
                "+response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self' 'unsafe-inline'\"",
                "+response.headers['X-Frame-Options'] = 'DENY'",
                "+response.headers['X-Content-Type-Options'] = 'nosniff'"
            ],
            "removed": []
        },
        # Debug mode properly disabled
        {
            "name": "Debug mode disabled for production",
            "file": "config/settings.py",
            "added": [
                "+if os.getenv('ENVIRONMENT') == 'production':",
                "+    DEBUG = False",
                "+    VERBOSE_LOGGING = False"
            ],
            "removed": []
        },
        # CORS properly restricted
        {
            "name": "CORS properly restricted to trusted domains",
            "file": "app/middleware.py",
            "added": [
                "+allow_origins = os.getenv('ALLOWED_ORIGINS', '').split(',')",
                "+app.add_middleware(CORSMiddleware, allow_origins=allow_origins)"
            ],
            "removed": []
        },
    ]
    
    # ========== EDGE CASES ==========
    print("\n" + "=" * 80)
    print("EDGE CASES (Borderline/Complex configuration scenarios)")
    print("=" * 80)
    
    edge_cases = [
        # Hardcoded config with comment
        {
            "name": "Edge: Hardcoded value with misleading comment",
            "file": "config/settings.py",
            "added": [
                "+# Using environment variables for security",
                "+API_URL = 'https://api.production.com'",
                "+API_KEY = 'hardcoded_key_12345'"
            ],
            "removed": []
        },
        # Backup file with timestamps
        {
            "name": "Edge: Backup file with sensitive data",
            "file": "config/config.backup.2024",
            "added": [
                "+database_password=prod_password_here",
                "+admin_api_key=admin_key_value"
            ],
            "removed": []
        },
        # HTTPS with weak TLS
        {
            "name": "Edge: HTTPS with outdated TLS version",
            "file": "nginx.conf",
            "added": [
                "+ssl_protocols TLSv1 TLSv1.1 TLSv1.2;",
                "+ssl_ciphers 'RC4-SHA:DES-CBC3-SHA';"
            ],
            "removed": [
                "-ssl_protocols TLSv1.2 TLSv1.3;",
                "-ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384';"
            ]
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
                findings = detect_configuration([mock_hunk])
                
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
    print("\nNOTE: Model temperature is set to 0.1 for nuanced configuration analysis.")
