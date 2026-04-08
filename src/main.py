# src/main.py
import sys
from collections import defaultdict
from core.models import VulnerabilityFinding, DiffHunk, ProsecutorVerdict, DefenderVerdict, CategoryTriageVerdict
from agents.triage.prosecutor import create_prosecutor
from agents.triage.defender import create_defender
from agents.triage.judge import create_judge
from agents.detectors.injection_detector import detect_injection
from agents.detectors.configuration_detector import detect_configuration
from agents.detectors.errorHandling_detector import detect_error_handling
from agents.diff_parser import parse_git_diff


def run_full_pipeline(raw_diff: str):
    """Run complete pipeline: parse diff → detectors → triage agents"""
    print("="*80)
    print("RUNNING FULL SECURITY AGENT PIPELINE")
    print("="*80)
    
    # 1. Parse diff
    print("\n1. Parsing git diff...")
    try:
        hunks = parse_git_diff(raw_diff)
        print(f"✓ Extracted {len(hunks)} code hunks")
        for hunk in hunks:
            print(f"  - {hunk.file_path}")
    except Exception as e:
        print(f"✗ Diff parsing failed: {str(e)[:100]}")
        return False
    
    # 2. Run detectors
    print("\n2. Running detectors (A05, A02, A10)...")
    try:
        a05_findings = detect_injection(hunks)
        a02_findings = detect_configuration(hunks)
        a10_findings = detect_error_handling(hunks)
        
        print(f"✓ A05 (Injection): {len(a05_findings)} findings")
        print(f"✓ A02 (Configuration): {len(a02_findings)} findings")
        print(f"✓ A10 (Error Handling): {len(a10_findings)} findings")
    except Exception as e:
        print(f"✗ Detector failed: {str(e)[:100]}")
        return False
    
    # 3. Group findings by category
    print("\n3. Grouping findings by category...")
    findings_by_category = defaultdict(lambda: {"findings": [], "hunks": []})
    
    for finding in a05_findings + a02_findings + a10_findings:
        findings_by_category[finding.category]["findings"].append(finding)
    
    # Track which hunks are relevant for each category
    for category in findings_by_category:
        for hunk in hunks:
            if hunk not in findings_by_category[category]["hunks"]:
                findings_by_category[category]["hunks"].append(hunk)
    
    # 4. Run triage for each category
    print("\n4. Running triage agents (Prosecutor → Defender → Judge)...")
    verdicts = []
    
    prosecutor = create_prosecutor()
    defender = create_defender()
    judge = create_judge()
    
    for category in sorted(findings_by_category.keys()):
        findings = findings_by_category[category]["findings"]
        hunks_list = list(findings_by_category[category]["hunks"])
        
        if not findings:
            continue
        
        print(f"\n   Category: {category} ({len(findings)} findings)")
        
        try:
            # Prosecutor
            print(f"   → Prosecutor...", end=" ", flush=True)
            prosecutor_verdict = prosecutor.prosecute(category, findings, hunks_list)
            print(f"✓ ({prosecutor_verdict.confidence_score}/100)")
            
            # Defender
            print(f"   → Defender...", end=" ", flush=True)
            defender_verdict = defender.defend(category, findings, hunks_list, prosecutor_verdict)
            print(f"✓ ({defender_verdict.confidence_score}/100)")
            
            # Judge
            print(f"   → Judge...", end=" ", flush=True)
            judge_verdict = judge.judge(category, findings, hunks_list, prosecutor_verdict, defender_verdict)
            print(f"✓ ({judge_verdict.risk_label})")
            
            # Store verdict
            verdict = CategoryTriageVerdict(
                category=category,
                findings=findings,
                diff_hunks=hunks_list,
                prosecutor=prosecutor_verdict,
                defender=defender_verdict,
                judge=judge_verdict
            )
            verdicts.append(verdict)
            
        except Exception as e:
            print(f"✗ Triage failed: {str(e)[:80]}")
            continue
    
    # 5. Print summary
    print("\n" + "="*80)
    print("SECURITY ASSESSMENT REPORT")
    print("="*80)
    for verdict in sorted(verdicts, key=lambda v: ["critical_risk", "medium_risk", "low_risk", "false_positive"].index(v.judge.risk_label)):
        print(f"\nCategory: {verdict.category}")
        print(f"  Findings: {len(verdict.findings)}")
        print(f"  Prosecutor: {verdict.prosecutor.confidence_score}/100")
        print(f"  Defender: {verdict.defender.confidence_score}/100")
        print(f"  Risk Label: {verdict.judge.risk_label}")
        print(f"  Judge Reasoning: {verdict.judge.reasoning[:150]}...")
    
    print("\n" + "="*80)
    return True


def mock_get_git_diff(repo_path: str) -> str:
    # Later: implemented with GitPython or subprocess
    return "diff --git a/test.py b/test.py\n+ eval(user_input)"


def main():
    # Mock git diff with actual security vulnerabilities
    raw_diff = """diff --git a/app.py b/app.py
index 1234567..abcdefg 100644
--- a/app.py
+++ b/app.py
@@ -15,8 +15,10 @@ from flask import Flask, request
 
 def get_user(user_id):
-    query = "SELECT * FROM users WHERE id = %s"
-    return db.execute(query, (user_id,))
+    # SQL Injection vulnerability - f-string in query
+    query = f"SELECT * FROM users WHERE id={user_id}"
+    return db.execute(query)
 
 def login(username, password):
-    ldap_filter = "(uid={})"
+    # Command injection - unsanitized shell command
+    os.system(f"ldap search -u {username} -p {password}")
 
@@ -25,7 +27,8 @@ def download_file(filename):
 
 def error_page(error_code):
-    return render_template('error.html', code=error_code)
+    # Error handling with stack trace exposure
+    return traceback.format_exc()
 
 def api_config():
-    return {"version": "1.0"}
+    return {"version": "1.0", "api_key": "sk-1234567890"}
"""
    
    # Run complete pipeline
    run_full_pipeline(raw_diff)


if __name__ == "__main__":
    main()