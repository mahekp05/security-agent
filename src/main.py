# src/main.py
import sys
from collections import defaultdict
from src.core.models import VulnerabilityFinding, DiffHunk, ProsecutorVerdict, DefenderVerdict, CategoryTriageVerdict, SecurityReport
from src.agents.triage.prosecutor import create_prosecutor
from src.agents.triage.defender import create_defender
from src.agents.triage.judge import create_judge
from src.agents.detectors.injection_detector import detect_injection
from src.agents.detectors.configuration_detector import detect_configuration
from src.agents.detectors.errorHandling_detector import detect_error_handling
from src.agents.diff_parser import parse_git_diff


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
        return None
    
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
        return None
    
    # 3. Group findings by category
    print("\n3. Grouping findings by category...")
    findings_by_category = defaultdict(lambda: {"findings": [], "hunks": []})
    
    for finding in a05_findings + a02_findings + a10_findings:
        findings_by_category[finding.category]["findings"].append(finding)
    
    # Track which hunks are relevant for each category
    # Only include hunks that contain findings for that category
    for category in findings_by_category:
        relevant_hunks = []
        for finding in findings_by_category[category]["findings"]:
            # For each finding, find which hunks contain the affected code
            for hunk in hunks:
                # Check if the affected code appears as substring in any line
                has_code = any(finding.affected_code in line for line in hunk.added_lines) or any(finding.affected_code in line for line in hunk.removed_lines)
                if has_code:
                    # Avoid duplicates by checking if hunk is already in list
                    if hunk not in relevant_hunks:
                        relevant_hunks.append(hunk)
        findings_by_category[category]["hunks"] = relevant_hunks
    
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
    
    # Create and return the final report
    all_findings = a05_findings + a02_findings + a10_findings
    report = SecurityReport(
        verdicts=verdicts,
        total_findings=len(all_findings),
        summary=f"Found {len(verdicts)} vulnerability categories with {len(all_findings)} total findings"
    )
    return report


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

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import List

from src.agents.diff_parser import parse_git_diff
from src.agents.detectors.configuration_detector import detect_configuration
from src.agents.detectors.errorHandling_detector import detect_error_handling
from src.agents.detectors.injection_detector import detect_injection
from src.core.models import VulnerabilityFinding
from src.github.client import get_pr_diff, post_issue_comment


def _read_github_pr_number_from_event(event_path: str) -> int:
    with open(event_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if "pull_request" not in payload or "number" not in payload["pull_request"]:
        raise ValueError("GitHub event payload missing pull_request.number")
    return int(payload["pull_request"]["number"])


def _format_report(findings: List[VulnerabilityFinding]) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines: List[str] = [
        "## Security Agent Report",
        f"_Generated: {ts}_",
        "",
    ]

    if not findings:
        lines += [
            "No potential A05/A02/A10 findings detected from the PR diff.",
            "",
            "_AI-assisted review. Please verify before acting._",
        ]
        return "\n".join(lines)

    # Group by category for readability
    categories = {"A05": [], "A02": [], "A10": []}
    for finding in findings:
        categories.setdefault(finding.category, []).append(finding)

    total = sum(len(v) for v in categories.values())
    lines.append(f"Found **{total}** potential findings:")
    lines.append("")

    for cat in ("A05", "A02", "A10"):
        cat_findings = categories.get(cat, [])
        if not cat_findings:
            continue
        lines.append(f"### {cat} ({len(cat_findings)})")
        for f in cat_findings[:20]:
            code = (f.affected_code or "").strip()
            if len(code) > 220:
                code = code[:220] + "…"
            desc = (f.description or "").strip()
            lines.append(f"- **{f.confidence}**: {desc}")
            if code:
                lines.append(f"  - Code: `{code}`")
        if len(cat_findings) > 20:
            lines.append(f"- …and {len(cat_findings) - 20} more")
        lines.append("")

    lines.append("_AI-assisted review. Please verify before acting._")
    return "\n".join(lines)


def run_on_diff(raw_diff: str) -> str:
    hunks = parse_git_diff(raw_diff)

    findings: List[VulnerabilityFinding] = []
    findings.extend(detect_injection(hunks))
    findings.extend(detect_configuration(hunks))
    findings.extend(detect_error_handling(hunks))

    return _format_report(findings)


def main() -> int:
    parser = argparse.ArgumentParser(description="Security agent runner")
    parser.add_argument("--github-pr", action="store_true", help="Run in GitHub Actions PR context and post a PR comment")
    parser.add_argument(
        "--test-comment",
        action="store_true",
        help="Post a basic test comment and skip all analysis (useful to validate GitHub Actions wiring)",
    )
    parser.add_argument("--repo", help="owner/repo (for local debugging without GitHub Actions)")
    parser.add_argument("--pr-number", type=int, help="PR number (for local debugging without GitHub Actions)")
    parser.add_argument("--diff-file", help="Path to a local diff file (offline run)")
    args = parser.parse_args()

    # Offline mode: useful for local testing without GitHub
    if args.diff_file:
        with open(args.diff_file, "r", encoding="utf-8") as f:
            raw_diff = f.read()
        print(run_on_diff(raw_diff))
        return 0

    # Local GitHub mode (manual): fetch diff and print report
    if args.repo and args.pr_number:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ValueError("GITHUB_TOKEN is required when using --repo/--pr-number")
        if args.test_comment:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            body = (
                "## Security Agent Test Comment\n"
                f"_Generated: {ts}_\n\n"
                "This is a wiring test. Analysis is currently skipped (test mode).\n"
            )
            post_issue_comment(args.repo, args.pr_number, token, body)
            print("Posted test comment to PR.")
            return 0

        raw_diff = get_pr_diff(args.repo, args.pr_number, token)
        print(run_on_diff(raw_diff))
        return 0

    # GitHub Actions mode: fetch diff and post comment
    if args.github_pr:
        repo = os.environ.get("GITHUB_REPOSITORY")
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        token = os.environ.get("GITHUB_TOKEN")

        if not repo or not event_path or not token:
            raise ValueError("Missing one of required env vars: GITHUB_REPOSITORY, GITHUB_EVENT_PATH, GITHUB_TOKEN")

        pr_number = _read_github_pr_number_from_event(event_path)

        if args.test_comment:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            body = (
                "## Security Agent Test Comment\n"
                f"_Generated: {ts}_\n\n"
                "This is a wiring test from GitHub Actions. Analysis is currently skipped (test mode).\n\n"
                f"- Repo: `{repo}`\n"
                f"- PR: `#{pr_number}`\n"
            )
            post_issue_comment(repo, pr_number, token, body)
            return 0

        try:
            raw_diff = get_pr_diff(repo, pr_number, token)
            report_md = run_on_diff(raw_diff)
        except Exception as e:
            # Best-effort: still post a comment so the developer sees the failure.
            report_md = _format_report([]) + f"\n\n---\n\n**Agent error:** {type(e).__name__}: {e}"

        post_issue_comment(repo, pr_number, token, report_md)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())