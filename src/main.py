# src/main.py
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