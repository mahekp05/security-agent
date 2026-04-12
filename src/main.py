"""Security agent runner.

This module is the backend entrypoint responsible for retrieving and processing PR diffs.
In GitHub PR mode it fetches the actual PR diff via the GitHub API, parses it, runs
detectors and triage agents, then posts a Markdown report as an issue comment.
"""

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Tuple

from src.agents.diff_parser import parse_git_diff
from src.agents.detectors.configuration_detector import detect_configuration
from src.agents.detectors.errorHandling_detector import detect_error_handling
from src.agents.detectors.injection_detector import detect_injection
from src.agents.triage.defender import create_defender
from src.agents.triage.judge import create_judge
from src.agents.triage.prosecutor import create_prosecutor
from src.core.models import CategoryTriageVerdict, DiffHunk, SecurityReport, VulnerabilityFinding
from src.github.client import get_pr_diff, post_issue_comment


def _normalize_diff_text(text: str) -> str:
    """Normalize code-ish text to make hunk matching more resilient."""
    if not text:
        return ""
    s = text.strip()
    if s[:1] in {"+", "-"}:
        s = s[1:]
    return s.strip()


def _iter_normalized_hunk_lines(hunk: DiffHunk) -> Iterable[str]:
    for line in hunk.added_lines:
        yield _normalize_diff_text(line)
    for line in hunk.removed_lines:
        yield _normalize_diff_text(line)


def _select_relevant_hunks(hunks: List[DiffHunk], findings: List[VulnerabilityFinding]) -> List[DiffHunk]:
    needles = [
        _normalize_diff_text(f.affected_code)
        for f in findings
        if getattr(f, "affected_code", None)
    ]
    needles = [n for n in needles if n]
    if not needles:
        return []

    relevant: List[DiffHunk] = []
    for hunk in hunks:
        haystack = list(_iter_normalized_hunk_lines(hunk))
        if any(
            any(needle in line or line in needle for line in haystack if line)
            for needle in needles
        ):
            relevant.append(hunk)
    return relevant


def _analyze_diff(raw_diff: str) -> Tuple[List[DiffHunk], List[VulnerabilityFinding], List[CategoryTriageVerdict]]:
    """Parse diff, run detectors, then run triage per category.

    Returns:
        (hunks, findings, verdicts)
    """
    hunks = parse_git_diff(raw_diff)

    findings: List[VulnerabilityFinding] = []
    findings.extend(detect_injection(hunks))
    findings.extend(detect_configuration(hunks))
    findings.extend(detect_error_handling(hunks))

    findings_by_category: Dict[str, List[VulnerabilityFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_category[finding.category].append(finding)

    prosecutor = create_prosecutor()
    defender = create_defender()
    judge = create_judge()

    verdicts: List[CategoryTriageVerdict] = []
    for category in sorted(findings_by_category.keys()):
        category_findings = findings_by_category[category]
        if not category_findings:
            continue

        relevant_hunks = _select_relevant_hunks(hunks, category_findings)
        if not relevant_hunks:
            # Fallback: do not fail triage if detector output doesn't exactly match diff lines.
            relevant_hunks = hunks

        prosecutor_verdict = prosecutor.prosecute(category, category_findings, relevant_hunks)
        defender_verdict = defender.defend(category, category_findings, relevant_hunks, prosecutor_verdict)
        judge_verdict = judge.judge(category, category_findings, relevant_hunks, prosecutor_verdict, defender_verdict)

        verdicts.append(
            CategoryTriageVerdict(
                category=category,
                findings=category_findings,
                diff_hunks=relevant_hunks,
                prosecutor=prosecutor_verdict,
                defender=defender_verdict,
                judge=judge_verdict,
            )
        )

    risk_order = {"critical_risk": 4, "medium_risk": 3, "low_risk": 2, "false_positive": 1}
    verdicts.sort(key=lambda v: risk_order.get(v.risk_label, 0), reverse=True)

    return hunks, findings, verdicts


def run_full_pipeline(raw_diff: str) -> SecurityReport:
    """Run complete pipeline: parse diff → detectors → triage agents."""
    _, findings, verdicts = _analyze_diff(raw_diff)
    return SecurityReport(
        verdicts=verdicts,
        total_findings=len(findings),
        summary=f"Found {len(verdicts)} vulnerability categories with {len(findings)} total findings",
    )


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


def _format_triage_section(verdicts: List[CategoryTriageVerdict]) -> str:
    lines: List[str] = [
        "## Triage (Judge)",
        "",
    ]

    if not verdicts:
        lines.append("No triage verdicts (no findings detected).")
        return "\n".join(lines)

    for v in verdicts:
        judge = v.judge
        finding_count = len(v.findings) if getattr(v, "findings", None) else 0
        lines.append(
            f"### {v.category}: **{judge.risk_label}** (confidence {judge.confidence_score}/100, findings {finding_count})"
        )
        lines.append("<details>")
        lines.append("<summary>Reasoning</summary>")
        lines.append("")
        lines.append((judge.reasoning or "").strip() or "(no reasoning provided)")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def run_on_diff(raw_diff: str, include_triage: bool = False) -> str:
    # Analyze using the full backend pipeline (includes triage).
    _, findings, verdicts = _analyze_diff(raw_diff)
    report_md = _format_report(findings)
    if include_triage:
        report_md = report_md + "\n\n---\n\n" + _format_triage_section(verdicts)
    return report_md


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
    parser.add_argument(
        "--include-triage",
        action="store_true",
        help="Include Judge triage verdicts in the generated report/comment",
    )
    args = parser.parse_args()

    # Offline mode: useful for local testing without GitHub
    if args.diff_file:
        with open(args.diff_file, "r", encoding="utf-8") as f:
            raw_diff = f.read()
        print(run_on_diff(raw_diff, include_triage=args.include_triage))
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
        print(run_on_diff(raw_diff, include_triage=args.include_triage))
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
            report_md = run_on_diff(raw_diff, include_triage=args.include_triage)
        except Exception as e:
            # Best-effort: still post a comment so the developer sees the failure.
            report_md = _format_report([]) + f"\n\n---\n\n**Agent error:** {type(e).__name__}: {e}"

        post_issue_comment(repo, pr_number, token, report_md)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())