# Written with help of GitHub Copilot
"""Security agent runner.

This module is the backend entrypoint responsible for retrieving and processing PR diffs.
In GitHub PR mode it fetches the actual PR diff via the GitHub API, parses it, runs
detectors and triage agents, then posts a Markdown report as an issue comment.

Phase 2: Supports chunking of large diffs with per-chunk analysis.
"""

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Tuple

from src.agents.diff_parser import parse_git_diff
from src.agents.chunker import create_chunker, Chunk
from src.agents.detectors.configuration_detector import detect_configuration
from src.agents.detectors.errorHandling_detector import detect_error_handling
from src.agents.detectors.injection_detector import detect_injection
from src.agents.triage.defender import create_defender
from src.agents.triage.judge import create_judge
from src.agents.triage.prosecutor import create_prosecutor
from src.agents.triage.aggregator import create_aggregator
from src.core.config import get_config
from src.core.models import CategoryTriageVerdict, DiffHunk, JudgeVerdict, SecurityReport, VulnerabilityFinding, ProsecutorVerdict, DefenderVerdict
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
    """Parse diff, run detectors (with optional chunking), then run triage per category.
    
    Phase 2: Implements intelligent chunking for large diffs:
    - If diff > 24k tokens: split by file boundaries
    - Analyze each chunk independently (detectors, triage)
    - Tag findings with chunk IDs for traceability
    - Aggregate verdicts: worst verdict wins

    Returns:
        (hunks, findings, verdicts)
    """
    hunks = parse_git_diff(raw_diff)
    
    # Determine if chunking is needed (check config.enabled first)
    config = get_config()
    chunking_cfg = config.get_chunking_config()
    chunking_enabled = chunking_cfg.get('enabled', True)
    max_chunk_tokens = chunking_cfg.get('max_chunk_tokens', 24000)
    overlap_tokens = chunking_cfg.get('overlap_tokens', 500)
    
    chunker = create_chunker(max_tokens=max_chunk_tokens, overlap_tokens=overlap_tokens)
    should_chunk = chunking_enabled and chunker.should_chunk(hunks)
    
    if should_chunk:
        try:
            chunks = chunker.chunk_diff(hunks)
            print(f"Chunking enabled: {len(chunks)} chunks (total {len(hunks)} hunks)")
        except ValueError as e:
            print(f"Chunking failed: {e}. Falling back to non-chunked analysis.")
            chunks = [Chunk(id="chunk_1", hunks=hunks, token_count=0)]
    else:
        # No chunking needed
        chunks = [Chunk(id="chunk_1", hunks=hunks, token_count=0)]
    
    # Run detectors on each chunk
    findings: List[VulnerabilityFinding] = []
    for chunk in chunks:
        print(f"Agent: Analyzing chunk {chunk.id}...")
        
        chunk_findings = []
        chunk_findings.extend(detect_injection(chunk.hunks))
        chunk_findings.extend(detect_configuration(chunk.hunks))
        chunk_findings.extend(detect_error_handling(chunk.hunks))
        
        # Tag findings with chunk ID
        for finding in chunk_findings:
            finding.chunk_id = chunk.id
        
        findings.extend(chunk_findings)

    # Group findings by category
    findings_by_category: Dict[str, List[VulnerabilityFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_category[finding.category].append(finding)

    # Run triage per category
    prosecutor = create_prosecutor()
    defender = create_defender()
    judge = create_judge()
    aggregator = create_aggregator()

    verdicts: List[CategoryTriageVerdict] = []
    
    for category in sorted(findings_by_category.keys()):
        category_findings = findings_by_category[category]
        if not category_findings:
            continue

        # Group findings by chunk
        chunk_verdicts_by_category: Dict[str, List] = defaultdict(list)
        
        for chunk in chunks:
            chunk_findings = [f for f in category_findings if f.chunk_id == chunk.id]
            if not chunk_findings:
                continue
            
            relevant_hunks = _select_relevant_hunks(chunk.hunks, chunk_findings)
            if not relevant_hunks:
                relevant_hunks = chunk.hunks

            prosecutor_verdict = prosecutor.prosecute(category, chunk_findings, relevant_hunks)
            defender_verdict = defender.defend(category, chunk_findings, relevant_hunks, prosecutor_verdict)
            judge_verdict = judge.judge(category, chunk_findings, relevant_hunks, prosecutor_verdict, defender_verdict)
            
            # Tag verdict with chunk ID and simplified verdict for aggregation
            judge_verdict.chunk_id = chunk.id
            
            # Map risk_label to simplified verdict for aggregation
            risk_to_verdict = {
                "critical_risk": "CRITICAL",
                "medium_risk": "MEDIUM",
                "low_risk": "LOW",
                "false_positive": "FALSE_POSITIVE"
            }
            judge_verdict.verdict = risk_to_verdict.get(judge_verdict.risk_label, "LOW")
            
            chunk_verdicts_by_category[category].append(judge_verdict)

        # Aggregate verdicts for this category across all chunks
        if chunk_verdicts_by_category[category]:
            aggregated = aggregator.aggregate_category_verdicts(
                category,
                chunk_verdicts_by_category[category]
            )
            
            # Select all relevant hunks for the final verdict
            all_relevant_hunks = _select_relevant_hunks(hunks, category_findings)
            if not all_relevant_hunks:
                all_relevant_hunks = hunks
            
            # Convert aggregated verdict back to risk_label format
            verdict_to_risk = {
                "CRITICAL": "critical_risk",
                "MEDIUM": "medium_risk",
                "LOW": "low_risk",
                "FALSE_POSITIVE": "false_positive"
            }
            final_risk_label = verdict_to_risk.get(aggregated.final_verdict, "low_risk")
            
            # Create final CategoryTriageVerdict using aggregated verdict
            judge_verdict = JudgeVerdict(
                risk_label=final_risk_label,
                verdict=aggregated.final_verdict,
                confidence_score=int(round(aggregated.confidence)),
                reasoning=aggregated.reasoning,
                chunk_id=None  # PR-level, not chunk-specific
            )
            
            verdicts.append(
                CategoryTriageVerdict(
                    category=category,
                    findings=category_findings,
                    diff_hunks=all_relevant_hunks,
                    prosecutor=ProsecutorVerdict(
                        category=category,
                        confidence_score=int(round(aggregated.confidence)),
                        reasoning=aggregated.reasoning
                    ),
                    defender=DefenderVerdict(
                        confidence_score=int(round(aggregated.confidence)),
                        reasoning=aggregated.reasoning,
                        agrees_with_prosecutor=True
                    ),
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

    # Category type descriptions
    category_types = {
        "A05": "Injection",
        "A02": "Sensitive File Exposure",
        "A10": "Mishandling of Exceptional Conditions",
    }

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
        cat_type = category_types.get(cat, "")
        lines.append(f"### {cat}: {cat_type}")
        lines.append(f"**Findings: {len(cat_findings)}**")
        lines.append("")
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
            f"### {v.category}: **{judge.risk_label}** (findings {finding_count})"
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