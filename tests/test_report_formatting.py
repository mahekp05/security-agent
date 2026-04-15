import pytest

from src.core.models import (
    CategoryTriageVerdict,
    DefenderVerdict,
    DiffHunk,
    JudgeVerdict,
    ProsecutorVerdict,
    VulnerabilityFinding,
)
from src.main import _format_triage_section


def test_format_triage_section_includes_judge_fields() -> None:
    verdict = CategoryTriageVerdict(
        category="A05",
        findings=[
            VulnerabilityFinding(
                category="A05",
                description="SQL injection via f-string",
                affected_code='query = f"SELECT * FROM users WHERE id={user_id}"',
                confidence="High",
            )
        ],
        diff_hunks=[
            DiffHunk(
                file_path="app.py",
                added_lines=['+query = f"SELECT * FROM users WHERE id={user_id}"'],
                removed_lines=['-query = "SELECT * FROM users WHERE id = %s"'],
            )
        ],
        prosecutor=ProsecutorVerdict(
            category="A05",
            confidence_score=55,
            reasoning="Prosecutor reasoning",
        ),
        defender=DefenderVerdict(
            confidence_score=44,
            reasoning="Defender reasoning",
            agrees_with_prosecutor=False,
        ),
        judge=JudgeVerdict(
            risk_label="critical_risk",
            reasoning="Judge says this is exploitable and high impact.",
            confidence_score=88,
        ),
    )

    md = _format_triage_section([verdict])

    assert "## Triage (Judge)" in md
    assert "A05" in md
    assert "critical_risk" in md

    # Ensure we include findings count in the header.
    assert "findings 1" in md
    assert "Judge says this is exploitable" in md
    assert "<details>" in md
    assert "</details>" in md
