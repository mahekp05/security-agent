# src/main.py
import sys
from core.models import VulnerabilityFinding, DiffHunk, ProsecutorVerdict, DefenderVerdict
from agents.triage.prosecutor import create_prosecutor
from agents.triage.defender import create_defender
from agents.triage.judge import create_judge


def test_all_agents():
    """Test Prosecutor, Defender, and Judge agents"""
    print("="*80)
    print("TESTING ALL THREE TRIAGE AGENTS")
    print("="*80)
    
    # Create test data
    print("\n1. Creating test findings and hunks...")
    finding = VulnerabilityFinding(
        category="A05",
        description="SQL Injection in user input",
        affected_code="query = f\"SELECT * FROM users WHERE id={user_id}\"",
        confidence="High"
    )
    
    hunk = DiffHunk(
        file_path="src/database.py",
        added_lines=[
            "def get_user(user_id):",
            "    query = f\"SELECT * FROM users WHERE id={user_id}\"",
            "    return db.execute(query)"
        ],
        removed_lines=[
            "def get_user(user_id):",
            "    query = \"SELECT * FROM users WHERE id=?\"",
            "    return db.execute(query, (user_id,))"
        ]
    )
    print(f"✓ Finding: {finding.category} - {finding.description}")
    print(f"✓ Hunk: {hunk.file_path}")
    
    # Test Prosecutor
    print("\n2. Running PROSECUTOR agent...")
    try:
        prosecutor = create_prosecutor()
        print(f"  ✓ Prosecutor initialized")
        
        prosecutor_verdict = prosecutor.prosecute(
            category="A05",
            findings=[finding],
            hunks=[hunk]
        )
        print(f"✓ PROSECUTOR VERDICT GENERATED")
        print(f"  Confidence Score: {prosecutor_verdict.confidence_score}/100")
        print(f"  Reasoning (first 150 chars): {prosecutor_verdict.reasoning[:150]}...")
        
    except Exception as e:
        print(f"✗ PROSECUTOR FAILED: {str(e)[:100]}")
        print(f"  [LLM call requires valid HuggingFace token]")
        return False
    
    # Test Defender
    print("\n3. Running DEFENDER agent...")
    try:
        defender = create_defender()
        print(f"  ✓ Defender initialized")
        
        defender_verdict = defender.defend(
            category="A05",
            findings=[finding],
            hunks=[hunk],
            prosecutor_verdict=prosecutor_verdict
        )
        print(f"✓ DEFENDER VERDICT GENERATED")
        print(f"  Confidence Score: {defender_verdict.confidence_score}/100")
        print(f"  Reasoning (first 150 chars): {defender_verdict.reasoning[:150]}...")
        
        score_diff = prosecutor_verdict.confidence_score - defender_verdict.confidence_score
        print(f"\n  Score Difference: {score_diff:+d} (Prosecutor {prosecutor_verdict.confidence_score} vs Defender {defender_verdict.confidence_score})")
        
    except Exception as e:
        print(f"✗ DEFENDER FAILED: {str(e)[:100]}")
        return False
    
    # Test Judge
    print("\n4. Running JUDGE agent...")
    try:
        judge = create_judge()
        print(f"  ✓ Judge initialized")
        
        judge_verdict = judge.judge(
            category="A05",
            findings=[finding],
            hunks=[hunk],
            prosecutor_verdict=prosecutor_verdict,
            defender_verdict=defender_verdict
        )
        print(f"✓ JUDGE VERDICT GENERATED")
        print(f"  Risk Label: {judge_verdict.risk_label}")
        print(f"  Reasoning (first 150 chars): {judge_verdict.reasoning[:150]}...")
        
    except Exception as e:
        print(f"✗ JUDGE FAILED: {str(e)[:100]}")
        return False
    
    print("\n" + "="*80)
    print("✓ ALL THREE AGENTS RUNNING SUCCESSFULLY")
    print("="*80)
    return True


def mock_get_git_diff(repo_path: str) -> str:
    # Later: implemented with GitPython or subprocess
    return "diff --git a/test.py b/test.py\n+ eval(user_input)"


def main():
    # 1. Get raw diff
    raw_diff = mock_get_git_diff(".")
    
    # 2. Parse diff
    # hunks = diff_parser_agent.run(raw_diff)
    print("Parsing diff...")
    
    # 3. Run Detectors
    # findings = []
    # findings.extend(a05_detector.run(hunks))
    # findings.extend(a02_detector.run(hunks))
    # findings.extend(a10_detector.run(hunks))
    print("Running A05, A02, A10 detectors...")
    
    # 4. Test all triage agents
    test_all_agents()
    
    # 5. Output Report
    # print(report)


if __name__ == "__main__":
    main()