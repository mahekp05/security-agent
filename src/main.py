# src/main.py
import sys

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
    
    # 4. Run Adversarial Triage
    # report = []
    # for finding in findings:
    #     verdict = judge_agent.evaluate(finding)
    #     report.append(verdict)
    print("Running prosecutor/defender debate...")
    
    # 5. Output Report
    # print(report)

if __name__ == "__main__":
    main()