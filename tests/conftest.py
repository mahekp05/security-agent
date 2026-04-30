# Written with help of GitHub Copilot
"""
conftest.py - Shared pytest fixtures for all test layers

This file makes fixtures available to all test files automatically.
Fixtures are test data, mocks, and utility functions used across tests.
"""

import sys
import os
from pathlib import Path
from unittest.mock import patch

# Add project root to sys.path so pytest can find the src module
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.core.models import (
    DiffHunk,
    VulnerabilityFinding,
    ProsecutorVerdict,
    DefenderVerdict,
    JudgeVerdict,
)


# ============================================================================
# AUTOUSE FIXTURES (applied to all tests)
# ============================================================================

@pytest.fixture(autouse=True)
def mock_huggingface_token(monkeypatch):
    """Auto-mock HuggingFace token for tests that need it, if not already set.
    
    This allows tests to run with either:
    - Real token from .env file (if present)
    - Mock token for tests that don't call the real API
    
    Priority: .env token > environment token > mock token
    """
    from dotenv import load_dotenv
    from pathlib import Path
    
    # First, try loading from .env
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    
    # Check if token is already set
    if not os.getenv("HUGGINGFACEHUB_API_TOKEN"):
        # No token set, use mock for testing
        monkeypatch.setenv("HUGGINGFACEHUB_API_TOKEN", "test_token_mock_12345")


# ============================================================================
# LAYER 1: RAW DIFF FIXTURES (for parser tests)
# ============================================================================

@pytest.fixture
def SIMPLE_SQL_INJECTION_DIFF():
    """Raw git diff with basic SQL injection vulnerability (f-string query)."""
    return """diff --git a/app.py b/app.py
index 1234567..abcdefg 100644
--- a/app.py
+++ b/app.py
@@ -10,8 +10,8 @@ def get_user(user_id):
     # SQL query function
-    query = "SELECT * FROM users WHERE id = %s"
-    return db.execute(query, (user_id,))
+    # SQL Injection vulnerability - f-string in query
+    query = f"SELECT * FROM users WHERE id={user_id}"
+    return db.execute(query)
 
 def login(username, password):
     pass
"""


@pytest.fixture
def MULTI_FILE_DIFF():
    """Raw git diff with changes across 3 different files."""
    return """diff --git a/utils/db.py b/utils/db.py
index 1111111..2222222 100644
--- a/utils/db.py
+++ b/utils/db.py
@@ -1,3 +1,3 @@
-def query(sql):
+def unsafe_query(sql):
     pass

diff --git a/config/settings.py b/config/settings.py
index 3333333..4444444 100644
--- a/config/settings.py
+++ b/config/settings.py
@@ -1,2 +1,2 @@
-DEBUG = False
+DEBUG = True

diff --git a/server/api.py b/server/api.py
index 5555555..6666666 100644
--- a/server/api.py
+++ b/server/api.py
@@ -1,3 +1,3 @@
-try:
     result = db.query(user_id)
-except Exception as e:
+# Uncaught exception risk
"""


@pytest.fixture
def COMMENT_ONLY_DIFF():
    """Raw git diff with only comment/whitespace changes, no code logic changes."""
    return """diff --git a/app.py b/app.py
index 7777777..8888888 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,4 @@
-# Old comment
+# New comment
 
 def hello():
-    pass
+    pass  # Added space
"""


@pytest.fixture
def MIXED_CATEGORY_DIFF():
    """Raw git diff containing vulnerabilities from multiple categories (A05, A02, A10)."""
    return """diff --git a/app.py b/app.py
index 9999999..aaaaaaa 100644
--- a/app.py
+++ b/app.py
@@ -15,13 +15,13 @@ from flask import Flask, request
 
 def get_user(user_id):
-    query = "SELECT * FROM users WHERE id = %s"
-    return db.execute(query, (user_id,))
+    query = f"SELECT * FROM users WHERE id={user_id}"
+    return db.execute(query)
 
 def login(username, password):
-    ldap_filter = "(uid={})"
+    os.system(f"ldap search -u {username} -p {password}")
 
 def error_page(error_code):
-    return render_template('error.html', code=error_code)
+    return traceback.format_exc()
 
 def api_config():
-    return {"version": "1.0"}
+    return {"version": "1.0", "api_key": "sk_live_1234567890"}
"""


# ============================================================================
# LAYER 2: DIFFHUNK FIXTURES (for detector tests)
# ============================================================================

@pytest.fixture
def OBVIOUS_SQL_INJECTION():
    """DiffHunk with obvious SQL injection (f-string query)."""
    return DiffHunk(
        file_path="app.py",
        added_lines=[
            '+    # SQL Injection - f-string query',
            '+    query = f"SELECT * FROM users WHERE id={user_id}"',
            '+    db.execute(query)'
        ],
        removed_lines=[
            '-    query = "SELECT * FROM users WHERE id = %s"',
            '-    db.execute(query, (user_id,))'
        ]
    )


@pytest.fixture
def SAFE_SQL_QUERY():
    """DiffHunk with safe parameterized SQL query (no injection)."""
    return DiffHunk(
        file_path="app.py",
        added_lines=[
            '+    query = "SELECT * FROM users WHERE id = %s"',
            '+    return db.execute(query, (user_id,))'
        ],
        removed_lines=[
            '-    result = raw_query(user_id)'
        ]
    )


@pytest.fixture
def EXPOSED_API_KEY():
    """DiffHunk with hardcoded/exposed API key."""
    return DiffHunk(
        file_path="config/settings.py",
        added_lines=[
            '+API_KEY = "sk_live_1234567890abcdefghijklmnop"',
            '+return {"key": API_KEY}'
        ],
        removed_lines=[
            '-API_KEY = os.getenv("API_KEY")',
            '-return {"key": os.getenv("API_KEY")}'
        ]
    )


@pytest.fixture
def SAFE_CONFIG():
    """DiffHunk with secure configuration (no exposed secrets)."""
    return DiffHunk(
        file_path="config/settings.py",
        added_lines=[
            '+API_KEY = os.getenv("API_KEY")',
            '+DEBUG = False'
        ],
        removed_lines=[
            '-API_KEY = "hardcoded"',
            '-DEBUG = True'
        ]
    )


@pytest.fixture
def UNCAUGHT_EXCEPTION():
    """DiffHunk with missing exception handling (uncaught exception risk)."""
    return DiffHunk(
        file_path="user_handler.py",
        added_lines=[
            '+def get_user(user_id):',
            '+    result = db.query(user_id)',
            '+    return result'
        ],
        removed_lines=[
            '-def get_user(user_id):',
            '-    try:',
            '-        result = db.query(user_id)',
            '-        return result',
            '-    except DatabaseError as e:',
            '-        log.error(f"Database error: {e}")',
            '-        return None'
        ]
    )


@pytest.fixture
def SAFE_ERROR_HANDLING():
    """DiffHunk with proper exception handling."""
    return DiffHunk(
        file_path="user_handler.py",
        added_lines=[
            '+try:',
            '+    result = db.query(user_id)',
            '+except DatabaseError as e:',
            '+    log.error(f"DB error: {e}")',
            '+    return None'
        ],
        removed_lines=[
            '-result = db.query(user_id)'
        ]
    )


# ============================================================================
# LAYER 3: VULNERABILITYFINDING FIXTURES (for triage agent tests)
# ============================================================================

@pytest.fixture
def SYNTHETIC_A05_OBVIOUS():
    """Synthetic VulnerabilityFinding for obvious SQL injection."""
    return VulnerabilityFinding(
        category="A05",
        description="SQL Injection: User input in f-string SQL query without parameterization. Attacker can inject arbitrary SQL.",
        affected_code='query = f"SELECT * FROM users WHERE id={user_id}"',
        confidence="High"
    )


@pytest.fixture
def SYNTHETIC_A05_AMBIGUOUS():
    """Synthetic VulnerabilityFinding for ambiguous/unclear injection scenario."""
    return VulnerabilityFinding(
        category="A05",
        description="Potential SQL Injection: Query uses string concatenation, but may have upstream validation.",
        affected_code='query = "SELECT * FROM users WHERE " + filter',
        confidence="Medium"
    )


@pytest.fixture
def SYNTHETIC_A02_EXPOSED_SECRET():
    """Synthetic VulnerabilityFinding for exposed API key."""
    return VulnerabilityFinding(
        category="A02",
        description="Exposed API Key: Hardcoded secret in config file that should use environment variables.",
        affected_code='API_KEY = "sk_live_1234567890"',
        confidence="High"
    )


# ============================================================================
# LAYER 4: MOCK LLM RESPONSES (for triage tests)
# ============================================================================

@pytest.fixture
def mock_prosecutor_obvious_high():
    """Mock LLM response for obvious vulnerability with high confidence."""
    return ProsecutorVerdict(
        category="A05",
        confidence_score=88,
        reasoning=(
            "This finding presents a clear SQL injection vulnerability. The code uses an f-string to construct a SQL query with unsanitized user input. "
            "The attack vector is obvious: an attacker can inject malicious SQL commands. The sink is dangerous (database query execution). "
            "There is no parameterization or input validation visible. From a red team perspective, this is exploitable on any public endpoint receiving user_id. "
            "Confidence: 88/100 because the code pattern is unmistakable and the impact would be severe (unauthorized data access, modification, or deletion). "
            "In addition, this change replaces a safer parameterized query with a direct string interpolation, which is a regression in security posture. "
            "Attackers can easily craft input to bypass authorization checks, enumerate records, or alter data. The absence of visible sanitization compounds the risk. "
            "Even if some upstream validation exists, relying on it is fragile and frequently bypassed. A single missed validation path would expose the database. "
            "The most reliable mitigation is parameterization, which was removed here. This is a high-impact, high-likelihood vulnerability in real-world conditions."
        ),
    )


@pytest.fixture
def mock_prosecutor_ambiguous_moderate():
    """Mock LLM response for ambiguous vulnerability with moderate confidence."""
    return ProsecutorVerdict(
        category="A05",
        confidence_score=55,
        reasoning=(
            "This finding has mixed signals. The query uses string concatenation which is a risky pattern, but the actual input source is unclear from the diff context. "
            "If the input is validated upstream or comes from a restricted source, the risk is lower. The SQL syntax looks complex which could also hint at parameterized queries in production. "
            "Confidence: 55/100 because there is evidence of risk but also plausible mitigations. "
            "The diff does not show whether the input is derived from user-controlled sources or internal constants. "
            "If the input is user-controlled, the risk would escalate quickly; if not, it may be negligible. "
            "I cannot confirm the presence of input validation, escaping, or ORM protections from this diff alone. "
            "Given typical production patterns, this is concerning but not definitive, which justifies a mid-range confidence score."
        ),
    )


@pytest.fixture
def mock_defender_agrees_high():
    """Mock LLM response where Defender agrees with Prosecutor on high confidence."""
    return DefenderVerdict(
        confidence_score=78,
        reasoning=(
            "The Prosecutor makes a strong case. I reviewed the code and the f-string SQL query with direct user input is indeed exploitable. "
            "However, I note that this endpoint may have authentication requirements that could limit attack surface. "
            "Also, I don't see error handling that would expose database details. Those factors lower my confidence slightly compared to the Prosecutor, but the core vulnerability is real. "
            "Confidence: 78/100 - I largely agree this is a significant risk that warrants fixing. "
            "Even with authentication, SQL injection can be exploited by any authenticated user, which still represents a serious threat. "
            "If the system is multi-tenant, the impact is amplified because data isolation can be broken. "
            "There is no evidence of parameterization or escaping, and the diff indicates a regression from a safer approach. "
            "Given the prevalence of SQL injection vulnerabilities and the clear sink, the risk remains high despite partial mitigations. "
            "The safest fix is to restore parameterization and add strict validation on any user-controlled values."
        ),
        agrees_with_prosecutor=True,
    )


@pytest.fixture
def mock_defender_disagrees_low():
    """Mock LLM response where Defender disagrees with Prosecutor significantly."""
    return DefenderVerdict(
        confidence_score=32,
        reasoning=(
            "While the Prosecutor identified a risky code pattern, I found several mitigating factors. "
            "First, the calling function applies input validation using a whitelist before this code. Second, this query is read-only and cannot modify data. "
            "Third, the environment is staging-only based on the file path. Fourth, database credentials have minimal permissions. "
            "Given these controls, the actual exploitability is much lower than presented. Confidence: 32/100 - likely a false positive in this specific context. "
            "Additionally, this code may be behind a feature flag or internal-only network restriction, further reducing external exposure. "
            "Even if an injection were possible, the read-only role and limited dataset reduce practical impact. "
            "The diff does not show the broader system context, but the existing mitigations are substantial. "
            "I therefore disagree with the Prosecutor's severity assessment for this specific case."
        ),
        agrees_with_prosecutor=False,
    )


@pytest.fixture
def mock_judge_critical():
    """Mock Judge response assigning critical_risk."""
    return JudgeVerdict(
        risk_label="critical_risk",
        reasoning=(
            "The Prosecutor presents clear, specific evidence of SQL injection with an attack path visible in the diff. The Defender raises context questions but provides no concrete mitigations in the provided code. "
            "The vulnerability pattern (f-string + unsanitized input + SQL sink) is textbook exploitable. For a public-facing endpoint, this poses severe risk of data breach. "
            "Recommendation: User should fix this immediately by parameterizing the query. "
            "The change represents a regression from a safer approach, and the exploitability is high with minimal attacker effort. "
            "Given the potential for data exfiltration or modification, the most appropriate classification is critical_risk with high confidence. "
            "Immediate remediation is necessary to prevent exploitation in production environments."
        ),
        confidence_score=90,
    )


@pytest.fixture
def mock_judge_medium():
    """Mock Judge response assigning medium_risk."""
    return JudgeVerdict(
        risk_label="medium_risk",
        reasoning=(
            "Both Prosecutor and Defender make valid points. There is evidence of injection risk (Prosecutor: 70), but also evidence of possible mitigations (Defender: 60). "
            "The diff alone doesn't show complete context (validation layers, permissions, environment). Recommendation: User should review the full context of this function, verify any upstream validation, "
            "check database permissions, and evaluate whether parameter-based queries are feasible. If mitigations are absent, elevate to critical_risk. "
            "Because the available evidence is mixed and the exploitability is plausible but not certain, a medium_risk label is appropriate. "
            "Further review should confirm whether additional safeguards reduce the likelihood of exploitation."
        ),
        confidence_score=60,
    )


@pytest.fixture
def mock_judge_false_positive():
    """Mock Judge response assigning false_positive."""
    return JudgeVerdict(
        risk_label="false_positive",
        reasoning=(
            "Prosecutor scored this 25/100 with weak evidence, and Defender scored 80/100 with concrete mitigations including input validation, read-only queries, and restricted permissions. "
            "The code pattern is risky in isolation, but the full context makes exploitation unlikely. The finding appears to be a detection false alarm. "
            "Recommendation: User can safely close this finding after documenting the mitigating controls. "
            "The mitigations are strong, consistent, and clearly described, which significantly reduces real-world risk. "
            "Given the combination of whitelisting, least-privilege access, and internal-only exposure, a false_positive classification is justified. "
            "This is a good example of a code pattern that looks risky but is rendered safe by strong controls. "
            "The evidence does not support an active exploitation path, and the residual risk is low."
        ),
        confidence_score=25,
    )
