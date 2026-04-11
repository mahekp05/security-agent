# Security Agent Test Suite Guide

## Overview
This test suite validates the security agent pipeline across 4 layers: **parser → detectors → triage agents → integration**. Total: **27 tests**.

---

## File Structure

```
tests/
├── TEST_GUIDE.md                 # This file
├── conftest.py                   # Shared fixtures for all tests
├── test_diff_parser.py           # Layer 1: Parser tests (5 tests)
├── test_detectors.py             # Layer 2: Detector tests (12 tests)
├── test_triage_agents.py         # Layer 3: Triage agent tests (7 tests)
└── test_integration.py           # Layer 4: Integration tests (3 tests)
```

---

## Layer Breakdown

### Layer 1: Diff Parser (5 tests)
**File:** `test_diff_parser.py`

Tests that the raw git diff string is correctly parsed into structured `DiffHunk` objects.

| Test Name | Input | Expected Output |
|-----------|-------|-----------------|
| `test_parser_extracts_hunks_from_raw_diff` | Simple SQL injection diff | 1 DiffHunk with file_path, added_lines, removed_lines |
| `test_parser_preserves_file_path` | Multi-file diff | 3 hunks with correct file paths |
| `test_parser_filters_irrelevant_changes` | Comment-only diff | Empty or filtered hunks |
| `test_parser_handles_added_and_removed_lines` | Any diff | non-empty lists for added/removed |
| `test_parser_handles_mixed_category_diff` | A05 + A02 + A10 diff | 3+ hunks preserved |

**Status:** ⏳ Not started

---

### Layer 2: Detectors (12 tests)
**File:** `test_detectors.py`

Tests that each detector (A05, A02, A10) correctly identifies vulnerabilities in code hunks.

#### A05 Injection Detector (4 tests)
| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_injection_detector_finds_obvious_sql_injection` | f-string SQL hunk | findings[0].category=="A05", confidence in ["High", "Medium"] |
| `test_injection_detector_skips_safe_parameterized_query` | Parameterized SQL hunk | Empty findings OR "Low" confidence |
| `test_injection_detector_references_specific_code` | SQL injection hunk | Description mentions "f-string" or "injection" |
| `test_injection_detector_handles_empty_hunks` | Empty DiffHunk | Empty findings |

#### A02 Configuration Detector (4 tests)
| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_config_detector_finds_exposed_api_key` | Hardcoded API key hunk | findings[0].category=="A02", high confidence |
| `test_config_detector_skips_safe_config` | Secure config hunk | Empty findings OR "Low" confidence |
| `test_config_detector_references_specific_config` | Exposed secret hunk | Description mentions the exposed pattern |
| `test_config_detector_handles_empty_hunks` | Empty DiffHunk | Empty findings |

#### A10 Error Handling Detector (4 tests)
| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_error_detector_finds_uncaught_exception` | Missing try-catch hunk | findings[0].category=="A10", high confidence |
| `test_error_detector_skips_safe_error_handling` | Proper error handling hunk | Empty findings OR "Low" confidence |
| `test_error_detector_references_specific_error_pattern` | Uncaught exception hunk | Description mentions missing handler |
| `test_error_detector_handles_empty_hunks` | Empty DiffHunk | Empty findings |

**Status:** ⏳ Not started

---

### Layer 3: Triage Agents (7 tests)
**File:** `test_triage_agents.py`

Tests that Prosecutor, Defender, and Judge agents produce valid verdicts with correct confidence scores and risk labels.

#### Prosecutor (2 tests)
| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_prosecutor_scores_obvious_vulnerability_high` | Obvious A05 findings | confidence_score >= 80, reasoning 150-400 words |
| `test_prosecutor_scores_ambiguous_vulnerability_moderate` | Ambiguous findings | 40 <= confidence_score <= 70 |

#### Defender (2 tests)
| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_defender_can_agree_with_prosecutor` | Prosecutor score 85 | Defender score 70+, references Prosecutor |
| `test_defender_can_disagree_with_prosecutor` | Prosecutor score 85 (with mitigations) | Defender score <= 50, explains disagreement |

#### Judge (3 tests)
| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_judge_assigns_critical_risk_when_prosecutor_high_defender_low` | Prosecutor 85, Defender 25 | risk_label=="critical_risk" |
| `test_judge_assigns_medium_risk_when_scores_mixed` | Prosecutor 70, Defender 60 | risk_label=="medium_risk" |
| `test_judge_assigns_false_positive_when_defender_strong` | Prosecutor 25, Defender 80 | risk_label=="false_positive" |

**Status:** ⏳ Not started

---

### Layer 4: Integration (3 tests)
**File:** `test_integration.py`

Tests the full pipeline from raw diff to final security report.

| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_full_pipeline_mixed_vulnerability_diff` | Raw diff with A05 + A02 + A10 | 3 verdicts with all required fields |
| `test_full_pipeline_safe_code_diff` | Raw diff with no vulnerabilities | Empty verdicts OR all false_positive |
| `test_full_pipeline_ambiguous_diff` | Raw diff with uncertain findings | medium_risk labels OR 40-60 confidence |

**Status:** ⏳ Not started

---

## Fixtures Reference

All fixtures are defined in `conftest.py` and available globally:

### Parser Fixtures
- `SIMPLE_SQL_INJECTION_DIFF` — Raw diff string with f-string SQL query
- `MULTI_FILE_DIFF` — Raw diff across 3 files
- `COMMENT_ONLY_DIFF` — Raw diff with no code changes
- `MIXED_CATEGORY_DIFF` — Raw diff with A05 + A02 + A10

### Detector Fixtures (DiffHunk objects)
- `OBVIOUS_SQL_INJECTION` — f-string SQL query
- `SAFE_SQL_QUERY` — Parameterized SQL query
- `EXPOSED_API_KEY` — Hardcoded API secret
- `SAFE_CONFIG` — Secure configuration
- `UNCAUGHT_EXCEPTION` — Missing try-catch block
- `SAFE_ERROR_HANDLING` — Proper error handling

### Triage Fixtures (VulnerabilityFinding objects)
- `SYNTHETIC_A05_OBVIOUS` — Clear SQL injection finding
- `SYNTHETIC_A05_AMBIGUOUS` — Unclear injection scenario
- `SYNTHETIC_A02_EXPOSED_SECRET` — Hardcoded key finding

---

## Running Tests

```bash
# Install pytest (one time)
pip install pytest

# Run all tests
pytest

# Run all tests with verbose output
pytest -v

# Run one test file
pytest tests/test_diff_parser.py -v

# Run one specific test
pytest tests/test_diff_parser.py::test_parser_extracts_hunks_from_raw_diff -v


# Unit tests (no API calls, use mocks) - Fast
pytest tests/test_detectors.py tests/test_diff_parser.py -v

# Integration tests (call real API) - Slow, needs credits
pytest tests/test_integration.py -v

# Run with coverage report
pytest --cov=src tests/

# Run and stop on first failure
pytest -x
```

---

## Test Status Tracking

Update this as you implement:

| Layer | File | Tests | Status |
|-------|------|-------|--------|
| 1 | test_diff_parser.py | 5 | ⏳ Not started |
| 2 | test_detectors.py | 12 | ⏳ Not started |
| 3 | test_triage_agents.py | 7 | ⏳ Not started |
| 4 | test_integration.py | 3 | ⏳ Not started |
| **Total** | - | **27** | - |

---

## Key Assertions to Remember

### Parser Tests
- `assert isinstance(hunks, list)`
- `assert len(hunks) == expected_count`
- `assert hunk.file_path == "expected.py"`

### Detector Tests
- `assert len(findings) >= 1`
- `assert findings[0].category == "A05"`
- `assert findings[0].confidence in ["High", "Medium", "Low"]`
- `assert "keyword" in findings[0].description`

### Triage Tests
- `assert isinstance(verdict.confidence_score, int)`
- `assert 1 <= verdict.confidence_score <= 100`
- `assert verdict.risk_label in ["critical_risk", "medium_risk", "low_risk", "false_positive"]`

### Integration Tests
- `assert isinstance(report.verdicts, list)`
- `assert all(v.category in ["A05", "A02", "A10"] for v in report.verdicts)`

---

## Debugging Tips

**Test fails with "fixture not found"?**
- Check that `conftest.py` is in the tests/ folder
- Restart pytest or Python interpreter

**Test times out?**
- LLM calls may be slow; use mocks if possible
- Check your internet connection

**Test passes locally but fails in CI?**
- Environment variables or API keys may differ
- Mock LLM calls for deterministic tests

**Want to skip a test temporarily?**
- Add `@pytest.mark.skip(reason="Not ready yet")` above the test function
