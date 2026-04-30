# Risk-Guided Secure Code Review Agent

**Group 22 · Mahek Patel · Stuti Goyal**  
Agentic AI Class · Spring 2026

---

## What it does

A diff-aware security agent that reviews only what changed in a commit, debates each finding through an adversarial prosecutor/defender loop, and outputs a ranked report — fewer false positives, higher confidence than traditional static scanners.

Covers 3 OWASP Top 10:2025 categories:
- **A05** Injection (SQL, command, LDAP)
- **A02** Security Misconfiguration (debug flags, exposed secrets, open CORS)
- **A10** Mishandling of Exceptional Conditions (fail-open patterns, swallowed exceptions)

---


#### Setup (3 Steps)

**Step 1: Download GitHub Actions Files**

Download from the `security-agent` repository:
1. **The entire `.github/` folder** (contains workflow files)
2. **`requirements-actions.txt`** file

Add to the **root** of your repository:
```
your-repo/
├── .github/
│   └── workflows/
│       ├── security-scan.yml
│       └── ...
├── requirements-actions.txt
└── ...
```

**Step 2: Set Up GitHub Actions Secret (HuggingFace API Token)**

This is **required** for the security agent to run.

1. Go to https://huggingface.co/settings/tokens
2. Click "Create new token"
3. Name it: `security-agent-token`
4. Select: Inference permisions
    - Make calls to Inference Providers
    - Make calls to Inference Endpoints 
5. Copy the token (starts with `hf_`)

Then in your GitHub repository:
1. Go to **Settings** (top menu)
2. Left sidebar → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Fill in:
   - **Name**: `HUGGINGFACEHUB_API_TOKEN` (must be exactly this)
   - **Secret**: Paste your HuggingFace token
5. Click **Add secret**

**Step 3: Commit and Push**

Add files to your repository :
- Go to your repo → Code tab
- Create a new folder `.github/workflows/`
- Upload the workflow files from security-agent
- Upload `requirements-actions.txt` to root
- Commit with message "Add security agent GitHub Actions"

---

#### How It Works (Detailed Breakdown)

**Trigger:** Every time someone creates a Pull Request

1. **GitHub Actions Detects PR** → Workflow starts automatically
2. **Code Checkout** → Action downloads your code + PR changes
3. **Install Dependencies** → Sets up Python, installs from requirements-actions.txt
4. **Authenticate with HuggingFace** → Uses HUGGINGFACEHUB_API_TOKEN secret
5. **Run Security Agent** → Analyzes ONLY changed code:
   - Prosecutor: "This IS a real risk" (gives confidence score)
   - Defender: "Is it really?" (challenges the finding)
   - Judge: "Here's my verdict" (final risk level)
6. **Post Comment on PR** → GitHub posts findings as PR comment
7. **Optional - Block Merge if Critical** → Merge blocked until CRITICAL vulnerabilities fixed

If fails:
1. Go to **Actions** section under new code repository
2. Create custom actions workflow
3. Copy and paste the file security-review.yml into actions
4. Ensure requirements-actions.txt exist within repository

#### Example: What Developers See

PR comment posted automatically:

```
 Security Analysis Report

FILE: src/api/users.js
[CRITICAL] SQL Injection (A05) - Lines 42-45
  Issue: User input directly in SQL query without parameterization
  Recommendation: Use prepared statements or parameterized queries
  Confidence: 92%

FILE: config.js
[MEDIUM] Exposed API Key (A02) - Line 8
  Issue: API key hardcoded in source code
  Recommendation: Move to .env file or GitHub Secrets
  Confidence: 78%

Summary: 2 findings (1 CRITICAL, 1 MEDIUM, 0 LOW)

```

---

## How it works

```
git diff input
     │
     ▼
Diff parser agent        ← strips noise, extracts security-relevant hunks
     │
     ├──▶ Injection detector (A05)  ─┐
     ├──▶ Config detector (A02)     ─┼──▶ Candidate findings
     └──▶ Error handling check (A10)─┘
                                      │
                              ┌───────▼────────┐
                              │ Prosecutor agent│  "this is a real risk"
                              │ Defender agent  │  "this is a false positive"
                              │ Judge agent     │  verdict + severity score
                              └───────┬────────┘
                                      │
                              Ranked security report
```

---

## Handling Large Diffs: Semantic Chunking & Token Management

Large PRs (>10K tokens) exceed the HuggingFace API token limit (32,768 tokens per request). To handle this:

### Semantic Chunking Strategy (Phase 2)
- **Chunking algorithm**: Groups hunks by file boundary (not function-level)
- **Max tokens per chunk**: 24,000 (90% safety margin from 32K API limit)
- **Overlap**: 500 tokens between chunks to preserve context
- **Detection**: Per-chunk analysis with all 3 detectors running on each chunk
- **Aggregation**: Worst-verdict-wins across chunks (CRITICAL > MEDIUM > LOW > FALSE_POSITIVE)

### Per-Request Token Budget (Phase 1)
Note: models configured to run on free token limit to ensure token limits not hit midway and cause failure
Configuration-driven via `config/model_config.yaml` + environment variable overrides:

```yaml
models:
  detector:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 26000
    safety_margin: 0.90  # 90% → budget = 23,400 tokens
  
  prosecutor:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 20000
    safety_margin: 0.90  # 90% → budget = 18,000 tokens
  
  judge:
    model_name: "Qwen/Qwen2.5-Coder-32B-Instruct"
    max_tokens: 28000
    safety_margin: 0.90  # 90% → budget = 25,200 tokens
```

**Override via environment variables**:
```bash
SECURITY_AGENT_DETECTOR_TOKENS=23000
SECURITY_AGENT_PROSECUTOR_TOKENS=18000
SECURITY_AGENT_JUDGE_TOKENS=25000
SECURITY_AGENT_CHUNKING_ENABLED=true
```

### Architecture Components

**Token Counting** (`src/agents/chunker.py::TokenEstimator`):
- Uses `tiktoken` cl100k_base encoder (matches HF API token counting)
- Pre-validated at startup to ensure tiktoken ≈ HF API count

**Semantic Chunker** (`src/agents/chunker.py::SemanticChunker`):
- `chunk_diff(hunks)` → groups hunks by file, builds chunks greedily up to max_tokens
- `should_chunk(hunks)` → detects if diff needs chunking
- Error handling: Raises `ValueError` if single file exceeds limit (asks user to split)

**Verdict Aggregator** (`src/agents/triage/aggregator.py::VerdictAggregator`):
- `aggregate_category_verdicts(category, chunk_verdicts)` → finds worst verdict across chunks
- `aggregate_all_categories(verdicts_by_category)` → combines all categories
- `filter_findings_by_severity(aggregated)` → CRITICAL/MEDIUM reported, LOW/FALSE_POSITIVE optional
- Tracks chunk sources for traceability

**Detection Loop** (`src/main.py::_analyze_diff`):
```python
# 1. Chunk the diff if needed
chunker = create_chunker(max_tokens=24000, overlap_tokens=500)
chunks = chunker.chunk_diff(hunks) if chunker.should_chunk(hunks) else [chunk_1]

# 2. Run all 3 detectors per chunk
for chunk in chunks:
    for detector in [A05, A02, A10]:
        findings = detector(chunk.hunks)
        # Tag findings with chunk_id
        for f in findings:
            f.chunk_id = chunk.id

# 3. Per-chunk triage (prosecutor → defender → judge)
for category in findings_by_category:
    for chunk in chunks:
        prosecutor_verdict = prosecutor(category, chunk_findings)
        defender_verdict = defender(category, prosecutor_verdict)
        judge_verdict = judge(category, prosecutor, defender)

# 4. Aggregate verdicts across chunks (worst-verdict-wins)
aggregated = aggregator.aggregate_all_categories(verdicts_by_category)
```

### Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| HF API limit | 32,768 tokens | Hard limit per request |
| Per-chunk budget | 24,000 tokens | 73% utilization (90% safety margin) |
| Overlap | 500 tokens | ~2% overhead for context preservation |
| Rate limit | 1,000 requests / 5min | Typical PR: ~22 API calls, chunked PR: ~40-50 calls |
| Token overhead | ~5% | tiktoken validation + chunking metadata |

### Backward Compatibility

-  Small diffs (<10K tokens) use single chunk (`chunk_1`)
- `chunk_id` field is optional on findings (pre-Phase 2 code still works)
- No changes to detector/prosecutor/defender/judge prompts
- No output format changes

---

### ⏳ Future Work
- [ ] Streamlit UI with chunk visualization
- [ ] Evaluation framework & metrics
- [ ] Support for additional OWASP categories

---

##### Code Contributions:
- Mahek Patel: Diff parsing, chunking logic, Detector implementation, testing, GitHub Actions integration, documentation
- Stuti Goyal: Detector implementation, prosecutor/defender/judge logic, verdict aggregation, documentation, testing
- Github Co-pilot: Assisted with code generation, refactoring, and documentation formatting