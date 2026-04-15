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

- ✅ Small diffs (<10K tokens) use single chunk (`chunk_1`)
- ✅ `chunk_id` field is optional on findings (pre-Phase 2 code still works)
- ✅ No changes to detector/prosecutor/defender/judge prompts
- ✅ No output format changes

---

## Setup

### Configuration

1. **Create `.env` file**:
```bash
HUGGINGFACEHUB_API_TOKEN=hf_xxxxx
```

2. **Optional: Override token limits**:
```bash
export SECURITY_AGENT_DETECTOR_TOKENS=23000
export SECURITY_AGENT_PROSECUTOR_TOKENS=18000
export SECURITY_AGENT_JUDGE_TOKENS=25000
export SECURITY_AGENT_CHUNKING_ENABLED=true
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

### Testing

**Phase 1-4 Tests** (Configuration, Chunking, Detection, Triage):
```bash
pytest tests/test_config.py tests/test_chunking.py tests/test_phase3_per_chunk_detection.py tests/test_phase4_triage_validation.py -v
```

**Phase 5 Tests** (Integration & error handling):
```bash
pytest tests/test_phase5_integration.py -v
```

**Full test suite**:
```bash
pytest tests/ -v
```

---

## Status

### ✅ Completed (Phases 1-5)

- [x] **Phase 1**: Configuration system (YAML + env overrides)
  - 23/23 unit tests pass
  - Singleton pattern with validation
  - Per-agent model/token config

- [x] **Phase 2**: Semantic chunking & token management
  - 21/21 unit tests pass
  - TokenEstimator, SemanticChunker, VerdictAggregator
  - 500-token overlap for context preservation
  - Worst-verdict-wins aggregation

- [x] **Phase 3**: Per-chunk detection validation
  - 9/11 tests pass* (*2 blocked by HF API credits)
  - Chunking loop integrated in _analyze_diff()
  - All 3 detectors run per chunk
  - Findings tagged with chunk_id

- [x] **Phase 4**: Per-chunk triage aggregation
  - 20/20 unit tests pass
  - Verdict aggregation across chunks
  - Multi-category aggregation (A05, A02, A10)
  - Severity filtering (CRITICAL/MEDIUM reported)

- [x] **Phase 5**: Full integration & error handling
  - 5+ integration tests pass
  - Large diff handling (40K+ tokens)
  - Error handling (empty diff, malformed, Unicode)
  - Chunking corner cases

- [x] Diff parser agent
- [x] Detection agents (A05, A02, A10)
- [x] Adversarial triage loop (prosecutor/defender/judge)
- [x] Severity scoring with chunking support

### ⏳ Future Work
- [ ] Streamlit UI with chunk visualization
- [ ] GitHub Actions integration
- [ ] Evaluation framework & metrics
- [ ] Support for additional OWASP categories
