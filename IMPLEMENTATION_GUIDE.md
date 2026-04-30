# Implementation Guide: Security Agent with Semantic Chunking

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [API Usage](#api-usage)
6. [Configuration](#configuration)
7. [Deployment](#deployment)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The Security Agent is a multi-LLM system that analyzes GitHub PRs for security vulnerabilities using semantic chunking to handle large diffs. It detects three OWASP categories:

- **A05**: Injection Attacks (SQL, Command, LDAP)
- **A02**: Security Misconfiguration (exposed secrets, debug flags, open CORS)
- **A10**: Mishandling of Exceptions (fail-open patterns, swallowed exceptions)

### Key Features

✅ **Large Diff Support**: Automatically chunks diffs >10K tokens  
✅ **Context Preservation**: 500-token overlap between chunks  
✅ **Worst-Verdict-Wins**: Conservative security aggregation  
✅ **Configuration-Driven**: YAML + environment variable overrides  
✅ **Traceability**: All findings tagged with chunk source  
✅ **Error Handling**: Graceful degradation for edge cases  

---

## Architecture

### High-Level Flow

```
GitHub PR
    │
    ├─► DiffParser → List[DiffHunk]
    │
    ├─► TokenEstimator (count tokens)
    │
    ├─► SemanticChunker (group by file)
    │       │
    │       └─► [Chunk1, Chunk2, ...]
    │
    └─► For each chunk:
            ├─► A05 Detector (injection)
            ├─► A02 Detector (config)
            ├─► A10 Detector (errors)
            │
            └─► Per category + chunk:
                    ├─► Prosecutor (build case)
                    ├─► Defender (counter-argue)
                    └─► Judge (decide verdict)
            
            └─► VerdictAggregator (worst-verdict-wins)
                    │
                    └─► CategoryTriageVerdict[]
                            │
                            └─► Formatted Report
```

### Component Responsibilities

| Component | Responsibility |
|-----------|-----------------|
| **DiffParser** | Parse raw git diff into structured hunks |
| **TokenEstimator** | Count tokens using tiktoken cl100k_base |
| **SemanticChunker** | Group hunks by file, build chunks up to max_tokens |
| **Detectors (A05/A02/A10)** | Identify potential vulnerabilities per chunk |
| **Prosecutor** | Build the case for why a finding is a vulnerability |
| **Defender** | Counter-argue the prosecutor's case |
| **Judge** | Render final verdict (CRITICAL/MEDIUM/LOW/FALSE_POSITIVE) |
| **VerdictAggregator** | Combine per-chunk verdicts using worst-verdict-wins |
| **ReportFormatter** | Generate human-readable output |

---

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone <repo-url>
cd security-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
echo "HUGGINGFACEHUB_API_TOKEN=hf_YOUR_TOKEN_HERE" > .env
```

### 2. Basic Usage

```python
from src.main import analyze_github_pr

# Analyze a PR
pr_diff = """
diff --git a/app.py b/app.py
index 1234567..abcdefg 100644
--- a/app.py
+++ b/app.py
@@ -10,7 +10,8 @@ def login(username, password):
-    query = f"SELECT * FROM users WHERE id = {user_id}"
+    user_id = request.args.get('id')
+    query = f"SELECT * FROM users WHERE id = {user_id}"
     db.execute(query)
"""

findings, verdicts = analyze_github_pr(pr_diff)

# Print results
for verdict in verdicts:
    print(f"{verdict.category}: {verdict.judge.verdict}")
    for finding in verdict.findings:
        print(f"  - {finding.title} (chunk: {finding.chunk_id})")
```

### 3. Run Tests

```bash
# Test configuration
pytest tests/test_config.py -v

# Test chunking
pytest tests/test_chunking.py -v

# Test full pipeline
pytest tests/test_integration.py -v

# Test specific category
pytest tests/test_detectors.py -k "test_sql_injection" -v
```

---

## Core Concepts

### Diff Hunks

A **hunk** is a contiguous section of changes in a file:

```python
@dataclass
class DiffHunk:
    file_path: str           # e.g., "src/main.py"
    start_line: int          # Line number in original file
    end_line: int            # Line number in modified file
    content: str             # The actual code change
    before: List[str]        # Lines before change
    after: List[str]         # Lines after change
```

### Chunks

A **chunk** groups hunks by file boundary with token awareness:

```python
@dataclass
class Chunk:
    id: str                  # e.g., "chunk_1", "chunk_2"
    hunks: List[DiffHunk]   # Hunks in this chunk
    token_count: int        # Total tokens (tiktoken count)
```

**Properties**:
- Max 24,000 tokens per chunk (90% safety margin)
- 500 tokens overlap between chunks
- Single file cannot exceed limit (ValueError if it does)

### Findings

A **finding** is a potential vulnerability detected by a detector:

```python
@dataclass
class VulnerabilityFinding:
    category: str            # "A05", "A02", or "A10"
    severity: str           # "CRITICAL", "MEDIUM", "LOW"
    title: str              # Brief title
    description: str        # Detailed description
    line_number: int        # Line in PR where found
    code_snippet: str       # The vulnerable code
    chunk_id: Optional[str] # Which chunk this came from (e.g., "chunk_1")
```

### Verdicts

A **verdict** is the final decision on a finding after prosecution/defense/judgment:

```python
@dataclass
class JudgeVerdict:
    category: str           # "A05", "A02", or "A10"
    verdict: str            # "CRITICAL", "MEDIUM", "LOW", "FALSE_POSITIVE"
    confidence_score: float # 0.0-1.0
    reasoning: str          # Why this verdict
    chunk_id: Optional[str] # Which chunk this verdict came from
```

### Aggregated Verdict

An **aggregated verdict** combines verdicts across chunks:

```python
@dataclass
class AggregatedVerdict:
    category: str                    # "A05", "A02", or "A10"
    final_verdict: str              # Worst verdict across chunks
    chunk_verdicts: List[JudgeVerdict]  # Per-chunk verdicts
    chunk_sources: List[str]        # Which chunks had this verdict
    confidence: float               # Average confidence
    reasoning: str                  # How verdict was aggregated
```

### Token Budget

Each LLM has a per-request token budget:

```
┌─────────────────────────────────────┐
│ HF API Hard Limit: 32,768 tokens    │
│                                     │
│ Safety Margin: 90%                  │
│ Available: 29,491 tokens            │
│                                     │
│ Per Chunk: 24,000 tokens (73%)      │
│ Buffer: 5,491 tokens                │
└─────────────────────────────────────┘
```

Budget applies to:
1. **Input tokens**: Diff content + system prompt + context
2. **Output tokens**: Detector output + prosecutor/defender/judge reasoning

If input exceeds budget, diff is chunked.

---

## API Usage

### Main Entry Point

```python
def analyze_github_pr(
    raw_diff: str,
    use_real_api: bool = True
) -> Tuple[List[VulnerabilityFinding], List[CategoryTriageVerdict]]:
    """
    Analyze a GitHub PR diff for vulnerabilities.
    
    Args:
        raw_diff: Raw git diff output
        use_real_api: Use real HF API (default) vs. mock
    
    Returns:
        (findings, verdicts) tuple
    """
```

### Chunker API

```python
from src.agents.chunker import create_chunker

chunker = create_chunker(max_tokens=24000, overlap_tokens=500)

# Check if chunking needed
if chunker.should_chunk(hunks):
    chunks = chunker.chunk_diff(hunks)
else:
    chunks = [Chunk("chunk_1", hunks, token_count=...)]

# Get specific chunk
chunk = chunker.get_chunk_by_id("chunk_2", chunks)

# Get hunks for chunk
chunk_hunks = chunker.get_hunks_by_chunk_id("chunk_2", chunks)
```

### Detector API

```python
from src.agents.detectors import (
    detect_injection,
    detect_config,
    detect_error_handling
)

hunks = parse_diff_to_hunks(raw_diff)

# Run each detector
findings_a05 = detect_injection(hunks)
findings_a02 = detect_config(hunks)
findings_a10 = detect_error_handling(hunks)

# Tag with chunk_id
for f in findings_a05:
    f.chunk_id = "chunk_1"
```

### Triage API

```python
from src.agents.triage import prosecutor_agent, defender_agent, judge_agent

category = "A05"
findings = [...]
hunks = [...]

# Prosecution
prosecutor_result = prosecutor_agent(category, findings, hunks)

# Defense
defender_result = defender_agent(category, prosecutor_result, hunks)

# Judgment
judge_verdict = judge_agent(category, prosecutor_result, defender_result)
# Returns: JudgeVerdict with verdict="CRITICAL"|"MEDIUM"|"LOW"|"FALSE_POSITIVE"
```

### Aggregation API

```python
from src.agents.triage.aggregator import create_aggregator

aggregator = create_aggregator()

# Aggregate per category
verdicts_by_category = {
    "A05": [verdict_chunk1, verdict_chunk2],
    "A02": [verdict_chunk1],
}

aggregated = aggregator.aggregate_all_categories(verdicts_by_category)
# Returns: {"A05": AggregatedVerdict(...), "A02": AggregatedVerdict(...)}

# Get PR-level verdict
pr_verdict = aggregator.get_pr_level_verdict(aggregated)  # "CRITICAL"

# Filter by severity
filtered = aggregator.filter_findings_by_severity(
    aggregated,
    include_low=False,
    include_false_positive=False
)
```

---

## Configuration

### YAML Configuration

File: `config/model_config.yaml`

```yaml
models:
  detector:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 26000
    output_reserve: 500
    safety_margin: 0.90
    temperature: 0.3
    top_p: 0.9

  prosecutor:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 20000
    output_reserve: 300
    safety_margin: 0.90
    temperature: 0.5
    top_p: 0.9

  defender:
    model_name: "Qwen/Qwen2.5-Coder-7B-Instruct"
    max_tokens: 20000
    output_reserve: 300
    safety_margin: 0.90
    temperature: 0.5
    top_p: 0.9

  judge:
    model_name: "Qwen/Qwen2.5-Coder-32B-Instruct"
    max_tokens: 28000
    output_reserve: 500
    safety_margin: 0.90
    temperature: 0.3
    top_p: 0.9

tokenization:
  encoder: "cl100k_base"
  validation_samples: 5

chunking:
  enabled: true
  max_chunk_tokens: 24000
  overlap_tokens: 500
  strategy: "semantic_file_boundary"

constants:
  hf_api_limit: 32768
  max_retries: 3
  backoff_factor: 2.0
```

### Environment Variable Overrides

All settings can be overridden via environment variables:

```bash
# Token budgets
export SECURITY_AGENT_DETECTOR_TOKENS=23000
export SECURITY_AGENT_PROSECUTOR_TOKENS=18000
export SECURITY_AGENT_DEFENDER_TOKENS=18000
export SECURITY_AGENT_JUDGE_TOKENS=25000

# Temperatures (0.0-1.0)
export SECURITY_AGENT_DETECTOR_TEMP=0.3
export SECURITY_AGENT_PROSECUTOR_TEMP=0.5
export SECURITY_AGENT_DEFENDER_TEMP=0.5
export SECURITY_AGENT_JUDGE_TEMP=0.3

# Chunking
export SECURITY_AGENT_CHUNKING_ENABLED=true
export SECURITY_AGENT_CHUNKING_MAX_TOKENS=24000
export SECURITY_AGENT_CHUNKING_OVERLAP=500

# API
export HUGGINGFACEHUB_API_TOKEN=hf_xxxxx
```

### Programmatic Configuration

```python
from src.core.config import Config

# Load configuration (singleton)
config = Config.load()

# Access model settings
print(config.get_model_tokens("detector"))  # 23400 (after safety margin)
print(config.get_model_temperature("prosecutor"))  # 0.5

# Override at runtime
import os
os.environ["SECURITY_AGENT_DETECTOR_TOKENS"] = "20000"
config = Config.load(force_reload=True)
```

---

## Deployment

### Local Development

```bash
# 1. Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Create .env
cat > .env << EOF
HUGGINGFACEHUB_API_TOKEN=hf_YOUR_TOKEN
SECURITY_AGENT_DETECTOR_TOKENS=23000
EOF

# 3. Run tests
pytest tests/ -v

# 4. Run analysis
python -c "from src.main import analyze_github_pr; ..."
```

### GitHub Actions Integration

Example workflow: `.github/workflows/security-analysis.yml`

```yaml
name: Security Analysis

on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-actions.txt

      - name: Run security analysis
        env:
          HUGGINGFACEHUB_API_TOKEN: ${{ secrets.HF_API_TOKEN }}
          SECURITY_AGENT_DETECTOR_TOKENS: 23000
          SECURITY_AGENT_PROSECUTOR_TOKENS: 18000
          SECURITY_AGENT_JUDGE_TOKENS: 25000
        run: |
          python -m pytest tests/test_integration.py -v

      - name: Analyze PR diff
        env:
          HUGGINGFACEHUB_API_TOKEN: ${{ secrets.HF_API_TOKEN }}
        run: |
          python scripts/analyze_pr.py ${{ github.event.pull_request.number }}

      - name: Comment on PR
        if: always()
        uses: actions/github-script@v6
        with:
          script: |
            // Read results from file
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('analysis_results.json', 'utf8'));
            
            // Post comment
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: results.comment_body
            });
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV HUGGINGFACEHUB_API_TOKEN=
ENV SECURITY_AGENT_CHUNKING_ENABLED=true

ENTRYPOINT ["python", "-m", "src.main"]
```

---

## Troubleshooting

### Common Issues

#### Issue 1: "Token count exceeds limit"

**Symptom**: `ValueError: Single file X.py is 28K tokens, exceeds max_chunk_tokens`

**Cause**: A single file is larger than 24K tokens

**Solution**:
```python
# Option 1: Split the file
# Break X.py into X_part1.py and X_part2.py

# Option 2: Disable chunking (not recommended)
# Set: SECURITY_AGENT_CHUNKING_ENABLED=false

# Option 3: Increase max_tokens (risky)
# Set: SECURITY_AGENT_CHUNKING_MAX_TOKENS=30000
# But ensure 90% safety margin still applies
```

#### Issue 2: "HUGGINGFACEHUB_API_TOKEN is missing"

**Symptom**: `RuntimeError: HUGGINGFACEHUB_API_TOKEN is missing`

**Solution**:
```bash
# Add to .env
echo "HUGGINGFACEHUB_API_TOKEN=hf_YOUR_TOKEN" > .env

# Or set environment variable
export HUGGINGFACEHUB_API_TOKEN=hf_YOUR_TOKEN

# For GitHub Actions
# Add to repository settings > Secrets and variables > Actions
# Create secret: HF_API_TOKEN
```

#### Issue 3: "Rate limit exceeded"

**Symptom**: `429 Too Many Requests`

**Cause**: HuggingFace API rate limit (1,000 requests/5 min)

**Solution**:
```python
# Use retry backoff
import time

max_retries = 3
for attempt in range(max_retries):
    try:
        result = analyze_github_pr(diff)
        break
    except RateLimitError:
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt  # Exponential backoff
            print(f"Rate limited. Waiting {wait_time}s...")
            time.sleep(wait_time)
        else:
            raise
```

#### Issue 4: "Findings missing from later chunks"

**Symptom**: A vulnerability in chunk_2 is not detected

**Cause**: Insufficient overlap or context loss

**Solution**:
```bash
# Increase overlap
export SECURITY_AGENT_CHUNKING_OVERLAP=1000  # 500 → 1000 tokens
```

#### Issue 5: "Tiktoken token count ≠ HF API count"

**Symptom**: Chunk exceeds limit during API call

**Cause**: Mismatch between tiktoken and HF API counting

**Solution**:
```python
# Validation runs at startup. If mismatch >5%, recalibration occurs.
# If still mismatch, reduce safety_margin:

# In config/model_config.yaml:
models:
  detector:
    safety_margin: 0.85  # Instead of 0.90
```

---

## Performance Tuning

### Optimization Strategies

1. **Reduce Chunk Size** (trades quality for speed)
   ```bash
   export SECURITY_AGENT_CHUNKING_MAX_TOKENS=16000
   ```

2. **Reduce Temperature** (more deterministic, faster)
   ```bash
   export SECURITY_AGENT_DETECTOR_TEMP=0.1
   ```

3. **Increase Overlap** (better accuracy, slower)
   ```bash
   export SECURITY_AGENT_CHUNKING_OVERLAP=1000
   ```

4. **Cache Verdicts** (avoid re-analyzing same files)
   - Not yet implemented

5. **Parallel Processing** (run chunks in parallel)
   - Not yet implemented

### Performance Targets

| Scenario | Time | Cost |
|----------|------|------|
| Small diff (2K tokens) | ~30s | $0.01 |
| Medium diff (15K tokens) | ~45s | $0.01 |
| Large diff (40K tokens) | ~90s | $0.02 |
| Huge diff (100K tokens) | ~3m | $0.05 |

---

## Advanced Topics

### Custom Detectors

Add a new detector for OWASP A04 (Insecure Design):

```python
# src/agents/detectors/insecure_design_detector.py
from src.core.models import DiffHunk, VulnerabilityFinding

def detect_insecure_design(hunks: List[DiffHunk]) -> List[VulnerabilityFinding]:
    """Detect insecure design patterns."""
    # Implementation using LLM
    pass

# Register in src/main.py
for detector_func in [
    detect_injection,
    detect_config,
    detect_error_handling,
    detect_insecure_design,  # New detector
]:
    findings.extend(detector_func(chunk.hunks))
```

### Custom Aggregation

Override worst-verdict-wins with custom logic:

```python
# In src/agents/triage/aggregator.py
def aggregate_category_verdicts(self, category, chunk_verdicts):
    # Default: worst-verdict-wins
    # Custom: majority vote
    
    vote_counts = {}
    for v in chunk_verdicts:
        vote_counts[v.verdict] = vote_counts.get(v.verdict, 0) + 1
    
    final_verdict = max(vote_counts, key=vote_counts.get)
    
    return AggregatedVerdict(
        category=category,
        final_verdict=final_verdict,
        chunk_verdicts=chunk_verdicts,
        reasoning=f"Majority vote: {final_verdict}",
        chunk_sources=...,
        confidence=...
    )
```

---

## Support & Feedback

- **Documentation**: See `README.md`, `CHUNKING.md`, `IMPLEMENTATION_GUIDE.md`
- **Tests**: Run `pytest tests/ -v` for comprehensive validation
- **Issues**: Check `TEST_RESULTS_SUMMARY.md` for known limitations
- **GitHub**: Create issue on repository

---

**Version**: 2.0 (Phases 1-5 implementation complete)  
**Last Updated**: [timestamp]  
**Status**: Production ready (phases 1-4); phase 5 partial (pending API credits)
