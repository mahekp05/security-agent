# Token Usage Plan: Large Diff Handling with Context Management

**Version**: 1.0  
**Date**: April 15, 2026  
**Status**: ✅ PRE-IMPLEMENTATION APPROVED - Ready for Phase 1 (Configuration Infrastructure)

---

## Executive Summary

This document outlines the strategy for handling large diffs (>10k tokens) in the security-agent while maintaining accuracy, staying within HuggingFace API token limits (32,768 per request), and enabling reproducible GitHub Actions workflows. The solution prioritizes **accuracy over speed** through intelligent chunking, per-chunk triage, and configuration-driven token management.

**Key Decision**: Stay with **HuggingFace API** (no vLLM deployment) + client-side chunking + per-chunk analysis.

---

## ✅ PRE-IMPLEMENTATION LOCKED DECISIONS

**Finalized & Approved** - Ready for Phase 1 implementation

### Decision 1: Chunking Strategy
- **Approach**: File boundary-based (Option A)
- **NOT**: Function-level splitting within files
- **Why**: Simpler implementation, easier debugging
- **Status**: ✅ LOCKED

### Decision 2: Token Overlap Between Chunks
- **Amount**: 500 tokens
- **Purpose**: Context preservation at chunk boundaries, prevents false negatives
- **Cost**: Minimal (~1% extra tokens)
- **Status**: ✅ LOCKED

### Decision 3: Verdict Reporting & Aggregation
- **Strategy**: Worst verdict only (security-conservative)
- **Output**: Show CRITICAL and MEDIUM findings only
- **Multiple chunks**: If ANY chunk critical → PR verdict critical
- **Status**: ✅ LOCKED

### Decision 4: API Call Budget
- **Target**: ~22 API calls per PR (acceptable)
- **Safety**: Well under 1,000 requests/5min free tier limit
- **No optimization**: Proceed as-is; optimize if issues arise
- **Status**: ✅ LOCKED

---

## Design Questions & Resolution

### Q1: Local Models (config.json) vs HuggingFace API?
**Decision**: Stay with **HuggingFace API**
- Current setup: `Qwen2.5-Coder-7B-Instruct` and `32B-Instruct` via LangChain
- Why API: No server infrastructure needed, managed by HF, automatic rope_scaling
- Why NOT local: vLLM deployment overhead, more ops burden
- YaRN/rope_scaling: Handled server-side by HF (not user config)

### Q2: Chunking vs Truncation?
**Decision**: **Chunking preferred** (with truncation as emergency fallback)
- Chunking: Split diffs semantically (by files/functions), analyze each independently
- Truncation: Keep most-relevant code, lose data
- Choose: No data loss (security-conservative), accept ~50% latency increase
- Emergency truncation: Only if chunking fails or >100k tokens

### Q3: Parallel Processing (Detectors)?
**Decision**: **Sequential detection** (no parallelization)
- Why: Detectors are fast (~1.5s each), LLM latency dominates
- Parallelization gain: ~10-20% latency reduction (not worth added complexity)
- Keep simple for debugging and maintenance
- Future: Can parallelize if latency becomes issue

### Q4: How to Handle Triage with Chunks?
**Decision**: **Per-chunk triage** with worst-verdict aggregation
- Each prosecutor/defender/judge works on ONE chunk only
- Eliminates token budget overruns in triage layer
- Aggregation: Take worst verdict across chunks (security-conservative)
- Metadata: Track which chunks analyzed, confidence per chunk

### Q5: Configuration Approach?
**Decision**: **YAML-driven with env var overrides**
- Config file: `config/model_config.yaml` (single source of truth)
- Env var overrides: For GitHub Actions customization per environment
- Example: `SECURITY_AGENT_DETECTOR_TOKENS=26000` in CI workflow
- Reproducibility: Configuration checked into git, versions with code

---

## Design Limits (Hard Constraints)

### Token Budget per Request

| Agent | Max Tokens | Safety Margin | Actual Budget | Reserve |
|-------|-----------|---------------|---------------|---------|
| **Detectors** | 26,000 | 90% (23,400) | 23,400 | 2,600 |
| **Prosecutor** | 20,000 | 90% (18,000) | 18,000 | 2,000 |
| **Defender** | 20,000 | 90% (18,000) | 18,000 | 2,000 |
| **Judge** | 28,000 | 90% (25,200) | 25,200 | 2,800 |
| **HF API Max** | **32,768** | - | - | - |

**Explanation**:
- Each request to HuggingFace gets isolated 32,768 context window
- Safety margin (90%): Circuit breaker to catch miscalculations before API rejection
- Reserve: Tokens for output reasoning from LLM

### Token Limits Are Per-Request, NOT Cumulative
- 50 API calls in one PR = 50 independent 32,768 windows
- GitHub Actions doesn't accumulate; each call is fresh
- No "budget exhaustion" across PR (only per individual call)

### Chunking Limits

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max chunk tokens | 24,000 | Fits safely in detector budget (26k with margin) |
| Min chunk tokens | 5,000 | Avoid micro-chunks (context < 5k often means no findings) |
| Max chunks per diff | 5+ | Acceptable (1-2 chunks typical) |
| Overlap between chunks | 500 | Context preservation (prevents false negatives at boundaries) |

### API Rate Limits (HuggingFace)

| Plan | Requests/5min | Calls per PR | Safety |
|------|---------------|-------------|--------|
| Free (per IP) | 1,000 | ~25 | ✅ 25 < 1,000 |
| Free user | 1,000 | ~25 | ✅ Single PR safe |
| PRO user | 2,500 | ~25 | ✅ 10+ concurrent PRs safe |
| Heavy CI (50 PRs/hour) | 1,000/5min | 1,250 | ⚠️ Exceeds free tier |

**Conclusion**: Free tier sufficient for typical CI (1-5 concurrent PRs). Upgrading to PRO ($9/mo) handles heavier load.

---

## Design Decisions

### Decision 1: Chunking Strategy = Semantic (Not Fixed-Size)
**What**: Split by logical units (functions, classes, files) instead of token count
**Why**: Preserves security context, avoids splitting vulnerable code patterns
**Trade-off**: Slightly more complex parsing, but better accuracy
**Implementation**: Use diff hunk boundaries as natural split points

### Decision 2: Per-Chunk Triage with Worst-Verdict Aggregation
**What**: 
- Detectors: Run all 3 (A05, A02, A10) on each chunk
- Triage: Prosecutor/defender/judge run per-chunk independently
- Aggregation: Final verdict = worst chunk's verdict (security-conservative)

**Why**: 
- Eliminates token budget risks in triage layer
- Conservative approach: if ANY chunk has critical finding, PR is critical
- Clear reasoning: each chunk analyzed independently

**Trade-off**: More API calls (~40-50/PR vs ~10-15 today), no data loss

### Decision 3: Add `chunk_id` Field to VulnerabilityFinding
**What**: Findings tagged with chunk they came from
**Why**: Fast hunk lookup, deterministic triage (no re-matching)
**Trade-off**: Minimal schema change, no breaking changes

```python
class VulnerabilityFinding(BaseModel):
    category: str
    description: str
    affected_code: str
    confidence: str
    chunk_id: Optional[str] = None  # ← NEW (optional for backward compatibility)
```

### Decision 4: Configuration Over Code
**What**: All token limits, model names, retry logic in YAML
**Why**: 
- Reproducible across environments (dev, CI, production)
- Easy to experiment (adjust without code changes)
- GitHub Actions friendly (env var overrides)
- Audit trail (config versioned in git)

### Decision 5: Sequential Processing (No Parallelization for Now)
**What**: Detectors → grouped by category → per-chunk triage (sequential)
**Why**:
- Simplicity: easier to debug, test, maintain
- LLM latency dominates (added parallelization only saves ~1.5s of 10s total)
- Can add later if needed

**Future enhancement**: Add `ThreadPoolExecutor` for 3 detectors if latency critical

### Decision 6: Graceful Degradation
**What**: Always try to produce findings, never crash
**Hierarchy**:
1. Full analysis (all data, no truncation)
2. Chunked analysis (multiple calls, complete)
3. Truncated analysis (single call, data loss, confidence reduced)
4. Graceful fail (clear error + fallback structure)

**Trade-off**: Some scenarios return lower-confidence findings, but analysis always runs

---

## Trade-Offs

### 1. Speed vs Accuracy
| Scenario | Approach | Time | Data Loss | Use Case |
|----------|----------|------|-----------|----------|
| Small PR (10k tokens) | Full | 10s | None | Normal PRs |
| Large PR (45k tokens) | Chunked | 18-20s | None | Feature branches |
| Urgent CI gate (48k) | Chunk → Truncate | 12-15s | Partial | Time-critical checks |
| Massive PR (150k) | Truncate | 8-10s | Significant loss | Emergency (split PR) |

**Decision**: Default to chunking (18-20s) for accuracy. Env var allows switching to truncation in CI if time-critical.

### 2. Configuration Complexity vs Flexibility
| Approach | Complexity | Flexibility | Reproducibility |
|----------|-----------|------------|-----------------|
| Hardcoded limits | Low | None | None (vary per build) |
| YAML config (chosen) | Medium | High | High ✅ |
| Full env vars | High | Very high | Low (env setup error-prone) |

**Decision**: YAML + env var overrides (best of both worlds)

### 3. API Calls vs Token Safety
| Approach | API Calls/PR | Token Risk | Cost |
|----------|------------|-----------|------|
| No chunking | ~10-15 | ⚠️ High (45k diffs exceed limit) | Low |
| Chunking (chosen) | ~40-50 | ✅ None (each <25k) | Medium (still <1000 free limit) |
| Full truncation | ~10-15 | ✅ None | Low |

**Decision**: Chunking (~40-50 calls) is worth cost for accuracy and elimination of truncation hazards.

### 4. Latency Trade-Off
```
Detector phase:
  Current: 3 sequential detectors × 1.5s = 4.5s/chunk
  Chunked: Same, but x2 chunks = 9s total
  Parallel detectors: Would save ~1s, adds complexity

Triage phase:
  Current: 1 prosecutor + 1 defender + 1 judge x3 categories = 9 calls
  Chunked: 2 chunks x3 categories = 18 calls (slight increase)
  
Total time: Current ~10-12s → Chunked ~18-20s (50-100% slower)
Acceptable for security (no rush to judge vulnerabilities)
```

---

## Implementation Plan

### ⚠️ IMPLEMENTATION GUARDRAILS (DO NOT TOUCH)

**RESTRICTED ZONES** - These areas are off-limits during implementation:

1. **Output Formatting Functions** 🚫
   - Location: TBD (identify in codebase)
   - Reason: Another team member is working on this; merge conflict risk
   - Allowed: Only read them (understand what they do)
   - NOT allowed: Modify, refactor, or call with new parameters

2. **.env File** 🚫
   - Do NOT read `.env` file in code
   - Do NOT load environment variables from it
   - Use only `os.environ` for env vars
   - Config will use YAML + env var overrides (no .env)

3. **Critical Working Code** 🚫
   - Do NOT delete any existing detector logic
   - Do NOT remove existing triage agent code
   - Do NOT modify core LLM integration (only extend)
   - Do NOT change existing test fixtures (unless unavoidable)

4. **Existing Schemas** 🚫
   - Do NOT change existing VulnerabilityFinding fields (only add optional ones)
   - Do NOT modify DiffHunk structure
   - Do NOT change ProsecutorVerdict, DefenderVerdict, JudgeVerdict output format
   - Backward compatibility: ALL changes must be additive only

5. **GitHub Integration** 🚫
   - Do NOT modify [src/github/client.py](src/github/client.py)
   - Do NOT change how PRs are fetched or comments posted
   - GitHub client stays as-is

6. **Existing Prompts** 🚫
   - Do NOT modify detector prompts in [src/agents/detectors/](src/agents/detectors/)
   - Do NOT change triage agent prompts
   - They are intentional; bypass via config only

7. **Existing Tests** 🚫
   - Do NOT delete test files
   - Do NOT break existing passing tests (unless integration requires it)
   - Add NEW tests, don't modify existing ones
   - Report any test failures immediately

### Safe to Modify/Create
✅ Create: `config/model_config.yaml`  
✅ Create: `src/core/config.py`  
✅ Create: `src/agents/chunker.py`  
✅ Create: `src/agents/triage/aggregator.py`  
✅ Modify: `src/core/llm.py` (only add config parameter)  
✅ Modify: `src/main.py` (detector/triage invocation only)  
✅ Modify: `src/core/models.py` (add optional `chunk_id` field)  
✅ Modify: `requirements.txt` (add dependencies)  
✅ Create: Test files (new tests only)

### Additional Implementation Constraints

**Token Counting** 🔒
- Once `tiktoken` encoder is validated against HF API, freeze it
- Do NOT change token counting logic mid-phase
- Do NOT adjust safety margins without retesting

**Secrets & Authentication** 🔒
- Do NOT hardcode `HUGGINGFACEHUB_API_TOKEN` anywhere
- Do NOT write to disk (env vars only)
- Config file is NOT secret—keep it in git

**Diff Parsing Core** 🔒
- Do NOT modify [src/agents/diff_parser.py](src/agents/diff_parser.py) core logic
- Extend it (add chunking), don't refactor existing functions
- Keep backward compatibility: old code path still works

**Category Definitions** 🔒
- Do NOT modify category strings: "A05", "A02", "A10"
- Do NOT add new categories
- These are hardcoded in detectors; mismatches break system

**No Caching** 🔒
- Do NOT add caching layer (each PR analyzed fresh)
- Risk: Stale findings if code changes
- Rationale: Security-critical; recency matters

**Token Count Validation** ⚠️
- After Phase 1 config: manually validate tiktoken counts vs 5 real PRs
- Document: "Token counts validated against X real PRs"
- If mismatch >5%: adjust safety margin

---
**Goal**: Build foundation; all subsequent phases depend on this

1. **Create `config/model_config.yaml`**
   - Per-agent token budgets (detector: 26k, prosecutor/defender: 20k, judge: 28k)
   - Model names (QwenCoder-7B, QwenCoder-32B)
   - Temperatures, retry policy, output formats
   - Support env var overrides
   - Location: `config/model_config.yaml`

2. **Create `src/core/config.py`**
   - Load YAML at startup
   - Validate (all tokens < 32,768, margins > 85%)
   - Merge env vars (e.g., `SECURITY_AGENT_DETECTOR_TOKENS`)
   - Singleton pattern: `config = Config.load()`
   - Log config on startup (for debugging)

3. **Update `src/core/llm.py`**
   - Change signature: `get_llm(config, agent_type='detector')` (was: no params)
   - No hard-coded model names or token limits
   - Pass config to `HuggingFaceEndpoint(model=config.models[agent_type].name, ...)`

4. **Update `requirements.txt`**
   - Add: `pyyaml` (YAML parsing)
   - Add: `tiktoken` (token counting)

5. **Tests**: Unit tests for config loading, validation, env var override

---

### Phase 2: Chunking & Token Management (Week 2)
**Goal**: Implement diff splitting and token counting

1. **Create `src/agents/chunker.py`**
   - `chunk_diff_semantic(hunks, max_tokens)`: Split hunks by files/functions
   - `estimate_tokens(hunks, encoder='cl100k_base')`: Count tokens via tiktoken
   - `get_hunks_for_chunk(chunk_id, chunks)`: Fast lookup
   - Data structures: `Chunk(id, hunks, token_count)`

2. **Update `src/agents/diff_parser.py`**
   - Add optional `chunking_enabled` param
   - Call `estimate_tokens()` before chunking decision
   - If >23,400 tokens: chunk automatically, tag findings with chunk_id

3. **Add optional chunk_id field to VulnerabilityFinding**
   - Update `src/core/models.py`
   - Add `chunk_id: Optional[str] = None`
   - Fully backward compatible

4. **Tests**: 
   - `test_chunk_boundaries()`: Verify semantic splits don't break code
   - `test_token_counting()`: Verify tiktoken matches HF API
   - `test_chunk_tagging()`: Findings correctly tagged with chunk_id

---

### Phase 3: Per-Chunk Detection (Week 2)
**Goal**: Detectors work on chunks, tag findings

1. **Update `src/main.py`** (detector invocation, ~lines 70-75)
   - Loop through chunks instead of all hunks at once
   - Call detectors on each chunk independently
   - Tag returned findings with chunk_id

2. **Detector code**: No changes needed
   - Detectors already accept `hunks` list
   - They work the same per-chunk

3. **Tests**: End-to-end detector test with chunked diffs

---

### Phase 4: Per-Chunk Triage (Week 3)
**Goal**: Prosecutor/defender/judge work per-chunk, aggregate verdicts

1. **Create `src/agents/triage/aggregator.py`**
   - `aggregate_chunk_verdicts()`: Combine per-chunk verdicts (worst wins)
   - Worst-verdict selection logic

2. **Update `src/main.py` triage loop** (lines ~80-115)
   - Group findings by chunk
   - For each chunk: prosecutor + defender + judge
   - Aggregate verdicts by category

3. **Tests**: Verify worst-verdict aggregation logic

---

### Phase 5: Testing & Documentation (Week 3-4)
**Goal**: Comprehensive testing, documentation for replication

1. **Create `tests/test_chunking.py`**:
   - `test_chunk_creation_respects_token_limit()`
   - `test_semantic_chunks_preserve_context()`
   - `test_token_estimation_accuracy()`

2. **Create `tests/test_large_diffs.py`**:
   - `test_detector_on_10k_diff()` → chunked
   - `test_detector_on_45k_diff()` → 2 chunks
   - `test_triage_per_chunk_aggregation()`

3. **Update `tests/test_integration.py`**:
   - Add scenarios: 1k, 5k, 10k, 20k, 50k token diffs
   - Verify no token limit errors
   - Verify findings complete (no data loss)

4. **Documentation**:
   - Update README with token budget limits
   - Add GitHub Actions workflow example with env var overrides
   - Document config.yaml fields
   - Add troubleshooting section

5. **Example GitHub Actions** (`.github/workflows/security-review.yml`):
   ```yaml
   - name: Security Analysis
     env:
       HUGGINGFACEHUB_API_TOKEN: ${{ secrets.HF_TOKEN }}
       # Optional: override for faster CI gate
       SECURITY_AGENT_DETECTOR_TOKENS: 24000
       SECURITY_AGENT_FALLBACK_STRATEGY: "truncate"
     run: |
       python -m pytest src/main.py --pr-url=${{ github.event.pull_request.html_url }}
   ```

---

## Verification Checklist

### Pre-Implementation ✅ APPROVED
- [x] Config YAML schema finalized (token budgets, model names) ✅ APPROVED
- [x] Chunk splitting logic reviewed (file boundary-based, 500-token overlap) ✅ APPROVED
- [x] Worst-verdict aggregation logic approved (critical+medium shown) ✅ APPROVED
- [x] API rate limit calculations validated (~22 calls/PR acceptable) ✅ APPROVED

### Implementation (In Progress)
- [ ] Phase 1 config infrastructure merged + tested
- [ ] Phase 2 chunking logic merged + tested
- [ ] Phase 3 detectors work per-chunk (no changes to detector code)
- [ ] Phase 4 triage per-chunk with aggregation working
- [ ] Phase 5 all tests passing

### Post-Implementation (Pending)
- [ ] 45k diff test: chunked into 2 parts, no token errors ✅
- [ ] Prosecutor/defender work on single chunk each (<20k tokens) ✅
- [ ] Judge aggregates verdicts correctly ✅
- [ ] GitHub Actions workflow with env var overrides works ✅
- [ ] No truncation in normal cases ✅
- [ ] Fallback truncation works for >50k diffs ✅

---

## Future Enhancements (Not in Scope)

1. **Parallelization**: Add `ThreadPoolExecutor` for 3 detectors if latency >15s becomes issue
2. **Adaptive chunking**: Adjust chunk size based on detector feedback (larger chunks for low-risk code)
3. **Per-chunk confidence**: Track confidence per chunk, weight aggregation
4. **Token usage monitoring**: Log token spend per agent, optimize prompt efficiency
5. **Model fallback routing**: When 32B API overloaded, route to 7B for detectors
6. **YaRN configuration**: If switching to local models (vLLM), add rope_scaling settings

---

## Risks & Mitigation

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Per-chunk verdicts miss cross-chunk vulnerabilities | Medium | Test with synthetic vulnerabilities spanning chunks |
| Token counting mismatch (tiktoken vs HF API) | Low | Validate against real API responses; add margin |
| Chunking breaks code patterns at boundaries | Low | Use overlap (500 tokens) between chunks |
| API rate limit hit in heavy CI | Low | Default conservative limits; PRO plan for scale |
| Config file wrong values | Low | Validation on startup, log config, tests |

---

## Success Metrics

1. **Token safety**: Zero "413 Payload Too Large" errors for diffs <50k tokens
2. **Accuracy**: No findings lost due to chunking (vs truncation)
3. **Performance**: Analysis complete in <20s for typical PRs (45k tokens)
4. **Reproducibility**: GitHub Actions workflow replicable with ENV var overrides
5. **Maintainability**: Config changes don't require code changes; documented well

---

## Questions for Review

1. **Aggregation logic**: Should we use worst verdict (current plan) or weighted average?
   - Recommendation: Worst verdict (security-conservative, simpler logic)

2. **Fallback strategy in CI**: Truncate for speed or chunk for accuracy?
   - Recommendation: Make configurable via env var

3. **Config location**: `config/model_config.yaml` or elsewhere?
   - Recommendation: Top-level config/ dir (matches project root structure)

4. **Backward compatibility**: Keep existing `get_llm()` signature or break?
   - Recommendation: New `get_llm_chunking()` function for now, deprecate old one

---

**Document status**: ✅ APPROVED - All pre-implementation decisions locked  
**Next milestone**: Phase 1 Implementation (Configuration Infrastructure)  
**Ready for**: Code generation and file creation
