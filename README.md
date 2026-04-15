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

## Setup

## Status

- [ ] Diff parser agent
- [ ] Detection agents (A05, A02, A10)
- [ ] Adversarial triage loop
- [ ] Severity scoring
- [ ] Streamlit UI
- [ ] Test PR Comment Bot integration
- [ ] Evaluation framework
