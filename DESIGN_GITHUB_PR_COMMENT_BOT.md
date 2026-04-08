# Design: GitHub PR Issue Comment Bot (Security Agent)

## Goal
Run this repo’s security agent automatically on every PR update and post a **Markdown report** as an **issue comment** on the PR (Conversation tab). This is **comment-only**: it never blocks merges.

## How it works (end-to-end)
1. A PR is opened or updated.
2. GitHub Actions starts a job on a clean runner VM.
3. The runner checks out the repo and installs Python + dependencies.
4. The workflow executes the agent runner: `python -m src.main --github-pr`.
5. The runner code:
   - Reads PR number from `GITHUB_EVENT_PATH` (JSON payload)
   - Fetches the PR diff from GitHub API using `GITHUB_TOKEN`
   - Runs the pipeline: diff parser → detectors (A05/A02/A10)
   - Formats a Markdown report string
   - Posts the report as an issue comment via GitHub API

## Why “issue comment”?
PRs are “issues” in GitHub’s API for comment purposes. Posting to:
- `POST /repos/{owner}/{repo}/issues/{pull_number}/comments`

…creates a comment in the PR Conversation timeline.

## Repo changes (implemented)
### 1) Workflow
File: `.github/workflows/security-review.yml`
- Trigger: `pull_request` (opened, synchronize, reopened)
- Permissions: `contents: read`, `issues: write`
- Default safety: skips fork PRs (secrets are not safely available)

### 2) CI dependencies
File: `requirements-actions.txt`
- Keeps the existing `requirements.txt` as a design/spec document.
- Used only by GitHub Actions to install runtime deps.

### 3) GitHub API helper
File: `src/github/client.py`
- `get_pr_diff(repo_full_name, pr_number, token) -> str`
- `post_issue_comment(repo_full_name, pr_number, token, body_md) -> None`

### 4) Agent runner
File: `src/main.py`
- `--github-pr` mode for GitHub Actions
- `--diff-file` mode for offline/local testing
- `--repo` + `--pr-number` mode for local testing against GitHub (requires `GITHUB_TOKEN`)

## Required secrets/env vars
### GitHub Actions provides automatically
- `GITHUB_REPOSITORY` (e.g., `mahekp05/security-agent`)
- `GITHUB_EVENT_PATH` (path to PR event JSON)
- `GITHUB_TOKEN` (injected from `secrets.GITHUB_TOKEN`)

### You must configure
- `HUGGINGFACEHUB_API_TOKEN`
  - Add it in GitHub repo settings → Secrets and variables → Actions → New repository secret
  - Name must match exactly: `HUGGINGFACEHUB_API_TOKEN`
  - Not required for `--test-comment` mode; required once you enable real analysis.

## Local testing
### 1) Offline diff test (no GitHub)
- Save a diff to a file (example: `sample.diff`)
- Run:
  - `python -m src.main --diff-file sample.diff`

### 2) Local GitHub PR fetch (requires token)
- Set env var `GITHUB_TOKEN` locally.
- Run:
  - `python -m src.main --repo owner/repo --pr-number 123`

## First GitHub test (recommended path)
1. Push these files to `main`.
2. Add GitHub secret `HUGGINGFACEHUB_API_TOKEN`.
3. Open a PR from a branch in the same repo (not a fork).
4. Push a commit to the PR.
5. Verify the workflow ran and a comment appears on the PR.

## Troubleshooting: 403 Forbidden when posting comment
If the job fails with `403 Forbidden` when calling the GitHub comments API, set:
- Repo → Settings → Actions → General → **Workflow permissions** → **Read and write permissions**

Also ensure:
- Repo → Settings → General → Features → **Issues** is enabled (PR conversation comments use the issues comments API).

### Important: why you may see “Checks: 0”
If the workflow file is only introduced/changed inside the PR, GitHub may not execute it for security reasons.
To reliably test PR triggers, ensure `.github/workflows/security-review.yml` already exists on the default branch (`main`), then open/update a separate PR.

### Manual testing
This workflow also supports manual runs via `workflow_dispatch` from the repo’s Actions tab (useful to confirm Actions is enabled and the workflow is recognized).

## Known limitations (expected for MVP)
- The workflow posts a new comment on every PR update (`synchronize`).
  - Later improvement: upsert/overwrite the previous bot comment.
- Current findings don’t include file paths in the Pydantic model output.
  - Later improvement: include file path in findings or in report formatting.
- Large diffs may be expensive/slow for LLM calls.
  - Later improvement: diff size limits, truncation, or heuristic filtering.
