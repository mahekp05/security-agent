from __future__ import annotations

import requests


def get_pr_diff(repo_full_name: str, pr_number: int, token: str) -> str:
    """Fetch a pull request diff from GitHub.

    Args:
        repo_full_name: "owner/repo"
        pr_number: Pull request number
        token: GitHub token with permission to read PR content

    Returns:
        Raw unified diff as a string.
    """
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
    }

    response = requests.get(url, headers=headers, timeout=60)
    response.raise_for_status()
    return response.text


def post_issue_comment(repo_full_name: str, pr_number: int, token: str, body_md: str) -> None:
    """Post a comment to a PR conversation (issue comment API).

    Note: GitHub treats pull requests as issues for comments.

    Args:
        repo_full_name: "owner/repo"
        pr_number: Pull request number
        token: GitHub token with permission to write issue comments
        body_md: Markdown body
    """
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    response = requests.post(url, headers=headers, json={"body": body_md}, timeout=60)
    response.raise_for_status()
