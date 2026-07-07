"""GitHub Code & Secret Leak Reconnaissance — native + container hybrid.

Native tools query GitHub Search API for leaked secrets, credentials,
and sensitive files. Container-based tools run gitleaks and trufflehog
against cloned repositories.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_DEFAULT_PER_PAGE = 30


def _github_headers() -> dict[str, str]:
    """Build request headers with optional GitHub token."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Nightwing-GitHub-Tool/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", os.environ.get("GH_TOKEN", ""))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@tool(
    name="search_github_code",
    description=(
        "Search GitHub code for leaked secrets, API keys, credentials, or "
        "sensitive file patterns (e.g. .env, id_rsa, config.yml)."
    ),
)
def search_github_code(
    query: str,
    max_results: int = 100,
) -> dict[str, Any]:
    """Search GitHub code via Search API.

    Args:
        query: GitHub search query. Examples:
            - "api_key org:targetorg"
            - "filename:.env password"
            - "AKIA extension:json"
        max_results: Cap on total results (default 100, max 1000).

    Returns:
        Dict with matched code snippets, repository info, and raw URLs.
    """
    headers = _github_headers()
    results: list[dict[str, Any]] = []
    page = 1
    per_page = min(_DEFAULT_PER_PAGE, max_results)

    while len(results) < max_results:
        url = (
            f"{_GITHUB_API}/search/code"
            f"?q={urllib.request.quote(query)}"
            f"&per_page={per_page}&page={page}"
        )
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return {
                    "error": "GitHub API rate limit exceeded. Set GITHUB_TOKEN env var.",
                    "results": results,
                }
            return {"error": f"GitHub API error {e.code}: {e.reason}", "results": results}
        except Exception as e:
            return {"error": f"Request failed: {e}", "results": results}

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            results.append(
                {
                    "repo": item.get("repository", {}).get("full_name"),
                    "repo_url": item.get("repository", {}).get("html_url"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                    "score": item.get("score"),
                }
            )

        if len(items) < per_page:
            break
        page += 1

    logger.info("GitHub code search '%s' returned %d results", query, len(results))
    return {
        "query": query,
        "total_count": data.get("total_count", len(results)),
        "results_returned": len(results),
        "results": results,
    }


@tool(
    name="search_github_commits",
    description=(
        "Search GitHub commit history for removed secrets or sensitive "
        "strings that may still exist in the commit log."
    ),
)
def search_github_commits(
    query: str,
    max_results: int = 100,
) -> dict[str, Any]:
    """Search GitHub commits via Search API for historical leaks.

    Args:
        query: GitHub commit search query. Examples:
            - "remove password"
            - "api_key"
            - "AKIA"
        max_results: Cap on total results.

    Returns:
        Dict with commit messages, authors, repos, and commit URLs.
    """
    headers = _github_headers()
    results: list[dict[str, Any]] = []
    page = 1
    per_page = min(_DEFAULT_PER_PAGE, max_results)

    while len(results) < max_results:
        url = (
            f"{_GITHUB_API}/search/commits"
            f"?q={urllib.request.quote(query)}"
            f"&per_page={per_page}&page={page}"
        )
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return {
                    "error": "GitHub API rate limit exceeded. Set GITHUB_TOKEN env var.",
                    "results": results,
                }
            return {"error": f"GitHub API error {e.code}: {e.reason}", "results": results}
        except Exception as e:
            return {"error": f"Request failed: {e}", "results": results}

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            commit = item.get("commit", {})
            results.append(
                {
                    "repo": item.get("repository", {}).get("full_name"),
                    "author": commit.get("author", {}).get("name"),
                    "email": commit.get("author", {}).get("email"),
                    "date": commit.get("author", {}).get("date"),
                    "message": commit.get("message", "")[:500],
                    "url": item.get("html_url"),
                }
            )

        if len(items) < per_page:
            break
        page += 1

    logger.info("GitHub commit search '%s' returned %d results", query, len(results))
    return {
        "query": query,
        "total_count": data.get("total_count", len(results)),
        "results_returned": len(results),
        "results": results,
    }


@tool(requires_approval=False)
def run_gitleaks(
    repo_path: str,
    options: str = "--verbose --redact",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run gitleaks to detect hardcoded secrets in a repository.

    gitleaks scans git repositories for secrets, API keys, and tokens
    using regex rules. Can scan the entire history or just HEAD.

    Args:
        repo_path: Absolute path to git repo inside the container.
        options: Extra flags (e.g. "--no-git" for filesystem-only scan).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (leak report), and error.
    """

    cmd = f"gitleaks detect -s {repo_path} {options}"
    logger.info("[%s] gitleaks: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_trufflehog(
    target: str,
    options: str = "--only-verified",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run TruffleHog to find and verify secrets in repositories, S3, etc.

    TruffleHog scans git repositories, GitHub/GitLab orgs, S3 buckets,
    and more for high-entropy strings and verifies them against APIs.

    Args:
        target: Git repo path, GitHub URL, or S3 bucket URI inside container.
        options: Extra flags (e.g. "--json --since-commit HEAD~10").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"trufflehog {options} {target}"
    logger.info("[%s] trufflehog: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )
