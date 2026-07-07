"""CI/CD Security Testing Tools — secret scanning, IaC misconfig, dependency audit, container vulns.

All tools execute inside Kali/Parrot Docker containers via PentestContainerManager.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


@tool(requires_approval=False)
def run_gitleaks(
    repo_path: str = ".",
    options: str = "--verbose",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Detect secrets in Git repositories using gitleaks.

    Scans the entire commit history for API keys, passwords, tokens,
    and other high-entropy strings that may have been committed accidentally.

    Args:
        repo_path: Path to the Git repository inside the container.
        options: gitleaks flags (default: --verbose).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"gitleaks detect --source {repo_path} {options}"
    logger.info("[%s] gitleaks: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_trufflehog(
    target: str = ".",
    options: str = "--only-verified",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """High-entropy secret scanning with live credential validation.

        TruffleHog scans Git history, filesystems, and S3 buckets for secrets.
        It verifies credentials aga
    inst live APIs when possible, reducing false positives.

        Args:
            target: Git URL, local path, or S3 URI to scan.
            options: trufflehog flags (default: --only-verified).
            container_id: Docker container ID; auto-discovers if None.
            distro: "kali" or "parrot".

        Returns:
            Dict with exit_code, output, and error.
    """

    cmd = f"trufflehog filesystem {target} {options}"
    logger.info("[%s] trufflehog: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_checkov(
    scan_path: str = ".",
    framework: str = "terraform,cloudformation,dockerfile,kubernetes",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Infrastructure-as-Code misconfiguration scanning.

    Checkov scans Terraform, CloudFormation, Dockerfile, Kubernetes,
    Helm, and ARM templates for security and compliance best practices.

    Args:
        scan_path: Path to IaC files inside the container.
        framework: Comma-separated list of frameworks to scan.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"checkov --directory {scan_path} --framework {framework} --compact"
    logger.info("[%s] checkov: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_trivy(
    target: str = ".",
    scan_type: str = "fs",
    options: str = "--scanners vuln",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Container image and filesystem vulnerability scanner.

    Trivy scans container images, filesystems, Git repositories, and
    Kubernetes clusters for OS packages, language dependencies, and
    IaC misconfigurations.

    Args:
        target: Docker image name, path, or URL to scan.
        scan_type: "fs", "image", "repo", "k8s".
        options: trivy flags (default: --scanners vuln).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"trivy {scan_type} {options} {target}"
    logger.info("[%s] trivy (%s): %s", distro, scan_type, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_semgrep(
    target: str = ".",
    config: str = "auto",
    options: str = "--json",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Static analysis rule-based security scanning.

    Semgrep scans code for OWASP Top 10, crypto misuse, injection,
    insecure deserialization, and custom rule patterns across 30+
    languages.

    Args:
        target: Path or repository URL to scan.
        config: Rule set — "auto", "p/owasp-top-ten", "p/security-audit".
        options: Additional flags (default: --json).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"semgrep --config={config} {options} {target}"
    logger.info("[%s] semgrep (%s): %s", distro, config, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_dependency_audit(
    manifest: str = "package.json",
    options: str = "--json",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Dependency confusion and known-vulnerability audit.

    Scans package-lock.json, Cargo.lock, yarn.lock, etc. for known
    CVEs and dependency-confusion / typosquatting risks. Supports
    npm, pip, cargo, gem, and maven.

    Args:
        manifest: Path to dependency manifest inside the container.
        options: Additional scanner flags (default: --json).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"python3 /opt/dependency-audit/audit.py --manifest {manifest} {options}"
    logger.info("[%s] dependency audit: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_kube_hunter(
    target: str = "",
    options: str = "--remote",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Kubernetes cluster vulnerability scanner.

    kube-hunter hunts for security weaknesses in Kubernetes clusters:
    exposed dashboards, privilege escalation paths, network policies,
    and RBAC misconfigurations.

    Args:
        target: Kubernetes API server address (optional; auto-discovers).
        options: kube-hunter flags (default: --remote for remote cluster).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"kube-hunter {options}"
    if target:
        cmd += f" --api {target}"
    logger.info("[%s] kube-hunter: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )
