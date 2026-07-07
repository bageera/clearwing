"""API Security Testing Tools — GraphQL, gRPC, IDOR, race conditions, etc.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# 1. GraphQL & gRPC
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_graphqlmap(
    target: str,
    options: str = "--dump",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """GraphQL introspection abuse, query-depth testing, and field suggestion.

    graphqlmap automates common GraphQL attack vectors: introspection,
    field suggestion, query depth recursion, and alias-based batching.
    Useful for identifying information leakage and DoS surfaces.

    Args:
        target: GraphQL endpoint URL (e.g. https://api.example.com/graphql).
        options: graphqlmap flags. Default: --dump.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"graphqlmap -u '{target}' {options}"
    logger.info("[%s] graphqlmap: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_grpcurl(
    target: str,
    proto_file: str = "",
    options: str = "list",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """gRPC / Protobuf service enumeration and method fuzzing.

    Uses grpcurl to list services, invoke methods, and fuzz protobuf
    message fields. Supports reflection discovery or explicit .proto file.

    Args:
        target: gRPC server host:port (e.g. api.example.com:443).
        proto_file: Path to .proto file inside the container (optional).
        options: grpcurl action — "list", "describe", "call <Method>".
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"grpcurl -plaintext '{target}' {options}"
    if proto_file:
        cmd = f"grpcurl -proto {proto_file} -plaintext '{target}' {options}"
    logger.info("[%s] grpcurl: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# 2. WebSocket / Real-Time API
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_wsprobe(
    target: str,
    message: str = '{"type":"test"}',
    iterations: int = 10,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """WebSocket message injection and frame manipulation fuzzer.

    Connects to a WebSocket endpoint, sends a payload, and reports
    the response. Supports JSON, binary frames, and connection-reuse
    for testing stateful real-time APIs.

    Args:
        target: WebSocket URL (e.g. wss://api.example.com/ws).
        message: JSON payload to send.
        iterations: Number of repeated sends (default: 10).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"python3 /opt/wsprobe/wsprobe.py "
        f"--url '{target}' --message {repr(message)} --iterations {iterations}"
    )
    logger.info("[%s] wsprobe: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# 3. IDOR, Race Conditions, Mass Assignment
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_idor_scanner(
    base_url: str,
    object_range: str = "1-100",
    cookie: str = "",
    header: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Automated IDOR (Insecure Direct Object Reference) scanner.

    Swaps numeric object IDs across sequential ranges and compares
    response sizes/headers to detect horizontal / vertical privilege
    escalation in REST APIs.

    Args:
        base_url: URL template with FUZZ placeholder (e.g. /api/users/FUZZ).
        object_range: ID range to test (e.g. "1-100" or "1000-2000").
        cookie: Session cookie string (optional).
        header: Additional headers (e.g. "Authorization: Bearer xxx").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"python3 /opt/idor-scanner/scan.py --url '{base_url}' --range {object_range}"
    if cookie:
        cmd += f" --cookie {repr(cookie)}"
    if header:
        cmd += f" --header {repr(header)}"
    logger.info("[%s] idor scanner: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_race_condition_tester(
    target: str,
    request_file: str = "/tmp/race.req",
    threads: int = 50,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Race-condition tester for gift-card / coupon / limit bypasses.

    Sends N parallel requests from multiple threads to exploit
    TOCTOU windows in API endpoints (e.g. redeem coupon, transfer funds).

    Args:
        target: Target URL or request file path inside container.
        request_file: Raw HTTP request file for replay.
        threads: Number of concurrent threads (default: 50).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"python3 /opt/race-tester/race.py "
        f"--target '{target}' --request-file {request_file} --threads {threads}"
    )
    logger.info("[%s] race condition tester: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_swagger_abuse(
    swagger_url: str,
    test_type: str = "mass_assignment",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """OpenAPI spec abuse: mass assignment, parameter pollution, schema injection.

    Downloads a Swagger/OpenAPI specification and generates malicious
    requests to test for mass assignment, parameter pollution, and
    schema injection vulnerabilities.

    Args:
        swagger_url: URL to the OpenAPI JSON/YAML spec.
        test_type: "mass_assignment", "param_pollution", "schema_injection".
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"python3 /opt/swagger-abuse/abuse.py --spec '{swagger_url}' --test {test_type}"
    logger.info("[%s] swagger abuse (%s): %s", distro, test_type, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# 4. 2FA, SSO, Auth Bypass
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_2fa_bypass_tester(
    target: str,
    method: str = "otp_brute",
    code_range: str = "000000-999999",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Two-factor authentication bypass testing.

    Tests OTP brute-force, TOTP reuse, backup-code enumeration,
    and push-notification race conditions.

    Args:
        target: 2FA verification endpoint URL.
        method: "otp_brute", "totp_reuse", "backup_code_enum", "push_race".
        code_range: OTP range for brute-force (default: 000000-999999).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"python3 /opt/2fa-bypass/bypass.py "
        f"--target '{target}' --method {method} --range {code_range}"
    )
    logger.info("[%s] 2FA bypass tester (%s): %s", distro, method, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_cors_misconfig_tester(
    target: str,
    origins: str = "https://evil.com,https://attacker.com,null",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Automated CORS misconfiguration exploitation tester.

    Tests for reflected origin, null-origin trust, subdomain trust,
    and wildcard-plus-credential misconfigurations.

    Args:
        target: API endpoint to test.
        origins: Comma-separated list of attacker origins.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"python3 /opt/cors-tester/test.py --target '{target}' --origins {origins}"
    logger.info("[%s] CORS misconfig tester: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
