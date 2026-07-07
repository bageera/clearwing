from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import PARROT


@tool
def parrot_setup() -> dict:
    """Start a ParrotOS Docker container for specialized security tools.

    Pulls parrotsec/core:latest (slim ~265 MB) if not present, starts a
    container, and returns the container ID. Reuses existing container if one
    is already running.

    Returns:
        Dict with keys: container_id, status, message.
    """
    return PARROT.setup()


@tool
def parrot_execute(container_id: str, command: str) -> dict:
    """Execute a command inside the ParrotOS Docker container. REQUIRES HUMAN APPROVAL.

    Args:
        container_id: Docker container ID.
        command: Shell command to execute.

    Returns:
        Dict with keys: exit_code, output.
    """
    return PARROT.execute(container_id, command)


@tool
def parrot_install_tool(container_id: str, package_name: str) -> dict:
    """Install a package in the ParrotOS Docker container via apt-get.

    Args:
        container_id: Docker container ID.
        package_name: Debian package name to install (e.g. 'nmap', 'sqlmap').

    Returns:
        Dict with keys: exit_code, output.
    """
    return PARROT.install(container_id, package_name)


@tool
def parrot_cleanup(container_id: str) -> dict:
    """Stop and remove the ParrotOS Docker container.

    Args:
        container_id: Docker container ID.

    Returns:
        Dict with keys: status, message.
    """
    return PARROT.cleanup(container_id)
