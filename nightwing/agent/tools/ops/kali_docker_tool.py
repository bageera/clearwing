from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import KALI


@tool
def kali_setup() -> dict:
    """Start a Kali Linux Docker container for specialized security tools.

    Pulls kalilinux/kali-rolling if not present, starts a container, and
    returns the container ID. Reuses existing container if one is already running.

    Returns:
        Dict with keys: container_id, status, message.
    """
    return KALI.setup()


@tool
def kali_execute(container_id: str, command: str) -> dict:
    """Execute a command inside the Kali Docker container. REQUIRES HUMAN APPROVAL.

    Args:
        container_id: Docker container ID.
        command: Shell command to execute.

    Returns:
        Dict with keys: exit_code, output.
    """
    return KALI.execute(container_id, command)


@tool
def kali_install_tool(container_id: str, package_name: str) -> dict:
    """Install a package in the Kali Docker container via apt-get.

    Args:
        container_id: Docker container ID.
        package_name: Debian package name to install (e.g. 'nmap', 'nikto').

    Returns:
        Dict with keys: exit_code, output.
    """
    return KALI.install(container_id, package_name)


@tool
def kali_cleanup(container_id: str) -> dict:
    """Stop and remove the Kali Docker container.

    Args:
        container_id: Docker container ID.

    Returns:
        Dict with keys: status, message.
    """
    return KALI.cleanup(container_id)
