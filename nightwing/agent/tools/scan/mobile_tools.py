"""Mobile Pentest Tools — Phase 13.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 13: Mobile Pentesting
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_frida(
    target_app: str,
    script: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Dynamic instrumentation of mobile apps with Frida.

    Injects JavaScript into running Android/iOS processes to hook
    functions, bypass SSL pinning, intercept crypto calls, and more.

    Args:
        target_app: Package name (Android) or process name (iOS).
        script: Path to Frida script inside container, or None for default.
        options: Extra frida flags (e.g. "--no-pause").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    script_flag = f"-l {script}" if script else ""
    cmd = f"frida {options} {script_flag} -f {target_app}"
    logger.info("[%s] frida: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_objection(
    target_app: str,
    command: str = "explore",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Runtime mobile exploration with objection.

    objection is a runtime mobile exploration toolkit built on Frida.
    Provides high-level commands for SSL pinning bypass, root/jailbreak
    detection bypass, heap dumping, and more.

    Args:
        target_app: Package name (Android) or bundle ID (iOS).
        command: objection command to run (default: "explore").
        options: Extra objection flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"objection {options} --gadget {target_app} {command}"
    logger.info("[%s] objection: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_mobsf(
    apk_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Mobile Security Framework (MobSF) static analysis.

    Performs automated static analysis on Android APK, iOS IPA, or
    Windows APPX files. Identifies hardcoded secrets, insecure configs,
    and known vulnerabilities.

    Args:
        apk_file: Path to mobile app package inside the container.
        options: Extra MobSF CLI flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"mobsf {options} {apk_file}"
    logger.info("[%s] mobsf: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_apktool(
    apk_file: str,
    output_dir: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """APK decompilation and reverse engineering with apktool.

    Disassembles Android APK files to smali code and extracts resources
    for manual analysis or modification.

    Args:
        apk_file: Path to APK inside the container.
        output_dir: Directory for decompiled output (default: apk name + ".out").
        options: Extra apktool flags (e.g. "-s" to skip disassembly).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    out_flag = f"-o {output_dir}" if output_dir else ""
    cmd = f"apktool d {options} {out_flag} {apk_file}"
    logger.info("[%s] apktool: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_jadx(
    apk_file: str,
    output_dir: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Android APK decompiler to Java source with jadx.

    Converts APK/DEX files back to readable Java source code for
    security auditing and reverse engineering.

    Args:
        apk_file: Path to APK inside the container.
        output_dir: Directory for decompiled Java sources.
        options: Extra jadx flags (e.g. "--deobf" for deobfuscation).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    out_flag = f"-d {output_dir}" if output_dir else ""
    cmd = f"jadx {options} {out_flag} {apk_file}"
    logger.info("[%s] jadx: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_drozer(
    package: str,
    command: str = "list",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Android security assessment framework (drozer).

    drozer allows you to search for security vulnerabilities in apps and
    devices by assuming the role of an app and interacting with the
    Android runtime and other apps.

    Args:
        package: Target Android package name.
        command: drozer module to run (e.g. "app.package.info").
        options: Extra drozer flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"drozer {options} console connect -c 'run {command} {package}'"
    logger.info("[%s] drozer: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
