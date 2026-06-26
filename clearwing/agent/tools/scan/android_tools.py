"""Android Mobile Pentest Tools — Comprehensive APK analysis and runtime testing.

Tools target Android APK/IPA static analysis, dynamic instrumentation,
network interception, and emulator-based testing. All execute inside
Kali/Parrot PentestContainers.
"""

import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Android Static Analysis Pipeline
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=False)
def run_apk_info(
    apk_file: str,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Extract basic APK metadata (package name, version, permissions, activities).

    Uses aapt, aapt2, or apkanalyzer to quickly surface the manifest
    without full decompilation.

    Args:
        apk_file: Path to APK inside the container.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (manifest dump), and error.
    """

    cmd = f"aapt dump badging {apk_file}"
    logger.info("[%s] apk-info: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_apk_permissions(
    apk_file: str,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Permission analysis and risk scoring for Android APKs.

    Extracts declared permissions, checks for dangerous permissions
    (camera, microphone, contacts, location, etc.), and flags
    overprivileged apps.

    Args:
        apk_file: Path to APK inside the container.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (permission list with risk scores), and error.
    """

    script = (
        f'python3 -c "'
        f"import zipfile, xml.etree.ElementTree as ET; "
        f"z = zipfile.ZipFile('{apk_file}'); "
        f"manifest = z.read('AndroidManifest.xml'); "
        f"root = ET.fromstring(manifest); "
        f"ns = '{{http://schemas.android.com/apk/res/android}}'; "
        f"perms = [p.get(ns+'name') "
        f"for p in root.iter('uses-permission') if p.get(ns+'name')]; "
        f"dangerous = ['CAMERA','RECORD_AUDIO','READ_CONTACTS','ACCESS_FINE_LOCATION','READ_SMS','READ_PHONE_STATE']; "
        f"print('Total:', len(perms)); "
        f"print('Dangerous:', [p for p in perms if any(d in p for d in dangerous)]); "
        f"print('All:', perms)\""
    )
    logger.info("[%s] apk-permissions: %s", distro, script[:80])
    return run_in_pentest_container(
        script,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_apk_components(
    apk_file: str,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Export Android components: activities, services, receivers, providers.

    Identifies exported components (android:exported="true") which are
    attack surfaces for intent hijacking, activity injection, and
    unauthorized data access.

    Args:
        apk_file: Path to APK inside the container.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (component list with exported flags), and error.
    """

    script = (
        f"androguard arsc {apk_file} | grep -E "
        f"'activity|service|receiver|provider' | head -50 || "
        f"python3 /opt/androguard/androarsc.py -i {apk_file}"
    )
    logger.info("[%s] apk-components: %s", distro, script[:80])
    return run_in_pentest_container(
        script,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_apk_strings(
    apk_file: str,
    min_length: int = 8,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Extract and analyze strings from APK resources and dex files.

    Searches for hardcoded URLs, API keys, passwords, tokens, and
    other sensitive strings. Filters by minimum length to reduce noise.

    Args:
        apk_file: Path to APK inside the container.
        min_length: Minimum string length to report.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (string dump with context), and error.
    """

    cmd = (
        f"strings {apk_file} | grep -E "
        f"'https?://|api[_-]?key|token|password|secret|auth|bearer|AWS|GCP|firebase' "
        f"| grep -v '^Binary' | sort -u | head -100"
    )
    logger.info("[%s] apk-strings: %s", distro, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


# ════════════════════════════════════════════════════════════════════════════
# Android Dynamic Analysis
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_frida_hook(
    target_app: str,
    hook_script: str | None = None,
    spawn: bool = True,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Dynamic instrumentation of Android app with Frida hook script.

    Injects a JavaScript hook into a running Android process to intercept
    function calls, modify return values, or bypass security checks.
    Requires Android device/emulator connected via ADB or frida-server.

    Args:
        target_app: Package name (e.g. "com.example.app").
        hook_script: Path to Frida JS script, or None for default SSL bypass.
        spawn: If True, spawn fresh process. If False, attach to running.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    default_script = "/opt/frida-scripts/ssl-pinning-bypass.js"
    script = hook_script or default_script
    spawn_flag = "-f" if spawn else ""

    cmd = f"frida {spawn_flag} {target_app} -l {script} --no-pause"
    logger.info("[%s] frida-hook: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_objection_explore(
    target_app: str,
    command: str = "explore",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Runtime mobile exploration with objection (Frida-based).

    Provides high-level commands for:
    - SSL pinning bypass (--gadget SSLPinning disable)
    - Root/jailbreak detection bypass (--gadget RootDetection disable)
    - Heap dump (--gadget memory dump all)
    - File system access
    - Intent interception
    - Screenshot capture

    Args:
        target_app: Package name (Android) or bundle ID (iOS).
        command: objection command (explore, run, or specific module).
        options: Extra objection flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"objection --gadget {target_app} {options} {command}"
    logger.info("[%s] objection-explore: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_frida_traffic_capture(
    target_app: str,
    output_pcap: str = "/tmp/capture.pcap",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Capture network traffic from Android app via Frida + tcpdump.

    Uses Frida to hook socket APIs and redirect traffic through a local
    proxy for capture and analysis. Combines with tcpdump or Wireshark
    for full packet inspection.

    Args:
        target_app: Package name to monitor.
        output_pcap: Path for captured traffic file.
        duration: Seconds to capture before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (capture summary), and error.
    """

    cmd = (
        f"timeout {duration} bash -c "
        f"'frida -U {target_app} -l /opt/frida-scripts/socket-monitor.js & "
        f"tcpdump -w {output_pcap} -i any port not 22'"
    )
    logger.info("[%s] frida-traffic-capture: %s", distro, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Android Emulator / ADB Testing
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_adb_shell(
    device_id: str | None = None,
    command: str = "shell",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Execute ADB (Android Debug Bridge) commands inside pentest container.

    Supports device enumeration, shell access, app installation,
    logcat monitoring, and file transfer. Requires Android emulator
    or physical device connected to container via USB passthrough.

    Args:
        device_id: ADB device serial. If None, uses first available device.
        command: ADB command (shell, install, logcat, pull, push, etc.).
        options: Extra ADB flags (e.g. "-s emulator-5554").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    device_flag = f"-s {device_id}" if device_id else ""
    cmd = f"adb {device_flag} {options} {command}"
    logger.info("[%s] adb-shell: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_android_emulator(
    avd_name: str,
    snapshot: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Launch Android Virtual Device (AVD) emulator for isolated testing.

    Starts an Android emulator instance with optional snapshot restore.
    Useful for creating reproducible testing environments without
    affecting physical devices.

    Args:
        avd_name: Name of the AVD to launch (e.g. "Pixel_4_API_30").
        snapshot: Snapshot name to restore, or None for clean boot.
        options: Extra emulator flags (e.g. "-no-window -gpu off").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (emulator status), and error.
    """

    snapshot_flag = f"-snapshot {snapshot}" if snapshot else ""
    cmd = f"emulator -avd {avd_name} {snapshot_flag} {options}"
    logger.info("[%s] android-emulator: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Android Network Interception
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_burp_mobile_proxy(
    target_app: str,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Intercept Android app HTTPS traffic via Burp Suite mobile proxy.

    Configures device/emulator to route traffic through Burp proxy,
    installs Burp CA certificate, and optionally bypasses SSL pinning
    via Frida/objection. Captures all app network traffic for analysis.

    Args:
        target_app: Package name to intercept.
        proxy_host: Burp proxy listener host.
        proxy_port: Burp proxy listener port.
        options: Extra flags (e.g. "--ssl-bypass" to auto-disable pinning).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"python3 /opt/mobile-proxy-setup.py "
        f"--app {target_app} --proxy {proxy_host}:{proxy_port} {options}"
    )
    logger.info("[%s] burp-mobile-proxy: %s", distro, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_mitmproxy_android(
    target_app: str,
    port: int = 8080,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """MITMproxy-based traffic interception for Android apps.

    Alternative to Burp for mobile traffic capture. Supports:
    - Automatic SSL pinning bypass via Frida script injection
    - Request/response modification
    - HAR export for later analysis
    - Certificate pinning detection

    Args:
        target_app: Package name to intercept.
        port: MITMproxy listen port.
        options: Extra mitmproxy flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"mitmproxy --mode regular --listen-port {port} {options}"
    logger.info("[%s] mitmproxy-android: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Android Security Bypass
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_ssl_pinning_bypass(
    target_app: str,
    method: str = "frida",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Bypass SSL certificate pinning in Android apps.

    Supports multiple methods:
    - "frida": Universal SSL pinning bypass script
    - "objection": objection android sslpinning disable
    - "patch": Manual APK patching with recompilation
    - "magisk": System-level CA injection (rooted devices)

    Args:
        target_app: Package name to target.
        method: Bypass technique ("frida", "objection", "patch", "magisk").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    if method == "frida":
        cmd = f"frida -U -f {target_app} -l /opt/frida-scripts/universal-ssl-bypass.js --no-pause"
    elif method == "objection":
        cmd = f"objection --gadget {target_app} explore -s 'android sslpinning disable'"
    elif method == "patch":
        cmd = f"python3 /opt/apk-patcher/ssl-patch.py {target_app}"
    elif method == "magisk":
        cmd = "adb shell su -c 'cp /data/local/tmp/cacert.pem /system/etc/security/cacerts/'"
    else:
        cmd = f"frida -U -f {target_app} -l /opt/frida-scripts/universal-ssl-bypass.js --no-pause"

    logger.info("[%s] ssl-pinning-bypass (%s): %s", distro, method, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_root_detection_bypass(
    target_app: str,
    method: str = "frida",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Bypass root/jailbreak detection in Android apps.

    Methods:
    - "frida": Hook root detection functions (SafetyNet, rootBeer, etc.)
    - "objection": objection android root disable
    - "magisk": Magisk Hide / Zygisk configuration
    - "patch": Remove root checks from smali bytecode

    Args:
        target_app: Package name to target.
        method: Bypass technique.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    if method == "frida":
        cmd = f"frida -U -f {target_app} -l /opt/frida-scripts/root-detection-bypass.js --no-pause"
    elif method == "objection":
        cmd = f"objection --gadget {target_app} explore -s 'android root disable'"
    elif method == "magisk":
        cmd = f"adb shell magisk --hide {target_app}"
    elif method == "patch":
        cmd = f"python3 /opt/apk-patcher/root-patch.py {target_app}"
    else:
        cmd = f"frida -U -f {target_app} -l /opt/frida-scripts/root-detection-bypass.js --no-pause"

    logger.info("[%s] root-detection-bypass (%s): %s", distro, method, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Android Forensics & Data Extraction
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_android_backup_extract(
    target_app: str,
    output_dir: str = "/tmp/android-backup",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Extract app data via Android backup mechanism (adb backup).

    Uses `adb backup` to create a full backup of the target app,
    then extracts SharedPreferences, databases, and files for
    offline analysis. Works even without root on some devices.

    Args:
        target_app: Package name to backup.
        output_dir: Directory for extracted backup contents.
        options: Extra flags (e.g. "--no-system" to skip system apps).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"adb backup -f /tmp/{target_app}.ab {target_app} && "
        f"mkdir -p {output_dir} && "
        f"dd if=/tmp/{target_app}.ab bs=24 skip=1 | openssl zlib -d | tar -xC {output_dir}"
    )
    logger.info("[%s] android-backup-extract: %s", distro, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_android_screenshot(
    output_file: str = "/tmp/android-screenshot.png",
    device_id: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Capture screenshot from Android device/emulator via ADB.

    Useful for documenting UI states, confirmation dialogs, or
    security warnings during dynamic testing.

    Args:
        output_file: Path for screenshot PNG.
        device_id: ADB device serial, or None for first device.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (file path), and error.
    """

    device_flag = f"-s {device_id}" if device_id else ""
    cmd = f"adb {device_flag} shell screencap -p {output_file}"
    logger.info("[%s] android-screenshot: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# APK Modification & Repackaging
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_apk_patch(
    apk_file: str,
    patch_type: str = "debuggable",
    output_apk: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Patch Android APK for pentesting (debuggable, backup, network config).

    Patch types:
    - "debuggable": Set android:debuggable="true"
    - "backup": Enable allowBackup="true"
    - "cleartext": Enable cleartext traffic
    - "network": Add network_security_config for proxy trust
    - "all": Apply all patches

    Args:
        apk_file: Input APK path.
        patch_type: Type of patch to apply.
        output_apk: Output path, or None for auto-generated.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output (new APK path), and error.
    """

    out = output_apk or f"{apk_file}.patched.apk"
    cmd = f"python3 /opt/apk-patcher/patch.py -i {apk_file} -o {out} -t {patch_type}"
    logger.info("[%s] apk-patch (%s): %s", distro, patch_type, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_apk_repack(
    smali_dir: str,
    output_apk: str,
    sign: bool = True,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Repackage modified smali code into installable APK.

    After decompiling with apktool and modifying smali bytecode,
    this tool rebuilds the APK, aligns it with zipalign, and
    optionally signs it with a debug key.

    Args:
        smali_dir: Directory containing modified smali/resources.
        output_apk: Path for rebuilt APK.
        sign: If True, sign with debug keystore.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    sign_cmd = (
        "&& jarsigner -keystore /opt/android/debug.keystore -storepass android {output_apk} androiddebugkey"
        if sign
        else ""
    )
    cmd = (
        f"apktool b {smali_dir} -o {output_apk} "
        f"&& zipalign -v 4 {output_apk} {output_apk}.aligned "
        f"&& mv {output_apk}.aligned {output_apk}"
        f"{sign_cmd}"
    )
    logger.info("[%s] apk-repack: %s", distro, cmd[:80])
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Android SafetyNet / Play Integrity Testing
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_safetynet_check(
    target_app: str,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Test Google SafetyNet / Play Integrity API implementation.

    Verifies whether the app properly validates SafetyNet/Play Integrity
    attestations and handles failure scenarios. Useful for identifying
    weak attestation validation that could allow tampered devices.

    Args:
        target_app: Package name to test.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"python3 /opt/android-pentest/safetynet-check.py --app {target_app}"
    logger.info("[%s] safetynet-check: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
