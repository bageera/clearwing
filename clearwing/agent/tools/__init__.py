"""Agent tool registry — lazy aggregator.

Importing one tool subpackage should not initialize the entire scanning stack.
Sourcehunt imports `clearwing.agent.tools.hunt`, and that path must stay free
of OT/scapy side effects.
"""

from typing import Any


def get_custom_tools() -> list[Any]:
    from .ops.dynamic_tool_creator import get_custom_tools as _get_custom_tools

    return _get_custom_tools()


def _get_browser_tools() -> list[Any]:
    try:
        from .recon.browser_tools import get_browser_tools

        return get_browser_tools()
    except ImportError:
        return []


def _get_proxy_tools() -> list[Any]:
    try:
        from .recon.proxy_tools import get_proxy_tools

        return get_proxy_tools()
    except ImportError:
        return []


def _get_webcrypto_tools() -> list[Any]:
    try:
        from .recon.webcrypto_hooks import get_webcrypto_tools

        return get_webcrypto_tools()
    except ImportError:
        return []


def _get_auth_recorder_tools() -> list[Any]:
    try:
        from .recon.auth_recorder import get_auth_recorder_tools

        return get_auth_recorder_tools()
    except ImportError:
        return []


def _get_mitm_tools() -> list[Any]:
    try:
        from .recon.mitm_proxy import get_mitm_tools

        return get_mitm_tools()
    except ImportError:
        return []


def _get_crypto_tools() -> list[Any]:
    try:
        from .crypto.srp_tools import get_srp_tools

        return get_srp_tools()
    except ImportError:
        return []


def _get_timing_tools() -> list[Any]:
    try:
        from .crypto.timing_tools import get_timing_tools

        return get_timing_tools()
    except ImportError:
        return []


def _get_kdf_tools() -> list[Any]:
    try:
        from .crypto.kdf_tools import get_kdf_tools

        return get_kdf_tools()
    except ImportError:
        return []


def _get_vault_tools() -> list[Any]:
    try:
        from .crypto.vault_tools import get_vault_tools

        return get_vault_tools()
    except ImportError:
        return []


def _get_credential_tools() -> list[Any]:
    try:
        from .crypto.credential_tools import get_credential_tools

        return get_credential_tools()
    except ImportError:
        return []


def _get_mycelium_tools() -> list[Any]:
    try:
        from .crypto.mycelium_tools import get_mycelium_tools

        return get_mycelium_tools()
    except ImportError:
        return []


def _get_recovery_tools() -> list[Any]:
    try:
        from .crypto.recovery_tools import get_recovery_tools

        return get_recovery_tools()
    except ImportError:
        return []


def _get_session_tools() -> list[Any]:
    try:
        from .recon.session_tools import get_session_tools

        return get_session_tools()
    except ImportError:
        return []


def _get_bundle_tools() -> list[Any]:
    try:
        from .recon.bundle_tools import get_bundle_tools

        return get_bundle_tools()
    except ImportError:
        return []


def _get_cc_tools() -> list[Any]:
    try:
        from .recon.cc_tools import get_cc_tools

        return get_cc_tools()
    except ImportError:
        return []


def _get_tls_tools() -> list[Any]:
    try:
        from .scan.tls_tools import get_tls_tools

        return get_tls_tools()
    except ImportError:
        return []


def _get_cve_tools() -> list[Any]:
    try:
        from .data.cve_tools import get_cve_tools

        return get_cve_tools()
    except ImportError:
        return []


def _get_analysis_tools() -> list[Any]:
    try:
        from .data.analysis_tools import analyze_source, clone_and_analyze, trace_taint_flows

        return [analyze_source, clone_and_analyze, trace_taint_flows]
    except ImportError:
        return []


def get_all_tools() -> list[Any]:
    """Return all built-in agent tools."""
    from .data.knowledge_tools import query_knowledge_graph
    from .data.memory_tools import recall_target_history, search_knowledge, store_knowledge
    from .exploit.exploit_search import get_exploit_search_tools
    from .exploit.exploit_tools import (
        crack_password,
        enumerate_privesc,
        exploit_vulnerability,
        metasploit_exploit,
        metasploit_list_sessions,
        metasploit_run_command,
    )
    from .exploit.payload_tools import get_payload_tools
    from .meta.ot_tools import get_ot_tools
    from .meta.remediation_tools import get_remediation_tools
    from .meta.reporting_tools import generate_report, query_scan_history, save_report, search_cves
    from .meta.sourcehunt_tools import get_sourcehunt_tools
    from .meta.utility_tools import calculate_severity, validate_target
    from .meta.wargame_tools import get_wargame_tools
    from .ops.dynamic_tool_creator import create_custom_tool, list_custom_tools
    from .ops.kali_docker_tool import kali_cleanup, kali_execute, kali_install_tool, kali_setup
    from .ops.mcp_tools import get_mcp_tools
    from .ops.parrot_docker_tool import (
        parrot_cleanup,
        parrot_execute,
        parrot_install_tool,
        parrot_setup,
    )
    from .ops.skill_tools import load_skills
    from .ops.windows_tools import (
        run_mimikatz,
        run_powerup,
        run_psexec,
        run_secretsdump,
        run_smbexec,
        run_winpeas,
    )
    from .recon.pivot_tools import get_pivot_tools
    from .scan.enumeration_tools import (
        run_arjun,
        run_dalfox,
        run_enum4linux,
        run_ffuf,
        run_gobuster,
        run_hydra,
        run_httpx,
        run_jwt_tool,
        run_nikto,
        run_nmap_scan,
        run_nosqlmap,
        run_oscanner,
        run_snmpwalk,
        run_sqlmap,
        run_sqlmate,
        run_sqlninja,
        run_sqlsus,
        run_whatweb,
    )
    from .scan.redteam_tools import run_bloodhound, run_chisel, run_crackmapexec
    from .scan.cloud_tools import (
        run_aws_ec2_enum,
        run_aws_iam_escalation,
        run_aws_lambda_enum,
        run_aws_metadata_exploit,
        run_aws_s3_enum,
        run_aws_secrets_enum,
        run_gcp_bucket_enum,
        run_gcp_cloudfunction_enum,
        run_gcp_iam_audit,
        run_gcp_metadata_exploit,
        run_gcp_secrets_enum,
    )
    from .scan.llm_security_tools import (
        run_adversarial_vision_tester,
        run_agent_escape_tester,
        run_bias_detector,
        run_indirect_prompt_injection,
        run_jailbreak_tester,
        run_model_consistency_tester,
        run_multi_turn_poisoning,
        run_pii_extraction_tester,
        run_prompt_injection_scanner,
        run_system_prompt_extraction,
        run_token_smuggling_tester,
        run_tool_poisoning_tester,
        run_training_data_extraction,
        run_toxicity_regression_tester,
    )
    from .scan.api_testing_tools import (
        run_2fa_bypass_tester,
        run_cors_misconfig_tester,
        run_graphqlmap,
        run_grpcurl,
        run_idor_scanner,
        run_race_condition_tester,
        run_swagger_abuse,
        run_wsprobe,
    )
    from .scan.cicd_tools import (
        run_checkov,
        run_dependency_audit,
        run_gitleaks,
        run_kube_hunter,
        run_semgrep,
        run_trivy,
        run_trufflehog,
    )
    from .scan.proxy_tools import (
        run_burp,
        run_burp_intruder,
        run_owaspzap,
        run_zap_api_scan,
    )
    from .scan.network_wireless_mobile_tools import (
        run_netdiscover,
        run_masscan,
        run_arp_scan,
        run_traceroute,
        run_aircrack_ng,
        run_airodump_ng,
        run_wifite,
        run_reaver,
        run_bully,
        run_frida,
        run_objection,
        run_mobsf,
        run_apktool,
        run_jadx,
        run_drozer,
        run_bettercap_bluetooth,
        run_ubertooth,
        run_firmwalker,
        run_binwalk,
    )
    from .scan.ics_osint_hw_tools import (
        run_modbus_scan,
        run_s7_scan,
        run_dnp3_scan,
        run_ethernet_ip_scan,
        run_bacnet_scan,
        run_ics_fuzzer,
        run_theharvester,
        run_maltego,
        run_social_engineer_toolkit,
        run_gophish,
        run_osint_framework,
        run_chipwhisperer,
        run_jtag_enum,
    )
    from .scan.scanner_tools import detect_os, detect_services, scan_ports, scan_vulnerabilities

    tools = [
        scan_ports,
        detect_services,
        scan_vulnerabilities,
        detect_os,
        run_nmap_scan,
        run_gobuster,
        run_ffuf,
        run_httpx,
        run_sqlmap,
        run_arjun,
        run_dalfox,
        run_jwt_tool,
        run_enum4linux,
        run_nikto,
        run_hydra,
        run_snmpwalk,
        run_whatweb,
        run_nosqlmap,
        run_oscanner,
        run_sqlninja,
        run_sqlsus,
        run_sqlmate,
        exploit_vulnerability,
        enumerate_privesc,
        crack_password,
        metasploit_exploit,
        metasploit_list_sessions,
        metasploit_run_command,
        run_chisel,
        run_crackmapexec,
        run_bloodhound,
        run_gcp_bucket_enum,
        run_gcp_metadata_exploit,
        run_gcp_iam_audit,
        run_gcp_secrets_enum,
        run_gcp_cloudfunction_enum,
        run_aws_s3_enum,
        run_aws_ec2_enum,
        run_aws_metadata_exploit,
        run_aws_secrets_enum,
        run_aws_lambda_enum,
        run_aws_iam_escalation,
        run_prompt_injection_scanner,
        run_jailbreak_tester,
        run_indirect_prompt_injection,
        run_system_prompt_extraction,
        run_training_data_extraction,
        run_pii_extraction_tester,
        run_model_consistency_tester,
        run_toxicity_regression_tester,
        run_bias_detector,
        run_agent_escape_tester,
        run_tool_poisoning_tester,
        run_multi_turn_poisoning,
        run_token_smuggling_tester,
        run_adversarial_vision_tester,
        run_graphqlmap,
        run_grpcurl,
        run_wsprobe,
        run_idor_scanner,
        run_race_condition_tester,
        run_swagger_abuse,
        run_2fa_bypass_tester,
        run_cors_misconfig_tester,
        run_gitleaks,
        run_trufflehog,
        run_checkov,
        run_trivy,
        run_semgrep,
        run_dependency_audit,
        run_kube_hunter,
        run_burp,
        run_burp_intruder,
        run_owaspzap,
        run_zap_api_scan,
        run_netdiscover,
        run_masscan,
        run_arp_scan,
        run_traceroute,
        run_aircrack_ng,
        run_airodump_ng,
        run_wifite,
        run_reaver,
        run_bully,
        run_frida,
        run_objection,
        run_mobsf,
        run_apktool,
        run_jadx,
        run_drozer,
        run_bettercap_bluetooth,
        run_ubertooth,
        run_firmwalker,
        run_binwalk,
        run_modbus_scan,
        run_s7_scan,
        run_dnp3_scan,
        run_ethernet_ip_scan,
        run_bacnet_scan,
        run_ics_fuzzer,
        run_theharvester,
        run_maltego,
        run_social_engineer_toolkit,
        run_gophish,
        run_osint_framework,
        run_chipwhisperer,
        run_jtag_enum,
        kali_setup,
        kali_execute,
        kali_install_tool,
        kali_cleanup,
        parrot_setup,
        parrot_execute,
        parrot_install_tool,
        parrot_cleanup,
        generate_report,
        save_report,
        query_scan_history,
        search_cves,
        validate_target,
        calculate_severity,
        create_custom_tool,
        list_custom_tools,
        recall_target_history,
        store_knowledge,
        search_knowledge,
        load_skills,
        run_mimikatz,
        run_powerup,
        run_psexec,
        run_secretsdump,
        run_smbexec,
        run_winpeas,
        query_knowledge_graph,
    ]

    tools.extend(_get_browser_tools())
    tools.extend(_get_proxy_tools())
    tools.extend(_get_webcrypto_tools())
    tools.extend(_get_auth_recorder_tools())
    tools.extend(_get_mitm_tools())
    tools.extend(_get_crypto_tools())
    tools.extend(_get_timing_tools())
    tools.extend(_get_kdf_tools())
    tools.extend(_get_vault_tools())
    tools.extend(_get_credential_tools())
    tools.extend(_get_mycelium_tools())
    tools.extend(_get_recovery_tools())
    tools.extend(_get_session_tools())
    tools.extend(_get_bundle_tools())
    tools.extend(_get_cc_tools())
    tools.extend(_get_tls_tools())
    tools.extend(_get_cve_tools())
    tools.extend(_get_analysis_tools())
    tools.extend(get_mcp_tools())
    tools.extend(get_exploit_search_tools())
    tools.extend(get_pivot_tools())
    tools.extend(get_remediation_tools())
    tools.extend(get_wargame_tools())
    tools.extend(get_payload_tools())
    tools.extend(get_ot_tools())
    tools.extend(get_sourcehunt_tools())

    return tools


__all__ = ["get_all_tools", "get_custom_tools"]
