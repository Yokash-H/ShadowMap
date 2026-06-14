"""
ShadowBox — Telemetry Collector
Parses sandbox execution output into structured telemetry.
"""
import re
from telemetry.parsers import (
    parse_strace_processes,
    parse_strace_network,
    parse_strace_files,
    parse_persistence_diffs,
)


def collect_telemetry(sandbox_result: dict, file_type: str) -> dict:
    """
    Collect and structure telemetry from sandbox execution results.
    Handles both Docker strace output and mock static analysis output.
    """
    source = sandbox_result.get("source", "unknown")

    if source == "mock":
        return _collect_mock_telemetry(sandbox_result)
    elif source == "apk_static":
        return _collect_apk_telemetry(sandbox_result)
    else:
        return _collect_docker_telemetry(sandbox_result)


def _collect_docker_telemetry(sandbox_result: dict) -> dict:
    """Parse strace output from real Docker execution."""
    strace_log = sandbox_result.get("strace_log", "")

    processes = parse_strace_processes(strace_log)
    network = parse_strace_network(strace_log)
    files = parse_strace_files(strace_log)
    persistence = parse_persistence_diffs(
        sandbox_result.get("crontab_diff", ""),
        sandbox_result.get("bashrc_diff", ""),
        sandbox_result.get("profile_diff", ""),
    )

    return {
        "processes": processes,
        "network": network,
        "files": files,
        "persistence": persistence,
    }


def _collect_mock_telemetry(sandbox_result: dict) -> dict:
    """Use pre-parsed mock telemetry from static analysis."""
    return {
        "processes": sandbox_result.get("mock_processes", []),
        "network": sandbox_result.get("mock_network", []),
        "files": sandbox_result.get("mock_files", []),
        "persistence": sandbox_result.get("mock_persistence", []),
    }


def _collect_apk_telemetry(sandbox_result: dict) -> dict:
    """Extract telemetry from APK static analysis."""
    permissions = sandbox_result.get("apk_permissions", [])
    suspicious = sandbox_result.get("apk_suspicious_files", [])

    processes = []
    network = []
    files = [{"path": f, "operation": "suspicious"} for f in suspicious]
    persistence = []

    # Map dangerous permissions to telemetry indicators
    dangerous_perms = {
        "READ_SMS": {"type": "credential_access", "detail": "App can read SMS (OTP interception)"},
        "SEND_SMS": {"type": "exfiltration", "detail": "App can send SMS (premium fraud)"},
        "CAMERA": {"type": "surveillance", "detail": "App can access camera"},
        "RECORD_AUDIO": {"type": "surveillance", "detail": "App can record audio"},
        "READ_CONTACTS": {"type": "data_harvest", "detail": "App can read contacts"},
        "ACCESS_FINE_LOCATION": {"type": "tracking", "detail": "App tracks precise GPS location"},
        "INTERNET": {"type": "network", "detail": "App has internet access"},
        "RECEIVE_BOOT_COMPLETED": {"type": "persistence", "detail": "App auto-starts on boot"},
    }

    for perm in permissions:
        perm_upper = perm.upper().split(".")[-1]
        if perm_upper in dangerous_perms:
            info = dangerous_perms[perm_upper]
            if info["type"] == "persistence":
                persistence.append({"type": "boot", "detail": info["detail"]})
            elif info["type"] == "network":
                network.append({"domain": "internet_access", "ip": "0.0.0.0", "port": 0, "protocol": "any"})

    return {
        "processes": processes,
        "network": network,
        "files": files,
        "persistence": persistence,
    }
