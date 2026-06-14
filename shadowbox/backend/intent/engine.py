"""
ShadowBox — Intent Engine
Rule-based scoring for behavioral intent classification.
No machine learning. Pure deterministic rules.
"""
import re


def classify_intents(telemetry: dict) -> list:
    """
    Classify telemetry into intent categories with scores.
    Each category is normalized to 0-100.
    """
    processes = telemetry.get("processes", [])
    network = telemetry.get("network", [])
    files = telemetry.get("files", [])
    persistence = telemetry.get("persistence", [])

    # Flatten all commands for pattern matching
    all_commands = " ".join([p.get("command", "") for p in processes]).lower()
    all_file_paths = " ".join([f.get("path", "") for f in files]).lower()
    all_domains = " ".join([n.get("domain", "") for n in network if n.get("domain")]).lower()

    intents = [
        _score_downloader(all_commands, network),
        _score_persistence(all_commands, persistence),
        _score_credential_theft(all_commands, all_file_paths, files),
        _score_tracking(all_domains, network),
        _score_remote_control(all_commands, network),
    ]

    return intents


def _score_downloader(all_commands: str, network: list) -> dict:
    """Detect download behavior."""
    score = 0
    reasons = []

    if "curl " in all_commands or "curl\t" in all_commands:
        score += 40
        reasons.append("curl command detected — downloads remote content")

    if "wget " in all_commands or "wget\t" in all_commands:
        score += 40
        reasons.append("wget command detected — downloads remote content")

    # Check for other download indicators
    if any(kw in all_commands for kw in ["fetch", "requests.get", "urllib", "httplib", "http.client"]):
        score += 20
        reasons.append("Remote fetch operation detected in code")

    if len(network) > 0 and score == 0:
        score += 20
        reasons.append("Network connections detected (potential remote fetch)")

    return {
        "category": "downloader",
        "score": min(100, score),
        "reasons": reasons
    }


def _score_persistence(all_commands: str, persistence: list) -> dict:
    """Detect persistence mechanisms."""
    score = 0
    reasons = []

    # Direct persistence indicators from telemetry
    for p in persistence:
        p_type = p.get("type", "")
        if p_type == "cron":
            score += 50
            reasons.append(f"Cron job modification detected: {p.get('detail', '')[:80]}")
        elif p_type in ("bashrc", "profile"):
            score += 50
            reasons.append(f"Startup script modification ({p_type}): {p.get('detail', '')[:80]}")
        elif p_type == "systemd":
            score += 50
            reasons.append(f"Systemd service modification: {p.get('detail', '')[:80]}")
        elif p_type == "boot":
            score += 40
            reasons.append(f"Boot persistence: {p.get('detail', '')[:80]}")

    # Command-based detection
    if "crontab" in all_commands:
        if score == 0:  # Don't double-count
            score += 50
            reasons.append("crontab command executed")

    if any(kw in all_commands for kw in ["systemctl enable", "update-rc.d", "chkconfig"]):
        score += 50
        reasons.append("System service registration detected")

    if ".bashrc" in all_commands or ".bash_profile" in all_commands or ".profile" in all_commands:
        if not any("bashrc" in r or "profile" in r for r in reasons):
            score += 50
            reasons.append("Shell startup file modification detected")

    return {
        "category": "persistence",
        "score": min(100, score),
        "reasons": reasons
    }


def _score_credential_theft(all_commands: str, all_file_paths: str, files: list) -> dict:
    """Detect credential theft indicators."""
    score = 0
    reasons = []

    # Browser data paths
    browser_paths = [
        ".mozilla/firefox", ".config/google-chrome", ".config/chromium",
        "local/google/chrome", "appdata/local/google"
    ]
    for bp in browser_paths:
        if bp in all_file_paths or bp in all_commands:
            score += 30
            reasons.append(f"Browser data directory accessed: {bp}")
            break

    # Cookie files
    cookie_indicators = ["cookies", "cookie", "login data", "web data", "history"]
    for ci in cookie_indicators:
        if ci in all_file_paths or ci in all_commands:
            score += 40
            reasons.append(f"Cookie/login database file accessed: {ci}")
            break

    # SSH keys
    ssh_indicators = [".ssh/", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts"]
    for si in ssh_indicators:
        if si in all_file_paths or si in all_commands:
            score += 30
            reasons.append(f"SSH credential file accessed: {si}")
            break

    # Password files
    if any(kw in all_commands or kw in all_file_paths for kw in ["/etc/shadow", "passwd", "credentials", "keychain"]):
        score += 40
        reasons.append("System password/credential file accessed")

    return {
        "category": "credential_theft",
        "score": min(100, score),
        "reasons": reasons
    }


def _score_tracking(all_domains: str, network: list) -> dict:
    """Detect analytics/tracking behavior."""
    score = 0
    reasons = []

    analytics_domains = [
        "google-analytics", "analytics", "tracking", "telemetry",
        "doubleclick", "facebook.com/tr", "pixel", "hotjar",
        "mixpanel", "amplitude", "segment.io", "sentry.io"
    ]

    for domain in analytics_domains:
        if domain in all_domains:
            score += 20
            reasons.append(f"Analytics/tracking endpoint detected: {domain}")

    # Telemetry-like outbound connections
    if len(network) > 3:
        score += 20
        reasons.append(f"Multiple outbound connections ({len(network)}) suggest telemetry/beaconing")

    return {
        "category": "tracking",
        "score": min(100, score),
        "reasons": reasons
    }


def _score_remote_control(all_commands: str, network: list) -> dict:
    """Detect remote control / C2 behavior."""
    score = 0
    reasons = []

    # Reverse shell patterns
    shell_patterns = [
        r"bash\s+-i\s+>&\s+/dev/tcp",
        r"nc\s+.*-e\s+/bin/(ba)?sh",
        r"python.*socket.*connect",
        r"perl.*socket.*INET",
        r"ruby.*TCPSocket",
        r"socat.*exec",
        r"mkfifo.*nc",
        r"/dev/tcp/",
    ]

    for pattern in shell_patterns:
        if re.search(pattern, all_commands):
            score += 50
            reasons.append(f"Reverse shell pattern detected")
            break

    # Continuous outbound connections
    if len(network) >= 5:
        score += 50
        reasons.append(f"Continuous outbound connections ({len(network)}) — potential C2 channel")
    elif len(network) >= 2:
        score += 20
        reasons.append(f"Multiple outbound connections ({len(network)})")

    # Known C2 tools
    c2_tools = ["meterpreter", "cobalt", "empire", "sliver", "metasploit", "ncat", "pwncat"]
    for tool in c2_tools:
        if tool in all_commands:
            score += 50
            reasons.append(f"Known C2 framework detected: {tool}")

    return {
        "category": "remote_control",
        "score": min(100, score),
        "reasons": reasons
    }
