"""
ShadowBox — Consequence Engine
Translates telemetry observations into human-readable impact statements.
"""


# ── Consequence Mapping Rules ────────────────────────────────────────────────

CONSEQUENCE_RULES = [
    # Persistence
    {
        "check": lambda t: any(p.get("type") == "cron" for p in t.get("persistence", [])),
        "observation": "Cron job created or modified",
        "consequence": "This file survives reboot — it will run again automatically on a schedule",
        "severity": "HIGH",
    },
    {
        "check": lambda t: any(p.get("type") in ("bashrc", "profile") for p in t.get("persistence", [])),
        "observation": "Shell startup script modified",
        "consequence": "Code will execute every time you open a terminal session",
        "severity": "HIGH",
    },
    {
        "check": lambda t: any(p.get("type") == "systemd" for p in t.get("persistence", [])),
        "observation": "Systemd service registered",
        "consequence": "A background service will start automatically on every boot",
        "severity": "CRITICAL",
    },
    {
        "check": lambda t: any(p.get("type") == "boot" for p in t.get("persistence", [])),
        "observation": "Boot persistence detected",
        "consequence": "This app auto-starts when the device powers on",
        "severity": "HIGH",
    },

    # Network / Downloads
    {
        "check": lambda t: any(
            "curl" in p.get("command", "") or "wget" in p.get("command", "")
            for p in t.get("processes", [])
        ),
        "observation": "Remote download command executed",
        "consequence": "Downloads additional software from the internet — payload could be anything",
        "severity": "HIGH",
    },
    {
        "check": lambda t: len(t.get("network", [])) >= 5,
        "observation": "Multiple sustained outbound connections",
        "consequence": "Opens a remote control channel to an external server (potential backdoor)",
        "severity": "CRITICAL",
    },
    {
        "check": lambda t: 1 <= len(t.get("network", [])) < 5,
        "observation": "Outbound network connection established",
        "consequence": "Communicates with external servers — data may be sent out",
        "severity": "MEDIUM",
    },

    # Credential Access
    {
        "check": lambda t: any(
            any(bp in f.get("path", "").lower() for bp in [".mozilla", "google-chrome", "chromium"])
            for f in t.get("files", [])
        ),
        "observation": "Browser data directory accessed",
        "consequence": "Your saved passwords, history, and cookies may be exposed",
        "severity": "CRITICAL",
    },
    {
        "check": lambda t: any(
            any(kw in f.get("path", "").lower() for kw in ["cookie", "login data", "web data"])
            for f in t.get("files", [])
        ),
        "observation": "Browser cookie/login database accessed",
        "consequence": "Session tokens and saved credentials could be stolen",
        "severity": "CRITICAL",
    },
    {
        "check": lambda t: any(
            any(kw in f.get("path", "").lower() for kw in [".ssh", "id_rsa", "id_ed25519", "authorized_keys"])
            for f in t.get("files", [])
        ),
        "observation": "SSH keys accessed",
        "consequence": "Your server access credentials could be compromised — attacker gains remote server access",
        "severity": "CRITICAL",
    },

    # File System
    {
        "check": lambda t: any(f.get("operation") == "deleted" for f in t.get("files", [])),
        "observation": "Files deleted from disk",
        "consequence": "Data on your system may be permanently removed (potential data destruction or evidence tampering)",
        "severity": "MEDIUM",
    },
    {
        "check": lambda t: any(
            "chmod" in p.get("command", "") and "+x" in p.get("command", "")
            for p in t.get("processes", [])
        ),
        "observation": "File permissions changed to executable",
        "consequence": "Downloaded content is being prepared for execution",
        "severity": "MEDIUM",
    },

    # Process behavior
    {
        "check": lambda t: any(
            any(kw in p.get("command", "").lower() for kw in ["/dev/tcp", "reverse", "meterpreter", "nc -e"])
            for p in t.get("processes", [])
        ),
        "observation": "Reverse shell pattern detected",
        "consequence": "An attacker can remotely control your machine through a hidden connection",
        "severity": "CRITICAL",
    },
]


def generate_consequences(telemetry: dict) -> list:
    """
    Evaluate all consequence rules against telemetry.
    Returns a list of triggered consequences with severity levels.
    """
    consequences = []

    for rule in CONSEQUENCE_RULES:
        try:
            if rule["check"](telemetry):
                consequences.append({
                    "observation": rule["observation"],
                    "consequence": rule["consequence"],
                    "severity": rule["severity"],
                })
        except Exception as e:
            print(f"[CONSEQUENCE ENGINE] Rule evaluation error: {e}")
            continue

    # If no consequences found, add a baseline
    if not consequences:
        consequences.append({
            "observation": "No high-risk behaviors detected",
            "consequence": "File appears to perform standard operations with no immediate threat indicators",
            "severity": "LOW",
        })

    return consequences
