"""
apk_engine.py — APK Shield AI
Analyzes Android app permissions for risk using Gemini + heuristics.
"""
import os
import re
import json
import google.generativeai as genai

API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

# ── Known dangerous permissions and their risk weights ──────────────────────
PERMISSION_RISK = {
    # Critical — direct privacy/security invasion
    "READ_SMS": {"weight": 35, "reason": "Can read your private SMS messages and OTP codes"},
    "RECEIVE_SMS": {"weight": 30, "reason": "Can intercept incoming SMS messages"},
    "SEND_SMS": {"weight": 30, "reason": "Can send SMS without your knowledge (premium SMS fraud)"},
    "RECORD_AUDIO": {"weight": 35, "reason": "Can secretly record audio at any time"},
    "CAMERA": {"weight": 25, "reason": "Can take photos/videos without user action"},
    "READ_CONTACTS": {"weight": 20, "reason": "Harvests your entire contacts database"},
    "ACCESS_FINE_LOCATION": {"weight": 25, "reason": "Tracks your precise GPS location"},
    "ACCESS_BACKGROUND_LOCATION": {"weight": 35, "reason": "Tracks location even when app is closed"},
    "READ_CALL_LOG": {"weight": 25, "reason": "Accesses your full call history"},
    "PROCESS_OUTGOING_CALLS": {"weight": 30, "reason": "Can intercept or redirect your calls"},
    "GET_ACCOUNTS": {"weight": 20, "reason": "Lists all Google/email accounts on device"},
    "USE_CREDENTIALS": {"weight": 30, "reason": "Can authenticate using stored account credentials"},
    "READ_EXTERNAL_STORAGE": {"weight": 10, "reason": "Reads files from device storage"},
    "WRITE_EXTERNAL_STORAGE": {"weight": 10, "reason": "Can write/delete files on device"},
    "INSTALL_PACKAGES": {"weight": 40, "reason": "Can silently install other apps on device"},
    "DELETE_PACKAGES": {"weight": 25, "reason": "Can uninstall apps, including security apps"},
    "BIND_ACCESSIBILITY_SERVICE": {"weight": 40, "reason": "Can read screen content and simulate taps (used in banking trojans)"},
    "BIND_DEVICE_ADMIN": {"weight": 45, "reason": "Full device administrator access — can lock/wipe device"},
    "REQUEST_INSTALL_PACKAGES": {"weight": 35, "reason": "Can prompt to install APKs from unknown sources"},
    "DISABLE_KEYGUARD": {"weight": 30, "reason": "Can disable screen lock"},
    "SYSTEM_ALERT_WINDOW": {"weight": 20, "reason": "Can draw overlays over other apps (overlay phishing)"},
    "READ_PHONE_STATE": {"weight": 15, "reason": "Reads device ID, IMEI, and call state"},
    "CHANGE_NETWORK_STATE": {"weight": 15, "reason": "Can change WiFi/network settings"},
    "BLUETOOTH_ADMIN": {"weight": 15, "reason": "Can control Bluetooth connectivity"},
    "NFC": {"weight": 15, "reason": "Can read/write NFC data (payment card skimming risk)"},
    "VIBRATE": {"weight": 0, "reason": "Safe — controls vibration"},
    "INTERNET": {"weight": 5, "reason": "Basic internet access (common but needed)"},
    "ACCESS_NETWORK_STATE": {"weight": 0, "reason": "Safe — checks network availability"},
    "RECEIVE_BOOT_COMPLETED": {"weight": 10, "reason": "Auto-starts when device boots"},
    "WAKE_LOCK": {"weight": 5, "reason": "Prevents device from sleeping"},
    "FOREGROUND_SERVICE": {"weight": 5, "reason": "Runs a visible foreground service"},
    "BILLING": {"weight": 5, "reason": "In-app purchase capability"},
}

# ── Dangerous permission combinations ───────────────────────────────────────
DANGEROUS_COMBOS = [
    (["RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION"],
     "🕵️ Spyware triad: microphone + contacts + location = covert surveillance app"),
    (["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
     "🏦 Banking trojan pattern: SMS interception + accessibility overlay"),
    (["CAMERA", "RECORD_AUDIO", "INTERNET"],
     "📹 Remote surveillance risk: camera + mic + internet upload"),
    (["INSTALL_PACKAGES", "INTERNET"],
     "💀 Dropper malware pattern: can download and install additional malicious apps"),
    (["BIND_DEVICE_ADMIN", "INTERNET"],
     "🔒 Ransomware risk: device admin + internet = remote lock/extortion potential"),
    (["READ_SMS", "GET_ACCOUNTS", "USE_CREDENTIALS"],
     "🔑 Account takeover kit: SMS OTPs + account credentials harvesting"),
    (["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"],
     "🎭 Overlay phishing combo: can fake login screens over banking apps"),
    (["SEND_SMS", "READ_SMS"],
     "💸 Premium SMS fraud: can read OTPs and re-send SMS to premium numbers"),
    (["ACCESS_BACKGROUND_LOCATION", "INTERNET"],
     "🌍 Location stalkerware: tracks you 24/7 and uploads location data"),
    (["REQUEST_INSTALL_PACKAGES", "RECEIVE_BOOT_COMPLETED"],
     "🔄 Persistence dropper: installs malware and survives reboots"),
]


def normalize_permission(p: str) -> str:
    """Normalize a permission string to the bare name."""
    p = p.strip().upper()
    # Handle android.permission.READ_SMS → READ_SMS
    if '.' in p:
        p = p.split('.')[-1]
    return p


def heuristic_analyze_apk(app_name: str, permissions: list) -> dict:
    norm_permissions = [normalize_permission(p) for p in permissions]
    dangerous = []
    safe = []
    total_risk = 0

    for perm in norm_permissions:
        info = PERMISSION_RISK.get(perm)
        if info:
            if info["weight"] >= 20:
                dangerous.append({"permission": perm, "reason": info["reason"], "weight": info["weight"]})
                total_risk += info["weight"]
            elif info["weight"] > 0:
                safe.append({"permission": perm, "reason": info["reason"]})
                total_risk += info["weight"]
            else:
                safe.append({"permission": perm, "reason": info["reason"]})
        else:
            # Unknown permission — low risk flag
            safe.append({"permission": perm, "reason": "Unknown permission — review manually"})

    # Check dangerous combos
    combo_flags = []
    for combo_perms, combo_reason in DANGEROUS_COMBOS:
        if all(p in norm_permissions for p in combo_perms):
            combo_flags.append(combo_reason)
            total_risk += 30  # Combo bonus

    # Normalize risk score 0-100
    risk_score = min(100, total_risk)
    risk_score = max(0, risk_score)

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 35:
        risk_level = "MEDIUM"
    elif risk_score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    # Check if app name vs permissions mismatch
    suspicious_combos_for_name = []
    low_permission_apps = ["calculator", "flashlight", "clock", "stopwatch", "timer", "compass", "unit converter"]
    if any(kw in app_name.lower() for kw in low_permission_apps):
        if any(p["permission"] in ["RECORD_AUDIO", "READ_SMS", "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS"] for p in dangerous):
            suspicious_combos_for_name.append(
                f"⚠ '{app_name}' is a simple utility app but requests high-risk permissions — typical trojan behavior"
            )

    all_flags = combo_flags + suspicious_combos_for_name

    eli12 = (
        f"This app called '{app_name}' is {'REALLY dangerous' if risk_score >= 70 else 'somewhat risky' if risk_score >= 35 else 'mostly safe'}. "
        f"It wants {len(dangerous)} dangerous permission(s) that could let it spy on you. "
        f"{'Do NOT install this app!' if risk_score >= 70 else 'Be careful before installing.' if risk_score >= 35 else 'Looks fairly normal.'}"
    )

    return {
        "app_name": app_name,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "dangerous_permissions": dangerous,
        "safe_permissions": safe,
        "combo_flags": all_flags,
        "explanation": eli12,
        "engine": "heuristic"
    }


def analyze_apk(app_name: str, permissions_str: str) -> dict:
    """
    Main entry point.
    permissions_str: comma-separated list e.g. "READ_SMS, CAMERA, INTERNET"
    """
    permissions = [p.strip() for p in permissions_str.split(',') if p.strip()]

    if not permissions:
        return {
            "app_name": app_name,
            "risk_score": 0,
            "risk_level": "SAFE",
            "dangerous_permissions": [],
            "safe_permissions": [],
            "combo_flags": [],
            "explanation": "No permissions provided.",
            "engine": "none"
        }

    heuristic = heuristic_analyze_apk(app_name, permissions)

    if not API_KEY:
        return heuristic

    perm_list = ', '.join([normalize_permission(p) for p in permissions])

    prompt = f"""You are ShadowMap APK Shield AI — an Android security expert.

App Name: "{app_name}"
Requested Permissions: {perm_list}

Analyze these permissions for security risks. Respond ONLY in this exact JSON format (no markdown):
{{
  "risk_score": <integer 0-100>,
  "risk_level": "<SAFE | LOW | MEDIUM | HIGH | CRITICAL>",
  "dangerous_permissions": [
    {{"permission": "<PERM_NAME>", "reason": "<why this is dangerous>"}}
  ],
  "safe_permissions": [
    {{"permission": "<PERM_NAME>", "reason": "<why this is ok>"}}
  ],
  "combo_flags": ["<dangerous combination warning 1>", ...],
  "explanation": "<2-3 sentence ELI12 explanation of what this app could do to the user>"
}}

Focus on:
1. Dangerous individual permissions (SMS, microphone, accessibility, device admin, etc.)
2. Suspicious combinations (e.g., calculator + microphone = spyware)
3. App name vs permission mismatch (simple apps with spy-grade permissions)
4. Known malware patterns (banking trojans, ransomware, stalkerware)
"""

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = re.sub(r'^```[a-z]*\n?', '', raw)
            raw = re.sub(r'\n?```$', '', raw)
        result = json.loads(raw)
        result["app_name"] = app_name
        result["engine"] = "gemini"
        return result
    except Exception as e:
        print(f"[APK Shield Gemini Error]: {e}")
        heuristic["engine"] = "heuristic_fallback"
        return heuristic
