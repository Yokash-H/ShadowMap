import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import google.generativeai as genai

from engines.shadow_score_engine import calculate_shadow_score
from engines.phishing_engine import detect_phishing
from engines.domain_analyzer import extract_domain
from engines.breach_checker import check_email, get_shadow_score, check_email_full
from engines.trust_engine import analyze_trust
from engines.ai_explainer import generate_explanation
from engines.email_engine import analyze_email
from engines.apk_engine import analyze_apk

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'shadow_secret'
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'shadowmap.db')

# Gemini for chat
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

current_context = {
    "url": "https://google.com",
    "title": "Google",
    "risk_cache": None,
    "updated_at": datetime.now().isoformat()
}

# =============================================================================
# HEALTH
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "context": current_context})

# =============================================================================
# URL TELEMETRY
# =============================================================================

@app.route('/api/cache/url', methods=['POST'])
def cache_url():
    global current_context
    data = request.json
    url = data.get('url')
    print(f"[TELEMETRY RECEIVED]: {url}")
    current_context = {
        "url": url,
        "title": data.get('title'),
        "risk_cache": 0,
        "updated_at": datetime.now().isoformat()
    }
    socketio.emit('context_update', current_context)
    return jsonify({"status": "success"})

# =============================================================================
# TRIGGER SCAN (Tab 1 — SCAN)
# =============================================================================

@app.route('/api/trigger_scan', methods=['POST'])
def trigger_scan_api():
    print("[TRIGGER SCAN REQUESTED]")
    data = request.json or {}
    url = data.get('url') or current_context['url']
    payload = data.get('payload')
    result = perform_full_scan(url, payload)
    if result:
        return jsonify({"status": "success", "result": result})
    return jsonify({"status": "error"})


def perform_full_scan(url, payload=None):
    print(f"[PERFORMING FULL SCAN]: {url}")
    if not url:
        return None

    domain = extract_domain(url)

    try:
        phishing_data = detect_phishing(payload or {}, domain) or {}
    except Exception as e:
        print("[PHISHING ENGINE ERROR]:", e)
        phishing_data = {}

    try:
        trust_analysis_result = analyze_trust(url, domain)
        trust_score = trust_analysis_result.get("trust_score")
        trust_reasons = trust_analysis_result.get("reasons", [])
    except Exception as e:
        print(f"[TRUST ENGINE ERROR]: {e}")
        trust_score = None
        trust_reasons = []

    base_reasons = []
    if trust_reasons:
        base_reasons.extend(trust_reasons)
    
    phish_reason = phishing_data.get("reason", "")
    if phish_reason and phish_reason != "No immediate threats detected.":
        for r in phish_reason.split("."):
            r_clean = r.strip()
            if r_clean:
                base_reasons.append(r_clean)

    result = calculate_shadow_score(
        url,
        payload,
        phishing_data,
        trust_score=trust_score,
        authenticity_score=None,
        privacy_score=None,
        threat_score=None,
        exposure_score=None,
        behavior_score=None,
        base_reasons=base_reasons
    )

    if not result:
        return None

    # ── Re-wire AI Explainer ──────────────────────────────────────────────
    # Merge in phishing data fields for the AI explainer
    enriched = {**result}
    enriched["phishing_probability"] = phishing_data.get("phishing_probability", 0)
    enriched["domain_spoof_probability"] = phishing_data.get("domain_spoof_probability", 0)
    enriched["credential_risk"] = phishing_data.get("credential_risk", 0)
    enriched["redirect_risk"] = phishing_data.get("redirect_risk", 0)
    enriched["exposure_score"] = 100 - result.get("shadow_score", 50)

    try:
        ai_explanation = generate_explanation(enriched)
        enriched["ai_explanation"] = ai_explanation
    except Exception as e:
        print(f"[AI EXPLAINER ERROR]: {e}")
        enriched["ai_explanation"] = f"ShadowMap analyzed {domain}. Score: {result.get('shadow_score', 0)} ({result.get('threat_level', 'UNKNOWN')})"

    print("========== FINAL RESULT ==========")
    print(json.dumps(enriched, indent=2))
    print("==================================")

    # Save to scan_history
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'INSERT INTO scan_history (domain, shadow_score, threat_level) VALUES (?, ?, ?)',
            (domain, enriched.get("shadow_score", 0), enriched.get("threat_level", "UNKNOWN"))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB scan_history Error]: {e}")

    socketio.emit("scan_result", enriched)
    print("[SCAN COMPLETE & BROADCASTED]")
    return enriched

# =============================================================================
# TAB 2 — PHISHGUARD
# =============================================================================

@app.route('/api/phishguard', methods=['POST'])
def phishguard():
    data = request.json or {}
    text = data.get('text', '')
    if not text.strip():
        return jsonify({"status": "error", "message": "No text provided"}), 400
    print(f"[PHISHGUARD] Analyzing text ({len(text)} chars)")
    result = analyze_email(text)
    return jsonify({"status": "success", "result": result})

# =============================================================================
# TAB 3 — APK SHIELD
# =============================================================================

@app.route('/api/apkshield', methods=['POST'])
def apkshield():
    data = request.json or {}
    app_name = data.get('app_name', 'Unknown App').strip()
    permissions_str = data.get('permissions', '').strip()
    if not permissions_str:
        return jsonify({"status": "error", "message": "No permissions provided"}), 400
    print(f"[APK SHIELD] Analyzing '{app_name}' with permissions: {permissions_str[:100]}")
    result = analyze_apk(app_name, permissions_str)
    return jsonify({"status": "success", "result": result})

# =============================================================================
# TAB 4 — BREACH RADAR
# =============================================================================

@app.route('/api/breach', methods=['POST'])
def breach():
    data = request.json or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"status": "error", "message": "No email provided"}), 400
    print(f"[BREACH RADAR] Checking: {email}")
    result = check_email_full(email)
    return jsonify({"status": "success", "result": result})

# =============================================================================
# TAB 5 — SHADOW CHAT
# =============================================================================

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json or {}
    message = data.get('message', '').strip()
    context = data.get('context', {})          # page scan result (optional)
    history = data.get('history', [])          # last N messages [{role, content}]

    if not message:
        return jsonify({"status": "error", "message": "No message provided"}), 400

    print(f"[SHADOW CHAT] User: {message[:80]}")

    # Build context string from current page scan
    ctx_str = ""
    if context:
        domain = context.get('domain', 'unknown domain')
        score = context.get('shadow_score', '?')
        level = context.get('threat_level', 'UNKNOWN')
        ctx_str = f"\nCurrent page context: {domain} (ShadowScore: {score}, Threat: {level})"

    if not GEMINI_API_KEY:
        fallback = (
            "I'm Shadow AI, your cybersecurity copilot! "
            "I'm running in offline mode right now (no API key). "
            "For full AI responses, please add your GEMINI_API_KEY to the .env file. "
            "In the meantime, here's a quick tip: always check that URLs use HTTPS and match the real domain before entering any credentials."
        )
        return jsonify({"status": "success", "reply": fallback})

    # Format conversation history for Gemini
    history_text = ""
    for msg in history[-10:]:  # Last 10 messages
        role = "User" if msg.get("role") == "user" else "Shadow"
        history_text += f"{role}: {msg.get('content', '')}\n"

    prompt = f"""You are Shadow, ShadowMap AI's cybersecurity assistant — expert, friendly, and concise.
You help users understand online threats, privacy risks, phishing, malware, and data breaches.{ctx_str}

Conversation so far:
{history_text}

User: {message}

Shadow: (respond in 2-4 sentences max, be specific and actionable. Use emojis sparingly for clarity.)"""

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        reply = response.text.strip()
        print(f"[SHADOW CHAT] Reply: {reply[:80]}...")
        return jsonify({"status": "success", "reply": reply})
    except Exception as e:
        print(f"[SHADOW CHAT ERROR]: {e}")
        return jsonify({
            "status": "success",
            "reply": "I'm having trouble connecting right now. Please check your API key or try again in a moment."
        })


# =============================================================================
# CREDENTIAL FIREWALL INCIDENT LOGGING
# =============================================================================

@app.route('/api/log_incident', methods=['POST'])
def log_incident():
    data = request.json or {}
    domain = data.get('domain', 'unknown')
    risk_score = data.get('risk_score', 0)
    action_taken = data.get('action', 'blocked')
    
    print(f"[FIREWALL INCIDENT]: Intercepted {domain} (Risk: {risk_score}%, Action: {action_taken})")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'INSERT INTO firewall_incidents (domain, risk_score, action_taken) VALUES (?, ?, ?)',
            (domain, int(risk_score), action_taken)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Incident logged successfully"})
    except Exception as e:
        print(f"[DB firewall_incidents Error]: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# =============================================================================
# SOCKET.IO
# =============================================================================

@socketio.on('connect')
def handle_connect():
    print('[ELECTRON APP CONNECTED]')
    emit('context_update', current_context)

@socketio.on('trigger_full_scan')
def handle_full_scan_socket(data):
    print("[F4 SOCKET TRIGGER RECEIVED]")
    perform_full_scan(current_context['url'])

# =============================================================================
# STARTUP
# =============================================================================

if __name__ == '__main__':
    print("[ShadowMap Backend starting on http://127.0.0.1:5000]")
    print("[Routes] /api/trigger_scan, /api/phishguard, /api/apkshield, /api/breach, /api/chat")
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
