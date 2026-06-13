import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

from engines.shadow_score_engine import calculate_shadow_score
from engines.phishing_engine import detect_phishing
from engines.domain_analyzer import extract_domain
from engines.breach_checker import check_email, get_shadow_score
from engines.ai_explainer import generate_explanation, generate_recommendation

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'shadow_secret'
CORS(app, resources={r"/*": {"origins": "*"}})

# Force 127.0.0.1 to avoid IPv6 issues
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'shadowmap.db')

current_context = {
    "url": "https://google.com",
    "title": "Google",
    "risk_cache": None,
    "updated_at": datetime.now().isoformat()
}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "context": current_context})

@app.route('/api/cache/url', methods=['POST'])
def cache_url():
    global current_context
    data = request.json
    url = data.get('url')
    print(f"[TELEMETRY RECEIVED]: {url}")
    
    risk_score = 0
    current_context = {
        "url": url,
        "title": data.get('title'),
        "risk_cache": risk_score,
        "updated_at": datetime.now().isoformat()
    }
    
    socketio.emit('context_update', current_context)
    return jsonify({"status": "success"})

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

    result = calculate_shadow_score(url, payload, phishing_data)

    if not result:
        return None

    result["ai_explanation"] = generate_explanation(result)

    result["recommended_actions"] = generate_recommendation(
        result.get("threat_level", "UNKNOWN"),
        result.get("reasons", [])
    )

    print("========== FINAL RESULT ==========")
    print(json.dumps(result, indent=2))
    print("==================================")

    socketio.emit("scan_result", result)

    print("[SCAN COMPLETE & BROADCASTED]")

    return result

@socketio.on('connect')
def handle_connect():
    print('[ELECTRON APP CONNECTED]')
    emit('context_update', current_context)

@socketio.on('trigger_full_scan')
def handle_full_scan_socket(data):
    print("[F4 SOCKET TRIGGER RECEIVED]")
    perform_full_scan(current_context['url'])

if __name__ == '__main__':
    print("[ShadowMap Backend starting on http://127.0.0.1:5000]")
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)
