"""
email_engine.py — PhishGuard AI
Analyzes raw email/SMS text for phishing indicators using Gemini + heuristics.
"""
import os
import re
import json
import google.generativeai as genai
from transformers import pipeline

# Pre-load the offline NLP model
try:
    nlp_sentiment = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
except:
    nlp_sentiment = None

API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

# ── Heuristic keyword sets ──────────────────────────────────────────────────
URGENCY_PATTERNS = [
    r'urgent', r'immediately', r'act now', r'within 24 hours', r'account suspended',
    r'verify now', r'limited time', r'expires today', r'last chance', r'final notice',
    r'your account (will be|has been) (suspended|closed|locked|terminated|hacked)',
    r'unusual (activity|login|sign-in)', r'security alert', r'confirm your identity',
]

CRITICAL_PATTERNS = [
    r'hacked', r'compromised', r'stolen', r'breach'
]

REWARD_PATTERNS = [
    r'congratulations', r'you (have been|are) selected', r'winner', r'prize', r'reward',
    r'free (gift|iphone|trip|voucher)', r'claim your', r'\$\d+', r'cash prize',
    r'lottery', r'sweepstakes',
]

CREDENTIAL_PATTERNS = [
    r'enter your (password|credentials|login|account details)',
    r'verify your (account|email|identity|information)',
    r'update (billing|payment|credit card)', r'confirm (card|bank) (details|information)',
    r'social security', r'ssn', r'date of birth', r'mother\'s maiden name',
]

SPOOFING_PATTERNS = [
    r'paypal', r'amazon', r'apple', r'microsoft', r'google', r'netflix', r'bank of america',
    r'irs', r'fbi', r'dhl', r'fedex', r'ups', r'your bank',
]

SUSPICIOUS_LINK_PATTERNS = [
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
    r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co',       # URL shorteners
    r'click here', r'login here', r'verify here',
]


def heuristic_analyze(text: str) -> dict:
    """Fast rule-based analysis — runs whether or not Gemini is available."""
    text_lower = text.lower()
    indicators = []
    score = 0

    def check_patterns(patterns, label, weight):
        nonlocal score
        for p in patterns:
            if re.search(p, text_lower):
                indicator = f"{label}: '{p.strip()}' pattern detected"
                if indicator not in indicators:
                    indicators.append(label)
                    score += weight
                break  # one hit per category is enough

    check_patterns(URGENCY_PATTERNS,   "⚠ Urgency manipulation detected",        25)
    check_patterns(REWARD_PATTERNS,    "🎁 Fake reward / prize bait detected",    20)
    check_patterns(CREDENTIAL_PATTERNS,"🔑 Credential harvesting language found", 30)
    check_patterns(SPOOFING_PATTERNS,  "🏢 Brand impersonation detected",         20)
    check_patterns(SUSPICIOUS_LINK_PATTERNS, "🔗 Suspicious link pattern found",  15)
    check_patterns(CRITICAL_PATTERNS,  "🚨 CRITICAL: Hack/Breach language detected", 85)

    # Length heuristic — very short texts with links are suspicious
    if len(text) < 200 and re.search(r'https?://', text_lower):
        score += 10
        indicators.append("📏 Short message with embedded link")
        
    # Advanced NLP Sentiment Analysis Check
    if nlp_sentiment:
        try:
            sentiment_result = nlp_sentiment(text[:512])[0]
            if sentiment_result['label'] == 'NEGATIVE' and sentiment_result['score'] > 0.90:
                score += 85
                indicators.append(f"🧠 NLP AI detected extreme negative urgency/threat (Score: {sentiment_result['score']:.2f})")
        except Exception:
            pass

    prob = min(score, 100)

    if prob >= 70:
        classification = "PHISHING"
    elif prob >= 40:
        classification = "SUSPICIOUS"
    elif prob >= 15:
        classification = "LOW_RISK"
    else:
        classification = "SAFE"

    eli12 = (
        f"This message looks {'dangerous' if prob >= 70 else 'suspicious' if prob >= 40 else 'mostly OK'}. "
        f"I found {len(indicators)} warning sign(s). "
        f"{'Do NOT click any links or enter your info!' if prob >= 40 else 'Still be cautious with any links.'}"
    )

    return {
        "phishing_probability": prob,
        "classification": classification,
        "indicators": indicators,
        "eli12_explanation": eli12,
        "engine": "heuristic"
    }


def analyze_email(text: str) -> dict:
    """
    Main entry point. Tries Gemini first, falls back to heuristics.
    Returns: { phishing_probability, classification, indicators[], eli12_explanation }
    """
    if not text or not text.strip():
        return {
            "phishing_probability": 0,
            "classification": "SAFE",
            "indicators": [],
            "eli12_explanation": "No text provided to analyze.",
            "engine": "none"
        }

    heuristic = heuristic_analyze(text)

    api_key = os.getenv("GEMINI_API_KEY")
    # Google API keys typically start with AIzaSy. If it's an OAuth token (like AQ.Ab...), force fallback
    if not api_key or not api_key.startswith("AIzaSy"):
        return heuristic
    
    genai.configure(api_key=api_key)

    prompt = f"""You are ShadowMap PhishGuard AI — a cybersecurity expert analyzing potentially malicious messages.

Analyze the following email/SMS text for phishing indicators:

---
{text[:3000]}
---

Respond ONLY in this exact JSON format (no markdown, no extra text):
{{
  "phishing_probability": <integer 0-100>,
  "classification": "<PHISHING | SUSPICIOUS | LOW_RISK | SAFE>",
  "indicators": ["<indicator 1>", "<indicator 2>", ...],
  "eli12_explanation": "<2-3 sentence plain English explanation a 12-year-old can understand>"
}}

Rules:
- phishing_probability: 0 = definitely safe, 100 = definitely phishing
- indicators: list all specific red flags you found (urgency, fake rewards, credential theft, brand spoofing, suspicious links, grammar issues etc.)
- eli12_explanation: explain what's suspicious in simple words, no jargon
- Be accurate and specific — don't just say "suspicious language", name what you found
"""

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        raw = response.text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = re.sub(r'^```[a-z]*\n?', '', raw)
            raw = re.sub(r'\n?```$', '', raw)
        result = json.loads(raw)
        result["engine"] = "gemini"
        return result
    except Exception as e:
        print(f"[PhishGuard Gemini Error]: {e}")
        heuristic["engine"] = "heuristic_fallback"
        return heuristic
