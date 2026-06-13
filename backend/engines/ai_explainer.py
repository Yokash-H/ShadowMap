import os
import google.generativeai as genai

API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

def generate_explanation(data):
    """
    Phase 7: AI Explainability using Gemini.
    Returns explanation exactly in the requested format.
    """
    domain = data.get('domain', 'Unknown')
    shadow_score = data.get('shadow_score', 0)
    threat_level = data.get('threat_level', 'UNKNOWN')
    reasons = data.get('reasons', [])
    
    # Format fallback first
    bullet_reasons = "\n".join([f"• {r}" for r in reasons]) if reasons else "• No immediate threats detected"
    
    if threat_level in ['CRITICAL', 'DANGEROUS']:
        rec = "Immediately close the tab and do not enter passwords."
    elif threat_level == 'SUSPICIOUS':
        rec = "Exercise caution. Check for HTTPS and avoid submitting personal forms."
    else:
        rec = "Site appears safe for normal browsing."

    fallback_text = f"ShadowMap AI analyzed {domain}\n\nShadowScore: {shadow_score} ({threat_level})\n\nFindings:\n{bullet_reasons}\n\nRecommendation:\n{rec}"
    
    if not API_KEY:
        return fallback_text

    prompt = f"""
    You are ShadowMap AI, a cybersecurity intelligence agent.
    You just analyzed the domain "{domain}".
    ShadowScore: {shadow_score}/100
    Threat Level: {threat_level}
    Technical Reasons/Flags: {', '.join(reasons)}
    
    Write an explanation exactly matching this format:

    ShadowMap AI analyzed {domain}

    ShadowScore: {shadow_score} ({threat_level})

    Findings:
    • [finding 1]
    • [finding 2]
    • [finding 3]

    Recommendation:
    [Concise 1-sentence security recommendation]
    """

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        text = response.text.strip()
        if "ShadowScore:" in text and "Findings:" in text:
            return text
        return fallback_text
    except Exception as e:
        print(f"Gemini Explanation Error: {e}")
        return fallback_text

def generate_recommendation(risk_level, reasons):
    if risk_level in ['CRITICAL', 'DANGEROUS']:
        return ["Immediately close the tab", "Do not enter passwords", "Report this domain"]
    if risk_level == 'SUSPICIOUS':
        return ["Check for HTTPS", "Avoid submitting personal forms", "Clear site cookies after visit"]
    return ["Site is safe for normal use"]
