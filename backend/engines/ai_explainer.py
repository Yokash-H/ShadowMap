import os


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
    
    return fallback_text

def generate_recommendation(risk_level, reasons):
    if risk_level in ['CRITICAL', 'DANGEROUS']:
        return ["Immediately close the tab", "Do not enter passwords", "Report this domain"]
    if risk_level == 'SUSPICIOUS':
        return ["Check for HTTPS", "Avoid submitting personal forms", "Clear site cookies after visit"]
    return ["Site is safe for normal use"]
