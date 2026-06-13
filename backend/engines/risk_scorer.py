import re
from urllib.parse import urlparse

def score_url(url):
    """
    Real-time URL risk scorer (Zero-dependency version).
    """
    if not url or not url.startswith("http"):
        return None

    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Base score
        score = 15
        reasons = []
        
        # Heuristic 1: Check for IP-based URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            score += 40
            reasons.append("IP-based URL")
            
        # Heuristic 2: Check for long URL
        if len(url) > 100:
            score += 15
            reasons.append("Unusually long URL")
            
        # Heuristic 3: Check for phishing keywords
        keywords = ["verify", "login", "update", "secure", "banking", "wallet", "amazon", "netflix"]
        for kw in keywords:
            if kw in url.lower() and kw not in domain.lower():
                score += 15
                reasons.append(f"Suspicious keyword: {kw}")
        
        # Heuristic 4: Check for unusual characters
        if "@" in url or "%%" in url:
            score += 20
            reasons.append("Contains obfuscated characters")

        # Risk Level
        risk_level = "LOW"
        if score > 75: risk_level = "CRITICAL"
        elif score > 50: risk_level = "HIGH"
        elif score > 25: risk_level = "MEDIUM"

        return {
            "url": url,
            "domain": domain,
            "risk_score": min(score, 100),
            "risk_level": risk_level,
            "reasons": reasons if reasons else ["No immediate threats detected"],
            "trust_status": "INSTINCT",
            "ssl_valid": url.startswith("https")
        }
    except Exception as e:
        print(f"Scoring error: {e}")
        return {
            "url": url,
            "domain": "Unknown",
            "risk_score": 10,
            "risk_level": "LOW",
            "reasons": ["Safe default"],
            "trust_status": "UNKNOWN",
            "ssl_valid": True
        }
