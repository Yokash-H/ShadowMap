from urllib.parse import urlparse
from engines.domain_analyzer import extract_domain, check_https, get_simulated_domain_age, detect_suspicious_patterns

def calculate_shadow_score(url, payload=None, phishing_data=None, trust_score=None, authenticity_score=None, privacy_score=None, threat_score=None, exposure_score=None, behavior_score=None, base_reasons=None):
    if not url:
        return None

    domain = extract_domain(url)
    reasons = list(base_reasons) if base_reasons else []
    
    if payload is None:
        payload = {}
    if phishing_data is None:
        phishing_data = {}
        
    # --- Context-Aware Adjustments Variables ---
    path = urlparse(url).path.lower()
    is_sensitive = any(kw in path for kw in ['login', 'signin', 'admin', 'bank', 'secure', 'billing', 'password'])
    is_auth_page = any(kw in path for kw in ['login', 'signin', 'auth'])

    # --- Derive/Set Category Scores (Temporary/Initial Implementation) ---
    # These will eventually come from dedicated engines

    # Authenticity Score (derived from domain_spoof_probability)
    if authenticity_score is None:
        domain_spoof_probability = float(phishing_data.get("domain_spoof_probability", 0))
        authenticity_score = max(0, 100 - domain_spoof_probability) # Higher spoof prob = lower authenticity
    
    # Threat Score (derived from phishing_probability, credential_risk, redirect_risk)
    if threat_score is None:
        phishing_probability = float(phishing_data.get("phishing_probability", 0))
        credential_risk = float(phishing_data.get("credential_risk", 0))
        redirect_risk = float(phishing_data.get("redirect_risk", 0))
        
        # Simple aggregation for initial threat score
        # Higher risk probabilities = lower threat score (as per 0-100 scale where 100 is good)
        avg_risk = (phishing_probability + credential_risk + redirect_risk) / 3
        threat_score = max(0, 100 - avg_risk)

    # Trust Score (initial: based on HTTPS)
    if trust_score is None:
        trust_score = 70 # Base trust
        if check_https(url):
            trust_score += 30 # Boost for HTTPS
        trust_score = min(100, trust_score)

    # If it's a sensitive page, lower the base scores to be more aggressive
    if is_sensitive:
        trust_score *= 0.9
        reasons.append(f"Sensitive subpage detected ({path}) - elevated monitoring active.")

    # Privacy Score (initial: based on number of trackers)
    if privacy_score is None:
        trackers = payload.get('trackers', [])
        privacy_score = 100 - (len(trackers) * 5) # Deduct 5 points per tracker
        privacy_score = max(0, privacy_score)

    # Exposure Score (placeholder)
    if exposure_score is None:
        exposure_score = 100 # Assume no exposure until engine is built

    # Behavior Score (Heuristic based on on-page elements)
    if behavior_score is None:
        behavior_score = 100
        forms = payload.get('forms', [])
        if forms:
            has_password_form = any(f.get('hasPassword') for f in forms)
            if has_password_form and not check_https(url):
                behavior_score -= 40
                reasons.append("CRITICAL: Password form detected over insecure connection!")
            elif has_password_form and is_auth_page:
                behavior_score -= 10
                reasons.append("Login form context analyzed.")

        if is_sensitive and authenticity_score < 80:
            behavior_score -= 20
            reasons.append("HIGH RISK: Low authenticity on sensitive subpage.")

    # --- Calculate ShadowScore using the new weighted formula ---
    shadow_score = (
        0.20 * trust_score +
        0.20 * authenticity_score +
        0.10 * privacy_score +
        0.30 * threat_score +
        0.10 * exposure_score +
        0.10 * behavior_score
    )
    shadow_score = max(0, min(100, int(shadow_score)))

    # Threat Classification System (New Ranges)
    if shadow_score >= 86:
        threat_level = "TRUSTED"
    elif shadow_score >= 71:
        threat_level = "SAFE"
    elif shadow_score >= 51:
        threat_level = "SUSPICIOUS"
    elif shadow_score >= 31:
        threat_level = "DANGEROUS"
    else:
        threat_level = "CRITICAL"
        
    # For demo fast-paths, if necessary (keep for now)
    if domain == "fake-amazon-login-security.net":
        shadow_score = 18
        threat_level = "CRITICAL"
        reasons.append("Demo Fast-Path: Known malicious domain.")

    if not reasons:
        reasons.append("Initial analysis complete.")

    # Print for debugging
    print(f"Trust Score: {trust_score}")
    print(f"Authenticity Score: {authenticity_score}")
    print(f"Privacy Score: {privacy_score}")
    print(f"Threat Score: {threat_score}")
    print(f"Exposure Score: {exposure_score}")
    print(f"Behavior Score: {behavior_score}")
    print(f"FINAL SHADOW SCORE: {shadow_score} ({threat_level})")

    return {
        "url": url,
        "domain": domain,
        "shadow_score": shadow_score,
        "threat_level": threat_level,
        "risk_score": 100 - shadow_score, # Still provide for compatibility if needed
        "exposure_score_legacy": 100 - shadow_score, # Renamed to avoid confusion with new category
        "trackers_detected": len(payload.get('trackers', [])),
        "reasons": reasons,
        "ssl_valid": check_https(url),
        "category_scores": {
            "trust": int(trust_score),
            "authenticity": int(authenticity_score),
            "privacy": int(privacy_score),
            "threat": int(threat_score),
            "exposure": int(exposure_score),
            "behavior": int(behavior_score),
        },
        "payload": payload
    }
