import os
import json
import google.generativeai as genai

API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

def detect_phishing(payload, domain):
    """
    Phase 4: Phishing Detection Engine.
    Computes real values from payload characteristics.
    """
    if not payload:
        payload = {}

    url = payload.get('url', '') or domain
    title = payload.get('title', 'Unknown').lower()
    forms = payload.get('forms', [])
    trackers = payload.get('trackers', [])
    
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    is_https = parsed_url.scheme == 'https'
    
    # 1. Credential Risk
    has_password = any(f.get('hasPassword', False) for f in forms)
    # Base noise so it's rarely exactly 0, but very low for normal sites
    credential_risk = 0
    if has_password:
        credential_risk += 15
        if not is_https:
            credential_risk += 50
    elif 'login' in url.lower() or 'signin' in url.lower() or 'auth' in url.lower():
        credential_risk += 35
            
    # 2. Domain Spoof Probability
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'support', 'auth']
    domain_spoof_probability = 0
    domain_lower = domain.lower()
    
    # Check verified domains
    verified_domains = ['github.com', 'amazon.in', 'amazon.com', 'google.com', 'roblox.com', 'microsoft.com', 'apple.com', 'paypal.com']
    is_verified = domain_lower in verified_domains

    # Brand Impersonation check
    brands = {
        'paypal': ['paypal.com'],
        'google': ['google.com', 'google.co.in'],
        'facebook': ['facebook.com'],
        'netflix': ['netflix.com'],
        'amazon': ['amazon.com', 'amazon.in'],
        'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
        'apple': ['apple.com', 'icloud.com'],
        'roblox': ['roblox.com'],
        'steam': ['steampowered.com', 'steamcommunity.com']
    }
    
    brand_spoofed = False
    for brand, leg_domains in brands.items():
        if brand in title or brand in domain_lower:
            if not any(domain_lower.endswith(ld) for ld in leg_domains):
                brand_spoofed = True
                domain_spoof_probability = max(domain_spoof_probability, 85)
                if has_password or 'login' in url.lower() or 'signin' in url.lower():
                    credential_risk = max(credential_risk, 80)

    if not is_verified and not brand_spoofed:
        if any(keyword in domain_lower for keyword in suspicious_keywords):
            domain_spoof_probability += 35
    
    # Check domain length (long domains often used in phishing)
    if len(domain_lower) > 20:
        domain_spoof_probability += 15
        
    if domain_lower.count('-') > 1:
        domain_spoof_probability += 25
        
    if parsed_url.netloc and parsed_url.netloc != domain:
        domain_spoof_probability += 40
        
    domain_spoof_probability = min(100, domain_spoof_probability)
    
    # 3. Redirect Risk
    redirect_risk = 0
    if any(param in url.lower() for param in ['redirect=', 'url=', 'next=', 'goto=', 'return_to=']):
        redirect_risk += 55
        
    redirects = int(payload.get('redirects', 0))
    if redirects > 0:
        redirect_risk += 30 + (redirects * 15)
        
    if payload.get('metaRefresh', False):
        redirect_risk += 45
        
    redirect_risk = min(100, redirect_risk)
    
    # 4. Phishing Probability (Composite)
    phishing_probability = 0
    
    if is_verified:
        # Strict zeroing for verified domains
        credential_risk = min(5, credential_risk)
        domain_spoof_probability = 0
        redirect_risk = min(5, redirect_risk)
    
    phishing_probability += (credential_risk * 0.35) + (domain_spoof_probability * 0.45) + (redirect_risk * 0.2)
    
    if not is_https:
        phishing_probability += 25
        
    # Suspicious if there's a password form but zero tracking/analytics (common in quick phishing clones)
    if len(trackers) == 0 and has_password:
        phishing_probability += 15
        
    # Extra penalty for IP-based domains
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        phishing_probability += 40
        domain_spoof_probability += 30
        
    phishing_probability = min(100, int(phishing_probability))
    credential_risk = min(100, int(credential_risk))
    domain_spoof_probability = min(100, int(domain_spoof_probability))
    redirect_risk = min(100, int(redirect_risk))
    
    reason = "No immediate threats detected."
    if phishing_probability > 40:
        reasons = []
        if credential_risk > 40: reasons.append("Elevated credential risk detected.")
        if domain_spoof_probability > 40: reasons.append("Domain exhibits possible spoofing patterns.")
        if redirect_risk > 40: reasons.append("Suspicious redirects found in URL.")
        if redirects > 0: reasons.append(f"Redirection chain detected ({redirects} redirect(s)).")
        if not is_https: reasons.append("Insecure HTTP connection.")
        if len(trackers) == 0 and has_password: reasons.append("Password field present but no standard site tracking found.")
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): reasons.append("IP address used instead of domain name.")
        reason = " ".join(reasons)
        
    result = {
        "phishing_probability": phishing_probability,
        "domain_spoof_probability": domain_spoof_probability,
        "credential_risk": credential_risk,
        "redirect_risk": redirect_risk,
        "reason": reason
    }
    
    # Enhance with Gemini if API key is present
    if API_KEY:
        prompt = f"""
        Analyze this webpage data for phishing.
        URL: {url}
        Domain: {domain}
        Title: {title}
        Forms: {json.dumps(forms)}
        Trackers: {trackers}
        Is HTTPS: {is_https}
        
        Current calculated heuristic risks:
        Phishing: {phishing_probability}%
        Spoof: {domain_spoof_probability}%
        Credential: {credential_risk}%
        Redirect: {redirect_risk}%
        
        Adjust these scores based on your AI analysis if you see clear threats.
        Return ONLY a valid JSON object with EXACTLY these fields:
        - phishing_probability (int 0-100)
        - domain_spoof_probability (int 0-100)
        - credential_risk (int 0-100)
        - redirect_risk (int 0-100)
        - reason (string, explain your findings clearly)
        """
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:-3]
            elif text.startswith("```"):
                text = text[3:-3]
            ai_result = json.loads(text)
            
            # Validate output keys
            if all(k in ai_result for k in ["phishing_probability", "domain_spoof_probability", "credential_risk", "redirect_risk", "reason"]):
                result = ai_result
        except Exception as e:
            print(f"Gemini Engine Error (fallback to heuristic): {e}")

    print("PHISHING ENGINE OUTPUT:", json.dumps(result, indent=2))
    return result
