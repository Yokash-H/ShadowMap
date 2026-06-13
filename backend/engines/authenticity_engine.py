import os
import json
import google.generativeai as genai
from urllib.parse import urlparse

API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

def analyze_authenticity(url, domain):
    authenticity_score = 100 # Start with high authenticity
    reasons = []

    # 1. Domain Spoofing (Heuristic from phishing_engine, but refined here)
    # This logic is similar to what was in phishing_engine, but now dedicated to authenticity.
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'wallet', 'support', 'auth']
    domain_lower = domain.lower()
    
    # Check verified domains
    verified_domains = ['github.com', 'amazon.in', 'amazon.com', 'google.com', 'roblox.com', 'microsoft.com', 'apple.com']
    is_verified = domain_lower in verified_domains

    if not is_verified:
        if any(keyword in domain_lower for keyword in suspicious_keywords):
            authenticity_score -= 20
            reasons.append("Domain contains suspicious keywords often used in spoofing.")
    
    # Check domain length (long domains often used in phishing)
    if len(domain_lower) > 20:
        authenticity_score -= 10
        reasons.append("Domain is unusually long, a common phishing tactic.")
        
    if domain_lower.count('-') > 1:
        authenticity_score -= 15
        reasons.append("Multiple hyphens in domain, often used to mimic legitimate sites.")
        
    parsed_url = urlparse(url)
    if parsed_url.netloc and parsed_url.netloc != domain:
        authenticity_score -= 30
        reasons.append("URL's network location does not match the extracted domain.")
        
    # Extra penalty for IP-based domains
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        authenticity_score -= 40
        reasons.append("IP address used instead of a human-readable domain name.")

    # 2. Brand Match (Gemini)
    if API_KEY:
        try:
            # More specific prompt for brand impersonation
            prompt = f"""
            Analyze the domain '{domain}' and the full URL '{url}'.
            Is this domain attempting to impersonate a well-known brand or service?
            Consider typosquatting, deceptive subdomains, and brand-related keywords.
            
            Return ONLY a valid JSON object with EXACTLY these fields:
            - impersonation_probability (int 0-100): Probability of impersonation.
            - brand_match_reason (string): A concise reason for the probability.
            """
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:-3]
            elif text.startswith("```"):
                text = text[3:-3]
            ai_result = json.loads(text)
            
            impersonation_probability = ai_result.get("impersonation_probability", 0)
            brand_match_reason = ai_result.get("brand_match_reason", "AI analysis completed.")

            if impersonation_probability > 70:
                authenticity_score -= 30
                reasons.append(f"High AI-detected brand impersonation ({impersonation_probability}%): {brand_match_reason}")
            elif impersonation_probability > 30:
                authenticity_score -= 15
                reasons.append(f"Moderate AI-detected brand impersonation ({impersonation_probability}%): {brand_match_reason}")
            else:
                reasons.append(f"Low AI-detected brand impersonation ({impersonation_probability}%): {brand_match_reason}")

        except Exception as e:
            print(f"Gemini Authenticity Engine Error: {e}")
            reasons.append("AI Brand Match analysis failed due to an error.")
    else:
        reasons.append("AI Brand Match analysis skipped (API key not set).")

    final_authenticity_score = max(0, min(100, authenticity_score))

    return {
        "authenticity_score": final_authenticity_score,
        "reasons": reasons
    }
