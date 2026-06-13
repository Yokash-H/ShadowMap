import whois
from datetime import datetime
import os
import google.generativeai as genai
from engines.domain_analyzer import check_https, extract_domain

API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

def analyze_trust(url, domain):
    trust_score = 0
    reasons = []

    # 1. SSL Check
    if check_https(url):
        trust_score += 20
        reasons.append("HTTPS is enabled (secure connection)")
    else:
        reasons.append("HTTPS is not enabled (insecure connection)")

    # 2. Domain Age Check
    domain_age_score = 0
    try:
        w = whois.whois(domain)
        if w.creation_date:
            # whois.whois can return a list of dates, take the first one
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_in_years = (datetime.now() - creation_date).days / 365
            if age_in_years > 5:
                domain_age_score = 20
                reasons.append(f"Domain is old ({int(age_in_years)} years), indicating stability")
            elif age_in_years > 2:
                domain_age_score = 10
                reasons.append(f"Domain is moderately old ({int(age_in_years)} years)")
            else:
                reasons.append(f"Domain is relatively new ({int(age_in_years)} years), exercise caution")
        else:
            reasons.append("Could not determine domain creation date")
    except Exception as e:
        print(f"WHOIS lookup error for {domain}: {e}")
        reasons.append("WHOIS lookup failed, unable to determine domain age")
    trust_score += domain_age_score

    # 3. Reputation (Placeholder)
    reputation_score = 15 # Default to a neutral score for now
    reasons.append("Reputation check (placeholder): Neutral score")
    trust_score += reputation_score

    # 4. Brand Match (Gemini) - This will contribute to Authenticity, but can also influence Trust
    # For now, let's keep it simple and just add a placeholder.
    # The full Brand Match logic will be part of the Authenticity Engine.
    brand_match_score = 0
    if API_KEY:
        try:
            # This is a simplified placeholder. The actual prompt will be more complex.
            prompt = f"Analyze if the domain '{domain}' is impersonating a well-known brand. Return a JSON object with 'impersonation_probability' (0-100)."
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:-3]
            elif text.startswith("```"):
                text = text[3:-3]
            ai_result = json.loads(text)
            impersonation_probability = ai_result.get("impersonation_probability", 0)
            
            # If high impersonation, reduce trust score
            if impersonation_probability > 70:
                brand_match_score = -20
                reasons.append(f"High probability of brand impersonation detected ({impersonation_probability}%)")
            elif impersonation_probability > 30:
                brand_match_score = -10
                reasons.append(f"Possible brand impersonation detected ({impersonation_probability}%)")
            else:
                brand_match_score = 10
                reasons.append(f"Low probability of brand impersonation ({impersonation_probability}%)")
        except Exception as e:
            print(f"Gemini Brand Match Error: {e}")
            reasons.append("AI Brand Match analysis failed.")
    else:
        reasons.append("AI Brand Match analysis skipped (API key not set).")
    trust_score += brand_match_score


    # Final Trust Score calculation
    final_trust_score = max(0, min(100, trust_score))

    return {
        "trust_score": final_trust_score,
        "reasons": reasons
    }
