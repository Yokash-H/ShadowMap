import whois
from datetime import datetime
import os
import json
from engines.domain_analyzer import check_https, extract_domain

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
    reasons.append("AI Brand Match analysis skipped (Offline Mode).")
    trust_score += brand_match_score


    # Final Trust Score calculation
    final_trust_score = max(0, min(100, trust_score))

    return {
        "trust_score": final_trust_score,
        "reasons": reasons
    }
