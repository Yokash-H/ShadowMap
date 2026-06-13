import sqlite3
import os
import json

def get_db_connection():
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'shadowmap.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_email(email):
    """Legacy simple check — kept for backward compatibility."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT source, severity, data_exposed FROM breach_records WHERE email = ?', (email,))
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "source": row["source"],
                "severity": row["severity"],
                "data_exposed": json.loads(row["data_exposed"])
            } for row in rows
        ]
    except Exception as e:
        print(f"Error checking email {email}: {e}")
        return []

def check_email_full(email: str) -> dict:
    """
    Full structured breach check for the BREACH tab.
    Returns { email, total_breaches, breaches[], highest_severity, overall_recommendation }
    """
    SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT source, severity, data_exposed, breach_date, recommendation
               FROM breach_records WHERE LOWER(email) = LOWER(?)''',
            (email,)
        )
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return {
                "email": email,
                "total_breaches": 0,
                "breaches": [],
                "highest_severity": "NONE",
                "overall_recommendation": "✅ No breaches found. Your email appears clean in our database. Stay vigilant and use unique passwords."
            }

        breaches = []
        highest_rank = 0
        highest_sev = "LOW"

        for row in rows:
            sev = row["severity"]
            rank = SEVERITY_RANK.get(sev, 1)
            if rank > highest_rank:
                highest_rank = rank
                highest_sev = sev

            try:
                data_exposed = json.loads(row["data_exposed"])
            except Exception:
                data_exposed = [row["data_exposed"]]

            breaches.append({
                "source": row["source"],
                "severity": sev,
                "data_exposed": data_exposed,
                "breach_date": row["breach_date"] or "Unknown",
                "recommendation": row["recommendation"] or "Change your password on this service."
            })

        # Sort by severity (worst first)
        breaches.sort(key=lambda b: SEVERITY_RANK.get(b["severity"], 0), reverse=True)

        # Overall recommendation based on highest severity
        if highest_sev == "CRITICAL":
            overall_rec = "🚨 CRITICAL: Your data was severely exposed. Change ALL passwords immediately, enable MFA everywhere, and place a credit freeze."
        elif highest_sev == "HIGH":
            overall_rec = "🔴 HIGH RISK: Change passwords on all affected services immediately. Enable two-factor authentication."
        elif highest_sev == "MEDIUM":
            overall_rec = "🟠 MEDIUM RISK: Update passwords on the listed services and enable MFA where available."
        else:
            overall_rec = "🟡 LOW RISK: Your exposure is minimal. Still update your passwords as a precaution."

        return {
            "email": email,
            "total_breaches": len(breaches),
            "breaches": breaches,
            "highest_severity": highest_sev,
            "overall_recommendation": overall_rec
        }

    except Exception as e:
        print(f"[Breach Checker Error] {email}: {e}")
        return {
            "email": email,
            "total_breaches": 0,
            "breaches": [],
            "highest_severity": "UNKNOWN",
            "overall_recommendation": "Error checking breach database. Please try again."
        }

def get_shadow_score(user_id="default"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT risk_score FROM risk_events ORDER BY scanned_at DESC LIMIT 20')
        scores = [row[0] for row in cursor.fetchall()]
        avg_site_risk = sum(scores) / len(scores) if scores else 0
        breaches = check_email("test@example.com")
        breach_penalty = len(breaches) * 5
        score = 100 - (avg_site_risk * 0.5) - breach_penalty
        score = max(0, min(100, int(score)))
        conn.close()
        return score
    except Exception as e:
        print(f"Error getting shadow score: {e}")
        return 50
