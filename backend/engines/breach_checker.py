import sqlite3
import os
import json

def get_db_connection():
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'shadowmap.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_email(email):
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

def get_shadow_score(user_id="default"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Simple calculation logic
        # Average of recent risk scores + breach penalty
        cursor.execute('SELECT risk_score FROM risk_events ORDER BY scanned_at DESC LIMIT 20')
        scores = [row[0] for row in cursor.fetchall()]
        
        avg_site_risk = sum(scores) / len(scores) if scores else 0
        
        # Mock breaches for default user (test@example.com)
        breaches = check_email("test@example.com")
        breach_penalty = len(breaches) * 5
        
        # Start from 100 and subtract risks
        score = 100 - (avg_site_risk * 0.5) - breach_penalty
        score = max(0, min(100, int(score)))
        
        conn.close()
        return score
    except Exception as e:
        print(f"Error getting shadow score: {e}")
        return 50
