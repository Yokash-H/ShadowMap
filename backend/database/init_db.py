import sqlite3
import os
import json

def init_db():
    db_path = os.path.join(os.path.dirname(__file__), 'shadowmap.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Drop old tables to allow schema upgrades cleanly
    cursor.execute('DROP TABLE IF EXISTS breach_records')
    cursor.execute('DROP TABLE IF EXISTS risk_events')
    cursor.execute('DROP TABLE IF EXISTS user_profile')
    cursor.execute('DROP TABLE IF EXISTS chat_sessions')
    cursor.execute('DROP TABLE IF EXISTS scan_history')
    cursor.execute('DROP TABLE IF EXISTS firewall_incidents')

    # --- risk_events ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS risk_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT,
      domain TEXT,
      risk_score INTEGER,
      risk_level TEXT,
      reasons TEXT,
      scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # --- breach_records (enriched schema) ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS breach_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      source TEXT,
      severity TEXT,
      data_exposed TEXT,
      breach_date TEXT,
      recommendation TEXT,
      detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # --- user_profile ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_profile (
      id INTEGER PRIMARY KEY,
      shadow_score INTEGER DEFAULT 50,
      total_scans INTEGER DEFAULT 0,
      high_risk_visits INTEGER DEFAULT 0,
      last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # --- chat_sessions ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chat_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      role TEXT,
      content TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # --- scan_history ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT,
      shadow_score INTEGER,
      threat_level TEXT,
      scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # --- firewall_incidents ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS firewall_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT,
      risk_score INTEGER,
      action_taken TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Seed user_profile
    cursor.execute('INSERT INTO user_profile (id, shadow_score) VALUES (1, 50)')

    # Seed breach_records — rich demo data
    breaches = [
        # test@example.com — 2 breaches for demo
        (
            'test@example.com', 'LinkedIn', 'HIGH',
            json.dumps(['email', 'password_hash', 'phone_number', 'location']),
            '2024-02-14',
            'Change your LinkedIn password immediately and enable two-factor authentication.'
        ),
        (
            'test@example.com', 'Adobe Creative Cloud', 'MEDIUM',
            json.dumps(['email', 'username', 'encrypted_password']),
            '2023-09-05',
            'Update your Adobe account password. Enable MFA on all Adobe services.'
        ),

        # victim@phishing.com — 3 breaches
        (
            'victim@phishing.com', 'RockYou2024', 'CRITICAL',
            json.dumps(['email', 'plaintext_password', 'ssn', 'credit_card']),
            '2024-07-04',
            'URGENT: Your plaintext password was exposed. Change all passwords immediately. Monitor for identity theft.'
        ),
        (
            'victim@phishing.com', 'Dropbox', 'HIGH',
            json.dumps(['email', 'password_hash', 'account_token']),
            '2022-08-31',
            'Revoke all Dropbox sessions and reset your password. Check for unauthorized file access.'
        ),
        (
            'victim@phishing.com', 'Twitter / X', 'HIGH',
            json.dumps(['email', 'username', 'phone_number', 'birth_date']),
            '2023-01-05',
            'Change your Twitter/X password and review connected apps for suspicious access.'
        ),

        # user@gmail.com
        (
            'user@gmail.com', 'Canva', 'HIGH',
            json.dumps(['email', 'name', 'password_hash']),
            '2019-05-24',
            'Update your Canva password. Check if same password used elsewhere and change those too.'
        ),

        # Demo fast-fill data
        (
            'admin@shadowmap.ai', 'HaveIBeenPwned Demo', 'MEDIUM',
            json.dumps(['email', 'username']),
            '2023-11-11',
            'Demo account. No action needed.'
        ),
    ]

    cursor.executemany(
        'INSERT INTO breach_records (email, source, severity, data_exposed, breach_date, recommendation) VALUES (?, ?, ?, ?, ?, ?)',
        breaches
    )

    conn.commit()
    conn.close()
    print(f"[ShadowMap] Database initialized at {db_path}")
    print(f"[ShadowMap] Seeded {len(breaches)} breach records across 4 test emails.")

if __name__ == "__main__":
    init_db()
