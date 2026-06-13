import sqlite3
import os
import json

def init_db():
    db_path = os.path.join(os.path.dirname(__file__), 'shadowmap.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create risk_events table
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

    # Create breach_records table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS breach_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      source TEXT,
      severity TEXT,
      data_exposed TEXT,
      detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Create user_profile table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_profile (
      id INTEGER PRIMARY KEY,
      shadow_score INTEGER DEFAULT 50,
      total_scans INTEGER DEFAULT 0,
      high_risk_visits INTEGER DEFAULT 0,
      last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Seed user_profile
    cursor.execute('SELECT COUNT(*) FROM user_profile')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO user_profile (id, shadow_score) VALUES (1, 50)')

    # Seed breach_records
    cursor.execute('SELECT COUNT(*) FROM breach_records')
    if cursor.fetchone()[0] == 0:
        breaches = [
            ('test@example.com', 'LinkedIn 2021', 'HIGH', json.dumps(['email', 'password_hash'])),
            ('test@example.com', 'Adobe 2013', 'MEDIUM', json.dumps(['email', 'username'])),
            ('user@gmail.com', 'Canva 2019', 'HIGH', json.dumps(['email', 'name', 'password'])),
        ]
        # Adding more fake records to reach 20 as per spec
        for i in range(17):
            breaches.append((f'user{i}@example.com', f'Site {i} Breach', 'LOW', json.dumps(['email'])))
            
        cursor.executemany('INSERT INTO breach_records (email, source, severity, data_exposed) VALUES (?, ?, ?, ?)', breaches)

    conn.commit()
    conn.close()
    print(f"Database initialized at {db_path}")

if __name__ == "__main__":
    init_db()
