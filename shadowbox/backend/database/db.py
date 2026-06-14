"""
ShadowBox — Database Layer
SQLite async connection manager and schema initialization.
"""
import aiosqlite
import os
import json
from datetime import datetime

DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "shadowbox.db"))


async def get_db() -> aiosqlite.Connection:
    """Get a database connection."""
    db = await aiosqlite.connect(DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    """Initialize the database schema."""
    db = await get_db()
    try:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                file_hash TEXT,
                status TEXT DEFAULT 'pending',
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'safe',
                created_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                category TEXT NOT NULL,
                data TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS intents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                category TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                reasons TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS consequences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                observation TEXT NOT NULL,
                consequence TEXT NOT NULL,
                severity TEXT DEFAULT 'LOW',
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                chain_data TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS narratives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL UNIQUE,
                summary TEXT NOT NULL,
                provider TEXT DEFAULT 'fallback',
                generated_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );
        """)
        await db.commit()
        print("[ShadowBox DB] Schema initialized successfully.")
    finally:
        await db.close()


# ── CRUD Helpers ─────────────────────────────────────────────────────────────

async def create_analysis(analysis_id: str, filename: str, file_type: str, file_size: int, file_hash: str) -> dict:
    db = await get_db()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        await db.execute(
            "INSERT INTO analyses (id, filename, file_type, file_size, file_hash, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (analysis_id, filename, file_type, file_size, file_hash, now)
        )
        await db.commit()
        return {"id": analysis_id, "filename": filename, "file_type": file_type, "status": "pending", "created_at": now}
    finally:
        await db.close()


async def update_analysis_status(analysis_id: str, status: str, risk_score: int = 0, risk_level: str = "safe", error_message: str = None):
    db = await get_db()
    try:
        completed_at = datetime.utcnow().isoformat() + "Z" if status in ("completed", "error") else None
        await db.execute(
            "UPDATE analyses SET status=?, risk_score=?, risk_level=?, completed_at=?, error_message=? WHERE id=?",
            (status, risk_score, risk_level, completed_at, error_message, analysis_id)
        )
        await db.commit()
    finally:
        await db.close()


async def get_analysis(analysis_id: str) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        analysis = dict(row)

        # Attach telemetry
        cursor = await db.execute("SELECT category, data FROM telemetry WHERE analysis_id=?", (analysis_id,))
        telemetry_rows = await cursor.fetchall()
        telemetry = {}
        for tr in telemetry_rows:
            telemetry[tr["category"]] = json.loads(tr["data"])
        analysis["telemetry"] = telemetry

        # Attach intents
        cursor = await db.execute("SELECT category, score, reasons FROM intents WHERE analysis_id=?", (analysis_id,))
        intent_rows = await cursor.fetchall()
        analysis["intents"] = [
            {"category": r["category"], "score": r["score"], "reasons": json.loads(r["reasons"]) if r["reasons"] else []}
            for r in intent_rows
        ]

        # Attach consequences
        cursor = await db.execute("SELECT observation, consequence, severity FROM consequences WHERE analysis_id=?", (analysis_id,))
        consequence_rows = await cursor.fetchall()
        analysis["consequences"] = [dict(r) for r in consequence_rows]

        # Attach attack chain
        cursor = await db.execute("SELECT chain_data FROM attack_chains WHERE analysis_id=?", (analysis_id,))
        chain_row = await cursor.fetchone()
        analysis["attack_chain"] = json.loads(chain_row["chain_data"]) if chain_row else {"nodes": [], "edges": []}

        # Attach narrative
        cursor = await db.execute("SELECT summary, provider FROM narratives WHERE analysis_id=?", (analysis_id,))
        narrative_row = await cursor.fetchone()
        analysis["narrative"] = {"summary": narrative_row["summary"], "provider": narrative_row["provider"]} if narrative_row else None

        return analysis
    finally:
        await db.close()


async def list_analyses() -> list:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT id, filename, file_type, file_size, status, risk_score, risk_level, created_at, completed_at FROM analyses ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def delete_analysis(analysis_id: str) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def save_telemetry(analysis_id: str, category: str, data: dict):
    db = await get_db()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        await db.execute(
            "INSERT INTO telemetry (analysis_id, category, data, collected_at) VALUES (?, ?, ?, ?)",
            (analysis_id, category, json.dumps(data), now)
        )
        await db.commit()
    finally:
        await db.close()


async def save_intents(analysis_id: str, intents: list):
    db = await get_db()
    try:
        for intent in intents:
            await db.execute(
                "INSERT INTO intents (analysis_id, category, score, reasons) VALUES (?, ?, ?, ?)",
                (analysis_id, intent["category"], intent["score"], json.dumps(intent.get("reasons", [])))
            )
        await db.commit()
    finally:
        await db.close()


async def save_consequences(analysis_id: str, consequences: list):
    db = await get_db()
    try:
        for c in consequences:
            await db.execute(
                "INSERT INTO consequences (analysis_id, observation, consequence, severity) VALUES (?, ?, ?, ?)",
                (analysis_id, c["observation"], c["consequence"], c["severity"])
            )
        await db.commit()
    finally:
        await db.close()


async def save_attack_chain(analysis_id: str, chain_data: dict):
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO attack_chains (analysis_id, chain_data) VALUES (?, ?)",
            (analysis_id, json.dumps(chain_data))
        )
        await db.commit()
    finally:
        await db.close()


async def save_narrative(analysis_id: str, summary: str, provider: str):
    db = await get_db()
    try:
        now = datetime.utcnow().isoformat() + "Z"
        await db.execute(
            "INSERT OR REPLACE INTO narratives (analysis_id, summary, provider, generated_at) VALUES (?, ?, ?, ?)",
            (analysis_id, summary, provider, now)
        )
        await db.commit()
    finally:
        await db.close()
