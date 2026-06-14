"""
ShadowBox — Analysis Pipeline
Orchestrates the full analysis flow: sandbox → telemetry → intent → consequence → narrator.
"""
import asyncio
import hashlib
import os
import traceback

from database.db import (
    update_analysis_status, save_telemetry, save_intents,
    save_consequences, save_attack_chain, save_narrative
)
from sandbox.orchestrator import run_sandbox
from telemetry.collector import collect_telemetry
from intent.engine import classify_intents
from consequence.engine import generate_consequences
from consequence.attack_chain import build_attack_chain
from narrator.narrator import generate_narrative


async def run_analysis_pipeline(analysis_id: str, file_path: str, file_type: str):
    """
    Execute the full ShadowBox analysis pipeline.
    This runs as a background task after file upload.
    """
    print(f"[PIPELINE] Starting analysis {analysis_id} for {file_path} ({file_type})")

    try:
        # ── Step 1: Update status to running ─────────────────────────────
        await update_analysis_status(analysis_id, "running")

        # ── Step 2: Sandbox Execution ────────────────────────────────────
        print(f"[PIPELINE] Step 2: Sandbox execution")
        sandbox_result = await run_sandbox(file_path, file_type, analysis_id)

        # ── Step 3: Telemetry Collection ─────────────────────────────────
        print(f"[PIPELINE] Step 3: Telemetry collection")
        telemetry = collect_telemetry(sandbox_result, file_type)

        # Save raw telemetry
        for category, data in telemetry.items():
            await save_telemetry(analysis_id, category, data)

        # ── Step 4: Intent Classification ────────────────────────────────
        print(f"[PIPELINE] Step 4: Intent classification")
        intents = classify_intents(telemetry)
        await save_intents(analysis_id, intents)

        # ── Step 5: Consequence Generation ───────────────────────────────
        print(f"[PIPELINE] Step 5: Consequence generation")
        consequences = generate_consequences(telemetry)
        await save_consequences(analysis_id, consequences)

        # ── Step 6: Attack Chain ─────────────────────────────────────────
        print(f"[PIPELINE] Step 6: Attack chain construction")
        attack_chain = build_attack_chain(telemetry, file_path)
        await save_attack_chain(analysis_id, attack_chain)

        # ── Step 7: AI Narrator ──────────────────────────────────────────
        print(f"[PIPELINE] Step 7: AI narration")
        narrative_text, provider = await generate_narrative(
            filename=os.path.basename(file_path),
            file_type=file_type,
            intents=intents,
            consequences=consequences,
            telemetry=telemetry
        )
        await save_narrative(analysis_id, narrative_text, provider)

        # ── Step 8: Risk Score Calculation ───────────────────────────────
        intent_score = max((i["score"] for i in intents), default=0)
        consequence_severity = _severity_score(consequences)
        persistence_score = _persistence_score(telemetry)
        network_score = _network_score(telemetry)

        risk_score = int(
            0.40 * intent_score +
            0.30 * consequence_severity +
            0.20 * persistence_score +
            0.10 * network_score
        )
        risk_score = max(0, min(100, risk_score))

        if risk_score <= 30:
            risk_level = "safe"
        elif risk_score <= 60:
            risk_level = "suspicious"
        else:
            risk_level = "dangerous"

        await update_analysis_status(analysis_id, "completed", risk_score, risk_level)
        print(f"[PIPELINE] Analysis {analysis_id} completed - Risk: {risk_score} ({risk_level})")

    except Exception as e:
        print(f"[PIPELINE ERROR] {analysis_id}: {e}")
        traceback.print_exc()
        await update_analysis_status(analysis_id, "error", error_message=str(e))


def _severity_score(consequences: list) -> int:
    """Convert consequence severities to a 0-100 score."""
    severity_map = {"LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 90}
    if not consequences:
        return 0
    scores = [severity_map.get(c["severity"], 10) for c in consequences]
    return min(100, max(scores))


def _persistence_score(telemetry: dict) -> int:
    """Score based on persistence indicators."""
    persistence = telemetry.get("persistence", [])
    if not persistence:
        return 0
    return min(100, len(persistence) * 40)


def _network_score(telemetry: dict) -> int:
    """Score based on network activity."""
    network = telemetry.get("network", [])
    if not network:
        return 0
    return min(100, len(network) * 20)
