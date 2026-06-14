"""
ShadowBox — AI Narrator
Generates human-readable explanations of analysis results.
Supports: Gemini, Ollama, deterministic fallback.
"""
import os
import json
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "fallback")


async def generate_narrative(
    filename: str,
    file_type: str,
    intents: list,
    consequences: list,
    telemetry: dict,
) -> tuple[str, str]:
    """
    Generate a human-readable narrative about the analysis.
    Returns (narrative_text, provider_name).
    """
    context = _build_context(filename, file_type, intents, consequences, telemetry)

    if LLM_PROVIDER == "gemini":
        try:
            return await _generate_gemini(context), "gemini"
        except Exception as e:
            print(f"[NARRATOR] Gemini failed: {e}. Using fallback.")
            return _generate_fallback(filename, intents, consequences, telemetry), "fallback"
    elif LLM_PROVIDER == "ollama":
        try:
            return await _generate_ollama(context), "ollama"
        except Exception as e:
            print(f"[NARRATOR] Ollama failed: {e}. Using fallback.")
            return _generate_fallback(filename, intents, consequences, telemetry), "fallback"
    else:
        return _generate_fallback(filename, intents, consequences, telemetry), "fallback"


def _build_context(filename: str, file_type: str, intents: list, consequences: list, telemetry: dict) -> str:
    """Build structured context for the LLM prompt."""
    intent_summary = "\n".join([
        f"  - {i['category']}: {i['score']}/100 ({', '.join(i.get('reasons', [])[:2])})"
        for i in intents if i['score'] > 0
    ]) or "  No significant intents detected."

    consequence_summary = "\n".join([
        f"  - [{c['severity']}] {c['consequence']}"
        for c in consequences
    ]) or "  No consequences generated."

    process_count = len(telemetry.get("processes", []))
    network_count = len(telemetry.get("network", []))
    file_count = len(telemetry.get("files", []))
    persistence_count = len(telemetry.get("persistence", []))

    return f"""You are a cybersecurity analyst explaining what a suspicious file does to a non-technical user.

FILE: {filename} (type: {file_type})

BEHAVIORAL INTENTS:
{intent_summary}

CONSEQUENCES:
{consequence_summary}

TELEMETRY SUMMARY:
  - Processes spawned: {process_count}
  - Network connections: {network_count}
  - File operations: {file_count}
  - Persistence mechanisms: {persistence_count}

INSTRUCTIONS:
Write a 3-5 sentence explanation of what this file would do if executed.
Use plain English. No jargon. Explain the risk like you're explaining it to your parent.
Focus on CONSEQUENCES, not technical details.
Start with "This file..." and explain what happens step by step."""


async def _generate_gemini(context: str) -> str:
    """Generate narrative using Google Gemini."""
    import google.generativeai as genai

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash")
    response = model.generate_content(context)
    return response.text.strip()


async def _generate_ollama(context: str) -> str:
    """Generate narrative using local Ollama instance."""
    import httpx

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            f"{base_url}/api/generate",
            json={
                "model": "llama3.2",
                "prompt": context,
                "stream": False,
            }
        )
        response.raise_for_status()
        return response.json()["response"].strip()


def _generate_fallback(filename: str, intents: list, consequences: list, telemetry: dict) -> str:
    """Generate deterministic narrative without any LLM."""
    parts = [f"This file ({filename})"]

    # Describe highest-scoring intent
    high_intents = sorted(
        [i for i in intents if i["score"] > 0],
        key=lambda x: x["score"],
        reverse=True
    )

    if not high_intents:
        return f"This file ({filename}) appears to perform standard operations with no detected malicious behavior. It does not download external content, modify system files, or establish network connections. The file is likely safe for normal use."

    top = high_intents[0]
    intent_descriptions = {
        "downloader": "attempts to download content from the internet",
        "persistence": "tries to install itself permanently on your system",
        "credential_theft": "attempts to access your saved passwords and credentials",
        "tracking": "sends tracking data to external analytics services",
        "remote_control": "opens a hidden connection allowing remote control of your machine",
    }
    parts.append(intent_descriptions.get(top["category"], "performs suspicious operations"))
    parts[0] = parts[0] + " " + parts.pop()

    # Add critical consequences
    critical = [c for c in consequences if c["severity"] in ("CRITICAL", "HIGH")]
    if critical:
        parts.append(". Specifically, it " + critical[0]["consequence"].lower())
        if len(critical) > 1:
            parts.append(", and it " + critical[1]["consequence"].lower())

    # Network summary
    network_count = len(telemetry.get("network", []))
    if network_count > 0:
        domains = [n.get("domain", n.get("ip", "unknown")) for n in telemetry.get("network", [])]
        parts.append(f". It connects to {network_count} external server(s)")
        if domains and domains[0]:
            parts.append(f" including {domains[0]}")

    # Final risk assessment
    max_score = max((i["score"] for i in intents), default=0)
    if max_score >= 70:
        parts.append(". This file is highly dangerous and should NOT be executed under any circumstances.")
    elif max_score >= 40:
        parts.append(". This file shows suspicious behavior and should be treated with extreme caution.")
    else:
        parts.append(". While not overtly malicious, this file warrants careful review before execution.")

    return "".join(parts)
