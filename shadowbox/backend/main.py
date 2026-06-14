"""
ShadowBox — Consequence Visualization Engine
FastAPI application entry point.
"""
import os
import sys
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from database.db import init_db
from api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    print("=" * 60)
    print("  ShadowBox - Consequence Visualization Engine")
    print("  Starting up...")
    print("=" * 60)

    # Initialize database
    await init_db()

    # Create upload directory
    upload_dir = os.getenv("UPLOAD_DIR", "./uploads")
    os.makedirs(upload_dir, exist_ok=True)
    print(f"[INIT] Upload directory: {os.path.abspath(upload_dir)}")

    # Check Docker availability
    try:
        import docker
        client = docker.from_env()
        client.ping()
        print("[INIT] Docker: [OK] Connected")
    except Exception as e:
        print(f"[INIT] Docker: [WARN] Not available ({e})")
        print("[INIT]   -> Mock sandbox will be used for analysis")

    # Check LLM provider
    llm_provider = os.getenv("LLM_PROVIDER", "fallback")
    print(f"[INIT] LLM Provider: {llm_provider}")

    print("=" * 60)
    print("  Ready. Swagger UI -> http://127.0.0.1:8000/docs")
    print("=" * 60)

    yield

    print("[ShadowBox] Shutting down.")


# ── App Configuration ────────────────────────────────────────────────────────

app = FastAPI(
    title="ShadowBox API",
    description="Consequence Visualization Engine — Execute, analyze, and explain untrusted files.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow dashboard and extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(router)


# ── Health Check ─────────────────────────────────────────────────────────────

@app.get("/", tags=["health"])
async def health_check():
    return {
        "status": "online",
        "service": "ShadowBox",
        "version": "1.0.0",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
