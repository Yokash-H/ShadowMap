"""
ShadowBox — API Routes
REST endpoints for file analysis.
"""
import os
import uuid
import hashlib
import shutil
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException
from database.db import get_analysis, list_analyses, delete_analysis, create_analysis
from models.schemas import AnalysisResponse, AnalysisListItem
from api.pipeline import run_analysis_pipeline

router = APIRouter(prefix="/api", tags=["analysis"])

UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads"))
ALLOWED_EXTENSIONS = {".sh", ".py", ".jar", ".apk"}


@router.post("/analyze", response_model=dict)
async def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Upload a file for behavioral analysis.
    Returns the analysis ID immediately; processing runs in background.
    """
    # Validate file extension
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {ext}. Supported: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Generate analysis ID
    analysis_id = str(uuid.uuid4())

    # Save uploaded file
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(UPLOAD_DIR, f"{analysis_id}{ext}")

    contents = await file.read()
    if ext in (".sh", ".py"):
        contents = contents.replace(b"\r\n", b"\n")

    with open(file_path, "wb") as f:
        f.write(contents)

    # Compute file hash
    file_hash = hashlib.sha256(contents).hexdigest()
    file_size = len(contents)

    # Create analysis record
    await create_analysis(analysis_id, filename, ext, file_size, file_hash)

    # Launch background pipeline
    background_tasks.add_task(run_analysis_pipeline, analysis_id, file_path, ext)

    return {
        "status": "accepted",
        "analysis_id": analysis_id,
        "message": f"Analysis started for {filename}"
    }


@router.get("/analysis/{analysis_id}")
async def get_analysis_result(analysis_id: str):
    """Get the full analysis result including telemetry, intents, consequences, etc."""
    result = await get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


@router.get("/analyses", response_model=list[AnalysisListItem])
async def get_all_analyses():
    """List all analyses, most recent first."""
    return await list_analyses()


@router.delete("/analysis/{analysis_id}")
async def remove_analysis(analysis_id: str):
    """Delete an analysis and its associated data."""
    deleted = await delete_analysis(analysis_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Clean up uploaded file
    for ext in ALLOWED_EXTENSIONS:
        path = os.path.join(UPLOAD_DIR, f"{analysis_id}{ext}")
        if os.path.exists(path):
            os.remove(path)

    return {"status": "deleted", "analysis_id": analysis_id}
