"""
ShadowBox — Pydantic Models
Request/response schemas for the API layer.
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ── Analysis ─────────────────────────────────────────────────────────────────

class AnalysisListItem(BaseModel):
    id: str
    filename: str
    file_type: str
    file_size: int = 0
    status: str = "pending"
    risk_score: int = 0
    risk_level: str = "safe"
    created_at: str
    completed_at: Optional[str] = None


class TelemetryProcess(BaseModel):
    pid: int
    ppid: int
    command: str


class TelemetryNetwork(BaseModel):
    domain: Optional[str] = None
    ip: str
    port: int
    protocol: str = "tcp"


class TelemetryFile(BaseModel):
    path: str
    operation: str  # created, modified, deleted


class TelemetryPersistence(BaseModel):
    type: str  # cron, bashrc, profile, systemd
    detail: str


class TelemetryReport(BaseModel):
    processes: list[TelemetryProcess] = []
    network: list[TelemetryNetwork] = []
    files: list[TelemetryFile] = []
    persistence: list[TelemetryPersistence] = []


class IntentScore(BaseModel):
    category: str  # downloader, persistence, credential_theft, tracking, remote_control
    score: int = Field(ge=0, le=100)
    reasons: list[str] = []


class ConsequenceItem(BaseModel):
    observation: str
    consequence: str
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL


class AttackChainNode(BaseModel):
    id: str
    label: str
    type: str  # file, download, file_op, persistence, network, process


class AttackChainEdge(BaseModel):
    source: str = Field(alias="from")
    target: str = Field(alias="to")

    class Config:
        populate_by_name = True


class AttackChain(BaseModel):
    nodes: list[AttackChainNode] = []
    edges: list[AttackChainEdge] = []


class NarrativeResponse(BaseModel):
    summary: str
    provider: str = "fallback"


class AnalysisResponse(BaseModel):
    id: str
    filename: str
    file_type: str
    file_size: int = 0
    file_hash: Optional[str] = None
    status: str = "pending"
    risk_score: int = 0
    risk_level: str = "safe"
    created_at: str
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    telemetry: Optional[TelemetryReport] = None
    intents: list[IntentScore] = []
    consequences: list[ConsequenceItem] = []
    attack_chain: Optional[AttackChain] = None
    narrative: Optional[NarrativeResponse] = None
