const API_BASE = '/api';

export interface AnalysisListItem {
  id: string;
  filename: string;
  file_type: string;
  file_size: number;
  status: string;
  risk_score: number;
  risk_level: string;
  created_at: string;
  completed_at: string | null;
}

export interface TelemetryProcess {
  pid: number;
  ppid: number;
  command: string;
}

export interface TelemetryNetwork {
  domain: string | null;
  ip: string;
  port: number;
  protocol: string;
}

export interface TelemetryFile {
  path: string;
  operation: string;
}

export interface TelemetryPersistence {
  type: string;
  detail: string;
}

export interface TelemetryReport {
  processes: TelemetryProcess[];
  network: TelemetryNetwork[];
  files: TelemetryFile[];
  persistence: TelemetryPersistence[];
}

export interface IntentScore {
  category: string;
  score: number;
  reasons: string[];
}

export interface ConsequenceItem {
  observation: string;
  consequence: string;
  severity: string;
}

export interface AttackChainNode {
  id: string;
  label: string;
  type: string;
}

export interface AttackChainEdge {
  from: string;
  to: string;
}

export interface AttackChain {
  nodes: AttackChainNode[];
  edges: AttackChainEdge[];
}

export interface NarrativeResponse {
  summary: string;
  provider: string;
}

export interface AnalysisResult {
  id: string;
  filename: string;
  file_type: string;
  file_size: number;
  file_hash: string | null;
  status: string;
  risk_score: number;
  risk_level: string;
  created_at: string;
  completed_at: string | null;
  error_message: string | null;
  telemetry: TelemetryReport;
  intents: IntentScore[];
  consequences: ConsequenceItem[];
  attack_chain: AttackChain;
  narrative: NarrativeResponse | null;
}

export async function uploadFile(file: File): Promise<{ analysis_id: string }> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/analyze`, { method: 'POST', body: formData });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Upload failed');
  }
  return res.json();
}

export async function getAnalysis(id: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE}/analysis/${id}`);
  if (!res.ok) throw new Error('Analysis not found');
  return res.json();
}

export async function listAnalyses(): Promise<AnalysisListItem[]> {
  const res = await fetch(`${API_BASE}/analyses`);
  if (!res.ok) throw new Error('Failed to fetch');
  return res.json();
}

export async function deleteAnalysis(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/analysis/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Delete failed');
}
