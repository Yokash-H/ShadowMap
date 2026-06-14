import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useStore } from '../store';

export default function UploadPage() {
  const navigate = useNavigate();
  const { upload, uploading, uploadError, analyses, fetchAnalyses, loading } = useStore();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    fetchAnalyses();
  }, [fetchAnalyses]);

  const handleFile = useCallback(async (file: File) => {
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    const allowed = ['.sh', '.py', '.jar', '.apk'];
    if (!allowed.includes(ext)) {
      alert(`Unsupported file type: ${ext}\nSupported: ${allowed.join(', ')}`);
      return;
    }
    try {
      const id = await upload(file);
      navigate(`/analysis/${id}`);
    } catch {
      // uploadError already set in store
    }
  }, [upload, navigate]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  }, [handleFile]);

  return (
    <div>
      {/* Hero Upload Zone */}
      <div
        className={`upload-zone animate-in ${dragOver ? 'drag-over' : ''}`}
        onClick={() => fileInputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".sh,.py,.jar,.apk"
          style={{ display: 'none' }}
          onChange={(e) => {
            if (e.target.files?.[0]) handleFile(e.target.files[0]);
          }}
        />
        {uploading ? (
          <>
            <div className="upload-icon">⏳</div>
            <div className="upload-title">Uploading & Analyzing...</div>
            <div className="upload-subtitle">ShadowBox is executing your file in a secure sandbox</div>
          </>
        ) : (
          <>
            <div className="upload-icon">🔬</div>
            <div className="upload-title">Drop a file to analyze</div>
            <div className="upload-subtitle">
              or click to browse — ShadowBox will show you what it does before you run it
            </div>
            <div className="upload-formats">
              <span className="format-tag">.sh</span>
              <span className="format-tag">.py</span>
              <span className="format-tag">.jar</span>
              <span className="format-tag">.apk</span>
            </div>
          </>
        )}
      </div>

      {uploadError && (
        <div style={{
          marginTop: 16,
          padding: '12px 16px',
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.2)',
          borderRadius: 10,
          color: '#f87171',
          fontSize: 13,
        }}>
          ❌ {uploadError}
        </div>
      )}

      {/* Recent Analyses */}
      <div style={{ marginTop: 48 }} className="animate-in animate-in-delay-2">
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 16,
        }}>
          <h2 style={{
            fontSize: 12,
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '1.5px',
            color: 'var(--text-muted)',
          }}>
            Recent Analyses
          </h2>
          {analyses.length > 0 && (
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {analyses.length} total
            </span>
          )}
        </div>

        {loading ? (
          <div className="loading-state">
            <div className="spinner" />
            <span>Loading analyses...</span>
          </div>
        ) : analyses.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>
            <div style={{ fontSize: 36, marginBottom: 12 }}>📭</div>
            <div style={{ fontSize: 14 }}>No analyses yet. Upload a file to get started.</div>
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table className="analysis-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Type</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((a) => (
                  <tr key={a.id} onClick={() => navigate(`/analysis/${a.id}`)}>
                    <td className="filename">{a.filename}</td>
                    <td>
                      <span className="format-tag" style={{ fontSize: 10 }}>{a.file_type}</span>
                    </td>
                    <td>
                      {a.status === 'completed' ? (
                        <span style={{
                          fontWeight: 800,
                          fontSize: 16,
                          color: a.risk_level === 'safe' ? 'var(--safe)' :
                                 a.risk_level === 'suspicious' ? 'var(--suspicious)' : 'var(--dangerous)'
                        }}>
                          {a.risk_score}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge badge-${a.status === 'completed' ? a.risk_level : a.status}`}>
                        {a.status === 'completed' ? a.risk_level : a.status}
                      </span>
                    </td>
                    <td className="time-col">{formatTime(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  const now = Date.now();
  const diff = Math.floor((now - d.getTime()) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}
