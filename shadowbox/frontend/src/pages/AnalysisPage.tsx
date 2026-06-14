import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { useStore } from '../store';
import AttackReplay from '../components/AttackReplay';

const INTENT_COLORS: Record<string, string> = {
  downloader: '#3b82f6',
  persistence: '#8b5cf6',
  credential_theft: '#ef4444',
  tracking: '#f59e0b',
  remote_control: '#ec4899',
};

const INTENT_LABELS: Record<string, string> = {
  downloader: 'Downloader',
  persistence: 'Persistence',
  credential_theft: 'Credential Theft',
  tracking: 'Tracking',
  remote_control: 'Remote Control',
};

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const { currentAnalysis: analysis, currentLoading, pollAnalysis, stopPolling } = useStore();
  const [showRawTelemetry, setShowRawTelemetry] = useState(false);

  useEffect(() => {
    if (id) pollAnalysis(id);
    return () => stopPolling();
  }, [id, pollAnalysis, stopPolling]);

  if (currentLoading && !analysis) {
    return (
      <div className="loading-state" style={{ minHeight: '60vh' }}>
        <div className="spinner" />
        <span>Loading analysis...</span>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="loading-state" style={{ minHeight: '60vh' }}>
        <div style={{ fontSize: 48 }}>🔍</div>
        <span>Analysis not found</span>
        <Link to="/" className="btn btn-ghost">← Back to Dashboard</Link>
      </div>
    );
  }

  const isRunning = analysis.status === 'running' || analysis.status === 'pending';
  const riskColor = analysis.risk_level === 'safe' ? 'var(--safe)' :
                    analysis.risk_level === 'suspicious' ? 'var(--suspicious)' : 'var(--dangerous)';

  const intentData = (analysis.intents || []).map((i) => ({
    name: INTENT_LABELS[i.category] || i.category,
    score: i.score,
    color: INTENT_COLORS[i.category] || '#6366f1',
    reasons: i.reasons,
  }));

  return (
    <div>
      {/* Back button */}
      <Link to="/" style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        fontSize: 13,
        color: 'var(--text-secondary)',
        marginBottom: 24,
        transition: 'color 0.2s',
      }}>
        ← Back to Dashboard
      </Link>

      {/* ═══ Section 1: Overview ═══════════════════════════════════════════ */}
      <div className="card animate-in" style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <h1 style={{
              fontSize: 24,
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-primary)',
              marginBottom: 8,
            }}>
              {analysis.filename}
            </h1>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="format-tag">{analysis.file_type}</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {formatBytes(analysis.file_size)}
              </span>
              {analysis.file_hash && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  SHA256: {analysis.file_hash.slice(0, 16)}...
                </span>
              )}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span className={`badge badge-${isRunning ? analysis.status : analysis.risk_level}`} style={{ fontSize: 12, padding: '6px 14px' }}>
              {isRunning ? `⏳ ${analysis.status}` : analysis.risk_level?.toUpperCase()}
            </span>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              {new Date(analysis.created_at).toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Loading state for running analyses */}
      {isRunning && (
        <div className="card animate-in" style={{ textAlign: 'center', padding: 48, marginBottom: 24 }}>
          <div className="spinner" style={{ margin: '0 auto 16px' }} />
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)' }}>
            Analyzing {analysis.filename}...
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8 }}>
            ShadowBox is executing this file in a secure sandbox and collecting behavioral telemetry.
            <br />This page will update automatically.
          </div>
        </div>
      )}

      {/* Error state */}
      {analysis.status === 'error' && (
        <div className="card animate-in" style={{
          borderColor: 'rgba(239,68,68,0.3)',
          marginBottom: 24,
        }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span style={{ fontSize: 24 }}>⚠️</span>
            <div>
              <div style={{ fontWeight: 700, color: 'var(--dangerous)', marginBottom: 4 }}>Analysis Error</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                {analysis.error_message || 'An unknown error occurred during analysis.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ Completed Analysis Sections ════════════════════════════════════ */}
      {analysis.status === 'completed' && (
        <>
          {/* ═══ Narrative ════════════════════════════════════════════════ */}
          {analysis.narrative && (
            <div className="narrative-box animate-in animate-in-delay-1" style={{ marginBottom: 24 }}>
              <div className="narrator-label">
                🤖 AI Analysis — {analysis.narrative.provider}
              </div>
              <div className="narrator-text">{analysis.narrative.summary}</div>
            </div>
          )}

          {/* ═══ Risk Score + Intent Grid ═════════════════════════════════ */}
          <div className="section-grid animate-in animate-in-delay-2" style={{ marginBottom: 24 }}>
            {/* Section 2: Risk Score */}
            <div className="card">
              <div className="card-header">
                <span className="icon">🎯</span>
                <h2>Risk Score</h2>
              </div>
              <div className="risk-gauge">
                <div className="score-ring">
                  <svg viewBox="0 0 160 160" style={{ width: '100%', height: '100%' }}>
                    {/* Background circle */}
                    <circle
                      cx="80" cy="80" r="70"
                      fill="none"
                      stroke="rgba(99,102,241,0.08)"
                      strokeWidth="8"
                    />
                    {/* Score arc */}
                    <circle
                      cx="80" cy="80" r="70"
                      fill="none"
                      stroke={riskColor}
                      strokeWidth="8"
                      strokeLinecap="round"
                      strokeDasharray={`${(analysis.risk_score / 100) * 440} 440`}
                      transform="rotate(-90 80 80)"
                      style={{
                        filter: `drop-shadow(0 0 8px ${riskColor})`,
                        transition: 'stroke-dasharray 1s ease',
                      }}
                    />
                  </svg>
                  <div className="score-value">
                    <div className={`score-number ${analysis.risk_level}`}>
                      {analysis.risk_score}
                    </div>
                    <div className="score-label" style={{ color: riskColor }}>
                      {analysis.risk_level}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 3: Intent Analysis */}
            <div className="card">
              <div className="card-header">
                <span className="icon">📊</span>
                <h2>Intent Analysis</h2>
              </div>
              {intentData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={intentData} layout="vertical" margin={{ left: 10, right: 20 }}>
                    <XAxis type="number" domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} />
                    <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} width={110} />
                    <Tooltip
                      contentStyle={{
                        background: '#0d1321',
                        border: '1px solid rgba(99,102,241,0.2)',
                        borderRadius: 8,
                        fontSize: 12,
                        color: '#e2e8f0',
                      }}
                      formatter={(value: any) => [`${value}/100`, 'Score']}
                    />
                    <Bar dataKey="score" radius={[0, 4, 4, 0]} barSize={18}>
                      {intentData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} fillOpacity={0.8} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                  No intent data available
                </div>
              )}

              {/* Intent reasons */}
              <div style={{ marginTop: 16 }}>
                {intentData.filter(i => i.score > 0).map((intent, idx) => (
                  <div key={idx} style={{
                    padding: '8px 12px',
                    marginBottom: 6,
                    borderRadius: 8,
                    background: 'rgba(15,23,42,0.5)',
                    borderLeft: `3px solid ${intent.color}`,
                  }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: intent.color, marginBottom: 2 }}>
                      {intent.name} — {intent.score}/100
                    </div>
                    {intent.reasons.slice(0, 2).map((r, i) => (
                      <div key={i} style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                        • {r}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ═══ Section 4: Consequences ═══════════════════════════════════ */}
          <div className="card animate-in animate-in-delay-3" style={{ marginBottom: 24 }}>
            <div className="card-header">
              <span className="icon">⚡</span>
              <h2>Consequences</h2>
            </div>
            {(analysis.consequences || []).length > 0 ? (
              analysis.consequences.map((c, i) => (
                <div key={i} className="consequence-item">
                  <span className={`badge badge-${c.severity.toLowerCase()}`}>
                    {c.severity}
                  </span>
                  <div className="consequence-text">
                    <div className="observation">{c.observation}</div>
                    <div className="impact">{c.consequence}</div>
                  </div>
                </div>
              ))
            ) : (
              <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                No consequences detected
              </div>
            )}
          </div>

          {/* ═══ Section 5: Attack Replay ═════════════════════════════════ */}
          {analysis.attack_chain && analysis.attack_chain.nodes.length > 0 && (
            <div className="card animate-in animate-in-delay-4" style={{ marginBottom: 24 }}>
              <div className="card-header">
                <span className="icon">🔗</span>
                <h2>Attack Replay</h2>
              </div>
              <div style={{ height: 400, borderRadius: 8, overflow: 'hidden', background: 'var(--bg-input)', border: '1px solid var(--border-default)' }}>
                <AttackReplay chain={analysis.attack_chain} />
              </div>
            </div>
          )}

          {/* ═══ Section 6: Raw Telemetry ═════════════════════════════════ */}
          <div className="card animate-in animate-in-delay-4" style={{ marginBottom: 24 }}>
            <div className="card-header" style={{ cursor: 'pointer' }} onClick={() => setShowRawTelemetry(!showRawTelemetry)}>
              <span className="icon">📋</span>
              <h2>Raw Telemetry</h2>
              <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                {showRawTelemetry ? '▼ Collapse' : '▶ Expand'}
              </span>
            </div>
            {showRawTelemetry && (
              <div className="json-viewer">
                <pre>{JSON.stringify(analysis.telemetry, null, 2)}</pre>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
