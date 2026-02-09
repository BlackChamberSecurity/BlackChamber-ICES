import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiFetch } from '../api';
import StageCard from '../components/StageCard';
import ObservationBadge from '../components/ObservationBadge';
import StatusBadge from '../components/StatusBadge';

export default function MessageDetail() {
    const { messageId } = useParams();
    const [trip, setTrip] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        loadTrip();
    }, [messageId]);

    async function loadTrip() {
        setLoading(true);
        try {
            const data = await apiFetch(`/messages/${encodeURIComponent(messageId)}`);
            setTrip(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    if (loading) return <div className="page-center"><div className="loading">Loading…</div></div>;
    if (error) return <div className="page-center"><div className="error-banner">{error}</div></div>;
    if (!trip) return null;

    const { ingestion, analysis, verdict } = trip;

    return (
        <div className="detail-page">
            <header className="topbar">
                <div className="topbar-left">
                    <button className="btn-ghost" onClick={() => navigate('/')}>← Back</button>
                    <h1>Message Trip</h1>
                </div>
            </header>

            <div className="trip-pipeline">
                <div className="pipeline-connector" />

                {/* Stage 1: Ingestion */}
                <StageCard stage="ingestion" title="Ingestion" icon="▼" number={1}>
                    <div className="detail-grid">
                        <div className="detail-item">
                            <span className="detail-label">Sender</span>
                            <span className="detail-value">{ingestion.sender || '—'}</span>
                        </div>
                        <div className="detail-item">
                            <span className="detail-label">Recipient</span>
                            <span className="detail-value">{(ingestion.recipients && ingestion.recipients.length > 0) ? ingestion.recipients.join(', ') : '—'}</span>
                        </div>
                        <div className="detail-item">
                            <span className="detail-label">Subject</span>
                            <span className="detail-value">{ingestion.subject || '(no subject)'}</span>
                        </div>
                        <div className="detail-item">
                            <span className="detail-label">Tenant</span>
                            <span className="detail-value">
                                <span className="tenant-badge">{ingestion.tenant_alias || ingestion.tenant_id}</span>
                            </span>
                        </div>
                        <div className="detail-item">
                            <span className="detail-label">User ID</span>
                            <span className="detail-value mono">{ingestion.user_id}</span>
                        </div>
                        <div className="detail-item">
                            <span className="detail-label">Received</span>
                            <span className="detail-value">{formatTime(ingestion.created_at)}</span>
                        </div>
                    </div>
                </StageCard>

                {/* Stage 2: Analysis */}
                <StageCard stage="analysis" title="Analysis" icon="◆" number={2}>
                    {analysis.length === 0 ? (
                        <div className="empty-state">No analysis results yet</div>
                    ) : (
                        <div className="analyzer-cards">
                            {analysis.map((result, i) => (
                                <div key={i} className="analyzer-card">
                                    <div className="analyzer-header">
                                        <span className="analyzer-name">{result.analyzer}</span>
                                        <div className="analyzer-meta">
                                            {result.processing_time_ms > 0 && (
                                                <span className="processing-time">{result.processing_time_ms.toFixed(1)}ms</span>
                                            )}
                                            <span className="observation-count">{result.observations?.length || 0} observations</span>
                                        </div>
                                    </div>
                                    <div className="observations">
                                        {(result.observations || []).map((obs, j) => (
                                            <ObservationBadge key={j} observation={obs} />
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </StageCard>

                {/* Stage 3: Verdict */}
                <StageCard stage="verdict" title="Verdict" icon="■" number={3}>
                    {verdict.length === 0 ? (
                        <div className="verdict-result">
                            <StatusBadge action="none" />
                            <span className="text-muted">No policy rules matched — message is clean</span>
                        </div>
                    ) : (
                        <div className="verdict-list">
                            {verdict.map((v, i) => (
                                <div key={i} className="verdict-item">
                                    <div className="verdict-row">
                                        <span className="verdict-policy">{v.policy_name || 'default'}</span>
                                        <StatusBadge action={v.action_taken} />
                                    </div>
                                    {v.matched_observations && Object.keys(v.matched_observations).length > 0 && (
                                        <div className="matched-details">
                                            <span className="detail-label">Matched:</span>
                                            <code>{JSON.stringify(v.matched_observations, null, 2)}</code>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </StageCard>
            </div>
        </div>
    );
}

function formatTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
}
