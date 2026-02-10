import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, clearToken } from '../api';
import StatsCard from '../components/StatsCard';
import StatusBadge from '../components/StatusBadge';

export default function Dashboard() {
    const [messages, setMessages] = useState([]);
    const [stats, setStats] = useState(null);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(0);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();
    const limit = 25;

    useEffect(() => {
        loadData();
    }, [page]);

    async function loadData() {
        setLoading(true);
        try {
            const [msgData, statsData] = await Promise.all([
                apiFetch(`/messages?limit=${limit}&offset=${page * limit}`),
                apiFetch('/stats'),
            ]);
            setMessages(msgData.messages);
            setTotal(msgData.total);
            setStats(statsData);
        } catch (err) {
            console.error('Failed to load data:', err);
        } finally {
            setLoading(false);
        }
    }

    function handleLogout() {
        clearToken();
        navigate('/login', { replace: true });
    }

    const totalPages = Math.ceil(total / limit);

    return (
        <div className="dashboard">
            <header className="topbar">
                <div className="topbar-left">
                    <span className="topbar-icon">◆</span>
                    <h1>BlackChamber ICES</h1>
                </div>
                <div className="topbar-nav">
                    <button className="btn-ghost btn-ghost-active">Dashboard</button>
                    <button className="btn-ghost" onClick={() => navigate('/saas')}>SaaS Usage</button>
                    <button className="btn-ghost" onClick={handleLogout}>Sign Out</button>
                </div>
            </header>

            {stats && (
                <div className="stats-row">
                    <StatsCard label="Messages Processed" value={stats.total_messages} icon="▶" />
                    <StatsCard label="Active Analyzers" value={stats.active_analyzers} icon="◇" />
                    <StatsCard label="Actions Taken" value={stats.actions_taken} accent="red" icon="▲" />
                    <StatsCard label="Clean" value={stats.clean_messages} accent="green" icon="●" />
                </div>
            )}

            <div className="card">
                <div className="card-header">
                    <h2>Message Pipeline</h2>
                    <span className="text-muted">{total} total</span>
                </div>

                {loading ? (
                    <div className="loading">Loading…</div>
                ) : messages.length === 0 ? (
                    <div className="empty-state">No messages processed yet</div>
                ) : (
                    <table className="message-table">
                        <thead>
                            <tr>
                                <th>Sender</th>
                                <th>Recipient</th>
                                <th>Subject</th>
                                <th>Tenant</th>
                                <th>Analyzers</th>
                                <th>Verdict</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {messages.map((msg) => (
                                <tr
                                    key={msg.id}
                                    className="message-row"
                                    onClick={() => navigate(`/messages/${encodeURIComponent(msg.message_id)}`)}
                                >
                                    <td className="sender-cell">{msg.sender || '—'}</td>
                                    <td className="recipient-cell">{(msg.recipients && msg.recipients.length > 0) ? msg.recipients[0] : '—'}</td>
                                    <td className="subject-cell">{msg.subject || '(no subject)'}</td>
                                    <td><span className="tenant-badge">{msg.tenant_alias || msg.tenant_id}</span></td>
                                    <td className="center">{msg.analyzer_count}</td>
                                    <td><StatusBadge action={msg.verdict_action} /></td>
                                    <td className="time-cell">{formatTime(msg.created_at)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}

                {totalPages > 1 && (
                    <div className="pagination">
                        <button disabled={page === 0} onClick={() => setPage(p => p - 1)}>← Prev</button>
                        <span>Page {page + 1} of {totalPages}</span>
                        <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next →</button>
                    </div>
                )}
            </div>
        </div>
    );
}

function formatTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
    });
}
