import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, clearToken } from '../api';
import StatsCard from '../components/StatsCard';

export default function SaaSUsage() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [days, setDays] = useState(30);
    const [userFilter, setUserFilter] = useState('');
    const [providerFilter, setProviderFilter] = useState('');
    const [expandedProvider, setExpandedProvider] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        loadData();
    }, [days, userFilter, providerFilter]);

    async function loadData() {
        setLoading(true);
        try {
            let url = `/saas-analytics?days=${days}`;
            if (userFilter) url += `&user=${encodeURIComponent(userFilter)}`;
            if (providerFilter) url += `&provider=${encodeURIComponent(providerFilter)}`;
            const res = await apiFetch(url);
            setData(res);
        } catch (err) {
            console.error('Failed to load SaaS analytics:', err);
        } finally {
            setLoading(false);
        }
    }

    function handleLogout() {
        clearToken();
        navigate('/login', { replace: true });
    }

    const filteredProviders = data?.providers || [];
    const maxCount = filteredProviders.length > 0
        ? Math.max(...filteredProviders.map(p => p.count))
        : 1;

    // Timeline helpers — use fixed dimensions for proper proportions
    const timeline = data?.timeline || [];
    const maxTimelineCount = timeline.length > 0
        ? Math.max(...timeline.map(t => t.count))
        : 1;
    const TBAR_W = 14;
    const TBAR_GAP = 4;
    const TBAR_STEP = TBAR_W + TBAR_GAP;
    const T_PADDING = 20;
    const T_HEIGHT = 160;
    const T_BAR_AREA = T_HEIGHT - 40; // room for labels below
    const T_WIDTH = Math.max(timeline.length * TBAR_STEP + T_PADDING * 2, 200);

    // Category colors for donut
    const CATEGORY_COLORS = {
        'usage': 'var(--color-success)',
        'marketing': 'var(--accent)',
        'transactional': '#0066cc',
        'productivity': '#0088cc',
        'security': '#cc0000',
        'devops': '#cc7700',
        'communication': '#1a8a1a',
        'finance': '#6633cc',
        'hr': '#cc3399',
        'analytics': '#0099cc',
        'storage': '#666666',
    };

    function getCategoryColor(cat, idx) {
        return CATEGORY_COLORS[cat?.toLowerCase()] || `hsl(${(idx * 47) % 360}, 45%, 45%)`;
    }

    function buildDonutSegments(categories) {
        if (!categories || categories.length === 0) return [];
        const total = categories.reduce((s, c) => s + c.count, 0);
        let cumulative = 0;
        return categories.map((cat, i) => {
            const pct = (cat.count / total) * 100;
            const offset = cumulative;
            cumulative += pct;
            return {
                ...cat,
                pct: Math.round(pct),
                offset,
                color: getCategoryColor(cat.category, i),
            };
        });
    }

    const donutSegments = buildDonutSegments(data?.categories);

    // Format user_id for display
    function displayUser(uid) {
        return uid || '—';
    }

    return (
        <div className="dashboard">
            <header className="topbar">
                <div className="topbar-left">
                    <span className="topbar-icon">◆</span>
                    <h1>BlackChamber ICES</h1>
                </div>
                <div className="topbar-nav">
                    <button className="btn-ghost" onClick={() => navigate('/')}>Dashboard</button>
                    <button className="btn-ghost btn-ghost-active">SaaS Usage</button>
                    <button className="btn-ghost" onClick={handleLogout}>Sign Out</button>
                </div>
            </header>

            {/* Filters */}
            <div className="saas-filters">
                <div className="filter-group">
                    <label className="filter-label">Time Range</label>
                    <div className="filter-buttons">
                        {[7, 30, 90].map(d => (
                            <button
                                key={d}
                                className={`filter-btn ${days === d ? 'filter-btn-active' : ''}`}
                                onClick={() => setDays(d)}
                            >
                                {d}d
                            </button>
                        ))}
                    </div>
                </div>

                {/* User filter */}
                {data?.users && data.users.length > 0 && (
                    <div className="filter-group">
                        <label className="filter-label">User</label>
                        <select
                            className="filter-select"
                            value={userFilter}
                            onChange={e => setUserFilter(e.target.value)}
                        >
                            <option value="">All Users</option>
                            {data.users.map(u => (
                                <option key={u} value={u}>{displayUser(u)}</option>
                            ))}
                        </select>
                    </div>
                )}

                {/* Provider filter */}
                {data?.providers && data.providers.length > 0 && (
                    <div className="filter-group">
                        <label className="filter-label">App</label>
                        <select
                            className="filter-select"
                            value={providerFilter}
                            onChange={e => setProviderFilter(e.target.value)}
                        >
                            <option value="">All Apps</option>
                            {data.providers.map(p => (
                                <option key={p.provider} value={p.provider}>{p.provider}</option>
                            ))}
                        </select>
                    </div>
                )}

                {/* Clear filters */}
                {(userFilter || providerFilter) && (
                    <button
                        className="filter-btn"
                        onClick={() => { setUserFilter(''); setProviderFilter(''); }}
                        style={{ marginLeft: 'auto' }}
                    >
                        ✕ Clear
                    </button>
                )}
            </div>

            {loading ? (
                <div className="loading">Scanning SaaS telemetry…</div>
            ) : !data ? (
                <div className="empty-state">No SaaS data available</div>
            ) : (
                <>
                    {/* Stats Row */}
                    <div className="stats-row">
                        <StatsCard
                            label="SaaS Emails"
                            value={data.totals?.total_saas_emails || 0}
                            icon="◇"
                        />
                        <StatsCard
                            label="Providers"
                            value={data.totals?.unique_providers || 0}
                            icon="▶"
                        />
                        <StatsCard
                            label="Users"
                            value={data.totals?.unique_users || 0}
                            icon="◎"
                        />
                        <StatsCard
                            label="Usage Rate"
                            value={`${data.classification?.usage_pct || 0}%`}
                            icon="●"
                            accent="green"
                        />
                    </div>

                    {/* Charts Grid */}
                    <div className="saas-grid">
                        {/* Provider Bar Chart */}
                        <div className="card saas-chart-card">
                            <div className="card-header">
                                <h2>Top Providers</h2>
                                <span className="text-muted">{filteredProviders.length} detected</span>
                            </div>
                            <div className="stage-content">
                                {filteredProviders.length === 0 ? (
                                    <div className="empty-state">No providers detected</div>
                                ) : (
                                    <div className="bar-chart">
                                        {filteredProviders.map((p, i) => {
                                            const users = data.provider_users?.[p.provider] || [];
                                            const isExpanded = expandedProvider === p.provider;
                                            return (
                                                <div key={p.provider} className="bar-group">
                                                    <div
                                                        className={`bar-row ${users.length > 0 ? 'bar-row-clickable' : ''}`}
                                                        onClick={() => users.length > 0 && setExpandedProvider(isExpanded ? null : p.provider)}
                                                    >
                                                        <span className="bar-label">
                                                            {users.length > 0 && (
                                                                <span className="bar-expand">{isExpanded ? '▾' : '▸'}</span>
                                                            )}
                                                            {p.provider}
                                                        </span>
                                                        <div className="bar-track">
                                                            <div
                                                                className="bar-fill"
                                                                style={{
                                                                    width: `${(p.count / maxCount) * 100}%`,
                                                                    animationDelay: `${i * 60}ms`,
                                                                }}
                                                            />
                                                        </div>
                                                        <span className="bar-value">{p.count}</span>
                                                    </div>
                                                    {/* Expanded user list */}
                                                    {isExpanded && users.length > 0 && (
                                                        <div className="bar-users">
                                                            {users.map(u => (
                                                                <div key={u.user_id} className="bar-user-row">
                                                                    <span className="bar-user-id">{displayUser(u.user_id)}</span>
                                                                    <span className="bar-user-count">{u.count} emails</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Category Donut + Usage Split */}
                        <div className="card saas-chart-card">
                            <div className="card-header">
                                <h2>Category Breakdown</h2>
                            </div>
                            <div className="stage-content">
                                <div className="donut-container">
                                    <svg viewBox="0 0 120 120" className="donut-svg">
                                        {donutSegments.map((seg, i) => {
                                            const circumference = 2 * Math.PI * 45;
                                            const strokeLen = (seg.pct / 100) * circumference;
                                            const strokeOffset = -((seg.offset / 100) * circumference);
                                            return (
                                                <circle
                                                    key={seg.category}
                                                    cx="60" cy="60" r="45"
                                                    fill="none"
                                                    stroke={seg.color}
                                                    strokeWidth="12"
                                                    strokeDasharray={`${strokeLen} ${circumference - strokeLen}`}
                                                    strokeDashoffset={strokeOffset}
                                                    className="donut-segment"
                                                    style={{ animationDelay: `${i * 100}ms` }}
                                                />
                                            );
                                        })}
                                        <text x="60" y="56" textAnchor="middle" className="donut-center-value">
                                            {data.totals?.unique_categories || 0}
                                        </text>
                                        <text x="60" y="70" textAnchor="middle" className="donut-center-label">
                                            TYPES
                                        </text>
                                    </svg>
                                    <div className="donut-legend">
                                        {donutSegments.map(seg => (
                                            <div key={seg.category} className="legend-item">
                                                <span
                                                    className="legend-dot"
                                                    style={{ background: seg.color }}
                                                />
                                                <span className="legend-label">{seg.category}</span>
                                                <span className="legend-value">{seg.pct}%</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Usage vs Marketing */}
                                <div className="usage-split">
                                    <div className="split-header">
                                        <span className="filter-label">Classification</span>
                                    </div>
                                    <div className="split-bar-track">
                                        <div
                                            className="split-bar-usage"
                                            style={{ width: `${data.classification?.usage_pct || 0}%` }}
                                        />
                                    </div>
                                    <div className="split-labels">
                                        <span className="split-label-usage">
                                            ● Usage {data.classification?.usage || 0}
                                        </span>
                                        <span className="split-label-marketing">
                                            ● Marketing {data.classification?.marketing || 0}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Timeline — fixed proportional chart */}
                    <div className="card" style={{ margin: '0 1.5rem 1.5rem' }}>
                        <div className="card-header">
                            <h2>Daily Volume</h2>
                            <span className="text-muted">Last {days} days</span>
                        </div>
                        <div className="stage-content">
                            {timeline.length === 0 ? (
                                <div className="empty-state">No timeline data</div>
                            ) : (
                                <div className="timeline-chart">
                                    <svg
                                        viewBox={`0 0 ${T_WIDTH} ${T_HEIGHT}`}
                                        preserveAspectRatio="none"
                                        className="timeline-svg"
                                    >
                                        {/* Grid lines */}
                                        {[0, 0.25, 0.5, 0.75, 1].map(frac => {
                                            const y = T_BAR_AREA * (1 - frac);
                                            return (
                                                <line
                                                    key={frac}
                                                    x1="0" y1={y} x2={T_WIDTH} y2={y}
                                                    stroke="var(--border)" strokeWidth="0.5" strokeDasharray="3,6"
                                                    vectorEffect="non-scaling-stroke"
                                                />
                                            );
                                        })}
                                        {/* Bars */}
                                        {timeline.map((t, i) => {
                                            const barH = Math.max((t.count / maxTimelineCount) * T_BAR_AREA, 2);
                                            const x = T_PADDING + i * TBAR_STEP;
                                            return (
                                                <rect
                                                    key={t.day}
                                                    x={x}
                                                    y={T_BAR_AREA - barH}
                                                    width={TBAR_W}
                                                    height={barH}
                                                    className="timeline-bar"
                                                    rx="1"
                                                    style={{ animationDelay: `${i * 40}ms` }}
                                                />
                                            );
                                        })}
                                    </svg>
                                    {/* Date labels rendered as HTML for proper scaling */}
                                    <div className="timeline-labels">
                                        {timeline.map((t, i) => {
                                            const showLabel = timeline.length <= 14
                                                || i === 0
                                                || i === timeline.length - 1
                                                || i % Math.ceil(timeline.length / 8) === 0;
                                            if (!showLabel) return null;
                                            const leftPct = ((T_PADDING + i * TBAR_STEP + TBAR_W / 2) / T_WIDTH) * 100;
                                            return (
                                                <span
                                                    key={t.day}
                                                    className="timeline-date-label"
                                                    style={{ left: `${leftPct}%` }}
                                                >
                                                    {new Date(t.day).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                                                </span>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Provider Table with Users */}
                    <div className="card" style={{ margin: '0 1.5rem 1.5rem' }}>
                        <div className="card-header">
                            <h2>All Providers</h2>
                            <span className="text-muted">{filteredProviders.length} total</span>
                        </div>
                        <table className="message-table">
                            <thead>
                                <tr>
                                    <th>Rank</th>
                                    <th>Provider</th>
                                    <th>Users</th>
                                    <th>Emails</th>
                                    <th>Share</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredProviders.map((p, i) => {
                                    const totalEmails = data.totals?.total_saas_emails || 1;
                                    const share = Math.round((p.count / totalEmails) * 100);
                                    const users = data.provider_users?.[p.provider] || [];
                                    return (
                                        <tr key={p.provider} className="message-row">
                                            <td className="center">{i + 1}</td>
                                            <td>
                                                <span className="provider-name">{p.provider}</span>
                                            </td>
                                            <td>
                                                <div className="provider-users-cell">
                                                    {users.slice(0, 3).map(u => (
                                                        <span
                                                            key={u.user_id}
                                                            className="user-chip"
                                                            title={u.user_id}
                                                            onClick={() => setUserFilter(u.user_id)}
                                                        >
                                                            {displayUser(u.user_id)}
                                                        </span>
                                                    ))}
                                                    {users.length > 3 && (
                                                        <span className="user-chip user-chip-more">
                                                            +{users.length - 3}
                                                        </span>
                                                    )}
                                                    {users.length === 0 && (
                                                        <span className="text-muted">—</span>
                                                    )}
                                                </div>
                                            </td>
                                            <td className="center">{p.count}</td>
                                            <td>
                                                <div className="share-bar">
                                                    <div className="share-fill" style={{ width: `${share}%` }} />
                                                    <span className="share-text">{share}%</span>
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </>
            )}
        </div>
    );
}
