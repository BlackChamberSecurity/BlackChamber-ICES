/**
 * StatsCard — Summary metric card for the dashboard.
 */
export default function StatsCard({ label, value, icon, accent }) {
    return (
        <div className={`stats-card ${accent ? `stats-${accent}` : ''}`}>
            <div className="stats-icon">{icon}</div>
            <div className="stats-body">
                <div className="stats-value">{value ?? '—'}</div>
                <div className="stats-label">{label}</div>
            </div>
        </div>
    );
}
