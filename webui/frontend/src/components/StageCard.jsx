/**
 * StageCard — Pipeline stage wrapper with color-coded left border.
 */
export default function StageCard({ stage, title, icon, number, children }) {
    return (
        <div className={`stage-card stage-${stage}`}>
            <div className="stage-header">
                <span className="stage-number">{number}</span>
                <span className="stage-icon">{icon}</span>
                <h3 className="stage-title">{title}</h3>
            </div>
            <div className="stage-content">
                {children}
            </div>
        </div>
    );
}
