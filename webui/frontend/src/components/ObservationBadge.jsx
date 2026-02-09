/**
 * ObservationBadge — Displays a single analyzer observation as a key=value badge.
 */
export default function ObservationBadge({ observation }) {
    if (!observation || typeof observation !== 'object') return null;

    const { key, value } = observation;

    // Color coding based on common observation patterns
    let className = 'obs-badge obs-info';
    const v = String(value).toLowerCase();

    if (v === 'pass' || v === 'true' || v === 'false' && key?.includes('mismatch')) {
        className = 'obs-badge obs-pass';
    } else if (v === 'fail' || v === 'true' && key?.includes('mismatch')) {
        className = 'obs-badge obs-fail';
    } else if (v === 'none' || v === 'not_found' || v === '0') {
        className = 'obs-badge obs-neutral';
    }

    return (
        <span className={className}>
            <span className="obs-key">{key}</span>
            <span className="obs-value">{String(value)}</span>
        </span>
    );
}
