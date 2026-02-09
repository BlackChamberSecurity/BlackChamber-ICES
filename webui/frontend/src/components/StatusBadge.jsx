/**
 * StatusBadge — Colored badge for verdict actions.
 */
const ACTION_STYLES = {
    none: { label: 'Clean', className: 'badge-green' },
    pending: { label: 'Pending', className: 'badge-gray' },
    quarantine: { label: 'Quarantine', className: 'badge-red' },
    tag: { label: 'Tagged', className: 'badge-amber' },
    delete: { label: 'Deleted', className: 'badge-red' },
    notify: { label: 'Notified', className: 'badge-blue' },
};

export default function StatusBadge({ action }) {
    const style = ACTION_STYLES[action] || { label: action, className: 'badge-gray' };
    return <span className={`badge ${style.className}`}>{style.label}</span>;
}
