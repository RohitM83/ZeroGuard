/** Small colored dot indicating online/offline/warning state */
const COLORS = {
  online:  'bg-emerald-400',
  offline: 'bg-red-500',
  warning: 'bg-yellow-400',
  idle:    'bg-slate-500',
};

export default function StatusDot({ status = 'idle', className = '' }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${COLORS[status] ?? COLORS.idle} ${className}`}
      aria-label={status}
    />
  );
}
