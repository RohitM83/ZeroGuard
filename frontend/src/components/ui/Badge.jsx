/**
 * Badge — severity / status labels
 * variant: 'critical' | 'high' | 'medium' | 'low' | 'info'
 *          | 'new' | 'investigating' | 'contained' | 'resolved'
 *          | 'online' | 'offline' | 'warning'
 */

const VARIANTS = {
  critical:      'bg-red-950 text-red-400 border border-red-800',
  high:          'bg-orange-950 text-orange-400 border border-orange-800',
  medium:        'bg-yellow-950 text-yellow-400 border border-yellow-800',
  low:           'bg-blue-950 text-blue-400 border border-blue-800',
  info:          'bg-slate-800 text-slate-300 border border-slate-700',
  new:           'bg-sky-950 text-sky-400 border border-sky-800',
  investigating: 'bg-purple-950 text-purple-400 border border-purple-800',
  contained:     'bg-amber-950 text-amber-400 border border-amber-800',
  resolved:      'bg-emerald-950 text-emerald-400 border border-emerald-800',
  online:        'bg-emerald-950 text-emerald-400 border border-emerald-800',
  offline:       'bg-red-950 text-red-400 border border-red-800',
  warning:       'bg-yellow-950 text-yellow-400 border border-yellow-800',
  blocked:       'bg-red-950 text-red-400 border border-red-800',
  active:        'bg-emerald-950 text-emerald-400 border border-emerald-800',
  inactive:      'bg-slate-800 text-slate-400 border border-slate-700',
};

export default function Badge({ variant = 'info', children, className = '' }) {
  const base = VARIANTS[variant] ?? VARIANTS.info;
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium tracking-wide ${base} ${className}`}>
      {children}
    </span>
  );
}
