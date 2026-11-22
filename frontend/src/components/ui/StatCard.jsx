/**
 * StatCard — metric card for dashboard
 * Props: icon, title, value, description, accent ('blue'|'red'|'orange'|'emerald'|'slate')
 */
const ACCENTS = {
  blue:    'text-blue-400 bg-blue-500/10',
  red:     'text-red-400 bg-red-500/10',
  orange:  'text-orange-400 bg-orange-500/10',
  emerald: 'text-emerald-400 bg-emerald-500/10',
  yellow:  'text-yellow-400 bg-yellow-500/10',
  purple:  'text-purple-400 bg-purple-500/10',
  slate:   'text-slate-400 bg-slate-500/10',
};

export default function StatCard({
  icon: Icon,
  title,
  value,
  description,
  accent = 'blue',
  loading = false,
}) {
  const accentClass = ACCENTS[accent] ?? ACCENTS.blue;
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-widest text-slate-500">{title}</p>
          <p className="mt-2 text-3xl font-bold text-white">
            {loading ? (
              <span className="inline-block h-8 w-12 animate-pulse rounded bg-slate-800" />
            ) : (
              value ?? '—'
            )}
          </p>
          {description && (
            <p className="mt-1 text-xs text-slate-600">{description}</p>
          )}
        </div>
        {Icon && (
          <div className={`rounded-lg p-2.5 ${accentClass}`}>
            <Icon size={18} />
          </div>
        )}
      </div>
    </div>
  );
}
