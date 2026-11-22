/** Centered empty state with icon and message */
export default function EmptyState({ icon: Icon, title, description, className = '' }) {
  return (
    <div className={`flex flex-col items-center justify-center py-16 text-center ${className}`}>
      {Icon && <Icon size={36} className="mb-4 text-slate-600" />}
      <p className="text-sm font-medium text-slate-400">{title}</p>
      {description && (
        <p className="mt-1 text-xs text-slate-600 max-w-xs">{description}</p>
      )}
    </div>
  );
}
