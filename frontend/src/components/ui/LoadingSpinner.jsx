/** Simple spinner for loading states */
export default function LoadingSpinner({ size = 'md', className = '' }) {
  const sizeClass = size === 'sm' ? 'h-4 w-4' : size === 'lg' ? 'h-8 w-8' : 'h-6 w-6';
  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div
        className={`${sizeClass} animate-spin rounded-full border-2 border-slate-700 border-t-blue-500`}
        role="status"
        aria-label="Loading"
      />
    </div>
  );
}
