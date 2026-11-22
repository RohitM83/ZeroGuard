import {
  Search,
  Bell,
  Wifi,
  WifiOff,
  RefreshCw,
  UserCircle,
} from "lucide-react";

function TopBar({ apiStatus }) {
  const {
    data,
    error,
    loading,
    refetch,
  } = apiStatus;

  const isOnline = !error && data;

  return (
    <header className="fixed left-0 right-0 top-0 z-40 h-16 border-b border-slate-800 bg-slate-950/95 backdrop-blur md:left-64">
      <div className="flex h-full items-center justify-between gap-4 px-4 md:px-6">

        {/* Left */}
        <div className="flex min-w-0 items-center gap-3">
          <div className="hidden sm:block">
            <p className="text-sm font-medium text-slate-200">
              Security Operations Center
            </p>

            <p className="text-xs text-slate-500">
              Real-time infrastructure monitoring
            </p>
          </div>
        </div>

        {/* Right */}
        <div className="flex items-center gap-2 sm:gap-3">

          {/* Search */}
          <div className="hidden items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 lg:flex">
            <Search
              size={16}
              className="text-slate-500"
            />

            <input
              type="text"
              placeholder="Search..."
              className="w-36 bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-600"
            />

            <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-500">
              Ctrl K
            </span>
          </div>

          {/* Backend Status */}
          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 ${
              isOnline
                ? "border-emerald-900/60 bg-emerald-950/30"
                : "border-red-900/60 bg-red-950/30"
            }`}
          >
            {isOnline ? (
              <Wifi
                size={15}
                className="text-emerald-400"
              />
            ) : (
              <WifiOff
                size={15}
                className="text-red-400"
              />
            )}

            <p
              className={`hidden text-xs font-medium sm:block ${
                isOnline
                  ? "text-emerald-400"
                  : "text-red-400"
              }`}
            >
              {loading
                ? "Checking..."
                : isOnline
                  ? "Backend Online"
                  : "Backend Offline"}
            </p>

            <span
              className={`h-2 w-2 rounded-full ${
                isOnline
                  ? "animate-pulse bg-emerald-400"
                  : "bg-red-400"
              }`}
            />
          </div>

          {/* Refresh */}
          <button
            onClick={refetch}
            className="rounded-lg border border-slate-800 bg-slate-900 p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
            title="Refresh backend status"
          >
            <RefreshCw
              size={17}
              className={loading ? "animate-spin" : ""}
            />
          </button>

          {/* Notifications */}
          <button
            className="relative rounded-lg border border-slate-800 bg-slate-900 p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
            title="Notifications"
          >
            <Bell size={17} />

            <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-blue-400" />
          </button>

          {/* User */}
          <div className="hidden items-center gap-2 border-l border-slate-800 pl-3 sm:flex">
            <UserCircle
              size={28}
              className="text-slate-500"
            />

            <div>
              <p className="text-xs font-medium text-slate-200">
                Administrator
              </p>

              <p className="text-[10px] text-slate-500">
                Security Analyst
              </p>
            </div>
          </div>

        </div>
      </div>
    </header>
  );
}

export default TopBar;