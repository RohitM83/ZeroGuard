import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

function ProtectedRoute({
  children,
  adminOnly = false,
}) {
  const {
    user,
    loading,
    isAdmin,
  } = useAuth();

  const location = useLocation();

  // --------------------------------------------------
  // Authentication is still being checked
  // --------------------------------------------------

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">

          <div className="w-10 h-10 border-4 border-slate-700 border-t-cyan-400 rounded-full animate-spin mx-auto mb-4" />

          <p className="text-slate-300 text-sm">
            Checking authentication...
          </p>

        </div>
      </div>
    );
  }

  // --------------------------------------------------
  // User is not logged in
  // --------------------------------------------------

  if (!user) {
    return (
      <Navigate
        to="/login"
        replace
        state={{
          from: location.pathname,
        }}
      />
    );
  }

  // --------------------------------------------------
  // Admin-only page
  // --------------------------------------------------

  if (adminOnly && !isAdmin) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6">

        <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8 text-center">

          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-red-500/10">

            <svg
              className="h-8 w-8 text-red-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="1.8"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v4m0 4h.01M10.29 3.86l-7.1 12.28A2 2 0 004.92 19h14.16a2 2 0 001.73-2.86l-7.1-12.28a2 2 0 00-3.42 0z"
              />
            </svg>

          </div>

          <h1 className="text-xl font-semibold text-white">
            Administrator Access Required
          </h1>

          <p className="mt-3 text-sm leading-6 text-slate-400">
            This ZeroGuard security operation is restricted
            to administrators.
          </p>

          <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950 p-4">

            <p className="text-xs uppercase tracking-wider text-slate-600">
              Current account
            </p>

            <p className="mt-1 text-sm font-medium text-slate-200">
              {user.name || user.username}
            </p>

            <p className="mt-1 text-xs text-emerald-400">
              Security User
            </p>

          </div>

          <button
            type="button"
            onClick={() => {
              window.location.href = "/";
            }}
            className="mt-6 w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-blue-500"
          >
            Return to Dashboard
          </button>

        </div>

      </div>
    );
  }

  // --------------------------------------------------
  // Authorized
  // --------------------------------------------------

  return children;
}

export default ProtectedRoute;