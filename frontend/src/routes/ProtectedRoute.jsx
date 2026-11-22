import {
  Navigate,
  useLocation,
} from "react-router-dom";

import { useAuth } from "../../context/AuthContext";

function ProtectedRoute({
  children,
  adminOnly = false,
}) {
  const {
    user,
    loading,
    isLoggedIn,
    isAdmin,
  } = useAuth();

  const location = useLocation();

  // ==========================================================
  // CHECKING AUTHENTICATION
  // ==========================================================

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        <div className="text-center">

          <div className="mx-auto mb-4 w-10 h-10 rounded-full border-2 border-slate-700 border-t-cyan-400 animate-spin" />

          <p className="text-sm text-slate-400">
            Checking authentication...
          </p>

        </div>
      </div>
    );
  }

  // ==========================================================
  // NOT LOGGED IN
  // ==========================================================

  if (!isLoggedIn || !user) {
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

  // ==========================================================
  // ADMIN-ONLY ROUTE
  // ==========================================================

  if (adminOnly && !isAdmin) {
    return (
      <Navigate
        to="/"
        replace
      />
    );
  }

  // ==========================================================
  // AUTHORIZED
  // ==========================================================

  return children;
}

export default ProtectedRoute;