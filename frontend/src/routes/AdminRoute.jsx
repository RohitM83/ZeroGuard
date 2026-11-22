import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

function AdminRoute() {
  const {
    user,
    loading,
    isAdmin,
    isLoggedIn,
  } = useAuth();

  const location = useLocation();

  // ==========================================================
  // CHECKING SESSION
  // ==========================================================

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        <div className="text-center">

          <div className="mx-auto mb-4 w-10 h-10 rounded-full border-2 border-slate-700 border-t-cyan-400 animate-spin" />

          <p className="text-sm text-slate-400">
            Checking administrator access...
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
  // LOGGED IN BUT NOT ADMIN
  // ==========================================================

  if (!isAdmin) {
    return (
      <Navigate
        to="/"
        replace
      />
    );
  }

  // ==========================================================
  // ADMINISTRATOR
  // ==========================================================

  return <Outlet />;
}

export default AdminRoute;