import { useEffect, useState } from "react";
import {
  Activity,
  Eye,
  EyeOff,
  LockKeyhole,
  ShieldCheck,
  User,
} from "lucide-react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";

function Login() {
  const {
    user,
    loading,
    login,
    clearAuthError,
  } = useAuth();

  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // ==========================================================
  // CLEAR OLD AUTH ERROR
  // ==========================================================

  useEffect(() => {
    clearAuthError();
  }, [clearAuthError]);

  // ==========================================================
  // ALREADY LOGGED IN
  // ==========================================================

  if (!loading && user) {
    return <Navigate to="/" replace />;
  }

  // ==========================================================
  // LOGIN SUBMIT
  // ==========================================================

  async function handleSubmit(event) {
    event.preventDefault();

    setError("");

    if (!username.trim()) {
      setError("Please enter your username.");
      return;
    }

    if (!password) {
      setError("Please enter your password.");
      return;
    }

    setSubmitting(true);

    try {
      const result = await login(
        username.trim(),
        password
      );

      if (!result?.success) {
        setError(
          result?.error ||
            "Invalid username or password."
        );

        return;
      }

      // ======================================================
      // REDIRECT AFTER SUCCESSFUL LOGIN
      // ======================================================

      const destination =
        location.state?.from || "/";

      navigate(destination, {
        replace: true,
      });
    } catch (err) {
      console.error("Login error:", err);

      setError(
        err?.message ||
          "Unable to sign in. Please try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  // ==========================================================
  // PAGE
  // ==========================================================

  return (
    <div className="min-h-screen bg-slate-950 text-white flex">

      {/* ======================================================
          LEFT PANEL
          ====================================================== */}

      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden bg-slate-900">

        {/* Background grid */}

        <div className="absolute inset-0 opacity-20">
          <div
            className="absolute inset-0"
            style={{
              backgroundImage:
                "linear-gradient(rgba(148,163,184,0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.15) 1px, transparent 1px)",
              backgroundSize: "40px 40px",
            }}
          />
        </div>

        {/* Glow */}

        <div className="absolute w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl top-20 left-20" />

        <div className="absolute w-80 h-80 bg-blue-500/10 rounded-full blur-3xl bottom-10 right-10" />

        {/* Content */}

        <div className="relative z-10 flex flex-col justify-between p-12 w-full">

          {/* Logo */}

          <div className="flex items-center gap-3">

            <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-400/20 flex items-center justify-center">
              <ShieldCheck
                className="text-cyan-400"
                size={25}
              />
            </div>

            <div>
              <h1 className="text-xl font-bold tracking-wide">
                ZeroGuard
              </h1>

              <p className="text-xs text-slate-500">
                Security Operations Center
              </p>
            </div>

          </div>

          {/* Main message */}

          <div className="max-w-lg">

            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-400/10 border border-cyan-400/20 text-cyan-300 text-xs font-medium mb-6">

              <Activity size={14} />

              AI-Powered Threat Detection

            </div>

            <h2 className="text-4xl xl:text-5xl font-bold leading-tight">

              Protect your network

              <span className="block text-cyan-400">
                before threats spread.
              </span>

            </h2>

            <p className="mt-6 text-slate-400 leading-relaxed max-w-md">

              ZeroGuard uses graph-based AI analysis
              to identify suspicious network behavior,
              detect potential zero-day attacks and
              coordinate defensive security responses.

            </p>

            {/* Security indicators */}

            <div className="grid grid-cols-3 gap-3 mt-10">

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">

                <p className="text-cyan-400 text-lg font-bold">
                  GNN
                </p>

                <p className="text-xs text-slate-500 mt-1">
                  Threat Analysis
                </p>

              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">

                <p className="text-cyan-400 text-lg font-bold">
                  SOC
                </p>

                <p className="text-xs text-slate-500 mt-1">
                  Operations
                </p>

              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">

                <p className="text-cyan-400 text-lg font-bold">
                  24/7
                </p>

                <p className="text-xs text-slate-500 mt-1">
                  Monitoring
                </p>

              </div>

            </div>

          </div>

          {/* Footer */}

          <p className="text-xs text-slate-600">
            ZeroGuard • AI-Based Zero-Day Attack Detection
          </p>

        </div>

      </div>

      {/* ======================================================
          RIGHT PANEL
          ====================================================== */}

      <div className="flex-1 flex items-center justify-center p-6">

        <div className="w-full max-w-md">

          {/* Mobile logo */}

          <div className="lg:hidden flex items-center justify-center gap-3 mb-10">

            <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-400/20 flex items-center justify-center">

              <ShieldCheck
                className="text-cyan-400"
                size={25}
              />

            </div>

            <div>

              <h1 className="text-xl font-bold">
                ZeroGuard
              </h1>

              <p className="text-xs text-slate-500">
                Security Operations Center
              </p>

            </div>

          </div>

          {/* Login header */}

          <div className="mb-8">

            <h2 className="text-3xl font-bold">
              Welcome back
            </h2>

            <p className="text-slate-400 mt-2">
              Sign in to access the ZeroGuard SOC.
            </p>

          </div>

          {/* Error */}

          {error && (
            <div className="mb-5 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3">

              <p className="text-sm text-red-300">
                {error}
              </p>

            </div>
          )}

          {/* Form */}

          <form
            onSubmit={handleSubmit}
            className="space-y-5"
          >

            {/* Username */}

            <div>

              <label
                htmlFor="username"
                className="block text-sm font-medium text-slate-300 mb-2"
              >
                Username
              </label>

              <div className="relative">

                <User
                  size={18}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(event) =>
                    setUsername(event.target.value)
                  }
                  placeholder="Enter your username"
                  autoComplete="username"
                  disabled={submitting}
                  className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 disabled:opacity-60"
                />

              </div>

            </div>

            {/* Password */}

            <div>

              <label
                htmlFor="password"
                className="block text-sm font-medium text-slate-300 mb-2"
              >
                Password
              </label>

              <div className="relative">

                <LockKeyhole
                  size={18}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  id="password"
                  type={
                    showPassword
                      ? "text"
                      : "password"
                  }
                  value={password}
                  onChange={(event) =>
                    setPassword(event.target.value)
                  }
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  disabled={submitting}
                  className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-3 pl-10 pr-11 text-sm text-white placeholder:text-slate-600 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 disabled:opacity-60"
                />

                <button
                  type="button"
                  onClick={() =>
                    setShowPassword(
                      (value) => !value
                    )
                  }
                  disabled={submitting}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  aria-label={
                    showPassword
                      ? "Hide password"
                      : "Show password"
                  }
                >

                  {showPassword ? (
                    <EyeOff size={18} />
                  ) : (
                    <Eye size={18} />
                  )}

                </button>

              </div>

            </div>

            {/* Login button */}

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-xl bg-cyan-500 py-3.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
            >

              {submitting
                ? "Signing in..."
                : "Sign in"}

            </button>

          </form>

          {/* Signup */}

          <div className="mt-7 text-center">

            <p className="text-sm text-slate-500">

              Don't have an account?{" "}

              <Link
                to="/signup"
                className="font-medium text-cyan-400 hover:text-cyan-300"
              >
                Create account
              </Link>

            </p>

          </div>

          {/* Security notice */}

          <div className="mt-8 flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/40 p-4">

            <ShieldCheck
              size={18}
              className="text-cyan-400 mt-0.5 shrink-0"
            />

            <p className="text-xs leading-relaxed text-slate-500">

              Your session is authenticated through the
              ZeroGuard security API. Access permissions
              are determined by your account role.

            </p>

          </div>

        </div>

      </div>

    </div>
  );
}

export default Login;