import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Eye,
  EyeOff,
  LockKeyhole,
  Mail,
  ShieldCheck,
  User,
  UserPlus,
} from "lucide-react";
import {
  Link,
  Navigate,
  useNavigate,
} from "react-router-dom";

import { useAuth } from "../context/AuthContext";

function Signup() {
  const {
    user,
    loading,
    signup,
    clearAuthError,
  } = useAuth();

  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] =
    useState("");

  const [showPassword, setShowPassword] =
    useState(false);

  const [showConfirmPassword, setShowConfirmPassword] =
    useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // ==========================================================
  // CLEAR AUTH ERROR
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
  // VALIDATION
  // ==========================================================

  function validateForm() {
    const cleanName = name.trim();
    const cleanUsername = username.trim();
    const cleanEmail = email.trim();

    if (!cleanName) {
      return "Please enter your name.";
    }

    if (cleanName.length < 2) {
      return "Name must contain at least 2 characters.";
    }

    if (!cleanUsername) {
      return "Please enter a username.";
    }

    if (cleanUsername.length < 3) {
      return "Username must contain at least 3 characters.";
    }

    if (!/^[a-zA-Z0-9_.-]+$/.test(cleanUsername)) {
      return "Username can contain only letters, numbers, dots, underscores, and hyphens.";
    }

    if (!cleanEmail) {
      return "Please enter your email address.";
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return "Please enter a valid email address.";
    }

    if (!password) {
      return "Please enter a password.";
    }

    if (password.length < 6) {
      return "Password must contain at least 6 characters.";
    }

    if (password !== confirmPassword) {
      return "Passwords do not match.";
    }

    return "";
  }

  // ==========================================================
  // SUBMIT
  // ==========================================================

  async function handleSubmit(event) {
    event.preventDefault();

    setError("");
    setSuccess("");

    const validationError = validateForm();

    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);

    try {
      const signupResult = await signup({
        name: name.trim(),
        username: username.trim(),
        email: email.trim(),
        password,
      });

      if (!signupResult?.success) {
        setError(
          signupResult?.error ||
            "Unable to create account."
        );
        return;
      }

      // ======================================================
      // ACCOUNT CREATED
      // ======================================================

      setSuccess(
        "Account created successfully. Redirecting to login..."
      );

      // Clear form
      setName("");
      setUsername("");
      setEmail("");
      setPassword("");
      setConfirmPassword("");

      // Give the user a moment to see success message
      setTimeout(() => {
        navigate("/login", {
          replace: true,
          state: {
            signupSuccess:
              "Account created successfully. Please sign in.",
          },
        });
      }, 1000);
    } catch (error) {
      console.error(
        "Signup submission failed:",
        error
      );

      setError(
        error?.message ||
          "Unable to create account."
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

        {/* Grid */}

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

        <div className="absolute w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl top-10 left-20" />

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

          {/* Main content */}

          <div className="max-w-lg">

            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-400/10 border border-cyan-400/20 text-cyan-300 text-xs font-medium mb-6">

              <UserPlus size={14} />

              Create your security account

            </div>

            <h2 className="text-4xl xl:text-5xl font-bold leading-tight">

              Join the

              <span className="block text-cyan-400">
                ZeroGuard SOC.
              </span>

            </h2>

            <p className="mt-6 text-slate-400 leading-relaxed max-w-md">

              Create an account to access the
              ZeroGuard security operations dashboard,
              monitor network activity and review
              AI-powered threat detections.

            </p>

            {/* Features */}

            <div className="mt-10 space-y-4">

              <div className="flex items-center gap-3">

                <div className="w-8 h-8 rounded-lg bg-cyan-400/10 flex items-center justify-center">

                  <CheckCircle2
                    size={17}
                    className="text-cyan-400"
                  />

                </div>

                <span className="text-sm text-slate-300">
                  Network security monitoring
                </span>

              </div>

              <div className="flex items-center gap-3">

                <div className="w-8 h-8 rounded-lg bg-cyan-400/10 flex items-center justify-center">

                  <CheckCircle2
                    size={17}
                    className="text-cyan-400"
                  />

                </div>

                <span className="text-sm text-slate-300">
                  AI-based threat detection
                </span>

              </div>

              <div className="flex items-center gap-3">

                <div className="w-8 h-8 rounded-lg bg-cyan-400/10 flex items-center justify-center">

                  <CheckCircle2
                    size={17}
                    className="text-cyan-400"
                  />

                </div>

                <span className="text-sm text-slate-300">
                  Security incident management
                </span>

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

      <div className="flex-1 flex items-center justify-center p-6 py-10 overflow-y-auto">

        <div className="w-full max-w-md">

          {/* Mobile logo */}

          <div className="lg:hidden flex items-center justify-center gap-3 mb-8">

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

          {/* Header */}

          <div className="mb-7">

            <h2 className="text-3xl font-bold">
              Create account
            </h2>

            <p className="text-slate-400 mt-2">
              Create your ZeroGuard user account.
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

          {/* Success */}

          {success && (
            <div className="mb-5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3">

              <p className="text-sm text-emerald-300">
                {success}
              </p>

            </div>
          )}

          {/* Form */}

          <form
            onSubmit={handleSubmit}
            className="space-y-4"
          >

            {/* Name */}

            <div>

              <label
                htmlFor="name"
                className="block text-sm font-medium text-slate-300 mb-2"
              >
                Full name
              </label>

              <div className="relative">

                <User
                  size={18}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(event) =>
                    setName(event.target.value)
                  }
                  placeholder="Enter your full name"
                  autoComplete="name"
                  disabled={submitting}
                  className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 disabled:opacity-60"
                />

              </div>

            </div>

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
                  placeholder="Choose a username"
                  autoComplete="username"
                  disabled={submitting}
                  className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 disabled:opacity-60"
                />

              </div>

            </div>

            {/* Email */}

            <div>

              <label
                htmlFor="email"
                className="block text-sm font-medium text-slate-300 mb-2"
              >
                Email address
              </label>

              <div className="relative">

                <Mail
                  size={18}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(event) =>
                    setEmail(event.target.value)
                  }
                  placeholder="you@example.com"
                  autoComplete="email"
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
                  placeholder="Create a password"
                  autoComplete="new-password"
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

            {/* Confirm password */}

            <div>

              <label
                htmlFor="confirmPassword"
                className="block text-sm font-medium text-slate-300 mb-2"
              >
                Confirm password
              </label>

              <div className="relative">

                <LockKeyhole
                  size={18}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  id="confirmPassword"
                  type={
                    showConfirmPassword
                      ? "text"
                      : "password"
                  }
                  value={confirmPassword}
                  onChange={(event) =>
                    setConfirmPassword(
                      event.target.value
                    )
                  }
                  placeholder="Confirm your password"
                  autoComplete="new-password"
                  disabled={submitting}
                  className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-3 pl-10 pr-11 text-sm text-white placeholder:text-slate-600 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 disabled:opacity-60"
                />

                <button
                  type="button"
                  onClick={() =>
                    setShowConfirmPassword(
                      (value) => !value
                    )
                  }
                  disabled={submitting}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  aria-label={
                    showConfirmPassword
                      ? "Hide password"
                      : "Show password"
                  }
                >
                  {showConfirmPassword ? (
                    <EyeOff size={18} />
                  ) : (
                    <Eye size={18} />
                  )}
                </button>

              </div>

            </div>

            {/* Submit */}

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-xl bg-cyan-500 py-3.5 mt-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {submitting
                ? "Creating account..."
                : "Create account"}
            </button>

          </form>

          {/* Login link */}

          <div className="mt-6 text-center">

            <p className="text-sm text-slate-500">

              Already have an account?{" "}

              <Link
                to="/login"
                className="font-medium text-cyan-400 hover:text-cyan-300"
              >
                Sign in
              </Link>

            </p>

          </div>

          {/* Security notice */}

          <div className="mt-7 flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/40 p-4">

            <ShieldCheck
              size={18}
              className="text-cyan-400 mt-0.5 shrink-0"
            />

            <p className="text-xs leading-relaxed text-slate-500">

              New accounts are created as
              <span className="text-slate-300">
                {" "}User
              </span>
              accounts. Administrative access is
              controlled separately by ZeroGuard.

            </p>

          </div>

        </div>

      </div>

    </div>
  );
}

export default Signup;