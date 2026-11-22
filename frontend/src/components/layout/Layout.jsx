import {
  Activity,
  BarChart3,
  Bell,
  ChevronDown,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  ShieldAlert,
  Users,
  Wifi,
  X,
} from "lucide-react";

import {
  Link,
  NavLink,
  Outlet,
  useNavigate,
} from "react-router-dom";

import { useEffect, useState } from "react";

import { getStatus } from "../../services/api";

import { useAuth } from "../../context/AuthContext";

function Layout() {
  const navigate = useNavigate();

  const {
    user,
    isAdmin,
    logout,
  } = useAuth();

  const [profileOpen, setProfileOpen] =
    useState(false);

  const [mobileMenuOpen, setMobileMenuOpen] =
    useState(false);

  const [apiStatus, setApiStatus] =
    useState(null);

  const [apiError, setApiError] =
    useState("");

  const [apiLoading, setApiLoading] =
    useState(true);

  // ==========================================================
  // BACKEND STATUS
  // ==========================================================

  async function checkBackend() {
    try {
      setApiLoading(true);
      setApiError("");

      const response = await getStatus();

      setApiStatus(response);
    } catch (error) {
      console.error(
        "Backend status check failed:",
        error
      );

      setApiError(
        error?.message ||
          "Backend unavailable"
      );

      setApiStatus(null);
    } finally {
      setApiLoading(false);
    }
  }

  useEffect(() => {
    checkBackend();

    const interval = setInterval(
      checkBackend,
      10000
    );

    return () => {
      clearInterval(interval);
    };
  }, []);

  // ==========================================================
  // LOGOUT
  // ==========================================================

  async function handleLogout() {
    setProfileOpen(false);
    setMobileMenuOpen(false);

    await logout();

    navigate("/login", {
      replace: true,
    });
  }

  // ==========================================================
  // USER INFORMATION
  // ==========================================================

  const displayName =
    user?.name ||
    user?.username ||
    "ZeroGuard User";

  const username =
    user?.username ||
    "user";

  const roleLabel = isAdmin
    ? "Administrator"
    : "Security User";

  const roleTitle = isAdmin
    ? "System Administrator"
    : "Security User";

  const avatarLetter =
    displayName
      .charAt(0)
      .toUpperCase();

  // ==========================================================
  // NAVIGATION
  // ==========================================================

  const navigation = [
    {
      name: "Dashboard",
      path: "/",
      icon: LayoutDashboard,
      adminOnly: false,
    },
    {
      name: "Devices",
      path: "/devices",
      icon: Wifi,
      adminOnly: false,
    },
    {
      name: "Network Activity",
      path: "/network",
      icon: Activity,
      adminOnly: false,
    },
    {
      name: "Threat Detection",
      path: "/threats",
      icon: ShieldAlert,
      adminOnly: false,
    },
    {
      name: "Incidents",
      path: "/incidents",
      icon: Bell,
      adminOnly: true,
    },
    {
      name: "Response Actions",
      path: "/response",
      icon: ShieldAlert,
      adminOnly: true,
    },
    {
      name: "Reports",
      path: "/reports",
      icon: BarChart3,
      adminOnly: false,
    },
    {
      name: "User Management",
      path: "/users",
      icon: Users,
      adminOnly: true,
    },
    {
      name: "Settings",
      path: "/settings",
      icon: Settings,
      adminOnly: true,
    },
  ];

  const visibleNavigation =
    navigation.filter(
      (item) =>
        !item.adminOnly || isAdmin
    );

  // ==========================================================
  // CLOSE MOBILE MENU
  // ==========================================================

  function closeMobileMenu() {
    setMobileMenuOpen(false);
  }

  // ==========================================================
  // PAGE
  // ==========================================================

  return (
    <div className="min-h-screen bg-slate-950 text-white">

      {/* ==================================================
          DESKTOP SIDEBAR
          ================================================== */}

      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 border-r border-slate-800 bg-slate-950 lg:block">

        {/* Logo */}

        <div className="flex h-16 items-center border-b border-slate-800 px-6">

          <Link
            to="/"
            className="flex items-center gap-3"
          >

            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600">

              <ShieldAlert
                className="h-5 w-5 text-white"
              />

            </div>

            <div>

              <p className="text-lg font-bold tracking-tight text-white">
                ZeroGuard
              </p>

              <p className="text-[10px] uppercase tracking-wider text-slate-500">
                Security Operations
              </p>

            </div>

          </Link>

        </div>

        {/* Navigation */}

        <nav className="space-y-1 px-3 py-5">

          <p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
            Security Operations
          </p>

          {visibleNavigation.map(
            (item) => {
              const Icon = item.icon;

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === "/"}
                  className={({ isActive }) =>
                    [
                      "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition",
                      isActive
                        ? "bg-blue-500/10 text-blue-400"
                        : "text-slate-400 hover:bg-slate-900 hover:text-slate-200",
                    ].join(" ")
                  }
                >

                  <Icon className="h-4.5 w-4.5 shrink-0" />

                  <span>
                    {item.name}
                  </span>

                  {item.name ===
                    "User Management" &&
                    isAdmin && (
                      <span className="ml-auto rounded-full bg-blue-500/10 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-blue-400">
                        Admin
                      </span>
                    )}

                </NavLink>
              );
            }
          )}

        </nav>

        {/* Sidebar user */}

        <div className="absolute bottom-0 left-0 right-0 border-t border-slate-800 p-4">

          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">

            <div className="flex items-center gap-3">

              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/10 text-xs font-semibold text-blue-400">
                {avatarLetter}
              </div>

              <div className="min-w-0 flex-1">

                <p className="truncate text-xs font-medium text-slate-200">
                  {displayName}
                </p>

                <p className="truncate text-[10px] text-slate-500">
                  {roleLabel}
                </p>

              </div>

            </div>

          </div>

        </div>

      </aside>

      {/* ==================================================
          MOBILE SIDEBAR OVERLAY
          ================================================== */}

      {mobileMenuOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={closeMobileMenu}
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
        />
      )}

      {/* ==================================================
          MOBILE SIDEBAR
          ================================================== */}

      <aside
        className={[
          "fixed inset-y-0 left-0 z-50 w-72 border-r border-slate-800 bg-slate-950 shadow-2xl transition-transform duration-200 lg:hidden",
          mobileMenuOpen
            ? "translate-x-0"
            : "-translate-x-full",
        ].join(" ")}
      >

        {/* Mobile Logo */}

        <div className="flex h-16 items-center justify-between border-b border-slate-800 px-5">

          <Link
            to="/"
            onClick={closeMobileMenu}
            className="flex items-center gap-3"
          >

            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600">

              <ShieldAlert
                className="h-5 w-5 text-white"
              />

            </div>

            <div>

              <p className="text-lg font-bold tracking-tight text-white">
                ZeroGuard
              </p>

              <p className="text-[10px] uppercase tracking-wider text-slate-500">
                Security Operations
              </p>

            </div>

          </Link>

          <button
            type="button"
            onClick={closeMobileMenu}
            className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-400 hover:bg-slate-900 hover:text-white"
            aria-label="Close navigation"
          >

            <X className="h-5 w-5" />

          </button>

        </div>

        {/* Mobile Navigation */}

        <nav className="space-y-1 px-3 py-5">

          <p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
            Security Operations
          </p>

          {visibleNavigation.map(
            (item) => {
              const Icon = item.icon;

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === "/"}
                  onClick={closeMobileMenu}
                  className={({ isActive }) =>
                    [
                      "group flex items-center gap-3 rounded-lg px-3 py-3 text-sm transition",
                      isActive
                        ? "bg-blue-500/10 text-blue-400"
                        : "text-slate-400 hover:bg-slate-900 hover:text-slate-200",
                    ].join(" ")
                  }
                >

                  <Icon className="h-5 w-5 shrink-0" />

                  <span>
                    {item.name}
                  </span>

                  {item.name ===
                    "User Management" &&
                    isAdmin && (
                      <span className="ml-auto rounded-full bg-blue-500/10 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-blue-400">
                        Admin
                      </span>
                    )}

                </NavLink>
              );
            }
          )}

        </nav>

        {/* Mobile user */}

        <div className="absolute bottom-0 left-0 right-0 border-t border-slate-800 p-4">

          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">

            <div className="flex items-center gap-3">

              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-500/10 text-sm font-semibold text-blue-400">
                {avatarLetter}
              </div>

              <div className="min-w-0 flex-1">

                <p className="truncate text-xs font-medium text-slate-200">
                  {displayName}
                </p>

                <p className="truncate text-[10px] text-slate-500">
                  {roleLabel}
                </p>

              </div>

            </div>

          </div>

        </div>

      </aside>

      {/* ==================================================
          MAIN
          ================================================== */}

      <div className="lg:pl-64">

        {/* ==================================================
            HEADER
            ================================================== */}

        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/95 px-4 backdrop-blur sm:px-6">

          {/* Mobile header */}

          <div className="flex items-center gap-3 lg:hidden">

            <button
              type="button"
              onClick={() =>
                setMobileMenuOpen(true)
              }
              className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-300 transition hover:bg-slate-900 hover:text-white"
              aria-label="Open navigation"
              aria-expanded={mobileMenuOpen}
            >

              <Menu className="h-5 w-5" />

            </button>

            <div className="flex items-center gap-2">

              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">

                <ShieldAlert className="h-4 w-4" />

              </div>

              <span className="font-semibold">
                ZeroGuard
              </span>

            </div>

          </div>

          {/* Backend status */}

          <div className="hidden items-center gap-3 sm:flex">

            <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-2">

              <span
                className={[
                  "h-2 w-2 rounded-full",
                  apiStatus
                    ? "bg-emerald-400"
                    : apiLoading
                    ? "animate-pulse bg-yellow-400"
                    : "bg-red-400",
                ].join(" ")}
              />

              <span className="text-xs text-slate-400">
                Backend
              </span>

              <span
                className={[
                  "text-xs font-medium",
                  apiStatus
                    ? "text-emerald-400"
                    : apiLoading
                    ? "text-yellow-400"
                    : "text-red-400",
                ].join(" ")}
              >
                {apiStatus
                  ? "Online"
                  : apiLoading
                  ? "Checking..."
                  : "Offline"}
              </span>

            </div>

            {apiStatus && (
              <div className="hidden items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-2 md:flex">

                <Activity className="h-3.5 w-3.5 text-cyan-400" />

                <span className="text-xs text-slate-400">
                  Protected
                </span>

              </div>
            )}

          </div>

          {/* Profile */}

          <div className="relative ml-auto">

            <button
              type="button"
              onClick={() =>
                setProfileOpen(
                  (current) => !current
                )
              }
              className="flex items-center gap-3 rounded-lg px-2 py-1.5 transition hover:bg-slate-900"
              aria-expanded={profileOpen}
              aria-haspopup="menu"
            >

              <div className="hidden text-right sm:block">

                <p className="text-xs font-medium text-slate-200">
                  {displayName}
                </p>

                <p className="text-[10px] text-slate-500">
                  {roleTitle}
                </p>

              </div>

              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-500/10 text-sm font-semibold text-blue-400">
                {avatarLetter}
              </div>

              <ChevronDown
                className="hidden h-4 w-4 text-slate-500 sm:block"
              />

            </button>

            {/* Profile menu */}

            {profileOpen && (
              <>

                {/* Overlay */}

                <button
                  type="button"
                  aria-label="Close profile menu"
                  onClick={() =>
                    setProfileOpen(false)
                  }
                  className="fixed inset-0 z-40 cursor-default"
                />

                {/* Menu */}

                <div className="absolute right-0 z-50 mt-2 w-64 overflow-hidden rounded-xl border border-slate-800 bg-slate-900 shadow-2xl">

                  {/* User information */}

                  <div className="border-b border-slate-800 p-4">

                    <div className="flex items-center gap-3">

                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/10 font-semibold text-blue-400">
                        {avatarLetter}
                      </div>

                      <div className="min-w-0">

                        <p className="truncate text-sm font-medium text-white">
                          {displayName}
                        </p>

                        <p className="truncate text-xs text-slate-500">
                          @{username}
                        </p>

                      </div>

                    </div>

                    <div className="mt-3 rounded-lg bg-slate-950 p-3">

                      <p className="text-[10px] uppercase tracking-wider text-slate-600">
                        Account Role
                      </p>

                      <p className="mt-1 text-xs font-medium text-slate-300">
                        {roleTitle}
                      </p>

                    </div>

                  </div>

                  {/* Actions */}

                  <div className="p-2">

                    <button
                      type="button"
                      onClick={handleLogout}
                      className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-red-400 transition hover:bg-red-500/10"
                    >

                      <LogOut className="h-4 w-4" />

                      Logout

                    </button>

                  </div>

                </div>

              </>

            )}

          </div>

        </header>

        {/* ==================================================
            API ERROR
            ================================================== */}

        {apiError && (
          <div className="border-b border-red-500/20 bg-red-500/5 px-4 py-2 sm:px-6">

            <div className="mx-auto flex max-w-[1600px] items-center gap-2">

              <X className="h-4 w-4 text-red-400" />

              <p className="text-xs text-red-300">
                Backend connection unavailable.
                Some security data may not be current.
              </p>

            </div>

          </div>
        )}

        {/* ==================================================
            PAGE CONTENT
            ================================================== */}

        <main className="min-h-[calc(100vh-4rem)] p-4 sm:p-6">

          <div className="mx-auto max-w-[1600px]">

            <Outlet
              context={{
                apiStatus,
                apiError,
                apiLoading,
              }}
            />

          </div>

        </main>

      </div>

    </div>
  );
}

export default Layout;