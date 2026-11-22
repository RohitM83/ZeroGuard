import { useEffect, useState } from "react";
import {
  Bell,
  CheckCircle2,
  Database,
  Globe,
  Lock,
  Monitor,
  RefreshCw,
  Save,
  Server,
  Shield,
  SlidersHorizontal,
} from "lucide-react";

import {
  getDatabaseSummary,
  getHealth,
  getStatus,
} from "../services/api";

function SectionCard({ icon: Icon, title, description, children }) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg">
      <div className="flex items-start gap-3 border-b border-slate-800 px-6 py-5">
        <div className="rounded-xl bg-blue-500/10 p-2.5 text-blue-400">
          <Icon size={20} />
        </div>

        <div>
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <p className="mt-1 text-sm text-slate-400">{description}</p>
        </div>
      </div>

      <div className="p-6">{children}</div>
    </section>
  );
}

function Toggle({ checked, onChange, label, description }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-6 rounded-xl border border-slate-800 bg-slate-950/40 p-4">
      <div>
        <p className="font-medium text-white">{label}</p>
        <p className="mt-1 text-sm text-slate-400">{description}</p>
      </div>

      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-11 shrink-0 rounded-full transition ${
          checked ? "bg-blue-600" : "bg-slate-700"
        }`}
        aria-pressed={checked}
      >
        <span
          className={`absolute top-1 h-4 w-4 rounded-full bg-white transition ${
            checked ? "left-6" : "left-1"
          }`}
        />
      </button>
    </label>
  );
}

function StatusRow({ label, value, ok = true }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 py-3 last:border-b-0">
      <span className="text-sm text-slate-400">{label}</span>

      <div className="flex items-center gap-2">
        <span
          className={`h-2.5 w-2.5 rounded-full ${
            ok ? "bg-emerald-400" : "bg-red-400"
          }`}
        />

        <span
          className={`text-sm font-medium ${
            ok ? "text-emerald-400" : "text-red-400"
          }`}
        >
          {value}
        </span>
      </div>
    </div>
  );
}

export default function Settings() {
  const [settings, setSettings] = useState({
    autoRefresh: true,
    threatNotifications: true,
    incidentNotifications: true,
    responseNotifications: true,
    soundAlerts: false,
    compactMode: false,
  });

  const [systemStatus, setSystemStatus] = useState({
    backend: "Checking...",
    health: "Checking...",
    database: "Checking...",
    devices: 0,
    threats: 0,
    incidents: 0,
    actions: 0,
  });

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const storedSettings = localStorage.getItem("zeroguard_settings");

    if (storedSettings) {
      try {
        setSettings((previous) => ({
          ...previous,
          ...JSON.parse(storedSettings),
        }));
      } catch (err) {
        console.error("Could not load saved settings:", err);
      }
    }

    loadSystemStatus();

    const interval = setInterval(() => {
      if (settings.autoRefresh) {
        loadSystemStatus(true);
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [settings.autoRefresh]);

  async function loadSystemStatus(isRefresh = false) {
    if (isRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    setError("");

    try {
      const [status, health, database] = await Promise.all([
        getStatus(),
        getHealth(),
        getDatabaseSummary(),
      ]);

      setSystemStatus({
        backend:
          status?.status ||
          status?.message ||
          "Online",

        health:
          health?.status ||
          health?.message ||
          "Healthy",

        database:
          database?.status ||
          "Connected",

        devices:
          Number(database?.devices ?? 0),

        threats:
          Number(database?.threats ?? 0),

        incidents:
          Number(database?.incidents ?? 0),

        actions:
          Number(database?.response_actions ?? 0),
      });
    } catch (err) {
      console.error("Settings status error:", err);

      setError(
        err?.message ||
          "Unable to retrieve ZeroGuard system status."
      );

      setSystemStatus((previous) => ({
        ...previous,
        backend: "Unavailable",
        health: "Unavailable",
        database: "Unavailable",
      }));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  function updateSetting(key, value) {
    setSettings((previous) => ({
      ...previous,
      [key]: value,
    }));

    setSaved(false);
  }

  function saveSettings() {
    localStorage.setItem(
      "zeroguard_settings",
      JSON.stringify(settings)
    );

    setSaved(true);

    setTimeout(() => {
      setSaved(false);
    }, 2500);
  }

  function resetSettings() {
    const defaults = {
      autoRefresh: true,
      threatNotifications: true,
      incidentNotifications: true,
      responseNotifications: true,
      soundAlerts: false,
      compactMode: false,
    };

    setSettings(defaults);
    localStorage.setItem(
      "zeroguard_settings",
      JSON.stringify(defaults)
    );

    setSaved(true);

    setTimeout(() => {
      setSaved(false);
    }, 2500);
  }

  return (
    <div className="min-h-full bg-slate-950 p-4 text-slate-200 sm:p-6 lg:p-8">
      <div className="mx-auto max-w-7xl space-y-6">

        {/* Header */}
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
          <div>
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-blue-500/10 p-3 text-blue-400">
                <SlidersHorizontal size={24} />
              </div>

              <div>
                <h1 className="text-2xl font-bold text-white">
                  Settings
                </h1>

                <p className="mt-1 text-sm text-slate-400">
                  Configure ZeroGuard monitoring, notifications and system preferences.
                </p>
              </div>
            </div>
          </div>

          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => loadSystemStatus(true)}
              disabled={refreshing}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCw
                size={17}
                className={refreshing ? "animate-spin" : ""}
              />

              Refresh
            </button>

            <button
              type="button"
              onClick={saveSettings}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-500"
            >
              <Save size={17} />
              Save Settings
            </button>
          </div>
        </div>

        {/* Messages */}
        {saved && (
          <div className="flex items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
            <CheckCircle2 size={18} />
            Settings saved successfully.
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="grid gap-6 lg:grid-cols-2">

          {/* Monitoring */}
          <SectionCard
            icon={Monitor}
            title="Monitoring"
            description="Control how ZeroGuard keeps the SOC dashboard updated."
          >
            <div className="space-y-3">
              <Toggle
                checked={settings.autoRefresh}
                onChange={(value) =>
                  updateSetting("autoRefresh", value)
                }
                label="Automatic refresh"
                description="Refresh monitoring data automatically every 10 seconds."
              />

              <Toggle
                checked={settings.compactMode}
                onChange={(value) =>
                  updateSetting("compactMode", value)
                }
                label="Compact interface"
                description="Use a denser dashboard layout when supported."
              />
            </div>
          </SectionCard>

          {/* Notifications */}
          <SectionCard
            icon={Bell}
            title="Notifications"
            description="Choose which security events should generate notifications."
          >
            <div className="space-y-3">
              <Toggle
                checked={settings.threatNotifications}
                onChange={(value) =>
                  updateSetting("threatNotifications", value)
                }
                label="Threat notifications"
                description="Notify when ZeroGuard records a new threat."
              />

              <Toggle
                checked={settings.incidentNotifications}
                onChange={(value) =>
                  updateSetting("incidentNotifications", value)
                }
                label="Incident notifications"
                description="Notify when incidents are created or updated."
              />

              <Toggle
                checked={settings.responseNotifications}
                onChange={(value) =>
                  updateSetting("responseNotifications", value)
                }
                label="Response action notifications"
                description="Notify when defensive response actions change state."
              />

              <Toggle
                checked={settings.soundAlerts}
                onChange={(value) =>
                  updateSetting("soundAlerts", value)
                }
                label="Sound alerts"
                description="Enable browser sound alerts for supported notifications."
              />
            </div>
          </SectionCard>

          {/* Security */}
          <SectionCard
            icon={Shield}
            title="Security"
            description="ZeroGuard security and response configuration."
          >
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <div className="flex items-start gap-3">
                  <Lock className="mt-0.5 text-emerald-400" size={19} />

                  <div>
                    <p className="font-medium text-white">
                      Defensive authorization enabled
                    </p>

                    <p className="mt-1 text-sm leading-6 text-slate-400">
                      High-impact response actions require the backend
                      authorization checks before execution.
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
                <p className="text-sm font-semibold text-amber-300">
                  Automatic blocking protection
                </p>

                <p className="mt-1 text-sm leading-6 text-slate-400">
                  ZeroGuard does not automatically block a source from a
                  GNN anomaly alone. Critical risk and additional safety
                  conditions are required.
                </p>
              </div>
            </div>
          </SectionCard>

          {/* System */}
          <SectionCard
            icon={Server}
            title="System Status"
            description="Live connection information from the ZeroGuard backend."
          >
            {loading ? (
              <div className="flex items-center justify-center py-10">
                <RefreshCw
                  size={24}
                  className="animate-spin text-blue-400"
                />
              </div>
            ) : (
              <div>
                <StatusRow
                  label="Backend API"
                  value={systemStatus.backend}
                  ok={systemStatus.backend !== "Unavailable"}
                />

                <StatusRow
                  label="Health"
                  value={systemStatus.health}
                  ok={systemStatus.health !== "Unavailable"}
                />

                <StatusRow
                  label="Database"
                  value={systemStatus.database}
                  ok={systemStatus.database !== "Unavailable"}
                />
              </div>
            )}
          </SectionCard>

          {/* Database */}
          <SectionCard
            icon={Database}
            title="Database Overview"
            description="Current ZeroGuard database record counts."
          >
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Devices
                </p>
                <p className="mt-2 text-2xl font-bold text-white">
                  {systemStatus.devices}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Threats
                </p>
                <p className="mt-2 text-2xl font-bold text-white">
                  {systemStatus.threats}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Incidents
                </p>
                <p className="mt-2 text-2xl font-bold text-white">
                  {systemStatus.incidents}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Response Actions
                </p>
                <p className="mt-2 text-2xl font-bold text-white">
                  {systemStatus.actions}
                </p>
              </div>
            </div>
          </SectionCard>

          {/* Network */}
          <SectionCard
            icon={Globe}
            title="Network Configuration"
            description="Current ZeroGuard local API configuration."
          >
            <div className="space-y-4">
              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                  API Endpoint
                </p>

                <div className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-sm text-blue-300">
                  http://127.0.0.1:8000
                </div>
              </div>

              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                  Frontend
                </p>

                <div className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-sm text-slate-300">
                  React + Vite + Tailwind CSS
                </div>
              </div>

              <div>
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                  Detection Engine
                </p>

                <div className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-sm text-slate-300">
                  Graph Neural Network + Risk Correlator
                </div>
              </div>
            </div>
          </SectionCard>
        </div>

        {/* Bottom controls */}
        <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:flex-row sm:items-center">
          <div>
            <h3 className="font-semibold text-white">
              Reset preferences
            </h3>

            <p className="mt-1 text-sm text-slate-400">
              Restore ZeroGuard frontend settings to their default values.
            </p>
          </div>

          <button
            type="button"
            onClick={resetSettings}
            className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white"
          >
            Reset Settings
          </button>
        </div>

        <div className="pb-4 text-center text-xs text-slate-500">
          ZeroGuard Security Operations Center • Settings
        </div>
      </div>
    </div>
  );
}