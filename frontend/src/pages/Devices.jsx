import { useEffect, useMemo, useState } from "react";

import {
  Activity,
  Computer,
  Copy,
  Cpu,
  Globe,
  KeyRound,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";

import {
  createDevicePairing,
  getDevices,
} from "../services/api";

function normalizeDevice(device) {
  return {
    id: device.id,
    name:
      device.name ||
      device.device_name ||
      `Device ${device.id}`,

    deviceName:
      device.device_name ||
      device.name ||
      `Device ${device.id}`,

    ip:
      device.ip_address ||
      "Unknown",

    mac:
      device.mac_address ||
      "Unknown",

    type:
      device.device_type ||
      "Computer",

    operatingSystem:
      device.operating_system ||
      "Unknown",

    status:
      device.status ||
      "offline",

    risk:
      device.risk_level ||
      "low",

    firstSeen:
      device.first_seen ||
      device.created_at ||
      null,

    lastSeen:
      device.last_seen ||
      null,
  };
}

function formatDate(value) {
  if (!value) {
    return "Never";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function getRiskClass(risk) {
  switch (String(risk).toLowerCase()) {
    case "critical":
      return "text-red-400 bg-red-500/10 border-red-500/20";

    case "high":
      return "text-orange-400 bg-orange-500/10 border-orange-500/20";

    case "medium":
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";

    default:
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  }
}

function getStatusClass(status) {
  if (String(status).toLowerCase() === "online") {
    return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  }

  return "text-slate-400 bg-slate-500/10 border-slate-500/20";
}

function isRecentlySeen(lastSeen) {
  if (!lastSeen) {
    return false;
  }

  const timestamp = new Date(lastSeen).getTime();

  if (Number.isNaN(timestamp)) {
    return false;
  }

  return Date.now() - timestamp <= 5 * 60 * 1000;
}

export default function Devices() {
  const [devices, setDevices] = useState([]);

  const [search, setSearch] = useState("");

  const [filter, setFilter] = useState("all");

  const [selectedDevice, setSelectedDevice] = useState(null);

  const [loading, setLoading] = useState(true);

  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");

  const [pairingOpen, setPairingOpen] = useState(false);

  const [pairingLoading, setPairingLoading] = useState(false);

  const [pairingCode, setPairingCode] = useState("");

  const [pairingExpires, setPairingExpires] = useState("");

  const [pairingError, setPairingError] = useState("");

  async function loadDevices(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const response = await getDevices();

      let rows = [];

      if (Array.isArray(response)) {
        rows = response;
      } else if (Array.isArray(response?.devices)) {
        rows = response.devices;
      } else if (Array.isArray(response?.value)) {
        rows = response.value;
      }

      setDevices(rows.map(normalizeDevice));
    } catch (err) {
      console.error("Failed to load devices:", err);

      setError(
        err?.message ||
        "Unable to load devices from the ZeroGuard backend."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadDevices();

    const interval = setInterval(() => {
      loadDevices(true);
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  async function handleGeneratePairing() {
    try {
      setPairingLoading(true);
      setPairingError("");
      setPairingCode("");
      setPairingExpires("");

      const response = await createDevicePairing();

      setPairingCode(response?.pairing_code || "");

      setPairingExpires(
        response?.expires_at ||
        ""
      );
    } catch (err) {
      console.error("Pairing generation failed:", err);

      setPairingError(
        err?.message ||
        "Unable to generate a pairing code."
      );
    } finally {
      setPairingLoading(false);
    }
  }

  async function handleCopyPairingCode() {
    if (!pairingCode) {
      return;
    }

    try {
      await navigator.clipboard.writeText(pairingCode);
    } catch (err) {
      console.error("Could not copy pairing code:", err);
    }
  }

  const filteredDevices = useMemo(() => {
    const searchValue = search.trim().toLowerCase();

    return devices.filter((device) => {
      const matchesSearch =
        !searchValue ||
        device.name.toLowerCase().includes(searchValue) ||
        device.ip.toLowerCase().includes(searchValue) ||
        device.mac.toLowerCase().includes(searchValue) ||
        device.operatingSystem.toLowerCase().includes(searchValue);

      const matchesFilter =
        filter === "all" ||
        (filter === "online" &&
          device.status.toLowerCase() === "online") ||
        (filter === "offline" &&
          device.status.toLowerCase() !== "online") ||
        (filter === "high" &&
          ["high", "critical"].includes(
            device.risk.toLowerCase()
          ));

      return matchesSearch && matchesFilter;
    });
  }, [devices, search, filter]);

  const totalDevices = devices.length;

  const onlineDevices = devices.filter(
    (device) =>
      device.status.toLowerCase() === "online"
  ).length;

  const highRiskDevices = devices.filter(
    (device) =>
      ["high", "critical"].includes(
        device.risk.toLowerCase()
      )
  ).length;

  const recentlyConnected = devices.filter(
    (device) => isRecentlySeen(device.lastSeen)
  ).length;

  return (
    <div className="space-y-6">

      {/* HEADER */}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

        <div>
          <h1 className="text-2xl font-bold text-white">
            Devices
          </h1>

          <p className="mt-1 text-sm text-slate-400">
            Connected endpoints monitored by ZeroGuard.
          </p>
        </div>

        <div className="flex gap-2">

          <button
            onClick={() => loadDevices(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800 disabled:opacity-50"
          >
            <RefreshCw
              size={16}
              className={
                refreshing
                  ? "animate-spin"
                  : ""
              }
            />

            Refresh
          </button>

          <button
            onClick={() => {
              setPairingOpen(true);
              setPairingError("");
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-500"
          >
            <KeyRound size={16} />

            Connect Device
          </button>

        </div>

      </div>

      {/* ERROR */}

      {error && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* SUMMARY */}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>
              <p className="text-sm text-slate-400">
                Total Devices
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {totalDevices}
              </p>
            </div>

            <div className="rounded-lg bg-blue-500/10 p-3 text-blue-400">
              <Computer size={22} />
            </div>

          </div>

        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>
              <p className="text-sm text-slate-400">
                Online
              </p>

              <p className="mt-2 text-3xl font-bold text-emerald-400">
                {onlineDevices}
              </p>
            </div>

            <div className="rounded-lg bg-emerald-500/10 p-3 text-emerald-400">
              <Wifi size={22} />
            </div>

          </div>

        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>
              <p className="text-sm text-slate-400">
                High Risk
              </p>

              <p className="mt-2 text-3xl font-bold text-orange-400">
                {highRiskDevices}
              </p>
            </div>

            <div className="rounded-lg bg-orange-500/10 p-3 text-orange-400">
              <ShieldCheck size={22} />
            </div>

          </div>

        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>
              <p className="text-sm text-slate-400">
                Recently Seen
              </p>

              <p className="mt-2 text-3xl font-bold text-cyan-400">
                {recentlyConnected}
              </p>
            </div>

            <div className="rounded-lg bg-cyan-500/10 p-3 text-cyan-400">
              <Activity size={22} />
            </div>

          </div>

        </div>

      </div>

      {/* SEARCH / FILTER */}

      <div className="flex flex-col gap-3 md:flex-row">

        <div className="relative flex-1">

          <Search
            size={18}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
          />

          <input
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
            placeholder="Search device, IP, MAC or operating system..."
            className="w-full rounded-lg border border-slate-800 bg-slate-900 py-3 pl-10 pr-4 text-sm text-white outline-none placeholder:text-slate-500 focus:border-blue-500"
          />

        </div>

        <select
          value={filter}
          onChange={(event) =>
            setFilter(event.target.value)
          }
          className="rounded-lg border border-slate-800 bg-slate-900 px-4 py-3 text-sm text-slate-200 outline-none focus:border-blue-500"
        >
          <option value="all">
            All Devices
          </option>

          <option value="online">
            Online
          </option>

          <option value="offline">
            Offline
          </option>

          <option value="high">
            High Risk
          </option>
        </select>

      </div>

      {/* LOADING */}

      {loading ? (
        <div className="flex min-h-[300px] items-center justify-center rounded-xl border border-slate-800 bg-slate-900/60">

          <div className="flex items-center gap-3 text-slate-400">

            <RefreshCw
              size={20}
              className="animate-spin"
            />

            Loading devices...

          </div>

        </div>
      ) : filteredDevices.length === 0 ? (

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center">

          <Computer
            size={42}
            className="mx-auto text-slate-600"
          />

          <h3 className="mt-4 text-lg font-semibold text-white">
            No devices found
          </h3>

          <p className="mt-2 text-sm text-slate-500">
            Connect a Windows device using a ZeroGuard agent.
          </p>

        </div>

      ) : (

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

          {filteredDevices.map((device) => {

            const online =
              device.status.toLowerCase() ===
              "online";

            return (
              <button
                key={device.id}
                onClick={() =>
                  setSelectedDevice(device)
                }
                className="group rounded-xl border border-slate-800 bg-slate-900/60 p-5 text-left transition hover:border-blue-500/40 hover:bg-slate-900"
              >

                <div className="flex items-start justify-between gap-4">

                  <div className="flex min-w-0 items-center gap-3">

                    <div className="rounded-lg bg-blue-500/10 p-3 text-blue-400">
                      {device.type
                        .toLowerCase()
                        .includes("server") ? (
                        <Server size={22} />
                      ) : (
                        <Computer size={22} />
                      )}
                    </div>

                    <div className="min-w-0">

                      <h3 className="truncate font-semibold text-white">
                        {device.name}
                      </h3>

                      <p className="mt-1 text-xs text-slate-500">
                        Device #{device.id}
                      </p>

                    </div>

                  </div>

                  <span
                    className={`rounded-full border px-2.5 py-1 text-xs font-medium ${getStatusClass(
                      device.status
                    )}`}
                  >
                    {online
                      ? "Online"
                      : "Offline"}
                  </span>

                </div>

                <div className="mt-5 grid grid-cols-2 gap-3">

                  <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">

                    <p className="text-xs text-slate-500">
                      IP Address
                    </p>

                    <p className="mt-1 truncate text-sm text-slate-200">
                      {device.ip}
                    </p>

                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">

                    <p className="text-xs text-slate-500">
                      Device Type
                    </p>

                    <p className="mt-1 truncate text-sm text-slate-200">
                      {device.type}
                    </p>

                  </div>

                </div>

                <div className="mt-3 flex items-center justify-between">

                  <span
                    className={`rounded-md border px-2 py-1 text-xs ${getRiskClass(
                      device.risk
                    )}`}
                  >
                    Risk: {device.risk}
                  </span>

                  <span className="text-xs text-slate-500">
                    Last seen:{" "}
                    {formatDate(
                      device.lastSeen
                    )}
                  </span>

                </div>

              </button>
            );
          })}

        </div>
      )}

      {/* DEVICE DETAILS MODAL */}

      {selectedDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">

          <div className="w-full max-w-2xl rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl">

            <div className="flex items-center justify-between border-b border-slate-800 p-5">

              <div>

                <h2 className="text-xl font-bold text-white">
                  {selectedDevice.name}
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Device #{selectedDevice.id}
                </p>

              </div>

              <button
                onClick={() =>
                  setSelectedDevice(null)
                }
                className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X size={20} />
              </button>

            </div>

            <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-2">

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-xs text-slate-500">
                  IP Address
                </p>

                <p className="mt-2 text-sm text-white">
                  {selectedDevice.ip}
                </p>

              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-xs text-slate-500">
                  MAC Address
                </p>

                <p className="mt-2 break-all text-sm text-white">
                  {selectedDevice.mac}
                </p>

              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-xs text-slate-500">
                  Operating System
                </p>

                <p className="mt-2 text-sm text-white">
                  {selectedDevice.operatingSystem}
                </p>

              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-xs text-slate-500">
                  Device Type
                </p>

                <p className="mt-2 text-sm text-white">
                  {selectedDevice.type}
                </p>

              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-xs text-slate-500">
                  Status
                </p>

                <p
                  className={`mt-2 text-sm font-medium ${selectedDevice.status ===
                      "online"
                      ? "text-emerald-400"
                      : "text-slate-400"
                    }`}
                >
                  {selectedDevice.status}
                </p>

              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-xs text-slate-500">
                  Last Seen
                </p>

                <p className="mt-2 text-sm text-white">
                  {formatDate(
                    selectedDevice.lastSeen
                  )}
                </p>

              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 sm:col-span-2">

                <div className="flex items-center gap-2">

                  <ShieldCheck
                    size={18}
                    className="text-emerald-400"
                  />

                  <p className="text-sm font-medium text-white">
                    ZeroGuard Monitoring
                  </p>

                </div>

                <p className="mt-2 text-sm text-slate-400">
                  This endpoint is registered with
                  ZeroGuard and its telemetry is being
                  monitored by the SOC.
                </p>

              </div>

            </div>

          </div>

        </div>
      )}

      {/* CONNECT DEVICE MODAL */}

      {pairingOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">

          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl">

            <div className="flex items-center justify-between border-b border-slate-800 p-5">

              <div>

                <h2 className="text-xl font-bold text-white">
                  Connect Device
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Pair a ZeroGuard agent with this SOC.
                </p>

              </div>

              <button
                onClick={() =>
                  setPairingOpen(false)
                }
                className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X size={20} />
              </button>

            </div>

            <div className="space-y-5 p-5">

              <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">

                <div className="flex gap-3">

                  <KeyRound
                    size={20}
                    className="mt-0.5 text-blue-400"
                  />

                  <div>

                    <p className="font-medium text-white">
                      Generate a pairing code
                    </p>

                    <p className="mt-1 text-sm text-slate-400">
                      The code is temporary and is used
                      by a ZeroGuard agent to register
                      a new device.
                    </p>

                  </div>

                </div>

              </div>

              {pairingCode && (
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5 text-center">

                  <p className="text-xs uppercase tracking-wider text-emerald-400">
                    Pairing Code
                  </p>

                  <div className="mt-3 flex items-center justify-center gap-3">

                    <p className="font-mono text-3xl font-bold tracking-widest text-white">
                      {pairingCode}
                    </p>

                    <button
                      onClick={handleCopyPairingCode}
                      className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800"
                      title="Copy pairing code"
                    >
                      <Copy size={17} />
                    </button>

                  </div>

                  {pairingExpires && (
                    <p className="mt-3 text-xs text-slate-500">
                      Expires:{" "}
                      {formatDate(
                        pairingExpires
                      )}
                    </p>
                  )}

                </div>
              )}

              {pairingError && (
                <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">
                  {pairingError}
                </div>
              )}

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">

                <p className="text-sm font-medium text-white">
                  Windows agent
                </p>

                <ol className="mt-3 space-y-2 text-sm text-slate-400">

                  <li>
                    1. Open the ZeroGuard agent folder on
                    the Windows device.
                  </li>

                  <li>
                    2. Run{" "}
                    <span className="font-mono text-slate-200">
                      zeroguard_agent.py
                    </span>
                  </li>

                  <li>
                    3. Enter the generated pairing code.
                  </li>

                  <li>
                    4. The device will appear here
                    automatically.
                  </li>

                </ol>

              </div>

              <button
                onClick={handleGeneratePairing}
                disabled={pairingLoading}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-3 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
              >

                {pairingLoading ? (
                  <>
                    <RefreshCw
                      size={17}
                      className="animate-spin"
                    />

                    Generating...
                  </>
                ) : (
                  <>
                    <KeyRound size={17} />

                    Generate Pairing Code
                  </>
                )}

              </button>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}