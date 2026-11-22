import {
  useEffect,
  useState,
} from "react";

import {
  Activity,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Search,
  ShieldCheck,
  Monitor,
} from "lucide-react";

import {
  getNetworkEventsPaginated,
} from "../services/api";

const PAGE_SIZE = 100;

function normalizeEvent(event) {
  return {
    ...event,

    id:
      event?.id ??
      event?.event_id ??
      null,

    sourceIp:
      event?.source_ip ||
      event?.sourceIp ||
      "",

    destinationIp:
      event?.destination_ip ||
      event?.destinationIp ||
      "",

    protocol:
      event?.protocol ||
      "UNKNOWN",

    port:
      event?.port ??
      "—",

    eventType:
      event?.event_type ||
      event?.eventType ||
      "UNKNOWN",

    risk:
      String(
        event?.risk ||
          event?.risk_level ||
          "low"
      ).toLowerCase(),

    timestamp:
      event?.timestamp ||
      event?.created_at ||
      null,

    threatId:
      event?.threat_id ??
      event?.threatId ??
      null,

    deviceId:
      event?.device_id ??
      event?.deviceId ??
      null,

    deviceName:
      event?.device_name ||
      event?.connected_device_name ||
      "",

    deviceIp:
      event?.device_ip ||
      "",

    deviceType:
      event?.device_type ||
      "",

    deviceOperatingSystem:
      event?.device_operating_system ||
      event?.operating_system ||
      "",

    deviceStatus:
      event?.device_status ||
      "",
  };
}

function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function getRiskClass(risk) {
  switch (
    String(risk || "").toLowerCase()
  ) {
    case "critical":
      return "border-red-500/30 bg-red-500/10 text-red-300";

    case "high":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";

    case "medium":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";

    case "low":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";

    default:
      return "border-slate-700 bg-slate-800 text-slate-300";
  }
}

function NetworkActivity() {
  const [events, setEvents] =
    useState([]);

  const [page, setPage] =
    useState(0);

  const [search, setSearch] =
    useState("");

  const [riskFilter, setRiskFilter] =
    useState("all");

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [lastUpdated, setLastUpdated] =
    useState(null);

  const [hasNextPage, setHasNextPage] =
    useState(false);

  const loadEvents = async (
    showRefresh = false
  ) => {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const data =
        await getNetworkEventsPaginated(
          PAGE_SIZE,
          page * PAGE_SIZE
        );

      console.log(
        "ZeroGuard network events:",
        data
      );

      if (!Array.isArray(data)) {
        throw new Error(
          "Invalid response received from network-events API."
        );
      }

      const formatted =
        data.map(normalizeEvent);

      setEvents(formatted);

      setHasNextPage(
        data.length === PAGE_SIZE
      );

      setLastUpdated(
        new Date()
      );
    } catch (err) {
      console.error(
        "Network events loading error:",
        err
      );

      setError(
        err?.message ||
          "Unable to load network events."
      );

      setEvents([]);
      setHasNextPage(false);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [page]);

  useEffect(() => {
    const interval =
      setInterval(() => {
        loadEvents();
      }, 10000);

    return () => {
      clearInterval(interval);
    };
  }, [page]);

  const searchText =
    search
      .toLowerCase()
      .trim();

  const filteredEvents =
    events.filter(
      (event) => {
        const matchesSearch =
          !searchText ||
          event.sourceIp
            .toLowerCase()
            .includes(searchText) ||
          event.destinationIp
            .toLowerCase()
            .includes(searchText) ||
          event.protocol
            .toLowerCase()
            .includes(searchText) ||
          event.eventType
            .toLowerCase()
            .includes(searchText) ||
          String(event.port)
            .toLowerCase()
            .includes(searchText) ||
          event.deviceName
            .toLowerCase()
            .includes(searchText) ||
          String(event.deviceId ?? "")
            .toLowerCase()
            .includes(searchText) ||
          event.deviceIp
            .toLowerCase()
            .includes(searchText);

        const matchesRisk =
          riskFilter === "all" ||
          event.risk ===
            riskFilter;

        return (
          matchesSearch &&
          matchesRisk
        );
      }
    );

  const highCount =
    events.filter(
      (event) =>
        event.risk === "high" ||
        event.risk === "critical"
    ).length;

  const mediumCount =
    events.filter(
      (event) =>
        event.risk === "medium"
    ).length;

  const threatLinkedCount =
    events.filter(
      (event) =>
        event.threatId !==
          null &&
        event.threatId !==
          undefined
    ).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            Security Operations
          </p>

          <h1 className="mt-2 text-3xl font-bold text-white">
            Network Activity
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Live network events collected by
            the ZeroGuard monitoring engine.
          </p>
        </div>

        <button
          type="button"
          onClick={() =>
            loadEvents(true)
          }
          disabled={refreshing}
          className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:border-cyan-500/50 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            size={17}
            className={
              refreshing
                ? "animate-spin"
                : ""
            }
          />

          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Events on Page
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {events.length}
              </p>
            </div>

            <Activity
              size={24}
              className="text-cyan-400"
            />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                High Risk
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {highCount}
              </p>
            </div>

            <AlertTriangle
              size={24}
              className="text-orange-400"
            />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Threat Linked
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {threatLinkedCount}
              </p>
            </div>

            <ShieldCheck
              size={24}
              className="text-emerald-400"
            />
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="flex flex-col gap-3 lg:flex-row">
          <div className="relative flex-1">
            <Search
              size={17}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <input
              type="text"
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value
                )
              }
              placeholder="Search IP, device, protocol, event type, port..."
              className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3 pl-10 pr-4 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-500"
            />
          </div>

          <select
            value={riskFilter}
            onChange={(event) =>
              setRiskFilter(
                event.target.value
              )
            }
            className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500"
          >
            <option value="all">
              All Risk Levels
            </option>

            <option value="low">
              Low
            </option>

            <option value="medium">
              Medium
            </option>

            <option value="high">
              High
            </option>

            <option value="critical">
              Critical
            </option>
          </select>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <span>
            Page {page + 1}
          </span>

          {lastUpdated && (
            <span>
              Last updated:{" "}
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {loading ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-10 text-center">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

          <p className="mt-4 text-sm text-slate-400">
            Loading network events...
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1350px]">
              <thead className="border-b border-slate-800 bg-slate-950/80">
                <tr>
                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    ID
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Source
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Destination
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Device
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Protocol
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Port
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Event
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Risk
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Threat
                  </th>

                  <th className="px-4 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Timestamp
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-800">
                {filteredEvents.map(
                  (event) => (
                    <tr
                      key={event.id}
                      className="transition hover:bg-slate-800/40"
                    >
                      <td className="px-4 py-4 text-sm font-medium text-slate-300">
                        {event.id}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-200">
                        {event.sourceIp ||
                          "—"}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-200">
                        {event.destinationIp ||
                          "—"}
                      </td>

                      <td className="px-4 py-4">
                        {event.deviceId !==
                          null &&
                        event.deviceId !==
                          undefined ? (
                          <div className="flex items-center gap-3">
                            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                              <Monitor
                                size={17}
                                className="text-cyan-400"
                              />
                            </div>

                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="max-w-[150px] truncate text-sm font-semibold text-white">
                                  {event.deviceName ||
                                    "Unknown Device"}
                                </span>

                                <span className="text-xs text-cyan-400">
                                  #{event.deviceId}
                                </span>
                              </div>

                              <p className="mt-1 max-w-[170px] truncate text-xs text-slate-500">
                                {event.deviceIp ||
                                  "IP unavailable"}
                              </p>
                            </div>
                          </div>
                        ) : (
                          <div className="text-sm text-slate-600">
                            Unknown
                          </div>
                        )}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-300">
                        {event.protocol}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-300">
                        {event.port}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-300">
                        {event.eventType}
                      </td>

                      <td className="px-4 py-4">
                        <span
                          className={`rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${getRiskClass(
                            event.risk
                          )}`}
                        >
                          {event.risk}
                        </span>
                      </td>

                      <td className="px-4 py-4 text-sm">
                        {event.threatId !==
                        null &&
                        event.threatId !==
                          undefined ? (
                          <span className="text-cyan-400">
                            #{event.threatId}
                          </span>
                        ) : (
                          <span className="text-slate-600">
                            —
                          </span>
                        )}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-500">
                        {formatDate(
                          event.timestamp
                        )}
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>
          </div>

          {filteredEvents.length ===
            0 && (
            <div className="p-10 text-center">
              <p className="text-sm text-slate-500">
                No network events match
                your search/filter.
              </p>
            </div>
          )}

          <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950/50 px-4 py-4">
            <button
              type="button"
              onClick={() =>
                setPage(
                  (current) =>
                    Math.max(
                      0,
                      current - 1
                    )
                )
              }
              disabled={
                page === 0 ||
                loading
              }
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft
                size={17}
              />

              Previous
            </button>

            <span className="text-xs text-slate-500">
              Page {page + 1}
            </span>

            <button
              type="button"
              onClick={() =>
                setPage(
                  (current) =>
                    current + 1
                )
              }
              disabled={
                !hasNextPage ||
                loading
              }
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next

              <ChevronRight
                size={17}
              />
            </button>
          </div>
        </div>
      )}

      <div className="text-xs text-slate-600">
        Medium-risk events on this page:{" "}
        {mediumCount}
      </div>
    </div>
  );
}

export default NetworkActivity;