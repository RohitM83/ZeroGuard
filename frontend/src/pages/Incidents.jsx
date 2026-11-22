import { useEffect, useMemo, useState } from "react";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Eye,
  FileWarning,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Target,
  XCircle,
  Zap,
} from "lucide-react";

import {
  getIncidents,
  getThreats,
  getThreatNetworkEvents,
  getResponseActions,
  updateIncidentStatus,
} from "../services/api";

/* =========================================================
   Utility Functions
========================================================= */

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function formatNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return number.toLocaleString();
}

function normalizeRiskLevel(value) {
  const risk = String(value || "").toLowerCase();

  if (risk.includes("critical")) return "critical";
  if (risk.includes("high")) return "high";
  if (risk.includes("medium")) return "medium";
  if (risk.includes("low")) return "low";

  return "unknown";
}

function getRiskLevel(incident, threat = null) {
  return normalizeRiskLevel(
    incident?.risk_level ||
      incident?.severity ||
      incident?.risk ||
      incident?.status_level ||
      threat?.severity ||
      "unknown"
  );
}

function getRiskBadgeClass(level) {
  switch (normalizeRiskLevel(level)) {
    case "critical":
      return "border-red-500/30 bg-red-500/10 text-red-300";

    case "high":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";

    case "medium":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";

    case "low":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";

    default:
      return "border-slate-500/30 bg-slate-500/10 text-slate-300";
  }
}

function getStatusBadgeClass(status) {
  const value = String(status || "").toLowerCase();

  if (value === "resolved") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }

  if (
    value === "investigating" ||
    value === "in_progress" ||
    value === "active"
  ) {
    return "border-blue-500/30 bg-blue-500/10 text-blue-300";
  }

  if (value === "new") {
    return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  }

  return "border-slate-500/30 bg-slate-500/10 text-slate-300";
}

function getActionIcon(actionType) {
  const action = String(actionType || "").toLowerCase();

  if (action.includes("alert")) {
    return AlertTriangle;
  }

  if (action.includes("block")) {
    return ShieldAlert;
  }

  if (action.includes("isolate")) {
    return ShieldCheck;
  }

  if (action.includes("terminate")) {
    return XCircle;
  }

  if (action.includes("quarantine")) {
    return ShieldAlert;
  }

  return Zap;
}

function extractNumber(text, pattern) {
  if (!text) return null;

  const match = String(text).match(pattern);

  if (!match) return null;

  const number = Number(match[1]);

  return Number.isFinite(number) ? number : null;
}

function extractInteger(text, pattern) {
  const number = extractNumber(text, pattern);

  if (number === null) return null;

  return Math.round(number);
}

function extractGnnEvidence(threat) {
  if (!threat) {
    return {
      anomalyScore: null,
      averageAnomaly: null,
      baselineZScore: null,
      suspiciousNodes: null,
      correlatedEvents: null,
      gnnSeverity: null,
      riskScore: null,
      riskLevel: null,
      description: "",
    };
  }

  const description = String(threat.description || "");

  const anomalyScore =
    threat.anomaly_score ??
    extractNumber(
      description,
      /maximum anomaly score:\s*([0-9.]+)\s*%?/i
    );

  const averageAnomaly =
    extractNumber(
      description,
      /average anomaly score:\s*([0-9.]+)\s*%?/i
    );

  const baselineZScore =
    threat.baseline_z_score ??
    extractNumber(
      description,
      /baseline z-score:\s*([0-9.]+)/i
    );

  const suspiciousNodes =
    extractInteger(
      description,
      /suspicious nodes:\s*([0-9]+)/i
    );

  const correlatedEvents =
    extractInteger(
      description,
      /correlated events:\s*([0-9]+)/i
    );

  const riskScore =
    threat.risk_score ??
    extractNumber(
      description,
      /(?:final contextual risk score|risk score):\s*([0-9.]+)\s*\/\s*100/i
    );

  let gnnSeverity = null;

  const gnnSeverityMatch = description.match(
    /GNN severity before contextual correlation:\s*(critical|high|medium|low)/i
  );

  if (gnnSeverityMatch) {
    gnnSeverity = gnnSeverityMatch[1].toUpperCase();
  } else if (threat.severity) {
    gnnSeverity = String(threat.severity).toUpperCase();
  }

  let riskLevel = null;

  const riskLevelMatch = description.match(
    /final risk level:\s*(critical|high|medium|low)/i
  );

  if (riskLevelMatch) {
    riskLevel = riskLevelMatch[1].toLowerCase();
  } else if (threat.risk_score !== null && threat.risk_score !== undefined) {
    const score = Number(threat.risk_score);

    if (score >= 80) riskLevel = "critical";
    else if (score >= 60) riskLevel = "high";
    else if (score >= 30) riskLevel = "medium";
    else riskLevel = "low";
  }

  return {
    anomalyScore:
      anomalyScore !== null && anomalyScore !== undefined
        ? Number(anomalyScore)
        : null,

    averageAnomaly:
      averageAnomaly !== null && averageAnomaly !== undefined
        ? Number(averageAnomaly)
        : null,

    baselineZScore:
      baselineZScore !== null && baselineZScore !== undefined
        ? Number(baselineZScore)
        : null,

    suspiciousNodes,
    correlatedEvents,

    gnnSeverity,

    riskScore:
      riskScore !== null && riskScore !== undefined
        ? Number(riskScore)
        : null,

    riskLevel,

    description,
  };
}

/* =========================================================
   Network Evidence Helpers
========================================================= */

function getUniqueDestinations(events) {
  const destinations = new Set();

  for (const event of events || []) {
    const destination =
      event?.destination_ip ||
      event?.destination ||
      event?.dest_ip ||
      event?.dst_ip;

    if (!destination) continue;

    const value = String(destination).trim();

    if (!value || value === "-" || value === "—") {
      continue;
    }

    destinations.add(value);
  }

  return Array.from(destinations);
}

function getObservedPorts(events) {
  const ports = new Set();

  for (const event of events || []) {
    const port =
      event?.port ??
      event?.destination_port ??
      event?.dest_port ??
      event?.src_port;

    if (
      port === null ||
      port === undefined ||
      String(port).trim() === ""
    ) {
      continue;
    }

    const value = String(port).trim();

    if (value === "-" || value === "—") {
      continue;
    }

    ports.add(value);
  }

  return Array.from(ports).sort((a, b) => {
    const numberA = Number(a);
    const numberB = Number(b);

    if (Number.isFinite(numberA) && Number.isFinite(numberB)) {
      return numberA - numberB;
    }

    return a.localeCompare(b);
  });
}

function getProtocolCounts(events) {
  let tcp = 0;
  let udp = 0;
  let other = 0;

  for (const event of events || []) {
    const protocol = String(
      event?.protocol ||
        event?.transport_protocol ||
        ""
    ).toUpperCase();

    if (protocol === "TCP") {
      tcp += 1;
    } else if (protocol === "UDP") {
      udp += 1;
    } else {
      other += 1;
    }
  }

  return {
    tcp,
    udp,
    other,
  };
}

function getRiskCounts(events) {
  let high = 0;
  let medium = 0;
  let low = 0;
  let critical = 0;

  for (const event of events || []) {
    const risk = normalizeRiskLevel(
      event?.risk ||
        event?.risk_level ||
        event?.severity
    );

    if (risk === "critical") {
      critical += 1;
    } else if (risk === "high") {
      high += 1;
    } else if (risk === "medium") {
      medium += 1;
    } else if (risk === "low") {
      low += 1;
    }
  }

  return {
    critical,
    high,
    medium,
    low,
  };
}

function getSourceIp(events, threat) {
  if (threat?.source_ip) {
    return threat.source_ip;
  }

  for (const event of events || []) {
    const source =
      event?.source_ip ||
      event?.source ||
      event?.src_ip;

    if (source) {
      return source;
    }
  }

  return null;
}

function getIncidentTitle(incident) {
  return (
    incident?.title ||
    incident?.name ||
    incident?.incident_type ||
    incident?.type ||
    "Security Incident"
  );
}

function isHistoricalIncident(incident) {
  return Number(incident?.id) !== 4;
}

/* =========================================================
   Small UI Components
========================================================= */

function StatusBadge({ status }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium capitalize ${getStatusBadgeClass(
        status
      )}`}
    >
      {String(status || "unknown").replaceAll("_", " ")}
    </span>
  );
}

function RiskBadge({ level }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium uppercase ${getRiskBadgeClass(
        level
      )}`}
    >
      {String(level || "unknown")}
    </span>
  );
}

function DestinationBadge({ value }) {
  return (
    <span className="inline-flex max-w-full items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-1.5 font-mono text-xs text-cyan-200 shadow-sm">
      {value}
    </span>
  );
}

function PortBadge({ value }) {
  return (
    <span className="inline-flex items-center rounded-lg border border-slate-600 bg-slate-800/80 px-2.5 py-1.5 font-mono text-xs font-medium text-slate-200 shadow-sm">
      {value}
    </span>
  );
}

/* =========================================================
   Response Actions
========================================================= */

function ResponseActionsSection({ actions }) {
  if (!actions || actions.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-sm text-slate-400">
        No response actions have been recorded for this incident.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Threat</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3">Reason</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800">
            {actions.map((action) => {
              const Icon = getActionIcon(
                action.action_type ||
                  action.type ||
                  action.action
              );

              return (
                <tr
                  key={action.id}
                  className="bg-slate-950/30 transition hover:bg-slate-900/60"
                >
                  <td className="whitespace-nowrap px-4 py-3 font-semibold text-slate-100">
                    #{action.id}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3">
                    <div className="flex items-center gap-2 text-slate-200">
                      <Icon
                        size={15}
                        className="text-cyan-300"
                      />
                      <span>
                        {action.action_type ||
                          action.type ||
                          action.action ||
                          "Unknown"}
                      </span>
                    </div>
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-300">
                    {action.target || "—"}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 font-semibold text-cyan-300">
                    {action.threat_id
                      ? `#${action.threat_id}`
                      : "—"}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3">
                    <StatusBadge status={action.status} />
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">
                    {formatDate(
                      action.created_at ||
                        action.timestamp
                    )}
                  </td>

                  <td className="min-w-[280px] px-4 py-3 text-xs leading-5 text-slate-400">
                    {action.reason || "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="border-t border-slate-800 bg-slate-900/40 px-4 py-3 text-xs leading-5 text-slate-400">
        <strong className="text-slate-300">
          Audit trail:
        </strong>{" "}
        These records show defensive actions associated with
        this incident. A completed{" "}
        <strong className="text-slate-200">
          Alert Generated
        </strong>{" "}
        action records the response workflow without modifying
        the network.
      </div>
    </div>
  );
}

/* =========================================================
   Network Events Table
========================================================= */

function NetworkEventsTable({ events }) {
  if (!events || events.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-sm text-slate-400">
        No linked network events were found for this threat.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800">
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/50 px-4 py-3">
        <div className="flex items-center gap-2">
          <Network
            size={16}
            className="text-cyan-300"
          />

          <span className="text-sm font-medium text-slate-200">
            {events.length} network events
          </span>
        </div>

        <span className="text-xs text-slate-500">
          Linked evidence
        </span>
      </div>

      <div className="max-h-[480px] overflow-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Event</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Destination</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Port</th>
              <th className="px-4 py-3">Risk</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800">
            {events.map((event) => {
              const risk =
                event?.risk ||
                event?.risk_level ||
                event?.severity ||
                "unknown";

              return (
                <tr
                  key={event.id}
                  className="bg-slate-950/20 hover:bg-slate-900/50"
                >
                  <td className="whitespace-nowrap px-4 py-3 font-semibold text-slate-200">
                    #{event.id}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-300">
                    {event.source_ip ||
                      event.source ||
                      event.src_ip ||
                      "—"}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-400">
                    {event.destination_ip ||
                      event.destination ||
                      event.dest_ip ||
                      event.dst_ip ||
                      "—"}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 text-xs font-medium text-slate-300">
                    {event.protocol ||
                      event.transport_protocol ||
                      "—"}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-300">
                    {event.port ??
                      event.destination_port ??
                      event.dest_port ??
                      event.src_port ??
                      "—"}
                  </td>

                  <td className="whitespace-nowrap px-4 py-3">
                    <RiskBadge level={risk} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* =========================================================
   Incident Card
========================================================= */

function IncidentCard({
  incident,
  threat,
  events,
  actions,
  expanded,
  onToggle,
  onStatusChange,
  updating,
}) {
  const riskLevel = getRiskLevel(
    incident,
    threat
  );

  const gnnEvidence = extractGnnEvidence(threat);

  const destinations = useMemo(
    () => getUniqueDestinations(events),
    [events]
  );

  const ports = useMemo(
    () => getObservedPorts(events),
    [events]
  );

  const protocolCounts = useMemo(
    () => getProtocolCounts(events),
    [events]
  );

  const riskCounts = useMemo(
    () => getRiskCounts(events),
    [events]
  );

  const sourceIp = getSourceIp(
    events,
    threat
  );

  const title = getIncidentTitle(incident);

  const status =
    incident?.status ||
    "unknown";

  const description =
    incident?.description ||
    threat?.description ||
    "No incident description is available.";

  return (
    <article className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/70 shadow-xl shadow-black/10">
      {/* =====================================================
          Header
      ===================================================== */}

      <div className="border-b border-slate-800 bg-gradient-to-r from-slate-900/80 to-slate-950/80 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-slate-200">
                Incident #{incident.id}
              </span>

              <RiskBadge level={riskLevel} />

              <StatusBadge status={status} />
            </div>

            <h2 className="text-xl font-semibold text-white">
              {title}
            </h2>

            <div className="mt-2 flex items-center gap-2 text-xs text-slate-500">
              <Clock size={14} />

              <span>
                Created{" "}
                {formatDate(
                  incident.created_at ||
                    incident.detected_at ||
                    incident.timestamp
                )}
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={onToggle}
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500/40 hover:bg-slate-800 hover:text-white"
          >
            {expanded ? (
              <>
                <ChevronUp size={16} />
                Hide Details
              </>
            ) : (
              <>
                <ChevronDown size={16} />
                Show Details
              </>
            )}
          </button>
        </div>
      </div>

      {/* =====================================================
          Details
      ===================================================== */}

      {expanded && (
        <div className="space-y-6 p-5">
          {/* =================================================
              Incident Description
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <FileWarning
                size={17}
                className="text-cyan-300"
              />

              <h3 className="text-base font-semibold text-slate-100">
                Incident Description
              </h3>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <p className="text-sm leading-6 text-slate-300">
                {description}
              </p>
            </div>
          </section>

          {/* =================================================
              Network Evidence
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <Network
                size={17}
                className="text-cyan-300"
              />

              <h3 className="text-base font-semibold text-slate-100">
                Network Evidence
              </h3>
            </div>

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Source IP
                </p>

                <p className="mt-2 break-all font-mono text-sm font-semibold text-cyan-300">
                  {sourceIp || "—"}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Destinations
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {destinations.length}
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  unique destinations
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Linked Events
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {events.length}
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  correlated network events
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Threat Status
                </p>

                <div className="mt-2">
                  <StatusBadge
                    status={
                      threat?.status ||
                      "unknown"
                    }
                  />
                </div>
              </div>
            </div>

            {/* =================================================
                Destination IPs
            ================================================= */}

            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <div className="flex flex-col gap-1">
                <h4 className="text-sm font-semibold text-slate-200">
                  Destination IPs
                </h4>

                <p className="text-xs text-slate-500">
                  Unique destinations observed in the correlated network events.
                </p>
              </div>

              {destinations.length > 0 ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  {destinations.map((destination) => (
                    <DestinationBadge
                      key={destination}
                      value={destination}
                    />
                  ))}
                </div>
              ) : (
                <p className="mt-4 text-sm text-slate-500">
                  No destination IPs were recorded.
                </p>
              )}
            </div>

            {/* =================================================
                Protocol Distribution
            ================================================= */}

            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <div className="flex flex-col gap-1">
                <h4 className="text-sm font-semibold text-slate-200">
                  Protocol Distribution
                </h4>

                <p className="text-xs text-slate-500">
                  TCP and UDP counts are calculated from the linked network events.
                </p>
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
                  <p className="text-xs uppercase tracking-wide text-blue-300">
                    TCP
                  </p>

                  <p className="mt-2 text-2xl font-semibold text-white">
                    {protocolCounts.tcp}
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    TCP events
                  </p>
                </div>

                <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
                  <p className="text-xs uppercase tracking-wide text-purple-300">
                    UDP
                  </p>

                  <p className="mt-2 text-2xl font-semibold text-white">
                    {protocolCounts.udp}
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    UDP events
                  </p>
                </div>

                {protocolCounts.other > 0 && (
                  <div className="rounded-xl border border-slate-700 bg-slate-800/30 p-4">
                    <p className="text-xs uppercase tracking-wide text-slate-400">
                      Other
                    </p>

                    <p className="mt-2 text-2xl font-semibold text-white">
                      {protocolCounts.other}
                    </p>

                    <p className="mt-1 text-xs text-slate-500">
                      Other protocol events
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* =================================================
                Observed Ports
            ================================================= */}

            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <div className="flex flex-col gap-1">
                <h4 className="text-sm font-semibold text-slate-200">
                  Observed Ports
                </h4>

                <p className="text-xs text-slate-500">
                  Unique ports observed across the linked events.
                </p>
              </div>

              {ports.length > 0 ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  {ports.map((port) => (
                    <PortBadge
                      key={port}
                      value={port}
                    />
                  ))}
                </div>
              ) : (
                <p className="mt-4 text-sm text-slate-500">
                  No ports were recorded.
                </p>
              )}
            </div>

            {/* =================================================
                Risk Counts
            ================================================= */}

            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-red-300">
                  Critical Risk Events
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {riskCounts.critical}
                </p>
              </div>

              <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-orange-300">
                  High Risk Events
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {riskCounts.high}
                </p>
              </div>

              <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-yellow-300">
                  Medium Risk Events
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {riskCounts.medium}
                </p>
              </div>

              <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-emerald-300">
                  Low Risk Events
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {riskCounts.low}
                </p>
              </div>
            </div>
          </section>

          {/* =================================================
              Threat Summary
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <Target
                size={17}
                className="text-cyan-300"
              />

              <h3 className="text-base font-semibold text-slate-100">
                Threat Summary
              </h3>
            </div>

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Source / Target
                </p>

                <p className="mt-2 break-all font-mono text-sm font-semibold text-slate-200">
                  {sourceIp || "—"}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Threat ID
                </p>

                <p className="mt-2 text-xl font-semibold text-cyan-300">
                  {threat?.id
                    ? `#${threat.id}`
                    : "—"}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Risk Score
                </p>

                <p className="mt-2 text-xl font-semibold text-white">
                  {gnnEvidence.riskScore !== null
                    ? `${gnnEvidence.riskScore.toFixed(1)} / 100`
                    : "—"}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Created
                </p>

                <p className="mt-2 text-sm font-medium text-slate-300">
                  {formatDate(
                    incident.created_at ||
                      incident.detected_at ||
                      incident.timestamp
                  )}
                </p>
              </div>
            </div>
          </section>

          {/* =================================================
              GNN Detection Evidence
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <ShieldAlert
                size={17}
                className="text-purple-300"
              />

              <h3 className="text-base font-semibold text-slate-100">
                GNN Detection Evidence
              </h3>
            </div>

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-purple-300">
                  GNN Anomaly
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.anomalyScore !== null
                    ? `${gnnEvidence.anomalyScore.toFixed(2)}%`
                    : "—"}
                </p>
              </div>

              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-purple-300">
                  Baseline Z-Score
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.baselineZScore !== null
                    ? gnnEvidence.baselineZScore.toFixed(3)
                    : "—"}
                </p>
              </div>

              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-purple-300">
                  Suspicious Nodes
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.suspiciousNodes ??
                    "—"}
                </p>
              </div>

              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-purple-300">
                  Correlated Events
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.correlatedEvents ??
                    events.length}
                </p>
              </div>

              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-purple-300">
                  GNN Severity
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.gnnSeverity ||
                    "—"}
                </p>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
              <div className="flex items-start gap-3">
                <ShieldAlert
                  size={18}
                  className="mt-0.5 shrink-0 text-purple-300"
                />

                <div>
                  <h4 className="font-semibold text-purple-200">
                    GNN Interpretation
                  </h4>

                  <p className="mt-1 text-xs font-medium uppercase tracking-wide text-purple-300/80">
                    Statistical anomaly detection
                  </p>

                  <p className="mt-2 text-sm leading-6 text-slate-300">
                    The GNN anomaly score represents statistical
                    deviation from the learned normal network
                    behavior. It is{" "}
                    <strong className="text-white">
                      not an attack probability
                    </strong>
                    . The final incident risk is determined
                    using additional contextual evidence.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* =================================================
              Contextual Risk
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <AlertTriangle
                size={17}
                className="text-yellow-300"
              />

              <h3 className="text-base font-semibold text-slate-100">
                Contextual Risk
              </h3>
            </div>

            <div className="grid gap-3 md:grid-cols-3">
              <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-yellow-300">
                  Final Risk
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.riskScore !== null
                    ? `${gnnEvidence.riskScore.toFixed(1)} / 100`
                    : "—"}
                </p>
              </div>

              <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-yellow-300">
                  Risk Level
                </p>

                <div className="mt-2">
                  <RiskBadge
                    level={
                      gnnEvidence.riskLevel ||
                      riskLevel
                    }
                  />
                </div>
              </div>

              <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
                <p className="text-xs uppercase tracking-wide text-yellow-300">
                  GNN Severity
                </p>

                <p className="mt-2 text-2xl font-semibold text-white">
                  {gnnEvidence.gnnSeverity ||
                    "—"}
                </p>
              </div>
            </div>
          </section>

          {/* =================================================
              Response Actions
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <Zap
                size={17}
                className="text-cyan-300"
              />

              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Response Actions
                </h3>

                <p className="text-xs text-slate-500">
                  Defensive response actions recorded for Incident #
                  {incident.id}.
                </p>
              </div>
            </div>

            <ResponseActionsSection
              actions={actions}
            />
          </section>

          {/* =================================================
              Linked Network Events
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <Network
                    size={17}
                    className="text-cyan-300"
                  />

                  <h3 className="text-base font-semibold text-slate-100">
                    Linked Network Events
                  </h3>
                </div>

                <p className="mt-1 text-xs text-slate-500">
                  {events.length} network events are currently
                  linked to Threat #
                  {threat?.id || "—"}.
                </p>
              </div>

              <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-300">
                {events.length} events
              </span>
            </div>

            <NetworkEventsTable
              events={events}
            />
          </section>

          {/* =================================================
              Incident Status
          ================================================= */}

          <section>
            <div className="mb-3 flex items-center gap-2">
              <CheckCircle2
                size={17}
                className="text-emerald-300"
              />

              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Incident Status
                </h3>

                <p className="text-xs text-slate-500">
                  Change the investigation state for this incident.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              {String(status).toLowerCase() !==
                "resolved" && (
                <button
                  type="button"
                  disabled={updating}
                  onClick={() =>
                    onStatusChange(
                      incident.id,
                      "resolved"
                    )
                  }
                  className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-300 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <CheckCircle2 size={16} />

                  {updating
                    ? "Updating..."
                    : "Mark Resolved"}
                </button>
              )}

              {String(status).toLowerCase() ===
                "resolved" && (
                <button
                  type="button"
                  disabled={updating}
                  onClick={() =>
                    onStatusChange(
                      incident.id,
                      "investigating"
                    )
                  }
                  className="inline-flex items-center gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-sm font-medium text-blue-300 transition hover:bg-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Eye size={16} />

                  {updating
                    ? "Updating..."
                    : "Reopen Investigation"}
                </button>
              )}
            </div>
          </section>
        </div>
      )}
    </article>
  );
}

/* =========================================================
   Main Page
========================================================= */

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [threats, setThreats] = useState([]);
  const [responseActions, setResponseActions] =
    useState([]);

  const [linkedEvents, setLinkedEvents] =
    useState({});

  const [expandedIncidents, setExpandedIncidents] = useState({});

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [updatingIncidentId, setUpdatingIncidentId] =
    useState(null);

  /* =======================================================
     Load Data
  ======================================================= */

  async function loadIncidents(showRefreshing = false) {
    if (showRefreshing) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    setError("");

    try {
      const [
        incidentsData,
        threatsData,
        actionsData,
      ] = await Promise.all([
        getIncidents(),
        getThreats(),
        getResponseActions(),
      ]);

      const incidentList = Array.isArray(
        incidentsData
      )
        ? incidentsData
        : incidentsData?.incidents || [];

      const threatList = Array.isArray(
        threatsData
      )
        ? threatsData
        : threatsData?.threats || [];

      const actionList = Array.isArray(
        actionsData
      )
        ? actionsData
        : actionsData?.actions || [];

      setIncidents(incidentList);
      setThreats(threatList);
      setResponseActions(actionList);

      const eventResults = {};

      for (const incident of incidentList) {
        const threatId =
          incident?.threat_id ||
          incident?.threatId;

        if (!threatId) {
          continue;
        }

        try {
          const result =
            await getThreatNetworkEvents(
              threatId
            );

          const events = Array.isArray(
            result
          )
            ? result
            : result?.events || [];

          eventResults[incident.id] =
            events;
        } catch (eventError) {
          console.error(
            `Failed to load events for incident ${incident.id}:`,
            eventError
          );

          eventResults[incident.id] = [];
        }
      }

      setLinkedEvents(eventResults);
    } catch (err) {
      console.error(
        "Failed to load incidents:",
        err
      );

      setError(
        err?.message ||
          "Failed to load security incidents."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadIncidents();

    const interval = setInterval(() => {
      loadIncidents(true);
    }, 15000);

    return () => {
      clearInterval(interval);
    };
  }, []);

  /* =======================================================
     Derived Data
  ======================================================= */

  const threatMap = useMemo(() => {
    const map = {};

    for (const threat of threats) {
      map[threat.id] = threat;
    }

    return map;
  }, [threats]);

  const sortedIncidents = useMemo(() => {
    return [...incidents].sort((a, b) => {
      const dateA = new Date(
        a?.created_at ||
          a?.detected_at ||
          a?.timestamp ||
          0
      ).getTime();

      const dateB = new Date(
        b?.created_at ||
          b?.detected_at ||
          b?.timestamp ||
          0
      ).getTime();

      return dateB - dateA;
    });
  }, [incidents]);

  const incidentCounts = useMemo(() => {
    let investigating = 0;
    let resolved = 0;

    for (const incident of incidents) {
      const status = String(
        incident?.status || ""
      ).toLowerCase();

      if (status === "resolved") {
        resolved += 1;
      } else {
        investigating += 1;
      }
    }

    return {
      all: incidents.length,
      investigating,
      resolved,
    };
  }, [incidents]);

  /* =======================================================
     Toggle Details
  ======================================================= */

  function toggleIncident(incidentId) {
    setExpandedIncidents((previous) => ({
      ...previous,
      [incidentId]:
        !previous[incidentId],
    }));
  }

  /* =======================================================
     Update Incident Status
  ======================================================= */

  async function handleStatusChange(
    incidentId,
    status
  ) {
    setUpdatingIncidentId(incidentId);
    setError("");

    try {
      await updateIncidentStatus(
        incidentId,
        status
      );

      await loadIncidents(true);
    } catch (err) {
      console.error(
        "Failed to update incident status:",
        err
      );

      setError(
        err?.message ||
          "Failed to update incident status."
      );
    } finally {
      setUpdatingIncidentId(null);
    }
  }

  /* =======================================================
     Loading
  ======================================================= */

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <RefreshCw
            size={18}
            className="animate-spin"
          />

          Loading security incidents...
        </div>
      </div>
    );
  }

  /* =======================================================
     Page
  ======================================================= */

  return (
    <div className="space-y-6">
      {/* =====================================================
          Page Header
      ===================================================== */}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <ShieldAlert
              size={26}
              className="text-cyan-300"
            />

            <h1 className="text-2xl font-semibold text-white">
              Security Incidents
            </h1>
          </div>

          <p className="mt-2 text-sm text-slate-400">
            Investigate detected threats and review their
            correlated network evidence.
          </p>
        </div>

        <button
          type="button"
          onClick={() =>
            loadIncidents(true)
          }
          disabled={refreshing}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500/40 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
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
      </div>

      {/* =====================================================
          Error
      ===================================================== */}

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">
          <XCircle
            size={18}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-medium">
              Incident data error
            </p>

            <p className="mt-1 text-red-300/80">
              {error}
            </p>
          </div>
        </div>
      )}

      {/* =====================================================
          Summary Cards
      ===================================================== */}

      <div className="grid gap-3 md:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-500">
            All
          </p>

          <p className="mt-2 text-2xl font-semibold text-white">
            {incidentCounts.all}
          </p>
        </div>

        <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
          <p className="text-xs uppercase tracking-wide text-blue-300">
            Investigating
          </p>

          <p className="mt-2 text-2xl font-semibold text-white">
            {incidentCounts.investigating}
          </p>
        </div>

        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
          <p className="text-xs uppercase tracking-wide text-emerald-300">
            Resolved
          </p>

          <p className="mt-2 text-2xl font-semibold text-white">
            {incidentCounts.resolved}
          </p>
        </div>
      </div>

      {/* =====================================================
          Incidents
      ===================================================== */}

      {sortedIncidents.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-8 text-center">
          <CheckCircle2
            size={32}
            className="mx-auto text-emerald-300"
          />

          <h2 className="mt-3 text-lg font-semibold text-white">
            No security incidents
          </h2>

          <p className="mt-2 text-sm text-slate-500">
            ZeroGuard has not recorded any security incidents yet.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {sortedIncidents.map(
            (incident) => {
              const threatId =
                incident?.threat_id ||
                incident?.threatId;

              const threat =
                threatMap[threatId];

              const events =
                linkedEvents[
                  incident.id
                ] || [];

              const actions =
                responseActions.filter(
                  (action) =>
                    Number(
                      action?.incident_id
                    ) ===
                    Number(incident.id)
                );

              /*
               * Incident #4 starts expanded.
               * All other incidents start collapsed.
               *
               * IMPORTANT:
               * We do NOT force Incident #4
               * to remain expanded.
               */
              const expanded = Boolean(
                expandedIncidents[
                  incident.id
                ]
              );

              return (
                <IncidentCard
                  key={incident.id}
                  incident={incident}
                  threat={threat}
                  events={events}
                  actions={actions}
                  expanded={expanded}
                  onToggle={() =>
                    toggleIncident(
                      incident.id
                    )
                  }
                  onStatusChange={
                    handleStatusChange
                  }
                  updating={
                    updatingIncidentId ===
                    incident.id
                  }
                />
              );
            }
          )}
        </div>
      )}
    </div>
  );
}