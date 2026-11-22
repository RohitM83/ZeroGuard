import { useEffect, useState } from "react";

import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  CircleAlert,
  Info,
  Link2,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Target,
  Zap,
} from "lucide-react";

import {
  analyzeNetwork,
  getThreats,
  getThreatNetworkEvents,
  linkThreatEvents,
} from "../services/api";

/* ============================================================
   SESSION STORAGE KEY
============================================================ */
const GNN_ANALYSIS_STORAGE_KEY =
  "zeroguard_gnn_analysis";

/* ============================================================
   IP ADDRESS DISPLAY HELPER
============================================================ */
function cleanIpAddress(value) {
  if (
    value === null ||
    value === undefined ||
    String(value).trim() === ""
  ) {
    return "—";
  }

  return String(value)
    .trim()
    .replace(/\\:/g, ":");
}

/* ============================================================
   SCORE BAR
============================================================ */
function ScoreBar({
  score,
  label = "Score",
}) {
  const numericScore =
    Number(score) || 0;

  const percentage = Math.max(
    0,
    Math.min(100, numericScore)
  );

  let barColor =
    "bg-emerald-500";

  if (percentage >= 70) {
    barColor =
      "bg-red-500";
  } else if (percentage >= 40) {
    barColor =
      "bg-orange-500";
  } else if (percentage >= 20) {
    barColor =
      "bg-yellow-500";
  }

  return (
    <div className="mt-4">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {label}
        </span>

        <span className="text-xs font-medium text-slate-300">
          {numericScore.toFixed(2)}%
        </span>
      </div>

      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{
            width: `${percentage}%`,
          }}
        />
      </div>
    </div>
  );
}

/* ============================================================
   STATUS BADGE
============================================================ */
function StatusBadge({
  status,
}) {
  const value = String(
    status || "unknown"
  ).toLowerCase();

  let className =
    "bg-slate-800 text-slate-400";

  if (
    value === "high" ||
    value === "critical" ||
    value === "threat"
  ) {
    className =
      "bg-red-950 text-red-400";
  } else if (
    value === "medium"
  ) {
    className =
      "bg-orange-950 text-orange-400";
  } else if (
    value === "low" ||
    value === "protected" ||
    value === "safe" ||
    value === "resolved"
  ) {
    className =
      "bg-emerald-950 text-emerald-400";
  } else if (
    value === "active" ||
    value === "new" ||
    value === "open" ||
    value === "investigating" ||
    value === "contained"
  ) {
    className =
      "bg-blue-950 text-blue-400";
  }

  return (
    <span
      className={`rounded-md px-2.5 py-1 text-xs font-medium ${className}`}
    >
      {value.toUpperCase()}
    </span>
  );
}

/* ============================================================
   RISK BADGE
============================================================ */
function RiskBadge({
  level,
}) {
  const value = String(
    level || "unknown"
  ).toLowerCase();

  let className =
    "bg-slate-800 text-slate-400";

  if (
    value === "critical"
  ) {
    className =
      "bg-red-950 text-red-300 ring-1 ring-red-800";
  } else if (
    value === "high"
  ) {
    className =
      "bg-red-950 text-red-400";
  } else if (
    value === "medium"
  ) {
    className =
      "bg-orange-950 text-orange-400";
  } else if (
    value === "low"
  ) {
    className =
      "bg-emerald-950 text-emerald-400";
  }

  return (
    <span
      className={`rounded-md px-3 py-1.5 text-xs font-semibold uppercase ${className}`}
    >
      {value}
    </span>
  );
}

/* ============================================================
   METRIC CARD
============================================================ */
function MetricCard({
  icon: Icon,
  title,
  value,
  description,
  color = "blue",
}) {
  const colors = {
    blue:
      "bg-blue-500/10 text-blue-400",
    purple:
      "bg-purple-500/10 text-purple-400",
    orange:
      "bg-orange-500/10 text-orange-400",
    red:
      "bg-red-500/10 text-red-400",
    green:
      "bg-emerald-500/10 text-emerald-400",
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            {title}
          </p>

          <p className="mt-3 break-words text-3xl font-semibold text-white">
            {value}
          </p>

          <p className="mt-1 text-xs text-slate-600">
            {description}
          </p>
        </div>

        <div
          className={`shrink-0 rounded-lg p-3 ${
            colors[color] ||
            colors.blue
          }`}
        >
          <Icon size={19} />
        </div>
      </div>
    </div>
  );
}

/* ============================================================
   RISK FACTOR LIST
============================================================ */
function RiskList({
  title,
  items,
  icon: Icon,
  type = "reason",
}) {
  if (
    !Array.isArray(items) ||
    items.length === 0
  ) {
    return null;
  }

  const isWarning =
    type === "warning";

  const isContext =
    type === "context";

  let iconClass =
    "text-orange-400";

  let backgroundClass =
    "border-orange-900/30 bg-orange-950/10";

  if (isWarning) {
    iconClass =
      "text-yellow-400";

    backgroundClass =
      "border-yellow-900/30 bg-yellow-950/10";
  }

  if (isContext) {
    iconClass =
      "text-blue-400";

    backgroundClass =
      "border-blue-900/30 bg-blue-950/10";
  }

  return (
    <div
      className={`rounded-lg border p-4 ${backgroundClass}`}
    >
      <div className="flex items-center gap-2">
        <Icon
          size={15}
          className={iconClass}
        />

        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          {title}
        </h4>
      </div>

      <div className="mt-3 space-y-2">
        {items.map(
          (item, index) => (
            <div
              key={`${type}-${index}`}
              className="flex gap-2"
            >
              <span
                className={`mt-1 text-xs ${iconClass}`}
              >
                •
              </span>

              <p className="text-xs leading-relaxed text-slate-500">
                {String(item)}
              </p>
            </div>
          )
        )}
      </div>
    </div>
  );
}

/* ============================================================
   GNN + RISK RESULT
============================================================ */
function GNNResult({
  result,
}) {
  if (!result) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-10 text-center">
        <Brain
          size={38}
          className="mx-auto text-slate-600"
        />

        <h2 className="mt-4 text-sm font-semibold text-slate-300">
          No GNN analysis available
        </h2>

        <p className="mt-2 text-xs text-slate-600">
          Click "Analyze Network" to run the Graph Neural Network analysis.
        </p>
      </div>
    );
  }

  const averageScore =
    Number(
      result?.average_anomaly_score
    ) ||
    Number(
      result?.anomaly_score
    ) ||
    0;

  const maximumScore =
    Number(
      result?.maximum_anomaly_score
    ) || 0;

  const baselineZScore =
    Number(
      result?.baseline_z_score
    ) || 0;

  const riskScore =
    Number(
      result?.risk_score
    ) || 0;

  const suspiciousNodes =
    Number(
      result?.suspicious_nodes
    ) || 0;

  const totalNodes =
    Number(
      result?.total_nodes
    ) || 0;

  const totalEdges =
    Number(
      result?.total_edges
    ) || 0;

  const linkedEvents =
    Number(
      result?.linked_events
    ) || 0;

  const correlatedEvents =
    Number(
      result?.correlated_event_count
    ) || 0;

  const localIpCount =
    Number(
      result?.local_ip_count
    ) || 0;

  const threatId =
    result?.threat_id !==
      undefined &&
    result?.threat_id !==
      null
      ? result.threat_id
      : null;

  const gnnSeverity =
    String(
      result?.gnn_severity ||
        result?.severity ||
        "low"
    ).toLowerCase();

  const riskLevel =
    String(
      result?.risk_level ||
        result?.status ||
        "low"
    ).toLowerCase();

  const automaticResponseAllowed =
    Boolean(
      result?.automatic_response_allowed
    );

  const recommendedAction =
    result?.recommended_action ||
    "Monitor the activity.";

  /* ==========================================================
     SUSPICIOUS NETWORK NODES
  ========================================================== */

  const suspiciousIps =
    Array.isArray(
      result?.suspicious_ips
    )
      ? [
          ...new Set(
            result.suspicious_ips
              .filter(
                (ip) =>
                  ip !== null &&
                  ip !== undefined &&
                  String(ip).trim() !== ""
              )
              .map(
                (ip) =>
                  cleanIpAddress(ip)
              )
          ),
        ]
      : [];

  let embeddingShape =
    "N/A";

  if (
    Array.isArray(
      result?.embeddings_shape
    )
  ) {
    embeddingShape =
      result.embeddings_shape.join(
        " × "
      );
  }

  return (
    <div className="space-y-4">
      {/* ANALYSIS HEADER */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-purple-500/10 p-3">
              <Brain
                size={21}
                className="text-purple-400"
              />
            </div>

            <div>
              <h2 className="text-sm font-semibold text-slate-200">
                GNN + Risk Correlation Analysis
              </h2>

              <p className="mt-1 text-xs text-slate-600">
                Statistical anomaly detection followed by contextual security risk assessment.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-600">
              Final Risk
            </span>

            <RiskBadge
              level={riskLevel}
            />
          </div>
        </div>

        {/* MAIN SCORE CARDS */}
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {/* GNN ANOMALY */}
          <div className="rounded-lg border border-purple-900/30 bg-purple-950/10 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500">
                GNN Anomaly
              </span>

              <Activity
                size={16}
                className="text-purple-400"
              />
            </div>

            <p className="mt-3 text-3xl font-semibold text-white">
              {maximumScore.toFixed(
                2
              )}
              %
            </p>

            <ScoreBar
              score={maximumScore}
              label="Statistical anomaly level"
            />

            <p className="mt-3 text-[11px] leading-relaxed text-slate-600">
              This is a statistical anomaly score, not an attack probability.
            </p>
          </div>

          {/* BASELINE Z */}
          <div className="rounded-lg border border-blue-900/30 bg-blue-950/10 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500">
                Baseline Z-Score
              </span>

              <Target
                size={16}
                className="text-blue-400"
              />
            </div>

            <p className="mt-3 text-3xl font-semibold text-white">
              {baselineZScore.toFixed(
                3
              )}
            </p>

            <p className="mt-4 text-xs leading-relaxed text-slate-600">
              Distance of the strongest observed behavior from the learned normal baseline.
            </p>
          </div>

          {/* FINAL RISK */}
          <div className="rounded-lg border border-emerald-900/30 bg-emerald-950/10 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500">
                Final Risk Score
              </span>

              <ShieldCheck
                size={16}
                className="text-emerald-400"
              />
            </div>

            <p className="mt-3 text-3xl font-semibold text-white">
              {riskScore.toFixed(
                1
              )}

              <span className="ml-1 text-sm font-normal text-slate-600">
                / 100
              </span>
            </p>

            <div className="mt-4 flex items-center gap-2">
              <RiskBadge
                level={riskLevel}
              />
            </div>
          </div>
        </div>

        {/* EXPLANATION */}
        <div className="mt-4 rounded-lg border border-blue-900/30 bg-blue-950/10 p-4">
          <div className="flex gap-3">
            <Info
              size={17}
              className="mt-0.5 shrink-0 text-blue-400"
            />

            <div>
              <p className="text-xs font-semibold text-blue-300">
                How to interpret this result
              </p>

              <p className="mt-2 text-xs leading-relaxed text-slate-500">
                The GNN identifies behavior that differs from the learned normal network pattern. The risk correlator then combines that anomaly with network evidence and host context before assigning the final risk level.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* RISK DECISION */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert
                size={17}
                className="text-orange-400"
              />

              <h2 className="text-sm font-semibold text-slate-200">
                Contextual Risk Decision
              </h2>
            </div>

            <p className="mt-2 text-xs text-slate-600">
              Final security decision after combining AI anomaly evidence with network context.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {automaticResponseAllowed ? (
              <>
                <Zap
                  size={15}
                  className="text-orange-400"
                />

                <span className="text-xs font-medium text-orange-400">
                  Automatic response permitted
                </span>
              </>
            ) : (
              <>
                <ShieldCheck
                  size={15}
                  className="text-emerald-400"
                />

                <span className="text-xs font-medium text-emerald-400">
                  Automatic blocking not permitted
                </span>
              </>
            )}
          </div>
        </div>

        {/* DECISION GRID */}
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              GNN Severity
            </p>

            <div className="mt-2">
              <StatusBadge
                status={gnnSeverity}
              />
            </div>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Final Risk
            </p>

            <div className="mt-2">
              <RiskBadge
                level={riskLevel}
              />
            </div>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Correlated Evidence
            </p>

            <p className="mt-2 text-xl font-semibold text-white">
              {correlatedEvents.toLocaleString()}
            </p>

            <p className="mt-1 text-[11px] leading-relaxed text-slate-600">
              Events used for contextual risk analysis
            </p>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Local IPs Detected
            </p>

            <p className="mt-2 text-xl font-semibold text-white">
              {localIpCount}
            </p>
          </div>
        </div>

        {/* RECOMMENDATION */}
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Recommended Action
          </p>

          <p className="mt-2 text-sm leading-relaxed text-slate-300">
            {String(
              recommendedAction
            )}
          </p>
        </div>

        {/* SUSPICIOUS IPS */}
        {suspiciousIps.length >
          0 && (
          <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Suspicious Network Nodes
            </p>

            <div className="mt-3 flex flex-wrap gap-2">
              {suspiciousIps.map(
                (ip, index) => (
                  <span
                    key={`${ip}-${index}`}
                    title={ip}
                    className="break-all rounded-md border border-red-900/40 bg-red-950/20 px-3 py-1.5 font-mono text-xs text-red-400"
                  >
                    {ip}
                  </span>
                )
              )}
            </div>
          </div>
        )}
      </div>

      {/* RISK REASONS / CONTEXT / WARNINGS */}
      <div className="grid gap-4 lg:grid-cols-3">
        <RiskList
          title="Why GNN flagged it"
          items={
            result?.risk_reasons
          }
          icon={AlertTriangle}
          type="reason"
        />

        <RiskList
          title="Context that reduced risk"
          items={
            result?.risk_context
          }
          icon={Info}
          type="context"
        />

        <RiskList
          title="Security warnings"
          items={
            result?.risk_warnings
          }
          icon={CircleAlert}
          type="warning"
        />
      </div>

      {/* GRAPH METRICS */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          icon={Network}
          title="Graph Nodes"
          value={totalNodes}
          description="Nodes analyzed by GNN"
          color="blue"
        />

        <MetricCard
          icon={Link2}
          title="Graph Edges"
          value={totalEdges}
          description="Network relationships"
          color="purple"
        />

        <MetricCard
          icon={AlertTriangle}
          title="Suspicious Nodes"
          value={suspiciousNodes}
          description="Nodes with anomalous behavior"
          color="orange"
        />

        <MetricCard
          icon={ShieldAlert}
          title="Threat Recorded"
          value={
            threatId !== null
              ? "Yes"
              : "No"
          }
          description={
            threatId !== null
              ? `Threat #${threatId}`
              : "No threat record"
          }
          color={
            threatId !== null
              ? "red"
              : "green"
          }
        />
      </div>

      {/* ANALYSIS INFORMATION */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="text-sm font-semibold text-slate-200">
          Analysis Information
        </h2>

        <div className="mt-4 grid gap-3 md:grid-cols-3 lg:grid-cols-5">
          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Embedding Shape
            </p>

            <p className="mt-2 text-sm font-medium text-slate-300">
              {embeddingShape}
            </p>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Average GNN Anomaly
            </p>

            <p className="mt-2 text-sm font-medium text-slate-300">
              {averageScore.toFixed(
                2
              )}
              %
            </p>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Correlated Evidence
            </p>

            <p className="mt-2 text-sm font-medium text-slate-300">
              {correlatedEvents.toLocaleString()}
            </p>

            <p className="mt-1 text-[11px] leading-relaxed text-slate-600">
              Events used for contextual risk analysis
            </p>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Linked Evidence
            </p>

            <p className="mt-2 text-sm font-medium text-slate-300">
              {linkedEvents.toLocaleString()}
            </p>

            <p className="mt-1 text-[11px] leading-relaxed text-slate-600">
              Matching events associated with this threat
            </p>
          </div>

          <div className="rounded-lg bg-slate-950 p-4">
            <p className="text-xs text-slate-600">
              Threat ID
            </p>

            <p className="mt-2 text-sm font-medium text-slate-300">
              {threatId !== null
                ? threatId
                : "None"}
            </p>
          </div>
        </div>

        {result?.message && (
          <div className="mt-4 rounded-lg border border-blue-900/40 bg-blue-950/20 p-4">
            <p className="text-xs leading-relaxed text-blue-400">
              {String(
                result.message
              )}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

/* ============================================================
   THREAT EVENT TABLE
============================================================ */
function ThreatEvents({
  events,
  loading,
  threatId,
}) {
  if (loading) {
    return (
      <div className="border-t border-slate-800 bg-slate-950/60 p-8 text-center">
        <RefreshCw
          size={20}
          className="mx-auto animate-spin text-blue-400"
        />

        <p className="mt-3 text-xs text-slate-600">
          Loading network events...
        </p>
      </div>
    );
  }

  if (
    !events ||
    events.length === 0
  ) {
    return (
      <div className="border-t border-slate-800 bg-slate-950/60 p-8 text-center">
        <Network
          size={24}
          className="mx-auto text-slate-700"
        />

        <p className="mt-3 text-sm font-medium text-slate-400">
          No linked network events
        </p>

        <p className="mt-1 text-xs text-slate-600">
          No network events are currently linked to Threat #
          {threatId}.
        </p>
      </div>
    );
  }

  const highRisk =
    events.filter(
      (event) =>
        String(
          event?.risk || ""
        ).toLowerCase() ===
        "high"
    ).length;

  const mediumRisk =
    events.filter(
      (event) =>
        String(
          event?.risk || ""
        ).toLowerCase() ===
        "medium"
    ).length;

  const lowRisk =
    events.filter(
      (event) =>
        String(
          event?.risk || ""
        ).toLowerCase() ===
        "low"
    ).length;

  return (
    <div className="border-t border-slate-800 bg-slate-950/60 p-5">
      {/* EVENT HEADER */}
      <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h4 className="text-sm font-semibold text-slate-200">
            Network Events
          </h4>

          <p className="mt-1 text-xs text-slate-600">
            Events linked to Threat #
            {threatId}
          </p>
        </div>

        <span className="rounded-md bg-blue-950 px-3 py-1.5 text-xs font-medium text-blue-400">
          {events.length} events
        </span>
      </div>

      {/* EVENT SUMMARY */}
      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-600">
            Total Events
          </p>

          <p className="mt-2 text-xl font-semibold text-white">
            {events.length}
          </p>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-600">
            High Risk
          </p>

          <p className="mt-2 text-xl font-semibold text-red-400">
            {highRisk}
          </p>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-600">
            Medium Risk
          </p>

          <p className="mt-2 text-xl font-semibold text-orange-400">
            {mediumRisk}
          </p>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-600">
            Low Risk
          </p>

          <p className="mt-2 text-xl font-semibold text-emerald-400">
            {lowRisk}
          </p>
        </div>
      </div>

      {/* EVENT TABLE */}
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="min-w-full text-left">
          <thead className="bg-slate-900">
            <tr>
              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Event
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Source IP
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Destination IP
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Protocol
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Port
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Event Type
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Risk
              </th>

              <th className="px-4 py-3 text-xs font-medium text-slate-500">
                Time
              </th>
            </tr>
          </thead>

          <tbody>
            {events.map(
              (event, index) => {
                const risk =
                  String(
                    event?.risk ||
                      "low"
                  ).toLowerCase();

                let riskClass =
                  "bg-emerald-950 text-emerald-400";

                if (
                  risk === "high"
                ) {
                  riskClass =
                    "bg-red-950 text-red-400";
                } else if (
                  risk === "medium"
                ) {
                  riskClass =
                    "bg-orange-950 text-orange-400";
                }

                return (
                  <tr
                    key={
                      event?.id ??
                      `event-${index}`
                    }
                    className="border-t border-slate-800 hover:bg-slate-900/70"
                  >
                    <td className="px-4 py-3 text-xs text-slate-500">
                      #
                      {event?.id ??
                        index + 1}
                    </td>

                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-300">
                      {cleanIpAddress(
                        event?.source_ip
                      )}
                    </td>

                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-400">
                      {cleanIpAddress(
                        event?.destination_ip
                      )}
                    </td>

                    <td className="px-4 py-3 text-xs text-slate-400">
                      {event?.protocol ||
                        "—"}
                    </td>

                    <td className="px-4 py-3 text-xs text-slate-400">
                      {event?.port ??
                        "—"}
                    </td>

                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">
                      {event?.event_type ||
                        "—"}
                    </td>

                    <td className="px-4 py-3">
                      <span
                        className={`rounded-md px-2 py-1 text-[10px] font-medium uppercase ${riskClass}`}
                      >
                        {risk}
                      </span>
                    </td>

                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-600">
                      {event?.timestamp ||
                        "—"}
                    </td>
                  </tr>
                );
              }
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ============================================================
   THREAT ROW
============================================================ */
function ThreatRow({
  threat,
  onLink,
  linking,
  expandedThreatId,
  onToggleEvents,
  threatEvents,
  eventsLoading,
}) {
  const severity =
    String(
      threat?.severity ||
        "low"
    ).toLowerCase();

  let iconColor =
    "bg-emerald-500/10 text-emerald-400";

  if (
    severity === "high" ||
    severity === "critical"
  ) {
    iconColor =
      "bg-red-500/10 text-red-400";
  } else if (
    severity === "medium"
  ) {
    iconColor =
      "bg-orange-500/10 text-orange-400";
  }

  const threatId =
    threat?.id ??
    threat?.threat_id ??
    null;

  const normalizedId =
    threatId !== null
      ? String(threatId)
      : null;

  const isLinking =
    linking !== null &&
    String(linking) ===
      String(threatId);

  const isExpanded =
    expandedThreatId !== null &&
    String(
      expandedThreatId
    ) ===
      String(threatId);

  const events =
    normalizedId &&
    threatEvents[normalizedId]
      ? threatEvents[normalizedId]
      : [];

  const isLoadingEvents =
    eventsLoading !== null &&
    String(eventsLoading) ===
      String(threatId);

  const riskScore =
    Number(
      threat?.risk_score
    ) || 0;

  const anomalyScore =
    Number(
      threat?.anomaly_score ??
        threat?.confidence
    ) || 0;

  const baselineZ =
    Number(
      threat?.baseline_z_score
    ) || 0;

  return (
    <div className="border-b border-slate-800 last:border-b-0">
      {/* THREAT INFORMATION */}
      <div className="p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 gap-4">
            <div
              className={`shrink-0 rounded-lg p-3 ${iconColor}`}
            >
              <ShieldAlert
                size={18}
              />
            </div>

            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-200">
                  {threat?.threat_type ||
                    threat?.type ||
                    "Unknown Threat"}
                </h3>

                <StatusBadge
                  status={severity}
                />

                <StatusBadge
                  status={
                    threat?.status ||
                    "new"
                  }
                />

                {threat?.risk_score !==
                  undefined &&
                  threat?.risk_score !==
                    null && (
                    <RiskBadge
                      level={
                        threat?.risk_level ||
                        threat?.severity
                      }
                    />
                  )}
              </div>

              <p className="mt-2 text-sm text-slate-500">
                {threat?.description ||
                  "No threat description available."}
              </p>

              {/* THREAT METADATA */}
              <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-600">
                <span>
                  Threat #
                  {threatId ??
                    "N/A"}
                </span>

                <span>
                  GNN Anomaly:{" "}
                  {anomalyScore.toFixed(
                    2
                  )}
                  %
                </span>

                {threat?.risk_score !==
                  undefined &&
                  threat?.risk_score !==
                    null && (
                    <span>
                      Risk:{" "}
                      {riskScore.toFixed(
                        1
                      )}
                      /100
                    </span>
                  )}

                {threat?.baseline_z_score !==
                  undefined &&
                  threat?.baseline_z_score !==
                    null && (
                    <span>
                      Baseline Z:{" "}
                      {baselineZ.toFixed(
                        3
                      )}
                    </span>
                  )}

                <span>
                  {threat?.detected_at ||
                    threat?.created_at ||
                    "Unknown time"}
                </span>

                {events.length >
                  0 && (
                  <span className="font-medium text-blue-400">
                    {events.length} linked events
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* BUTTONS */}
          <div className="flex shrink-0 flex-wrap gap-2">
            <button
              type="button"
              disabled={
                threatId === null ||
                threatId ===
                  undefined ||
                isLoadingEvents
              }
              onClick={() => {
                if (
                  threatId !==
                    null &&
                  threatId !==
                    undefined
                ) {
                  onToggleEvents(
                    threatId
                  );
                }
              }}
              className="flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Network
                size={14}
              />

              {isLoadingEvents
                ? "Loading..."
                : isExpanded
                  ? "Hide Events"
                  : "View Events"}
            </button>

            <button
              type="button"
              disabled={
                isLinking ||
                threatId ===
                  null ||
                threatId ===
                  undefined
              }
              onClick={() => {
                if (
                  threatId !==
                    null &&
                  threatId !==
                    undefined
                ) {
                  onLink(
                    threatId
                  );
                }
              }}
              className="flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Link2
                size={14}
              />

              {isLinking
                ? "Linking..."
                : "Link Events"}
            </button>
          </div>
        </div>
      </div>

      {/* EXPANDED EVENTS */}
      {isExpanded && (
        <ThreatEvents
          events={events}
          loading={
            isLoadingEvents
          }
          threatId={threatId}
        />
      )}
    </div>
  );
}

/* ============================================================
   MAIN COMPONENT
============================================================ */
export default function ThreatDetection() {
  const [threats, setThreats] =
    useState([]);

  const [analysis, setAnalysis] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [analyzing, setAnalyzing] =
    useState(false);

  const [linking, setLinking] =
    useState(null);

  const [
    expandedThreatId,
    setExpandedThreatId,
  ] = useState(null);

  const [
    threatEvents,
    setThreatEvents,
  ] = useState({});

  const [
    eventsLoading,
    setEventsLoading,
  ] = useState(null);

  const [error, setError] =
    useState("");

  const [
    lastUpdated,
    setLastUpdated,
  ] = useState(null);

  /* ==========================================================
     NORMALIZE EVENTS
  ========================================================== */
  function normalizeEvents(data) {
    if (Array.isArray(data)) {
      return data;
    }

    if (
      data &&
      Array.isArray(
        data.events
      )
    ) {
      return data.events;
    }

    if (
      data &&
      Array.isArray(
        data.network_events
      )
    ) {
      return data.network_events;
    }

    if (
      data &&
      Array.isArray(
        data.data
      )
    ) {
      return data.data;
    }

    if (
      data &&
      Array.isArray(
        data.value
      )
    ) {
      return data.value;
    }

    return [];
  }

  /* ==========================================================
     RESTORE SAVED GNN ANALYSIS
  ========================================================== */
  function restoreSavedAnalysis() {
    try {
      const savedAnalysis =
        sessionStorage.getItem(
          GNN_ANALYSIS_STORAGE_KEY
        );

      if (!savedAnalysis) {
        return;
      }

      const parsedAnalysis =
        JSON.parse(
          savedAnalysis
        );

      if (
        parsedAnalysis &&
        typeof parsedAnalysis ===
          "object"
      ) {
        console.log(
          "Restored saved GNN analysis:",
          parsedAnalysis
        );

        setAnalysis(
          parsedAnalysis
        );
      }
    } catch (
      restoreError
    ) {
      console.error(
        "Unable to restore saved GNN analysis:",
        restoreError
      );

      sessionStorage.removeItem(
        GNN_ANALYSIS_STORAGE_KEY
      );
    }
  }

  /* ==========================================================
     LOAD THREATS
  ========================================================== */
  async function loadThreats() {
    try {
      setLoading(true);
      setError("");

      const data =
        await getThreats();

      console.log(
        "Threat API response:",
        data
      );

      let threatList = [];

      if (Array.isArray(data)) {
        threatList = data;
      } else if (
        data &&
        Array.isArray(
          data.threats
        )
      ) {
        threatList =
          data.threats;
      } else if (
        data &&
        Array.isArray(
          data.data
        )
      ) {
        threatList =
          data.data;
      } else if (
        data &&
        Array.isArray(
          data.value
        )
      ) {
        threatList =
          data.value;
      }

      setThreats(
        threatList
      );

      setLastUpdated(
        new Date()
      );
    } catch (err) {
      console.error(
        "Failed to load threats:",
        err
      );

      setThreats([]);

      setError(
        err?.message ||
          "Unable to load threats."
      );
    } finally {
      setLoading(false);
    }
  }

  /* ==========================================================
     LOAD THREAT NETWORK EVENTS
  ========================================================== */
  async function loadThreatEvents(
    threatId
  ) {
    if (
      threatId === null ||
      threatId === undefined
    ) {
      return [];
    }

    try {
      setEventsLoading(
        threatId
      );

      const data =
        await getThreatNetworkEvents(
          threatId
        );

      console.log(
        `Network events for Threat #${threatId}:`,
        data
      );

      const events =
        normalizeEvents(
          data
        );

      setThreatEvents(
        (previous) => ({
          ...previous,
          [String(threatId)]:
            events,
        })
      );

      return events;
    } catch (err) {
      console.error(
        `Failed to load events for Threat #${threatId}:`,
        err
      );

      setError(
        err?.message ||
          `Unable to load events for Threat #${threatId}.`
      );

      return [];
    } finally {
      setEventsLoading(
        null
      );
    }
  }

  /* ==========================================================
     TOGGLE THREAT EVENTS
  ========================================================== */
  async function toggleThreatEvents(
    threatId
  ) {
    if (
      threatId === null ||
      threatId === undefined
    ) {
      return;
    }

    const normalizedId =
      String(threatId);

    if (
      String(
        expandedThreatId
      ) === normalizedId
    ) {
      setExpandedThreatId(
        null
      );

      return;
    }

    setExpandedThreatId(
      threatId
    );

    const existingEvents =
      threatEvents[
        normalizedId
      ];

    if (
      existingEvents ===
      undefined
    ) {
      await loadThreatEvents(
        threatId
      );
    }
  }

  /* ==========================================================
     CHECK ACTIVE / OPEN THREAT
  ========================================================== */
  function isOpenThreat(
    threat
  ) {
    const status =
      String(
        threat?.status || ""
      ).toLowerCase();

    return [
      "active",
      "new",
      "open",
      "investigating",
      "contained",
    ].includes(status);
  }

  /* ==========================================================
     LOAD EXISTING OPEN THREAT EVENTS
  ========================================================== */
  async function loadExistingThreatEvents(
    threatList
  ) {
    if (
      !Array.isArray(
        threatList
      ) ||
      threatList.length === 0
    ) {
      return;
    }

    const activeThreats =
      threatList.filter(
        (threat) =>
          threat?.id !==
            undefined &&
          threat?.id !==
            null &&
          isOpenThreat(
            threat
          )
      );

    for (
      const threat of activeThreats
    ) {
      const threatId =
        threat.id;

      if (
        threatEvents[
          String(threatId)
        ] !== undefined
      ) {
        continue;
      }

      try {
        const data =
          await getThreatNetworkEvents(
            threatId
          );

        const events =
          normalizeEvents(
            data
          );

        setThreatEvents(
          (previous) => ({
            ...previous,
            [String(threatId)]:
              events,
          })
        );
      } catch (err) {
        console.error(
          `Unable to preload events for Threat #${threatId}:`,
          err
        );
      }
    }
  }

  /* ==========================================================
     RUN GNN + RISK ANALYSIS
  ========================================================== */
  async function runAnalysis() {
    try {
      setAnalyzing(true);
      setError("");

      const result =
        await analyzeNetwork();

      console.log(
        "GNN + Risk analysis response:",
        result
      );

      if (!result) {
        throw new Error(
          "The backend returned an empty GNN analysis response."
        );
      }

      /*
        Save the COMPLETE backend response.
      */
      setAnalysis(
        result
      );

      sessionStorage.setItem(
        GNN_ANALYSIS_STORAGE_KEY,
        JSON.stringify(
          result
        )
      );

      /* ------------------------------------------------------
         GET REAL LINKED EVENTS
      ------------------------------------------------------ */
      if (
        result?.threat_id !==
          null &&
        result?.threat_id !==
          undefined
      ) {
        const generatedThreatId =
          result.threat_id;

        const events =
          await loadThreatEvents(
            generatedThreatId
          );

        /*
          Update linked event count and
          persist the updated analysis.
        */
        setAnalysis(
          (previous) => {
            if (!previous) {
              return previous;
            }

            const updatedAnalysis =
              {
                ...previous,
                linked_events:
                  events.length,
              };

            sessionStorage.setItem(
              GNN_ANALYSIS_STORAGE_KEY,
              JSON.stringify(
                updatedAnalysis
              )
            );

            return updatedAnalysis;
          }
        );

        /*
          Automatically expand the newly
          generated threat.
        */
        setExpandedThreatId(
          generatedThreatId
        );
      }

      /*
        Refresh threat records from database.
      */
      await loadThreats();
    } catch (err) {
      console.error(
        "GNN analysis failed:",
        err
      );

      setError(
        err?.message ||
          "GNN analysis failed."
      );
    } finally {
      setAnalyzing(false);
    }
  }

  /* ==========================================================
     LINK THREAT EVENTS
  ========================================================== */
  async function handleLinkEvents(
    threatId
  ) {
    if (
      threatId === null ||
      threatId === undefined
    ) {
      setError(
        "Invalid threat ID."
      );

      return;
    }

    try {
      setLinking(
        threatId
      );

      setError("");

      const result =
        await linkThreatEvents(
          threatId
        );

      console.log(
        "Link events response:",
        result
      );

      /*
        Reload the real linked events
        after linking.
      */
      const events =
        await loadThreatEvents(
          threatId
        );

      setExpandedThreatId(
        threatId
      );

      setAnalysis(
        (previous) => {
          if (!previous) {
            return previous;
          }

          if (
            String(
              previous.threat_id
            ) !==
            String(
              threatId
            )
          ) {
            return previous;
          }

          const updatedAnalysis =
            {
              ...previous,
              linked_events:
                events.length,
              correlated_event_count:
                previous.correlated_event_count ??
                events.length,
            };

          /*
            Keep session copy synchronized
            with the UI state.
          */
          sessionStorage.setItem(
            GNN_ANALYSIS_STORAGE_KEY,
            JSON.stringify(
              updatedAnalysis
            )
          );

          return updatedAnalysis;
        }
      );

      await loadThreats();
    } catch (err) {
      console.error(
        "Failed to link events:",
        err
      );

      setError(
        err?.message ||
          "Unable to link network events."
      );
    } finally {
      setLinking(
        null
      );
    }
  }

  /* ==========================================================
     INITIAL LOAD
  ========================================================== */
  useEffect(() => {
    /*
      Restore the full GNN analysis only once
      when the page is mounted.
    */
    restoreSavedAnalysis();

    async function initialize() {
      await loadThreats();
    }

    initialize();

    const interval =
      setInterval(
        () => {
          loadThreats();
        },
        10000
      );

    return () => {
      clearInterval(
        interval
      );
    };
  }, []);

  /* ==========================================================
     LOAD EVENTS AFTER THREATS CHANGE
  ========================================================== */
  useEffect(() => {
    if (
      threats.length > 0
    ) {
      loadExistingThreatEvents(
        threats
      );
    }
  }, [threats]);

  /* ==========================================================
     THREAT COUNTS
  ========================================================== */
  const highThreats =
    threats.filter(
      (threat) => {
        const severity =
          String(
            threat?.severity ||
              ""
          ).toLowerCase();

        return (
          severity === "high" ||
          severity ===
            "critical"
        );
      }
    ).length;

  const mediumThreats =
    threats.filter(
      (threat) =>
        String(
          threat?.severity ||
            ""
        ).toLowerCase() ===
        "medium"
    ).length;

  const resolvedThreats =
    threats.filter(
      (threat) =>
        String(
          threat?.status ||
            ""
        ).toLowerCase() ===
        "resolved"
    ).length;

  /* ==========================================================
     UI
  ========================================================== */
  return (
    <div className="space-y-6">
      {/* HEADER */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-orange-500/10 p-2">
              <ShieldAlert
                size={20}
                className="text-orange-400"
              />
            </div>

            <h1 className="text-xl font-semibold text-white">
              Threat Detection
            </h1>
          </div>

          <p className="mt-2 text-sm text-slate-500">
            AI-powered network anomaly detection using Graph Neural Networks with contextual risk correlation.
          </p>

          {lastUpdated && (
            <p className="mt-1 text-xs text-slate-700">
              Last updated:{" "}
              {lastUpdated.toLocaleTimeString()}
            </p>
          )}
        </div>

        <div className="flex gap-2">
          {/* REFRESH */}
          <button
            type="button"
            onClick={
              loadThreats
            }
            disabled={loading}
            className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-xs font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-50"
          >
            <RefreshCw
              size={14}
              className={
                loading
                  ? "animate-spin"
                  : ""
              }
            />

            Refresh
          </button>

          {/* ANALYZE */}
          <button
            type="button"
            onClick={
              runAnalysis
            }
            disabled={
              analyzing
            }
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-xs font-medium text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Brain
              size={15}
              className={
                analyzing
                  ? "animate-pulse"
                  : ""
              }
            />

            {analyzing
              ? "Analyzing..."
              : "Analyze Network"}
          </button>
        </div>
      </div>

      {/* ERROR */}
      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-red-900/50 bg-red-950/20 p-4">
          <AlertTriangle
            size={18}
            className="mt-0.5 shrink-0 text-red-400"
          />

          <div className="min-w-0">
            <p className="text-sm font-medium text-red-400">
              Detection Error
            </p>

            <p className="mt-1 break-words text-xs text-red-500">
              {error}
            </p>
          </div>
        </div>
      )}

      {/* SUMMARY METRICS */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          icon={ShieldAlert}
          title="Total Threats"
          value={
            threats.length
          }
          description="Threats stored in database"
          color="orange"
        />

        <MetricCard
          icon={AlertTriangle}
          title="High Severity"
          value={
            highThreats
          }
          description="High-severity detections"
          color="red"
        />

        <MetricCard
          icon={CircleAlert}
          title="Medium Severity"
          value={
            mediumThreats
          }
          description="Medium-severity detections"
          color="orange"
        />

        <MetricCard
          icon={CheckCircle2}
          title="Resolved"
          value={
            resolvedThreats
          }
          description="Resolved security threats"
          color="green"
        />
      </div>

      {/* GNN + RISK ANALYSIS */}
      <GNNResult
        result={analysis}
      />

      {/* DETECTED THREATS */}
      <div className="rounded-xl border border-slate-800 bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-orange-500/10 p-2">
              <ShieldAlert
                size={16}
                className="text-orange-400"
              />
            </div>

            <div>
              <h2 className="text-sm font-semibold text-slate-200">
                Detected Threats
              </h2>

              <p className="mt-1 text-xs text-slate-600">
                Threats generated by ZeroGuard
              </p>
            </div>
          </div>

          <span className="text-xs text-slate-600">
            {threats.length} total
          </span>
        </div>

        {loading ? (
          <div className="p-10 text-center">
            <RefreshCw
              size={22}
              className="mx-auto animate-spin text-blue-400"
            />

            <p className="mt-3 text-xs text-slate-600">
              Loading threats...
            </p>
          </div>
        ) : threats.length ===
          0 ? (
          <div className="p-10 text-center">
            <CheckCircle2
              size={28}
              className="mx-auto text-emerald-400"
            />

            <p className="mt-3 text-sm font-medium text-slate-300">
              No threats detected
            </p>

            <p className="mt-1 text-xs text-slate-600">
              Run a network analysis to check for anomalies.
            </p>
          </div>
        ) : (
          threats.map(
            (
              threat,
              index
            ) => (
              <ThreatRow
                key={
                  threat?.id ??
                  threat?.threat_id ??
                  `threat-${index}`
                }
                threat={
                  threat
                }
                onLink={
                  handleLinkEvents
                }
                linking={
                  linking
                }
                expandedThreatId={
                  expandedThreatId
                }
                onToggleEvents={
                  toggleThreatEvents
                }
                threatEvents={
                  threatEvents
                }
                eventsLoading={
                  eventsLoading
                }
              />
            )
          )
        )}
      </div>

      {/* HOW IT WORKS */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-purple-500/10 p-2">
            <Brain
              size={17}
              className="text-purple-400"
            />
          </div>

          <div>
            <h2 className="text-sm font-semibold text-slate-200">
              How ZeroGuard GNN Detection Works
            </h2>

            <p className="mt-1 text-xs text-slate-600">
              ZeroGuard separates statistical anomaly detection from contextual security risk.
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-5">
          {/* COLLECT */}
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs font-medium text-blue-400">
              01 — Collect
            </p>

            <p className="mt-2 text-xs leading-relaxed text-slate-600">
              Network activity and connection information are collected from the monitored system.
            </p>
          </div>

          {/* BUILD GRAPH */}
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs font-medium text-purple-400">
              02 — Build Graph
            </p>

            <p className="mt-2 text-xs leading-relaxed text-slate-600">
              Network entities become graph nodes and their relationships become graph edges.
            </p>
          </div>

          {/* GNN */}
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs font-medium text-orange-400">
              03 — GNN
            </p>

            <p className="mt-2 text-xs leading-relaxed text-slate-600">
              The GNN learns network structure and identifies behavior that differs from the normal baseline.
            </p>
          </div>

          {/* CORRELATE */}
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs font-medium text-yellow-400">
              04 — Correlate
            </p>

            <p className="mt-2 text-xs leading-relaxed text-slate-600">
              Network evidence, host context and suspicious activity are combined to reduce false positives.
            </p>
          </div>

          {/* DECIDE */}
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs font-medium text-red-400">
              05 — Decide
            </p>

            <p className="mt-2 text-xs leading-relaxed text-slate-600">
              ZeroGuard assigns a final risk level and recommends monitoring, investigation or response.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}