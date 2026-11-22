import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  FileText,
  Globe,
  Network,
  Printer,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Target,
} from "lucide-react";

import {
  getStatus,
  getThreats,
  getIncidents,
  getResponseActions,
  getThreatNetworkEvents,
} from "../services/api";

/* =========================================================
   HELPERS
========================================================= */

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatPercent(value) {
  return `${Number(value || 0).toFixed(2)}%`;
}

function formatDate(value) {
  if (!value) return "Not available";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function getSeverityClass(severity) {
  const value = String(severity || "").toLowerCase();

  if (value === "critical") {
    return "text-red-400 bg-red-500/10 border-red-500/30";
  }

  if (value === "high") {
    return "text-orange-400 bg-orange-500/10 border-orange-500/30";
  }

  if (value === "medium") {
    return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
  }

  if (value === "low") {
    return "text-green-400 bg-green-500/10 border-green-500/30";
  }

  return "text-slate-300 bg-slate-500/10 border-slate-500/30";
}

function getActionStatusClass(status) {
  const value = String(status || "").toLowerCase();

  if (value === "completed") {
    return "text-green-400 bg-green-500/10 border-green-500/30";
  }

  if (value === "denied") {
    return "text-orange-400 bg-orange-500/10 border-orange-500/30";
  }

  if (value === "failed") {
    return "text-red-400 bg-red-500/10 border-red-500/30";
  }

  if (value === "pending") {
    return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
  }

  return "text-slate-300 bg-slate-500/10 border-slate-500/30";
}

/*
 * Identifies records that were clearly created as
 * development / validation / workflow tests.
 *
 * This does NOT modify or delete the records.
 */
function isTestAction(action) {
  const text = String(
    `${action?.reason || ""} ${action?.action_type || ""}`
  ).toLowerCase();

  const testKeywords = [
    "test",
    "testing",
    "validation",
    "workflow test",
    "frontend response",
    "end-to-end",
    "e2e",
    "safe alert generation",
  ];

  return testKeywords.some((keyword) =>
    text.includes(keyword)
  );
}

function getActionClassification(action) {
  if (isTestAction(action)) {
    return "TEST / VALIDATION";
  }

  return "DEFENSIVE ACTION";
}

function getActionClassificationClass(action) {
  if (isTestAction(action)) {
    return "text-purple-400 bg-purple-500/10 border-purple-500/30";
  }

  return "text-cyan-400 bg-cyan-500/10 border-cyan-500/30";
}

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
}) {
  return (
    <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg print:bg-white print:text-black">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-slate-400 print:text-slate-600">
            {title}
          </p>

          <h3 className="mt-2 text-3xl font-bold text-white print:text-black">
            {value}
          </h3>

          {subtitle && (
            <p className="mt-1 text-xs text-slate-500 print:text-slate-600">
              {subtitle}
            </p>
          )}
        </div>

        <div className="rounded-xl bg-slate-800 p-3 print:hidden">
          <Icon className="h-5 w-5 text-cyan-400" />
        </div>
      </div>
    </div>
  );
}

function SectionTitle({
  icon: Icon,
  title,
  subtitle,
}) {
  return (
    <div className="mb-5 flex items-center gap-3">
      <div className="rounded-xl bg-cyan-500/10 p-2 print:hidden">
        <Icon className="h-5 w-5 text-cyan-400" />
      </div>

      <div>
        <h2 className="text-lg font-semibold text-white print:text-black">
          {title}
        </h2>

        {subtitle && (
          <p className="text-sm text-slate-500 print:text-slate-600">
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}

function extractNumber(
  description,
  patterns,
  fallback = 0
) {
  const text = String(description || "");

  for (const pattern of patterns) {
    const match = text.match(pattern);

    if (match?.[1] !== undefined) {
      const number = Number(match[1]);

      if (!Number.isNaN(number)) {
        return number;
      }
    }
  }

  return fallback;
}

function extractText(description, label) {
  const text = String(description || "");

  const escapedLabel = label.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );

  const regex = new RegExp(
    `${escapedLabel}:\\s*([^\\.]+(?:\\.[^A-Z][^\\.]+)*)`,
    "i"
  );

  const match = text.match(regex);

  return match?.[1]?.trim() || "";
}

function splitRiskReasons(description) {
  const text = String(description || "");

  const match = text.match(
    /Risk reasons:\s*(.*?)(?:\.\s*Positive context:|$)/i
  );

  if (!match?.[1]) {
    return [];
  }

  return match[1]
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) =>
      item.endsWith(".") ? item : `${item}.`
    );
}

function splitPositiveContext(description) {
  const text = String(description || "");

  const match = text.match(
    /Positive context:\s*(.*?)(?:\.\s*Warnings:|$)/i
  );

  if (!match?.[1]) {
    return [];
  }

  return match[1]
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) =>
      item.endsWith(".") ? item : `${item}.`
    );
}

function splitWarnings(description) {
  const text = String(description || "");

  const match = text.match(
    /Warnings:\s*(.*?)(?:\.\s*Automatic blocking|\.?\s*Recommended action:|$)/i
  );

  if (!match?.[1]) {
    return [];
  }

  return match[1]
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) =>
      item.endsWith(".") ? item : `${item}.`
    );
}

function extractRecommendedAction(description) {
  const text = String(description || "");

  const match = text.match(
    /Recommended action:\s*(.*?)(?:\.?$)/i
  );

  return match?.[1]?.trim() || "";
}

function getDestination(event) {
  const destination =
    event?.destination_ip ??
    event?.destination ??
    "";

  return destination ? String(destination) : "";
}

function getSource(event) {
  const source =
    event?.source_ip ??
    event?.source ??
    "";

  return source ? String(source) : "";
}

function getProtocol(event) {
  return String(
    event?.protocol ?? ""
  ).toUpperCase();
}

function getPort(event) {
  const port =
    event?.port ??
    event?.destination_port ??
    event?.source_port ??
    null;

  return port !== null &&
    port !== undefined &&
    port !== ""
    ? String(port)
    : "";
}

/*
 * Returns the most frequently observed values.
 * This makes the report much more useful than showing
 * a random list of 220 destinations / 311 ports.
 */
function getTopValues(
  events,
  getter,
  limit = 5
) {
  const counts = new Map();

  events.forEach((event) => {
    const value = getter(event);

    if (!value) return;

    counts.set(
      value,
      (counts.get(value) || 0) + 1
    );
  });

  return [...counts.entries()]
    .sort(
      (a, b) =>
        b[1] - a[1] ||
        String(a[0]).localeCompare(
          String(b[0])
        )
    )
    .slice(0, limit)
    .map(([value, count]) => ({
      value,
      count,
    }));
}

function CompactList({
  items,
  label,
  icon: Icon,
  limit = 6,
  mono = false,
  showCounts = false,
}) {
  const visibleItems = items.slice(0, limit);
  const remaining = Math.max(
    items.length - limit,
    0
  );

  return (
    <div>
      <p className="mb-2 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </p>

      {items.length === 0 ? (
        <p className="text-sm text-slate-500">
          Not available
        </p>
      ) : (
        <div className="space-y-2">
          {visibleItems.map((item, index) => {
            const value =
              typeof item === "object"
                ? item.value
                : item;

            const count =
              typeof item === "object"
                ? item.count
                : null;

            return (
              <div
                key={`${value}-${index}`}
                className={`flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-sm text-slate-300 print:bg-slate-50 print:text-slate-700 ${
                  mono ? "font-mono" : ""
                }`}
              >
                <div className="flex min-w-0 items-center gap-2">
                  {Icon && (
                    <Icon className="h-4 w-4 shrink-0 text-cyan-400" />
                  )}

                  <span className="break-all">
                    {value}
                  </span>
                </div>

                {showCounts &&
                  count !== null && (
                    <span className="shrink-0 rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-xs text-slate-500 print:border-slate-300 print:bg-white">
                      {formatNumber(count)}
                    </span>
                  )}
              </div>
            );
          })}

          {remaining > 0 && (
            <p className="px-2 text-xs text-slate-500">
              + {formatNumber(remaining)} more
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/* =========================================================
   REPORTS PAGE
========================================================= */

export default function Reports() {
  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [status, setStatus] =
    useState(null);

  const [threats, setThreats] =
    useState([]);

  const [incidents, setIncidents] =
    useState([]);

  const [responseActions, setResponseActions] =
    useState([]);

  const [selectedIncidentId, setSelectedIncidentId] =
    useState(null);

  const [incidentEvents, setIncidentEvents] =
    useState([]);

  const [showDetailedEvidence, setShowDetailedEvidence] =
    useState(false);

  const [error, setError] =
    useState("");

  async function loadReports(
    showRefresh = false
  ) {
    try {
      setError("");

      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      /*
       * Reports only READ existing evidence.
       * Opening or refreshing Reports does not trigger
       * a new GNN detection.
       */

      const [
        statusData,
        threatsData,
        incidentsData,
        responseData,
      ] = await Promise.all([
        getStatus(),
        getThreats(),
        getIncidents(),
        getResponseActions(),
      ]);

      const safeThreats = Array.isArray(
        threatsData
      )
        ? threatsData
        : [];

      const safeIncidents = Array.isArray(
        incidentsData
      )
        ? incidentsData
        : [];

      const safeActions = Array.isArray(
        responseData
      )
        ? responseData
        : [];

      setStatus(statusData);
      setThreats(safeThreats);
      setIncidents(safeIncidents);
      setResponseActions(safeActions);

      const sortedIncidents =
        [...safeIncidents].sort(
          (a, b) =>
            new Date(
              b.updated_at ||
                b.created_at ||
                0
            ) -
            new Date(
              a.updated_at ||
                a.created_at ||
                0
            )
        );

      const preferredIncident =
        sortedIncidents.find(
          (incident) =>
            String(
              incident.status || ""
            ).toLowerCase() ===
            "investigating"
        ) ||
        sortedIncidents[0] ||
        null;

      if (preferredIncident) {
        setSelectedIncidentId(
          preferredIncident.id
        );

        setShowDetailedEvidence(false);

        if (preferredIncident.threat_id) {
          try {
            const events =
              await getThreatNetworkEvents(
                preferredIncident.threat_id
              );

            setIncidentEvents(
              Array.isArray(events)
                ? events
                : []
            );
          } catch (eventError) {
            console.error(
              "Failed to load incident events:",
              eventError
            );

            setIncidentEvents([]);
          }
        } else {
          setIncidentEvents([]);
        }
      } else {
        setSelectedIncidentId(null);
        setIncidentEvents([]);
      }
    } catch (err) {
      console.error(
        "Reports loading error:",
        err
      );

      setError(
        err?.message ||
          "Failed to load report data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadReports();

    const interval = setInterval(() => {
      loadReports(true);
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  async function handleIncidentChange(
    incidentId
  ) {
    const id = Number(incidentId);

    setSelectedIncidentId(id);
    setIncidentEvents([]);
    setShowDetailedEvidence(false);

    const incident = incidents.find(
      (item) =>
        Number(item.id) === id
    );

    if (!incident?.threat_id) {
      return;
    }

    try {
      const events =
        await getThreatNetworkEvents(
          incident.threat_id
        );

      setIncidentEvents(
        Array.isArray(events)
          ? events
          : []
      );
    } catch (err) {
      console.error(
        "Failed to load selected incident events:",
        err
      );

      setError(
        err?.message ||
          "Could not load network evidence for this incident."
      );
    }
  }

  function printReport() {
    window.print();
  }

  const selectedIncident = useMemo(() => {
    return (
      incidents.find(
        (incident) =>
          Number(incident.id) ===
          Number(selectedIncidentId)
      ) || null
    );
  }, [
    incidents,
    selectedIncidentId,
  ]);

  const selectedThreat = useMemo(() => {
    if (!selectedIncident) {
      return null;
    }

    return (
      threats.find(
        (threat) =>
          Number(threat.id) ===
          Number(
            selectedIncident.threat_id
          )
      ) || null
    );
  }, [
    selectedIncident,
    threats,
  ]);

  const selectedActions = useMemo(() => {
    if (!selectedIncident) {
      return [];
    }

    return responseActions
      .filter(
        (action) =>
          Number(action.incident_id) ===
          Number(selectedIncident.id)
      )
      .sort(
        (a, b) =>
          new Date(
            b.created_at || 0
          ) -
          new Date(
            a.created_at || 0
          )
      );
  }, [
    responseActions,
    selectedIncident,
  ]);

  const evidence = useMemo(() => {
    const threat = selectedThreat;

    const description =
      threat?.description ||
      selectedIncident?.description ||
      "";

    const sourceFromThreat =
      threat?.source_ip || "";

    const sourceFromEvents =
      incidentEvents
        .map(getSource)
        .find(Boolean) || "";

    const sourceIp =
      sourceFromThreat ||
      sourceFromEvents ||
      "Not available";

    const destinations = [
      ...new Set(
        incidentEvents
          .map(getDestination)
          .filter(Boolean)
      ),
    ];

    const protocols = [
      ...new Set(
        incidentEvents
          .map(getProtocol)
          .filter(Boolean)
      ),
    ];

    const ports = [
      ...new Set(
        incidentEvents
          .map(getPort)
          .filter(Boolean)
      ),
    ];

    const riskCounts =
      incidentEvents.reduce(
        (counts, event) => {
          const risk = String(
            event?.risk ||
              event?.risk_level ||
              ""
          ).toLowerCase();

          if (risk === "high") {
            counts.high += 1;
          } else if (risk === "medium") {
            counts.medium += 1;
          } else if (risk === "low") {
            counts.low += 1;
          }

          return counts;
        },
        {
          high: 0,
          medium: 0,
          low: 0,
        }
      );

    const maximumAnomaly =
      Number(
        threat?.anomaly_score ??
          extractNumber(
            description,
            [
              /maximum anomaly score:\s*([\d.]+)/i,
              /anomaly score:\s*([\d.]+)/i,
            ]
          )
      ) || 0;

    const averageAnomaly =
      extractNumber(
        description,
        [
          /average anomaly score:\s*([\d.]+)/i,
        ],
        0
      );

    const baselineZScore =
      Number(
        threat?.baseline_z_score ??
          extractNumber(
            description,
            [
              /baseline z-score:\s*([\d.]+)/i,
            ]
          )
      ) || 0;

    const suspiciousNodes =
      extractNumber(
        description,
        [
          /suspicious nodes:\s*(\d+)/i,
        ],
        0
      );

    const correlatedEvents =
      extractNumber(
        description,
        [
          /correlated events:\s*(\d+)/i,
        ],
        incidentEvents.length
      );

    const riskScore =
      Number(
        threat?.risk_score ??
          extractNumber(
            description,
            [
              /final contextual risk score:\s*([\d.]+)/i,
            ]
          )
      ) || 0;

    const riskLevel = String(
      threat?.severity ||
        extractText(
          description,
          "Final risk level"
        ) ||
        selectedIncident?.severity ||
        "unknown"
    ).toUpperCase();

    /*
     * IMPORTANT:
     * GNN severity is intentionally extracted as a
     * simple severity value such as HIGH / MEDIUM / LOW.
     *
     * The detailed explanation stays in the description
     * and contextual-risk sections.
     */
    const gnnSeverityRaw =
      extractText(
        description,
        "GNN severity before contextual correlation"
      );

    const gnnSeverity =
      String(
        gnnSeverityRaw
          .split(".")[0]
          .trim() || "unknown"
      ).toUpperCase();

    const gnnScoreFromThreat =
      threat?.anomaly_score !== null &&
      threat?.anomaly_score !== undefined
        ? Number(threat.anomaly_score)
        : maximumAnomaly;

    const topDestinations =
      getTopValues(
        incidentEvents,
        getDestination,
        5
      );

    const topPorts =
      getTopValues(
        incidentEvents,
        getPort,
        8
      );

    const topProtocols =
      getTopValues(
        incidentEvents,
        getProtocol,
        8
      );

    return {
      description,
      sourceIp,
      destinations,
      protocols,
      ports,
      riskCounts,
      maximumAnomaly,
      averageAnomaly,
      baselineZScore,
      suspiciousNodes,
      correlatedEvents,
      riskScore,
      riskLevel,
      gnnSeverity,
      gnnScoreFromThreat,
      topDestinations,
      topPorts,
      topProtocols,
      riskReasons:
        splitRiskReasons(
          description
        ),
      positiveContext:
        splitPositiveContext(
          description
        ),
      warnings:
        splitWarnings(description),
      recommendedAction:
        extractRecommendedAction(
          description
        ),
    };
  }, [
    selectedThreat,
    selectedIncident,
    incidentEvents,
  ]);

  /* =========================================================
     OVERALL SYSTEM COUNTS
  ========================================================= */

  const totalThreats =
    threats.length;

  const activeThreats =
    threats.filter(
      (threat) =>
        ![
          "resolved",
          "closed",
          "mitigated",
        ].includes(
          String(
            threat.status || ""
          ).toLowerCase()
        )
    ).length;

  const resolvedThreats =
    threats.filter(
      (threat) =>
        [
          "resolved",
          "closed",
          "mitigated",
        ].includes(
          String(
            threat.status || ""
          ).toLowerCase()
        )
    ).length;

  const activeIncidents =
    incidents.filter(
      (incident) =>
        ![
          "resolved",
          "closed",
        ].includes(
          String(
            incident.status || ""
          ).toLowerCase()
        )
    ).length;

  const resolvedIncidents =
    incidents.filter(
      (incident) =>
        [
          "resolved",
          "closed",
        ].includes(
          String(
            incident.status || ""
          ).toLowerCase()
        )
    ).length;

  const completedActions =
    responseActions.filter(
      (action) =>
        String(
          action.status || ""
        ).toLowerCase() ===
        "completed"
    ).length;

  const pendingActions =
    responseActions.filter(
      (action) =>
        String(
          action.status || ""
        ).toLowerCase() ===
        "pending"
    ).length;

  const deniedActions =
    responseActions.filter(
      (action) =>
        String(
          action.status || ""
        ).toLowerCase() ===
        "denied"
    ).length;

  const failedActions =
    responseActions.filter(
      (action) =>
        String(
          action.status || ""
        ).toLowerCase() ===
        "failed"
    ).length;

  const criticalCount =
    threats.filter(
      (threat) =>
        String(
          threat.severity || ""
        ).toLowerCase() ===
        "critical"
    ).length;

  const highCount =
    threats.filter(
      (threat) =>
        String(
          threat.severity || ""
        ).toLowerCase() ===
        "high"
    ).length;

  const mediumCount =
    threats.filter(
      (threat) =>
        String(
          threat.severity || ""
        ).toLowerCase() ===
        "medium"
    ).length;

  const lowCount =
    threats.filter(
      (threat) =>
        String(
          threat.severity || ""
        ).toLowerCase() ===
        "low"
    ).length;

  /* =========================================================
     JSON EXPORT
  ========================================================= */

  function downloadJsonReport() {
    const reportData = {
      report_name:
        "ZeroGuard Security Incident Report",

      generated_at:
        new Date().toISOString(),

      incident:
        selectedIncident,

      threat:
        selectedThreat,

      evidence: {
        source_ip:
          evidence.sourceIp,

        destination_ips:
          evidence.destinations,

        protocols:
          evidence.protocols,

        observed_ports:
          evidence.ports,

        correlated_events:
          evidence.correlatedEvents,

        returned_linked_events:
          incidentEvents.length,

        high_risk_events:
          evidence.riskCounts.high,

        medium_risk_events:
          evidence.riskCounts.medium,

        low_risk_events:
          evidence.riskCounts.low,

        maximum_anomaly_score:
          evidence.maximumAnomaly,

        average_anomaly_score:
          evidence.averageAnomaly,

        baseline_z_score:
          evidence.baselineZScore,

        suspicious_nodes:
          evidence.suspiciousNodes,

        gnn_severity:
          evidence.gnnSeverity,

        final_risk_score:
          evidence.riskScore,

        final_risk_level:
          evidence.riskLevel,

        risk_reasons:
          evidence.riskReasons,

        positive_context:
          evidence.positiveContext,

        warnings:
          evidence.warnings,

        recommended_action:
          evidence.recommendedAction,
      },

      response_actions:
        selectedActions,

      linked_network_events:
        incidentEvents,
    };

    const blob = new Blob(
      [
        JSON.stringify(
          reportData,
          null,
          2
        ),
      ],
      {
        type: "application/json",
      }
    );

    const url =
      URL.createObjectURL(blob);

    const link =
      document.createElement("a");

    link.href = url;

    link.download =
      `zeroguard-incident-report-${
        selectedIncident?.id ||
        "current"
      }-${new Date()
        .toISOString()
        .slice(0, 10)}.json`;

    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);
  }

  /* =========================================================
     LOADING
  ========================================================= */

  if (loading) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <div className="text-center">
          <RefreshCw className="mx-auto mb-3 h-8 w-8 animate-spin text-cyan-400" />

          <p className="text-slate-400">
            Loading security report...
          </p>
        </div>
      </div>
    );
  }

  /* =========================================================
     UI
  ========================================================= */

  return (
    <div className="space-y-6 pb-10 print:bg-white print:text-black">

      {/* =====================================================
          PRINT HEADER
      ===================================================== */}

      <div className="hidden print:block print:mb-8">
        <div className="border-b-2 border-slate-800 pb-4">
          <h1 className="text-3xl font-bold">
            ZeroGuard Security Incident Report
          </h1>

          <p className="mt-2 text-sm">
            AI-Based Zero-Day Attack Detection Using
            Graph Neural Networks
          </p>

          <p className="mt-1 text-xs text-slate-500">
            Generated on{" "}
            {new Date().toLocaleString()}
          </p>
        </div>
      </div>

      {/* =====================================================
          HEADER
      ===================================================== */}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between print:mb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-cyan-500/10 p-3 print:hidden">
              <FileText className="h-6 w-6 text-cyan-400" />
            </div>

            <div>
              <h1 className="text-2xl font-bold text-white print:text-black">
                Security Reports
              </h1>

              <p className="text-sm text-slate-400 print:text-slate-700">
                Evidence-based SOC investigation and response report.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap gap-2 print:hidden">
          <button
            onClick={() =>
              loadReports(true)
            }
            disabled={refreshing}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-300 transition hover:border-cyan-500/40 hover:text-white disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${
                refreshing
                  ? "animate-spin"
                  : ""
              }`}
            />

            Refresh
          </button>

          <button
            onClick={printReport}
            className="flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-500"
          >
            <Printer className="h-4 w-4" />

            Print / Save PDF
          </button>

          <button
            onClick={
              downloadJsonReport
            }
            className="flex items-center gap-2 rounded-xl bg-cyan-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-cyan-500"
          >
            <FileText className="h-4 w-4" />

            Export JSON
          </button>
        </div>
      </div>

      {/* =====================================================
          ERROR
      ===================================================== */}

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300 print:text-red-700">
          {error}
        </div>
      )}

      {/* =====================================================
          SYSTEM SUMMARY
      ===================================================== */}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-7">
        <StatCard
          title="Network Events"
          value={formatNumber(
            status?.network_events
          )}
          subtitle="Backend total"
          icon={Activity}
        />

        <StatCard
          title="Threats"
          value={formatNumber(
            totalThreats
          )}
          subtitle={`${activeThreats} active`}
          icon={ShieldAlert}
        />

        <StatCard
          title="Incidents"
          value={formatNumber(
            incidents.length
          )}
          subtitle={`${activeIncidents} active`}
          icon={AlertTriangle}
        />

        <StatCard
          title="Completed Actions"
          value={formatNumber(
            completedActions
          )}
          subtitle={`${pendingActions} pending`}
          icon={ShieldCheck}
        />

        <StatCard
          title="Devices"
          value={formatNumber(
            status?.devices
          )}
          subtitle="Monitored devices"
          icon={Target}
        />

        <StatCard
          title="Resolved Threats"
          value={formatNumber(
            resolvedThreats
          )}
          subtitle="Resolved / closed threats"
          icon={CheckCircle2}
        />

        <StatCard
          title="Resolved Incidents"
          value={formatNumber(
            resolvedIncidents
          )}
          subtitle="Resolved / closed incidents"
          icon={CheckCircle2}
        />
      </div>

      {/* =====================================================
          INCIDENT SELECTOR
      ===================================================== */}

      <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:bg-white">
        <SectionTitle
          icon={FileText}
          title="Incident Report"
          subtitle="Select the incident whose evidence should appear in this report"
        />

        {incidents.length === 0 ? (
          <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 text-sm text-yellow-300">
            No incident records are currently available.
          </div>
        ) : (
          <select
            value={
              selectedIncidentId ?? ""
            }
            onChange={(event) =>
              handleIncidentChange(
                event.target.value
              )
            }
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500 print:border-slate-400 print:bg-white print:text-black"
          >
            {incidents
              .slice()
              .sort(
                (a, b) =>
                  new Date(
                    b.updated_at ||
                      b.created_at ||
                      0
                  ) -
                  new Date(
                    a.updated_at ||
                      a.created_at ||
                      0
                  )
              )
              .map((incident) => (
                <option
                  key={incident.id}
                  value={incident.id}
                >
                  Incident #{incident.id} •{" "}
                  {incident.title ||
                    `Threat #${
                      incident.threat_id ||
                      "N/A"
                    }`}{" "}
                  •{" "}
                  {String(
                    incident.status ||
                      "unknown"
                  ).toUpperCase()}
                </option>
              ))}
          </select>
        )}
      </div>

      {selectedIncident && (
        <>
          {/* =================================================
              INCIDENT OVERVIEW
          ================================================= */}

          <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
            <SectionTitle
              icon={AlertTriangle}
              title={`Incident #${selectedIncident.id}`}
              subtitle="Security incident overview"
            />

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Incident ID
                </p>

                <p className="mt-2 text-xl font-bold text-cyan-400 print:text-cyan-700">
                  #{selectedIncident.id}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Threat ID
                </p>

                <p className="mt-2 text-xl font-bold text-white print:text-black">
                  {selectedIncident.threat_id
                    ? `#${selectedIncident.threat_id}`
                    : "Not available"}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Status
                </p>

                <p className="mt-2 text-xl font-bold text-yellow-400 print:text-yellow-700">
                  {String(
                    selectedIncident.status ||
                      "unknown"
                  ).toUpperCase()}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Severity
                </p>

                <span
                  className={`mt-2 inline-flex rounded-full border px-3 py-1 text-sm font-medium ${getSeverityClass(
                    selectedIncident.severity ||
                      selectedThreat?.severity
                  )}`}
                >
                  {String(
                    selectedIncident.severity ||
                      selectedThreat?.severity ||
                      "unknown"
                  ).toUpperCase()}
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Created
                </p>

                <p className="mt-2 text-sm font-semibold text-white print:text-black">
                  {formatDate(
                    selectedIncident.created_at
                  )}
                </p>
              </div>
            </div>

            <div className="mt-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5 print:border-cyan-700 print:bg-cyan-50">
              <p className="text-xs uppercase tracking-wide text-cyan-400 print:text-cyan-700">
                Incident Title
              </p>

              <h3 className="mt-2 text-xl font-semibold text-white print:text-black">
                {selectedIncident.title ||
                  "Security Incident"}
              </h3>

              {selectedIncident.description && (
                <p className="mt-4 whitespace-pre-line text-sm leading-7 text-slate-400 print:text-slate-700">
                  {selectedIncident.description}
                </p>
              )}
            </div>
          </div>

          {/* =================================================
              NETWORK EVIDENCE SUMMARY
          ================================================= */}

          <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
            <SectionTitle
              icon={Network}
              title="Network Evidence Summary"
              subtitle="Compact view of network evidence correlated with this incident"
            />

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Primary Source
                </p>

                <p className="mt-2 break-all font-mono text-sm font-semibold text-cyan-300 print:text-cyan-700">
                  {evidence.sourceIp}
                </p>
              </div>

              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 print:bg-cyan-50">
                <p className="text-xs text-slate-500">
                  Correlated Events
                </p>

                <p className="mt-2 text-2xl font-bold text-cyan-400 print:text-cyan-700">
                  {formatNumber(
                    evidence.correlatedEvents
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Returned Linked Events
                </p>

                <p className="mt-2 text-2xl font-bold text-white print:text-black">
                  {formatNumber(
                    incidentEvents.length
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Unique Destinations
                </p>

                <p className="mt-2 text-2xl font-bold text-cyan-400 print:text-cyan-700">
                  {formatNumber(
                    evidence.destinations.length
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Unique Ports
                </p>

                <p className="mt-2 text-2xl font-bold text-cyan-400 print:text-cyan-700">
                  {formatNumber(
                    evidence.ports.length
                  )}
                </p>
              </div>
            </div>

            {/* RISK COUNTS */}

            <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 print:bg-red-50">
                <p className="text-xs text-slate-500">
                  High Risk — Returned Events
                </p>

                <p className="mt-2 text-2xl font-bold text-red-400 print:text-red-700">
                  {formatNumber(
                    evidence.riskCounts.high
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 print:bg-yellow-50">
                <p className="text-xs text-slate-500">
                  Medium Risk — Returned Events
                </p>

                <p className="mt-2 text-2xl font-bold text-yellow-400 print:text-yellow-700">
                  {formatNumber(
                    evidence.riskCounts.medium
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-4 print:bg-green-50">
                <p className="text-xs text-slate-500">
                  Low Risk — Returned Events
                </p>

                <p className="mt-2 text-2xl font-bold text-green-400 print:text-green-700">
                  {formatNumber(
                    evidence.riskCounts.low
                  )}
                </p>
              </div>
            </div>

            {/* COMPACT NETWORK VALUES */}

            <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-3">
              <CompactList
                items={evidence.topDestinations}
                label="Top Destination IPs"
                icon={Globe}
                limit={5}
                mono
                showCounts
              />

              <CompactList
                items={evidence.topProtocols}
                label="Protocols"
                limit={8}
                showCounts
              />

              <CompactList
                items={evidence.topPorts}
                label="Top Observed Ports"
                limit={8}
                mono
                showCounts
              />
            </div>

            {/* DETAILED EVIDENCE BUTTON */}

            <div className="mt-6 border-t border-slate-800 pt-5 print:hidden">
              <button
                type="button"
                onClick={() =>
                  setShowDetailedEvidence(
                    (current) => !current
                  )
                }
                className="flex w-full items-center justify-between rounded-xl border border-slate-700 bg-slate-950/50 px-4 py-3 text-left transition hover:border-cyan-500/40"
              >
                <div>
                  <p className="font-semibold text-white">
                    Detailed Network Evidence
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    View individual linked network events when detailed investigation is required.
                  </p>
                </div>

                {showDetailedEvidence ? (
                  <ChevronUp className="h-5 w-5 text-cyan-400" />
                ) : (
                  <ChevronDown className="h-5 w-5 text-cyan-400" />
                )}
              </button>
            </div>
          </div>

          {/* =================================================
              DETAILED NETWORK EVENTS
          ================================================= */}

          {showDetailedEvidence && (
            <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:hidden">
              <SectionTitle
                icon={Activity}
                title="Detailed Network Events"
                subtitle={`${formatNumber(
                  incidentEvents.length
                )} linked events returned for Threat #${
                  selectedIncident.threat_id ||
                  "N/A"
                }`}
              />

              {incidentEvents.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-500">
                  No linked network events were returned for this incident.
                </div>
              ) : (
                <>
                  <div className="mb-4 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 text-sm text-slate-400">
                    Showing all returned linked events for detailed investigation. The JSON export also contains the complete returned evidence set.
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[900px] text-left">
                      <thead>
                        <tr className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                          <th className="px-3 py-3">
                            Event ID
                          </th>

                          <th className="px-3 py-3">
                            Source
                          </th>

                          <th className="px-3 py-3">
                            Destination
                          </th>

                          <th className="px-3 py-3">
                            Protocol
                          </th>

                          <th className="px-3 py-3">
                            Port
                          </th>

                          <th className="px-3 py-3">
                            Risk
                          </th>
                        </tr>
                      </thead>

                      <tbody>
                        {incidentEvents.map(
                          (
                            event,
                            index
                          ) => {
                            const risk =
                              event?.risk ||
                              event?.risk_level ||
                              "unknown";

                            return (
                              <tr
                                key={
                                  event.id ||
                                  `${getSource(
                                    event
                                  )}-${getPort(
                                    event
                                  )}-${index}`
                                }
                                className="border-b border-slate-800/70"
                              >
                                <td className="px-3 py-3 font-mono text-sm text-cyan-300">
                                  {event.id
                                    ? `#${event.id}`
                                    : "—"}
                                </td>

                                <td className="px-3 py-3 font-mono text-sm text-slate-300">
                                  {getSource(
                                    event
                                  ) || "—"}
                                </td>

                                <td className="px-3 py-3 font-mono text-sm text-slate-300">
                                  {getDestination(
                                    event
                                  ) || "—"}
                                </td>

                                <td className="px-3 py-3 text-sm text-slate-300">
                                  {getProtocol(
                                    event
                                  ) || "—"}
                                </td>

                                <td className="px-3 py-3 font-mono text-sm text-slate-300">
                                  {getPort(
                                    event
                                  ) || "—"}
                                </td>

                                <td className="px-3 py-3">
                                  <span
                                    className={`rounded-full border px-2 py-1 text-xs font-medium ${getSeverityClass(
                                      risk
                                    )}`}
                                  >
                                    {String(
                                      risk
                                    ).toUpperCase()}
                                  </span>
                                </td>
                              </tr>
                            );
                          }
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {/* =================================================
              GNN EVIDENCE
          ================================================= */}

          <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
            <SectionTitle
              icon={Network}
              title="GNN Detection Evidence"
              subtitle="Statistical anomaly detection evidence"
            />

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 print:bg-red-50">
                <p className="text-xs text-slate-500">
                  Maximum Anomaly
                </p>

                <p className="mt-2 text-2xl font-bold text-red-400 print:text-red-700">
                  {formatPercent(
                    evidence.maximumAnomaly
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4 print:bg-orange-50">
                <p className="text-xs text-slate-500">
                  Average Anomaly
                </p>

                <p className="mt-2 text-2xl font-bold text-orange-400 print:text-orange-700">
                  {formatPercent(
                    evidence.averageAnomaly
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4 print:bg-purple-50">
                <p className="text-xs text-slate-500">
                  Baseline Z-Score
                </p>

                <p className="mt-2 text-2xl font-bold text-purple-400 print:text-purple-700">
                  {evidence.baselineZScore.toFixed(
                    3
                  )}
                </p>
              </div>

              <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 print:bg-yellow-50">
                <p className="text-xs text-slate-500">
                  Suspicious Nodes
                </p>

                <p className="mt-2 text-2xl font-bold text-yellow-400 print:text-yellow-700">
                  {evidence.suspiciousNodes}
                </p>
              </div>

              {/* ONLY SEVERITY HERE */}

              <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4 print:bg-orange-50">
                <p className="text-xs text-slate-500">
                  GNN Severity
                </p>

                <span
                  className={`mt-2 inline-flex rounded-full border px-3 py-1 text-sm font-medium ${getSeverityClass(
                    evidence.gnnSeverity
                  )}`}
                >
                  {evidence.gnnSeverity}
                </span>
              </div>
            </div>

            <div className="mt-5 rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-5 print:border-yellow-700 print:bg-yellow-50">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-yellow-400 print:text-yellow-700" />

                <div>
                  <h3 className="font-semibold text-yellow-300 print:text-yellow-800">
                    Important GNN interpretation
                  </h3>

                  <p className="mt-2 text-sm leading-7 text-slate-400 print:text-slate-700">
                    The GNN anomaly score represents statistical deviation from the learned normal network baseline. It is{" "}
                    <strong>
                      not an attack probability
                    </strong>
                    . A high anomaly score means that the observed behavior is unusual compared with learned normal behavior.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* =================================================
              CONTEXTUAL RISK
          ================================================= */}

          <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
            <SectionTitle
              icon={BarChart3}
              title="Contextual Risk Assessment"
              subtitle="Final risk after correlating GNN evidence with network context"
            />

            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-5 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Final Risk Score
                </p>

                <p className="mt-2 text-4xl font-bold text-cyan-400 print:text-cyan-700">
                  {evidence.riskScore.toFixed(
                    1
                  )}
                  <span className="text-lg text-slate-500">
                    /100
                  </span>
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-5 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Final Risk Level
                </p>

                <span
                  className={`mt-3 inline-flex rounded-full border px-4 py-2 text-sm font-semibold ${getSeverityClass(
                    evidence.riskLevel
                  )}`}
                >
                  {evidence.riskLevel}
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-5 print:bg-slate-50">
                <p className="text-xs text-slate-500">
                  Incident Status
                </p>

                <p className="mt-3 text-xl font-semibold text-yellow-400 print:text-yellow-700">
                  {String(
                    selectedIncident.status ||
                      "unknown"
                  ).toUpperCase()}
                </p>
              </div>
            </div>

            {evidence.riskReasons.length >
              0 && (
              <div className="mt-6">
                <h3 className="mb-3 font-semibold text-white print:text-black">
                  Risk Reasons
                </h3>

                <div className="space-y-2">
                  {evidence.riskReasons.map(
                    (reason, index) => (
                      <div
                        key={`${reason}-${index}`}
                        className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-slate-300 print:bg-red-50 print:text-slate-700"
                      >
                        • {reason}
                      </div>
                    )
                  )}
                </div>
              </div>
            )}

            {evidence.positiveContext.length >
              0 && (
              <div className="mt-6">
                <h3 className="mb-3 font-semibold text-white print:text-black">
                  Positive Context
                </h3>

                <div className="space-y-2">
                  {evidence.positiveContext.map(
                    (reason, index) => (
                      <div
                        key={`${reason}-${index}`}
                        className="rounded-lg border border-green-500/20 bg-green-500/5 p-3 text-sm text-slate-300 print:bg-green-50 print:text-slate-700"
                      >
                        • {reason}
                      </div>
                    )
                  )}
                </div>
              </div>
            )}

            {evidence.warnings.length >
              0 && (
              <div className="mt-6">
                <h3 className="mb-3 font-semibold text-white print:text-black">
                  Warnings
                </h3>

                <div className="space-y-2">
                  {evidence.warnings.map(
                    (warning, index) => (
                      <div
                        key={`${warning}-${index}`}
                        className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 text-sm text-slate-300 print:bg-yellow-50 print:text-slate-700"
                      >
                        • {warning}
                      </div>
                    )
                  )}
                </div>
              </div>
            )}

            {evidence.recommendedAction && (
              <div className="mt-6 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 print:border-cyan-700 print:bg-cyan-50">
                <p className="text-xs uppercase tracking-wide text-cyan-400 print:text-cyan-700">
                  Recommended Action
                </p>

                <p className="mt-2 text-sm leading-6 text-slate-300 print:text-slate-700">
                  {evidence.recommendedAction}
                </p>
              </div>
            )}
          </div>

          {/* =================================================
              RESPONSE ACTION AUDIT
          ================================================= */}

          <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
            <SectionTitle
              icon={ShieldCheck}
              title="Response Action Audit Trail"
              subtitle="Defensive actions and workflow validation records associated with this incident"
            />

            {selectedActions.length ===
            0 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-500 print:bg-slate-50">
                No response actions are associated with this incident.
              </div>
            ) : (
              <>
                <div className="mb-4 rounded-xl border border-slate-700 bg-slate-950/40 p-4 text-sm text-slate-400 print:bg-slate-50 print:text-slate-700">
                  Test / validation records are retained as part of the audit history and are clearly marked. They are not deleted from ZeroGuard.
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[1050px] text-left">
                    <thead>
                      <tr className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                        <th className="px-3 py-3">
                          ID
                        </th>

                        <th className="px-3 py-3">
                          Type
                        </th>

                        <th className="px-3 py-3">
                          Action
                        </th>

                        <th className="px-3 py-3">
                          Target
                        </th>

                        <th className="px-3 py-3">
                          Status
                        </th>

                        <th className="px-3 py-3">
                          Created
                        </th>

                        <th className="px-3 py-3">
                          Reason
                        </th>
                      </tr>
                    </thead>

                    <tbody>
                      {selectedActions.map(
                        (action) => (
                          <tr
                            key={action.id}
                            className="border-b border-slate-800/70"
                          >
                            <td className="px-3 py-4 font-mono text-sm text-cyan-300 print:text-cyan-700">
                              #{action.id}
                            </td>

                            <td className="px-3 py-4">
                              <span
                                className={`rounded-full border px-2 py-1 text-[10px] font-medium ${getActionClassificationClass(
                                  action
                                )}`}
                              >
                                {getActionClassification(
                                  action
                                )}
                              </span>
                            </td>

                            <td className="px-3 py-4 text-sm text-slate-300 print:text-slate-700">
                              {action.action_type ||
                                "Unknown"}
                            </td>

                            <td className="px-3 py-4 font-mono text-sm text-slate-300 print:text-slate-700">
                              {action.target ||
                                "—"}
                            </td>

                            <td className="px-3 py-4">
                              <span
                                className={`rounded-full border px-2 py-1 text-xs font-medium ${getActionStatusClass(
                                  action.status
                                )}`}
                              >
                                {String(
                                  action.status ||
                                    "unknown"
                                ).toUpperCase()}
                              </span>
                            </td>

                            <td className="px-3 py-4 text-xs text-slate-400 print:text-slate-700">
                              {formatDate(
                                action.created_at
                              )}
                            </td>

                            <td className="max-w-[320px] px-3 py-4 text-xs leading-5 text-slate-400 print:text-slate-700">
                              {action.reason ||
                                "—"}
                            </td>
                          </tr>
                        )
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            <div className="mt-5 rounded-xl border border-orange-500/20 bg-orange-500/5 p-4 print:border-orange-700 print:bg-orange-50">
              <p className="text-sm leading-6 text-slate-400 print:text-slate-700">
                Response-action records document the defensive workflow. A completed{" "}
                <strong>
                  Alert Generated
                </strong>{" "}
                action records the response process without modifying the network. Test and validation records are retained for auditability. Disruptive actions should only be used when the evidence and authorization support them.
              </p>
            </div>
          </div>

          {/* =================================================
              FINAL CONCLUSION
          ================================================= */}

          <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
            <SectionTitle
              icon={CheckCircle2}
              title="Investigation Conclusion"
              subtitle="Evidence-based ZeroGuard assessment"
            />

            <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5 print:border-cyan-700 print:bg-cyan-50">
              <p className="text-sm leading-7 text-slate-300 print:text-slate-700">
                ZeroGuard identified statistically unusual network behavior through its Graph Neural Network detection layer. The GNN produced a maximum anomaly score of{" "}
                <strong>
                  {formatPercent(
                    evidence.maximumAnomaly
                  )}
                </strong>{" "}
                with a baseline Z-score of{" "}
                <strong>
                  {evidence.baselineZScore.toFixed(
                    3
                  )}
                </strong>
                . The detection was correlated with{" "}
                <strong>
                  {formatNumber(
                    evidence.correlatedEvents
                  )}
                </strong>{" "}
                network events.
              </p>

              <p className="mt-4 text-sm leading-7 text-slate-300 print:text-slate-700">
                After contextual correlation, the final risk assessment is{" "}
                <strong>
                  {evidence.riskScore.toFixed(
                    1
                  )}
                  /100
                </strong>{" "}
                with a{" "}
                <strong>
                  {evidence.riskLevel}
                </strong>{" "}
                risk level.
              </p>

              <p className="mt-4 text-sm leading-7 text-slate-300 print:text-slate-700">
                The anomaly score represents statistical deviation from learned normal behavior and should not be interpreted as an attack probability. Based on the current evidence, disruptive automatic blocking is not recommended without additional investigation and authorization.
              </p>
            </div>

            <div className="mt-5 flex items-start gap-3 rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 print:border-yellow-700 print:bg-yellow-50">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-yellow-400 print:text-yellow-700" />

              <div>
                <p className="font-semibold text-yellow-300 print:text-yellow-800">
                  Recommended investigation posture
                </p>

                <p className="mt-1 text-sm leading-6 text-slate-400 print:text-slate-700">
                  Continue monitoring the associated network evidence, review the suspicious node and correlated events, and use defensive response actions only when justified by the evidence and authorized by the SOC operator.
                </p>
              </div>
            </div>
          </div>
        </>
      )}

      {/* =====================================================
          THREAT DISTRIBUTION
      ===================================================== */}

      <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
        <SectionTitle
          icon={BarChart3}
          title="Overall Threat Distribution"
          subtitle="Threat records currently stored in ZeroGuard"
        />

        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5 print:bg-red-50">
            <p className="text-sm text-slate-400">
              Critical
            </p>

            <p className="mt-2 text-3xl font-bold text-red-400 print:text-red-700">
              {criticalCount}
            </p>
          </div>

          <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-5 print:bg-orange-50">
            <p className="text-sm text-slate-400">
              High
            </p>

            <p className="mt-2 text-3xl font-bold text-orange-400 print:text-orange-700">
              {highCount}
            </p>
          </div>

          <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-5 print:bg-yellow-50">
            <p className="text-sm text-slate-400">
              Medium
            </p>

            <p className="mt-2 text-3xl font-bold text-yellow-400 print:text-yellow-700">
              {mediumCount}
            </p>
          </div>

          <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-5 print:bg-green-50">
            <p className="text-sm text-slate-400">
              Low
            </p>

            <p className="mt-2 text-3xl font-bold text-green-400 print:text-green-700">
              {lowCount}
            </p>
          </div>
        </div>
      </div>

      {/* =====================================================
          RESPONSE SUMMARY
      ===================================================== */}

      <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
        <SectionTitle
          icon={ShieldCheck}
          title="Response Operations Summary"
          subtitle="Overall defensive action status"
        />

        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-5 print:bg-green-50">
            <p className="text-sm text-slate-400">
              Completed
            </p>

            <p className="mt-2 text-3xl font-bold text-green-400 print:text-green-700">
              {completedActions}
            </p>
          </div>

          <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-5 print:bg-yellow-50">
            <p className="text-sm text-slate-400">
              Pending
            </p>

            <p className="mt-2 text-3xl font-bold text-yellow-400 print:text-yellow-700">
              {pendingActions}
            </p>
          </div>

          <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-5 print:bg-orange-50">
            <p className="text-sm text-slate-400">
              Denied
            </p>

            <p className="mt-2 text-3xl font-bold text-orange-400 print:text-orange-700">
              {deniedActions}
            </p>
          </div>

          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5 print:bg-red-50">
            <p className="text-sm text-slate-400">
              Failed
            </p>

            <p className="mt-2 text-3xl font-bold text-red-400 print:text-red-700">
              {failedActions}
            </p>
          </div>
        </div>
      </div>

      {/* =====================================================
          REPORT NOTES
      ===================================================== */}

      <div className="report-card rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl print:break-inside-avoid print:bg-white">
        <SectionTitle
          icon={FileText}
          title="Report Notes"
          subtitle="Important interpretation and limitations"
        />

        <div className="space-y-4 text-sm leading-7 text-slate-400 print:text-slate-700">
          <p>
            <strong className="text-white print:text-black">
              GNN anomaly:
            </strong>{" "}
            indicates statistical deviation from the learned network baseline. It is not an attack probability.
          </p>

          <p>
            <strong className="text-white print:text-black">
              Contextual risk:
            </strong>{" "}
            combines the GNN result with available network evidence and contextual signals before assigning the final risk level.
          </p>

          <p>
            <strong className="text-white print:text-black">
              Network evidence:
            </strong>{" "}
            the main report displays summarized evidence to keep the report readable. Detailed linked events remain available through the detailed evidence section and are included in JSON export.
          </p>

          <p>
            <strong className="text-white print:text-black">
              Correlated vs returned events:
            </strong>{" "}
            correlated events represent the count recorded by the detection evidence, while returned linked events represent the records returned by the threat-event query. These values may differ depending on the evidence scope and backend correlation process.
          </p>

          <p>
            <strong className="text-white print:text-black">
              Missing destination:
            </strong>{" "}
            a dash means the network collector did not record a destination IP for that event. No destination value is invented by the report.
          </p>

          <p>
            <strong className="text-white print:text-black">
              Historical incidents:
            </strong>{" "}
            older incidents may contain fewer evidence fields because they were created before the current evidence-rich detection pipeline.
          </p>

          <p>
            <strong className="text-white print:text-black">
              Response actions:
            </strong>{" "}
            completed alert-generation actions document the defensive workflow without modifying the network. Test and validation records remain visible for auditability. Disruptive actions require appropriate evidence and authorization.
          </p>
        </div>
      </div>

      {/* =====================================================
          FOOTER
      ===================================================== */}

      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-center print:mt-8 print:bg-white">
        <p className="text-xs text-slate-500 print:text-slate-700">
          ZeroGuard Security Incident Report • Evidence-based SOC reporting
        </p>

        <p className="mt-1 hidden text-xs text-slate-500 print:block">
          Generated:{" "}
          {new Date().toLocaleString()}
        </p>
      </div>
    </div>
  );
}