import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  Filter,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import {
  createResponseAction,
  executeResponseAction,
  getIncidents,
  getResponseActions,
  getThreats,
} from "../services/api";

const ACTION_TYPES = [
  "Alert Generated",
  "Block Source",
  "Isolate Device",
  "Terminate Connection",
  "Network Quarantine",
];

const STATUS_FILTERS = [
  "all",
  "completed",
  "pending",
  "denied",
  "failed",
];

function normalizeStatus(status) {
  return String(status || "unknown").toLowerCase();
}

function getStatusClass(status) {
  switch (normalizeStatus(status)) {
    case "completed":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";

    case "failed":
      return "text-red-400 bg-red-500/10 border-red-500/20";

    case "pending":
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";

    case "denied":
      return "text-orange-400 bg-orange-500/10 border-orange-500/20";

    default:
      return "text-slate-400 bg-slate-500/10 border-slate-500/20";
  }
}

function StatusIcon({ status }) {
  switch (normalizeStatus(status)) {
    case "completed":
      return <CheckCircle2 size={15} />;

    case "failed":
      return <XCircle size={15} />;

    case "pending":
      return <CircleAlert size={15} />;

    case "denied":
      return <ShieldAlert size={15} />;

    default:
      return <CircleAlert size={15} />;
  }
}

function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function getActionIcon(actionType) {
  switch (String(actionType || "").toLowerCase()) {
    case "block source":
    case "isolate device":
    case "network quarantine":
      return <ShieldAlert size={16} className="text-blue-400" />;

    case "terminate connection":
      return <XCircle size={16} className="text-orange-400" />;

    default:
      return <Shield size={16} className="text-blue-400" />;
  }
}

function getRiskLevel(riskScore, severity) {
  const numericRisk = Number(riskScore);

  if (Number.isFinite(numericRisk)) {
    if (numericRisk >= 70) return "HIGH";
    if (numericRisk >= 40) return "MEDIUM";
    return "LOW";
  }

  if (severity) {
    return String(severity).toUpperCase();
  }

  return "UNKNOWN";
}

function getRiskClass(riskLevel) {
  switch (String(riskLevel).toUpperCase()) {
    case "HIGH":
      return "text-red-400 bg-red-500/10 border-red-500/20";

    case "MEDIUM":
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";

    case "LOW":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";

    default:
      return "text-slate-400 bg-slate-500/10 border-slate-500/20";
  }
}

function getIncidentTitle(incident) {
  return (
    incident?.title ||
    `Incident #${incident?.id ?? "—"}`
  );
}

function getThreatForIncident(incident, threats) {
  if (!incident) {
    return null;
  }

  const threatId = Number(incident.threat_id);

  if (!Number.isFinite(threatId)) {
    return null;
  }

  return (
    threats.find(
      (threat) =>
        Number(threat.id) === threatId
    ) || null
  );
}

function getThreatTarget(threat) {
  if (!threat) {
    return "";
  }

  return (
    threat.source_ip ||
    threat.destination_ip ||
    threat.target ||
    ""
  );
}

function extractLinkedEvents(incident, threat) {
  const possibleValues = [
    incident?.linked_events,
    incident?.correlated_events,
    threat?.linked_events,
  ];

  for (const value of possibleValues) {
    const numericValue = Number(value);

    if (
      Number.isFinite(numericValue) &&
      numericValue >= 0
    ) {
      return numericValue;
    }
  }

  const description =
    incident?.description ||
    threat?.description ||
    "";

  const match = String(description).match(
    /(?:Correlated|Linked)\s+events:\s*(\d+)/i
  );

  return match ? Number(match[1]) : null;
}

function extractAnomalyScore(incident, threat) {
  const possibleValues = [
    incident?.anomaly_score,
    threat?.anomaly_score,
  ];

  for (const value of possibleValues) {
    const numericValue = Number(value);

    if (Number.isFinite(numericValue)) {
      return numericValue;
    }
  }

  const description =
    incident?.description ||
    threat?.description ||
    "";

  const match = String(description).match(
    /(?:maximum\s+)?anomaly\s+score:\s*([\d.]+)/i
  );

  return match ? Number(match[1]) : null;
}

function extractBaselineZScore(incident, threat) {
  const possibleValues = [
    incident?.baseline_z_score,
    threat?.baseline_z_score,
  ];

  for (const value of possibleValues) {
    const numericValue = Number(value);

    if (Number.isFinite(numericValue)) {
      return numericValue;
    }
  }

  const description =
    incident?.description ||
    threat?.description ||
    "";

  const match = String(description).match(
    /Baseline\s+Z-score:\s*([\d.]+)/i
  );

  return match ? Number(match[1]) : null;
}

function extractSuspiciousNodes(incident, threat) {
  const possibleValues = [
    incident?.suspicious_nodes,
    threat?.suspicious_nodes,
  ];

  for (const value of possibleValues) {
    const numericValue = Number(value);

    if (Number.isFinite(numericValue)) {
      return numericValue;
    }
  }

  const description =
    incident?.description ||
    threat?.description ||
    "";

  const match = String(description).match(
    /Suspicious\s+nodes:\s*(\d+)/i
  );

  return match ? Number(match[1]) : null;
}

function extractGnnSeverity(incident, threat) {
  const possibleValues = [
    incident?.gnn_severity,
    threat?.gnn_severity,
  ];

  for (const value of possibleValues) {
    if (value) {
      return String(value).toUpperCase();
    }
  }

  const description =
    incident?.description ||
    threat?.description ||
    "";

  const match = String(description).match(
    /GNN severity before contextual correlation:\s*([A-Za-z]+)/i
  );

  return match
    ? match[1].toUpperCase()
    : null;
}

export default function ResponseActions() {
  const [actions, setActions] = useState([]);

  const [incidents, setIncidents] = useState([]);
  const [threats, setThreats] = useState([]);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadingEvidence, setLoadingEvidence] =
    useState(false);

  const [executingId, setExecutingId] =
    useState(null);

  const [creating, setCreating] =
    useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] =
    useState("all");

  const [showCreateForm, setShowCreateForm] =
    useState(false);

  const [incidentId, setIncidentId] =
    useState("");

  const [threatId, setThreatId] =
    useState("");

  const [actionType, setActionType] =
    useState("Alert Generated");

  const [target, setTarget] =
    useState("");

  const [reason, setReason] =
    useState("");

  const selectedIncident = useMemo(() => {
    if (!incidentId) {
      return null;
    }

    return (
      incidents.find(
        (incident) =>
          Number(incident.id) ===
          Number(incidentId)
      ) || null
    );
  }, [incidents, incidentId]);

  const selectedThreat = useMemo(() => {
    if (!selectedIncident) {
      return null;
    }

    return getThreatForIncident(
      selectedIncident,
      threats
    );
  }, [selectedIncident, threats]);

  const selectedRiskScore = useMemo(() => {
    if (!selectedIncident && !selectedThreat) {
      return null;
    }

    const values = [
      selectedIncident?.risk_score,
      selectedThreat?.risk_score,
    ];

    for (const value of values) {
      const numericValue = Number(value);

      if (Number.isFinite(numericValue)) {
        return numericValue;
      }
    }

    const description =
      selectedIncident?.description ||
      selectedThreat?.description ||
      "";

    const match = String(description).match(
      /(?:Final contextual risk score|Final Risk):\s*([\d.]+)/i
    );

    return match
      ? Number(match[1])
      : null;
  }, [selectedIncident, selectedThreat]);

  const selectedRiskLevel = useMemo(() => {
    return getRiskLevel(
      selectedRiskScore,
      selectedIncident?.severity ||
        selectedThreat?.severity
    );
  }, [
    selectedRiskScore,
    selectedIncident,
    selectedThreat,
  ]);

  const selectedAnomalyScore = useMemo(() => {
    return extractAnomalyScore(
      selectedIncident,
      selectedThreat
    );
  }, [selectedIncident, selectedThreat]);

  const selectedBaselineZScore = useMemo(() => {
    return extractBaselineZScore(
      selectedIncident,
      selectedThreat
    );
  }, [selectedIncident, selectedThreat]);

  const selectedSuspiciousNodes = useMemo(() => {
    return extractSuspiciousNodes(
      selectedIncident,
      selectedThreat
    );
  }, [selectedIncident, selectedThreat]);

  const selectedGnnSeverity = useMemo(() => {
    return extractGnnSeverity(
      selectedIncident,
      selectedThreat
    );
  }, [selectedIncident, selectedThreat]);

  const selectedLinkedEvents = useMemo(() => {
    return extractLinkedEvents(
      selectedIncident,
      selectedThreat
    );
  }, [selectedIncident, selectedThreat]);

  async function loadPageData(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const [
        actionsData,
        incidentsData,
        threatsData,
      ] = await Promise.all([
        getResponseActions(),
        getIncidents(),
        getThreats(),
      ]);

      if (Array.isArray(actionsData)) {
        setActions(actionsData);
      } else if (
        Array.isArray(actionsData?.value)
      ) {
        setActions(actionsData.value);
      } else if (
        Array.isArray(actionsData?.actions)
      ) {
        setActions(actionsData.actions);
      } else {
        setActions([]);
      }

      if (Array.isArray(incidentsData)) {
        setIncidents(incidentsData);
      } else if (
        Array.isArray(incidentsData?.value)
      ) {
        setIncidents(incidentsData.value);
      } else if (
        Array.isArray(incidentsData?.incidents)
      ) {
        setIncidents(
          incidentsData.incidents
        );
      } else {
        setIncidents([]);
      }

      if (Array.isArray(threatsData)) {
        setThreats(threatsData);
      } else if (
        Array.isArray(threatsData?.value)
      ) {
        setThreats(threatsData.value);
      } else if (
        Array.isArray(threatsData?.threats)
      ) {
        setThreats(threatsData.threats);
      } else {
        setThreats([]);
      }
    } catch (err) {
      setError(
        err.message ||
          "Unable to load response action data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadPageData();
  }, []);

  useEffect(() => {
    if (!selectedIncident) {
      return;
    }

    setLoadingEvidence(false);

    const relatedThreatId =
      selectedIncident.threat_id;

    if (relatedThreatId !== undefined &&
        relatedThreatId !== null) {
      setThreatId(String(relatedThreatId));
    } else {
      setThreatId("");
    }

    const automaticTarget =
      getThreatTarget(selectedThreat);

    if (automaticTarget) {
      setTarget(automaticTarget);
    } else {
      setTarget("");
    }

    const defaultReason =
      selectedIncident.title ||
      selectedThreat?.threat_type
        ? `Response action for ${
            selectedIncident.title ||
            selectedThreat?.threat_type ||
            `Incident #${selectedIncident.id}`
          }`
        : `Response action for Incident #${selectedIncident.id}`;

    setReason(defaultReason);
  }, [selectedIncident, selectedThreat]);

  function handleOpenCreateForm() {
    setError("");
    setSuccess("");

    setShowCreateForm(true);

    /*
     * Incident #4 is currently the active
     * evidence-rich incident in ZeroGuard.
     *
     * Preselect it when available so the user
     * does not have to manually enter IDs.
     */
    const activeIncident =
      incidents.find(
        (incident) =>
          Number(incident.id) === 4
      ) ||
      incidents.find(
        (incident) =>
          normalizeStatus(
            incident.status
          ) === "investigating"
      );

    if (activeIncident) {
      setIncidentId(
        String(activeIncident.id)
      );
    }
  }

  function handleIncidentChange(event) {
    const value = event.target.value;

    setIncidentId(value);
    setThreatId("");
    setTarget("");
    setReason("");
    setError("");
    setSuccess("");
  }

  async function handleCreateAction(event) {
    event.preventDefault();

    setError("");
    setSuccess("");

    if (!incidentId) {
      setError("Please select an incident.");
      return;
    }

    if (!target.trim()) {
      setError("Response target is required.");
      return;
    }

    try {
      setCreating(true);

      await createResponseAction({
        incident_id: Number(incidentId),

        threat_id: threatId
          ? Number(threatId)
          : null,

        action_type: actionType,

        target: target.trim(),

        reason: reason.trim(),
      });

      setSuccess(
        "Response action created successfully."
      );

      setIncidentId("");
      setThreatId("");
      setActionType("Alert Generated");
      setTarget("");
      setReason("");

      setShowCreateForm(false);

      await loadPageData(true);
    } catch (err) {
      setError(
        err.message ||
          "Unable to create response action."
      );
    } finally {
      setCreating(false);
    }
  }

  async function handleExecute(actionId) {
    try {
      setExecutingId(actionId);
      setError("");
      setSuccess("");

      const result =
        await executeResponseAction(
          actionId
        );

      const returnedStatus =
        normalizeStatus(
          result?.status
        );

      if (
        returnedStatus === "denied"
      ) {
        setSuccess(
          `Response action #${actionId} was denied by ZeroGuard safety controls.`
        );
      } else {
        setSuccess(
          `Response action #${actionId} executed successfully.`
        );
      }

      await loadPageData(true);
    } catch (err) {
      setError(
        err.message ||
          "Unable to execute response action."
      );

      await loadPageData(true);
    } finally {
      setExecutingId(null);
    }
  }

  const filteredActions = useMemo(() => {
    const searchValue =
      search.trim().toLowerCase();

    return actions.filter((action) => {
      const status =
        normalizeStatus(
          action.status
        );

      if (
        statusFilter !== "all" &&
        status !== statusFilter
      ) {
        return false;
      }

      if (!searchValue) {
        return true;
      }

      const searchableText = [
        action.id,
        action.incident_id,
        action.threat_id,
        action.action_type,
        action.target,
        action.reason,
        action.status,
        action.created_at,
        action.executed_at,
      ]
        .filter(
          (value) =>
            value !== undefined &&
            value !== null
        )
        .join(" ")
        .toLowerCase();

      return searchableText.includes(
        searchValue
      );
    });
  }, [
    actions,
    search,
    statusFilter,
  ]);

  const completedCount =
    actions.filter(
      (action) =>
        normalizeStatus(
          action.status
        ) === "completed"
    ).length;

  const pendingCount =
    actions.filter(
      (action) =>
        normalizeStatus(
          action.status
        ) === "pending"
    ).length;

  const deniedCount =
    actions.filter(
      (action) =>
        normalizeStatus(
          action.status
        ) === "denied"
    ).length;

  const failedCount =
    actions.filter(
      (action) =>
        normalizeStatus(
          action.status
        ) === "failed"
    ).length;

  return (
    <div className="space-y-6">

      {/* HEADER */}

      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">

        <div>
          <div className="flex items-center gap-3">

            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-500/10">
              <ShieldAlert
                size={23}
                className="text-blue-400"
              />
            </div>

            <div>
              <h1 className="text-2xl font-bold text-white">
                Response Actions
              </h1>

              <p className="mt-1 text-sm text-slate-400">
                Monitor and execute ZeroGuard defensive response actions.
              </p>
            </div>

          </div>
        </div>

        <div className="flex flex-wrap gap-2">

          <button
            type="button"
            onClick={() =>
              loadPageData(true)
            }
            disabled={refreshing}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
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
            type="button"
            onClick={
              handleOpenCreateForm
            }
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-500"
          >
            <Shield size={16} />

            Create Action
          </button>

        </div>

      </div>

      {/* SUCCESS */}

      {success && (
        <div className="flex items-start gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-sm text-emerald-300">

          <CheckCircle2
            size={18}
            className="mt-0.5 shrink-0"
          />

          <span>{success}</span>

        </div>
      )}

      {/* ERROR */}

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">

          <AlertTriangle
            size={18}
            className="mt-0.5 shrink-0"
          />

          <span>{error}</span>

        </div>
      )}

      {/* SAFETY NOTICE */}

      <div className="flex items-start gap-3 rounded-xl border border-blue-500/20 bg-blue-500/10 p-4">

        <ShieldAlert
          size={19}
          className="mt-0.5 shrink-0 text-blue-400"
        />

        <div>

          <p className="text-sm font-semibold text-blue-300">
            ZeroGuard response safety controls
          </p>

          <p className="mt-1 text-xs leading-5 text-slate-400">
            High-impact actions such as blocking a
            source are authorized only when backend
            risk controls permit them. A GNN anomaly
            alone does not automatically justify
            blocking or isolating a device.
          </p>

        </div>

      </div>

      {/* CREATE FORM */}

      {showCreateForm && (
        <form
          onSubmit={handleCreateAction}
          className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg"
        >

          <div className="mb-5">

            <h2 className="text-lg font-semibold text-white">
              Create Response Action
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Select an existing incident. ZeroGuard
              will automatically load its related threat
              and available evidence.
            </p>

          </div>

          {/* INCIDENT SELECTOR */}

          <div className="mb-5">

            <label className="mb-2 block text-sm font-medium text-slate-300">
              Incident
            </label>

            <select
              value={incidentId}
              onChange={
                handleIncidentChange
              }
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-blue-500"
            >

              <option value="">
                Select an incident
              </option>

              {incidents.map(
                (incident) => (
                  <option
                    key={incident.id}
                    value={incident.id}
                  >
                    {`#${incident.id} — ${
                      getIncidentTitle(
                        incident
                      )
                    } — ${
                      incident.severity
                        ? String(
                            incident.severity
                          ).toUpperCase()
                        : "UNKNOWN"
                    } — ${
                      incident.status ||
                      "unknown"
                    }`}
                  </option>
                )
              )}

            </select>

          </div>

          {/* EVIDENCE */}

          {selectedIncident && (
            <div className="mb-5 rounded-xl border border-slate-800 bg-slate-950/60 p-4">

              <div className="mb-4 flex items-center justify-between">

                <div>
                  <p className="text-sm font-semibold text-white">
                    Incident Evidence
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    Evidence currently retained by ZeroGuard
                  </p>
                </div>

                <span
                  className={
                    "rounded-full border px-2.5 py-1 text-xs font-semibold " +
                    getRiskClass(
                      selectedRiskLevel
                    )
                  }
                >
                  {selectedRiskLevel}
                </span>

              </div>

              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Incident
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    #{selectedIncident.id}
                  </p>

                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Threat
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedThreat?.id
                      ? `#${selectedThreat.id}`
                      : selectedIncident.threat_id
                        ? `#${selectedIncident.threat_id}`
                        : "—"}
                  </p>

                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Final Risk
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedRiskScore !== null
                      ? `${selectedRiskScore}/100`
                      : "Not available"}
                  </p>

                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Severity
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedIncident.severity
                      ? String(
                          selectedIncident.severity
                        ).toUpperCase()
                      : "Not available"}
                  </p>

                </div>

              </div>

              <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    GNN Anomaly
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedAnomalyScore !== null
                      ? `${selectedAnomalyScore}%`
                      : "Not available"}
                  </p>

                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Baseline Z-Score
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedBaselineZScore !== null
                      ? selectedBaselineZScore
                      : "Not available"}
                  </p>

                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Suspicious Nodes
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedSuspiciousNodes !== null
                      ? selectedSuspiciousNodes
                      : "Not available"}
                  </p>

                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

                  <p className="text-xs text-slate-500">
                    Linked Events
                  </p>

                  <p className="mt-1 text-sm font-semibold text-white">
                    {selectedLinkedEvents !== null
                      ? selectedLinkedEvents
                      : "Not available"}
                  </p>

                </div>

              </div>

              <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-3">

                <p className="text-xs text-slate-500">
                  Current Target
                </p>

                <p className="mt-1 break-all text-sm font-medium text-slate-200">
                  {getThreatTarget(
                    selectedThreat
                  ) ||
                    "Target information not available"}
                </p>

              </div>

              {selectedGnnSeverity && (
                <div className="mt-3 rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">

                  <p className="text-xs text-blue-400">
                    GNN Severity Before Contextual Correlation
                  </p>

                  <p className="mt-1 text-sm font-semibold text-blue-200">
                    {selectedGnnSeverity}
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    The GNN anomaly represents statistical
                    deviation from learned normal behavior,
                    not an attack probability.
                  </p>

                </div>
              )}

              {!selectedThreat && (
                <div className="mt-3 rounded-lg border border-orange-500/20 bg-orange-500/5 p-3">

                  <p className="text-xs font-medium text-orange-300">
                    Historical evidence limitation
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    Detailed threat evidence was not retained
                    for this historical incident.
                  </p>

                </div>
              )}

            </div>
          )}

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">

            {/* THREAT */}

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Threat ID
              </label>

              <input
                type="number"
                min="1"
                value={threatId}
                readOnly
                placeholder="Automatically populated"
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-slate-300 outline-none"
              />

            </div>

            {/* ACTION */}

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Action Type
              </label>

              <select
                value={actionType}
                onChange={(event) =>
                  setActionType(
                    event.target.value
                  )
                }
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none focus:border-blue-500"
              >

                {ACTION_TYPES.map(
                  (type) => (
                    <option
                      key={type}
                      value={type}
                    >
                      {type}
                    </option>
                  )
                )}

              </select>

            </div>

            {/* TARGET */}

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Target
              </label>

              <input
                type="text"
                value={target}
                onChange={(event) =>
                  setTarget(
                    event.target.value
                  )
                }
                placeholder="Example: 192.0.2.10"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-blue-500"
              />

            </div>

            {/* REASON */}

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Reason
              </label>

              <input
                type="text"
                value={reason}
                onChange={(event) =>
                  setReason(
                    event.target.value
                  )
                }
                placeholder="Why should ZeroGuard perform this action?"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-blue-500"
              />

            </div>

          </div>

          <div className="mt-5 rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3">

            <p className="text-xs font-semibold text-yellow-300">
              Safe testing recommendation
            </p>

            <p className="mt-1 text-xs leading-5 text-slate-500">
              Use <span className="font-semibold text-slate-300">
                Alert Generated
              </span> for end-to-end testing.
              High-impact actions remain subject to
              backend safety authorization.
            </p>

          </div>

          <div className="mt-5 flex justify-end gap-3">

            <button
              type="button"
              onClick={() => {
                setShowCreateForm(false);
                setError("");
                setSuccess("");
              }}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-300 transition hover:bg-slate-800"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={
                creating ||
                !incidentId ||
                !target.trim()
              }
              className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-medium text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {creating
                ? "Creating..."
                : "Create Action"}
            </button>

          </div>

        </form>
      )}

      {/* SUMMARY CARDS */}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-sm text-slate-400">
                Completed
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {completedCount}
              </p>

            </div>

            <div className="rounded-xl bg-emerald-500/10 p-3">

              <CheckCircle2
                size={22}
                className="text-emerald-400"
              />

            </div>

          </div>

        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-sm text-slate-400">
                Pending
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {pendingCount}
              </p>

            </div>

            <div className="rounded-xl bg-yellow-500/10 p-3">

              <CircleAlert
                size={22}
                className="text-yellow-400"
              />

            </div>

          </div>

        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-sm text-slate-400">
                Denied
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {deniedCount}
              </p>

            </div>

            <div className="rounded-xl bg-orange-500/10 p-3">

              <ShieldAlert
                size={22}
                className="text-orange-400"
              />

            </div>

          </div>

        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-sm text-slate-400">
                Failed
              </p>

              <p className="mt-2 text-3xl font-bold text-white">
                {failedCount}
              </p>

            </div>

            <div className="rounded-xl bg-red-500/10 p-3">

              <XCircle
                size={22}
                className="text-red-400"
              />

            </div>

          </div>

        </div>

      </div>

      {/* SEARCH + FILTER */}

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">

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
              placeholder="Search by action, target, incident, threat, reason..."
              className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2.5 pl-10 pr-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-blue-500"
            />

          </div>

          <div className="relative">

            <Filter
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(
                  event.target.value
                )
              }
              className="w-full min-w-[180px] appearance-none rounded-lg border border-slate-700 bg-slate-950 py-2.5 pl-9 pr-8 text-sm text-white outline-none focus:border-blue-500"
            >

              {STATUS_FILTERS.map(
                (status) => (
                  <option
                    key={status}
                    value={status}
                  >
                    {status === "all"
                      ? "All Statuses"
                      : status.charAt(0).toUpperCase() +
                        status.slice(1)}
                  </option>
                )
              )}

            </select>

          </div>

        </div>

      </div>

      {/* ACTION HISTORY */}

      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60">

        <div className="flex flex-col gap-2 border-b border-slate-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">

          <div>

            <h2 className="font-semibold text-white">
              Action History
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Response actions recorded by ZeroGuard.
            </p>

          </div>

          <div className="flex gap-2">

            <span className="rounded-full bg-slate-800 px-3 py-1 text-xs font-medium text-slate-300">
              {filteredActions.length} shown
            </span>

            <span className="rounded-full bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-300">
              {actions.length} total
            </span>

          </div>

        </div>

        {loading ? (

          <div className="flex items-center justify-center px-5 py-16 text-slate-400">

            <RefreshCw
              size={18}
              className="mr-2 animate-spin"
            />

            Loading response actions...

          </div>

        ) : filteredActions.length === 0 ? (

          <div className="px-5 py-16 text-center">

            <Shield
              size={30}
              className="mx-auto text-slate-600"
            />

            <p className="mt-3 text-sm text-slate-400">
              {actions.length === 0
                ? "No response actions recorded yet."
                : "No response actions match your current search or filter."}
            </p>

          </div>

        ) : (

          <div className="overflow-x-auto">

            <table className="min-w-[1100px]">

              <thead className="border-b border-slate-800 bg-slate-950/40">

                <tr className="text-left text-xs uppercase tracking-wide text-slate-500">

                  <th className="px-5 py-3">
                    ID
                  </th>

                  <th className="px-5 py-3">
                    Incident
                  </th>

                  <th className="px-5 py-3">
                    Action
                  </th>

                  <th className="px-5 py-3">
                    Target
                  </th>

                  <th className="px-5 py-3">
                    Threat
                  </th>

                  <th className="px-5 py-3">
                    Status
                  </th>

                  <th className="px-5 py-3">
                    Created
                  </th>

                  <th className="px-5 py-3 text-right">
                    Operation
                  </th>

                </tr>

              </thead>

              <tbody className="divide-y divide-slate-800">

                {filteredActions.map(
                  (action) => {

                    const status =
                      normalizeStatus(
                        action.status
                      );

                    const canExecute =
                      status === "pending";

                    return (
                      <tr
                        key={action.id}
                        className="transition hover:bg-slate-800/30"
                      >

                        <td className="whitespace-nowrap px-5 py-4 text-sm font-semibold text-white">
                          #{action.id}
                        </td>

                        <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-300">
                          {action.incident_id
                            ? `#${action.incident_id}`
                            : "—"}
                        </td>

                        <td className="min-w-[250px] px-5 py-4">

                          <div className="flex items-start gap-3">

                            <div className="mt-0.5 rounded-lg bg-blue-500/10 p-2">

                              {getActionIcon(
                                action.action_type
                              )}

                            </div>

                            <div>

                              <div className="font-medium text-slate-200">
                                {action.action_type ||
                                  "Unknown Action"}
                              </div>

                              {action.reason && (
                                <div className="mt-1 max-w-sm text-xs leading-5 text-slate-500">
                                  {action.reason}
                                </div>
                              )}

                            </div>

                          </div>

                        </td>

                        <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-300">
                          {action.target ||
                            "—"}
                        </td>

                        <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-300">
                          {action.threat_id
                            ? `#${action.threat_id}`
                            : "—"}
                        </td>

                        <td className="whitespace-nowrap px-5 py-4">

                          <span
                            className={
                              "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium " +
                              getStatusClass(
                                action.status
                              )
                            }
                          >

                            <StatusIcon
                              status={
                                action.status
                              }
                            />

                            {action.status ||
                              "unknown"}

                          </span>

                        </td>

                        <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-400">
                          {formatDate(
                            action.created_at ||
                              action.createdAt
                          )}
                        </td>

                        <td className="whitespace-nowrap px-5 py-4 text-right">

                          {canExecute ? (

                            <button
                              type="button"
                              onClick={() =>
                                handleExecute(
                                  action.id
                                )
                              }
                              disabled={
                                executingId ===
                                action.id
                              }
                              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                            >

                              {executingId ===
                              action.id ? (
                                <>
                                  <RefreshCw
                                    size={14}
                                    className="animate-spin"
                                  />

                                  Executing...
                                </>
                              ) : (
                                <>
                                  <Play
                                    size={14}
                                  />

                                  Execute
                                </>
                              )}

                            </button>

                          ) : status ===
                            "completed" ? (

                            <span className="text-xs text-emerald-500/70">
                              Completed
                            </span>

                          ) : status ===
                            "denied" ? (

                            <span className="text-xs text-orange-400/70">
                              Safety denied
                            </span>

                          ) : status ===
                            "failed" ? (

                            <span className="text-xs text-red-400/70">
                              Failed
                            </span>

                          ) : (

                            <span className="text-xs text-slate-600">
                              —
                            </span>

                          )}

                        </td>

                      </tr>
                    );
                  }
                )}

              </tbody>

            </table>

          </div>

        )}

      </div>

    </div>
  );
}