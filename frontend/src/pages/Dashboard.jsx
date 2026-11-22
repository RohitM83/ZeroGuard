import { useEffect, useMemo, useState } from "react";

import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  CircleAlert,
  FileText,
  FileWarning,
  Info,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Target,
} from "lucide-react";

import {
  analyzeNetwork,
  getDevices,
  getNetworkEvents,
  getThreats,
  getIncidents,
  getResponseActions,
} from "../services/api";

import { useAuth } from "../context/AuthContext";

/* =========================================================
   BASIC HELPERS
========================================================= */

function formatNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "0";
  }

  return number.toLocaleString();
}

function formatAnomalyPercent(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "0.00%";
  }

  const percentage = number <= 1 ? number * 100 : number;

  return `${percentage.toFixed(2)}%`;
}

function normalizeSeverity(value) {
  if (!value) {
    return "unknown";
  }

  return String(value).trim().toLowerCase();
}

function getSeverityClass(value) {
  const severity = normalizeSeverity(value);

  if (severity === "critical") {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }

  if (severity === "high") {
    return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  }

  if (severity === "medium") {
    return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  }

  if (severity === "low") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }

  return "border-slate-700 bg-slate-800/60 text-slate-300";
}

function getStatusClass(value) {
  const status = String(value || "").trim().toLowerCase();

  if (
    status === "active" ||
    status === "open" ||
    status === "investigating" ||
    status === "ongoing" ||
    status === "new"
  ) {
    return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  }

  if (
    status === "resolved" ||
    status === "closed" ||
    status === "completed"
  ) {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }

  if (status === "failed") {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }

  return "border-slate-700 bg-slate-800/60 text-slate-300";
}

function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

/* =========================================================
   NETWORK EVENT HELPERS
========================================================= */

function getEventSource(event) {
  return (
    event?.source_ip ??
    event?.sourceIp ??
    event?.src_ip ??
    event?.srcIp ??
    event?.src ??
    event?.source ??
    event?.source_address ??
    event?.sourceAddress ??
    event?.local_ip ??
    event?.localIp ??
    event?.client_ip ??
    event?.clientIp ??
    ""
  );
}

function getEventDestination(event) {
  return (
    event?.destination_ip ??
    event?.destinationIp ??
    event?.dest_ip ??
    event?.destIp ??
    event?.dst_ip ??
    event?.dstIp ??
    event?.dst ??
    event?.destination ??
    event?.destination_address ??
    event?.destinationAddress ??
    event?.remote_ip ??
    event?.remoteIp ??
    event?.remote_address ??
    event?.remoteAddress ??
    event?.target_ip ??
    event?.targetIp ??
    ""
  );
}

function getEventPort(event) {
  return (
    event?.destination_port ??
    event?.destinationPort ??
    event?.dest_port ??
    event?.destPort ??
    event?.dst_port ??
    event?.dstPort ??
    event?.remote_port ??
    event?.remotePort ??
    event?.port ??
    ""
  );
}

function getEventProtocol(event) {
  return (
    event?.protocol ??
    event?.transport_protocol ??
    event?.transportProtocol ??
    event?.proto ??
    ""
  );
}

function getEventRisk(event) {
  return (
    event?.risk ??
    event?.risk_level ??
    event?.riskLevel ??
    event?.severity ??
    "low"
  );
}

/* =========================================================
   IP HELPERS
========================================================= */

function isPrivateIp(address) {
  if (!address) {
    return false;
  }

  const value = String(address).trim();

  return (
    value.startsWith("10.") ||
    value.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(value) ||
    value === "localhost" ||
    value === "127.0.0.1"
  );
}

/* =========================================================
   GNN NODE HELPERS
========================================================= */

function getNodeAddress(node) {
  if (!node) {
    return "";
  }

  if (typeof node === "string") {
    return node;
  }

  return (
    node.ip ??
    node.address ??
    node.node ??
    node.node_id ??
    node.nodeId ??
    node.source_ip ??
    node.sourceIp ??
    node.host ??
    node.hostname ??
    ""
  );
}

function getNodeAnomaly(node) {
  if (!node || typeof node !== "object") {
    return 0;
  }

  return Number(
    node.anomaly_score ??
    node.anomalyScore ??
    node.score ??
    node.anomaly ??
    0
  );
}

function getNodeReconstructionError(node) {
  if (!node || typeof node !== "object") {
    return 0;
  }

  return Number(
    node.reconstruction_error ??
    node.reconstructionError ??
    node.error ??
    0
  );
}

function getNodeBaselineZ(node) {
  if (!node || typeof node !== "object") {
    return 0;
  }

  return Number(
    node.baseline_z_score ??
    node.baselineZScore ??
    node.z_score ??
    node.zScore ??
    0
  );
}

/* =========================================================
   DETECTION HELPERS
========================================================= */

function extractNodeDetails(detection) {
  if (!detection) {
    return [];
  }

  const candidates = [
    detection.node_details,
    detection.nodeDetails,
    detection.suspicious_node_details,
    detection.suspiciousNodeDetails,
    detection.anomalous_nodes,
    detection.anomalousNodes,
    detection.suspicious_nodes,
    detection.suspiciousNodes,
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate) && candidate.length > 0) {
      return candidate;
    }
  }

  return [];
}

function extractExplicitSuspiciousNodes(detection) {
  if (!detection) {
    return [];
  }

  const candidates = [
    detection.suspicious_nodes,
    detection.suspiciousNodes,
    detection.suspicious_ips,
    detection.suspiciousIps,
    detection.anomalous_nodes,
    detection.anomalousNodes,
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate) && candidate.length > 0) {
      return candidate;
    }
  }

  return [];
}

function findNodeDetails(detection, address) {
  const details = extractNodeDetails(detection);

  const normalizedAddress = String(address || "")
    .trim()
    .toLowerCase();

  return (
    details.find(
      (node) =>
        String(getNodeAddress(node)).trim().toLowerCase() ===
        normalizedAddress
    ) || null
  );
}

function getSuspiciousNodes(detection) {
  const explicit = extractExplicitSuspiciousNodes(detection);

  const explicitAddresses = explicit
    .map((item) => getNodeAddress(item) || String(item))
    .filter(Boolean);

  if (explicitAddresses.length > 0) {
    return [...new Set(explicitAddresses)];
  }

  const details = extractNodeDetails(detection);

  const suspicious = details
    .filter((node) => {
      const anomaly = getNodeAnomaly(node);
      const baselineZ = getNodeBaselineZ(node);

      return anomaly >= 0.5 && baselineZ >= 2;
    })
    .map((node) => getNodeAddress(node))
    .filter(Boolean);

  return [...new Set(suspicious)];
}

function getSuspiciousNodeCount(detection) {
  const explicit = Number(
    detection?.suspicious_nodes_count ??
    detection?.suspiciousNodesCount ??
    detection?.suspicious_node_count ??
    detection?.suspiciousNodeCount ??
    NaN
  );

  if (Number.isFinite(explicit)) {
    return explicit;
  }

  return getSuspiciousNodes(detection).length;
}

/* =========================================================
   INCIDENT HELPERS
========================================================= */

function isActiveIncident(incident) {
  const status = String(incident?.status || "").toLowerCase();

  return [
    "active",
    "new",
    "open",
    "investigating",
    "ongoing",
  ].includes(status);
}

function isResolvedIncident(incident) {
  const status = String(incident?.status || "").toLowerCase();

  return ["resolved", "closed"].includes(status);
}

/* =========================================================
   LIVE NETWORK GRAPH
========================================================= */

function buildNetworkGraph(events, suspiciousAddresses = []) {
  const nodeMap = new Map();
  const edgeMap = new Map();

  const suspiciousSet = new Set(
    suspiciousAddresses.map((address) =>
      String(address).trim().toLowerCase()
    )
  );

  function addNode(address) {
    const normalized = String(address || "").trim();

    if (!normalized) {
      return;
    }

    const key = normalized.toLowerCase();

    if (!nodeMap.has(key)) {
      nodeMap.set(key, {
        id: key,
        address: normalized,
        degree: 0,
        incoming: 0,
        outgoing: 0,
        suspicious: suspiciousSet.has(key),
        private: isPrivateIp(normalized),
      });
    }
  }

  if (!Array.isArray(events)) {
    return {
      nodes: [],
      edges: [],
      totalNodes: 0,
      totalEdges: 0,
      hasRelationships: false,
    };
  }

  events.forEach((event) => {
    const source = String(getEventSource(event) || "").trim();
    const destination = String(
      getEventDestination(event) || ""
    ).trim();

    if (!source) {
      return;
    }

    addNode(source);

    if (!destination || destination === source) {
      return;
    }

    addNode(destination);

    const sourceKey = source.toLowerCase();
    const destinationKey = destination.toLowerCase();

    const edgeKey = `${sourceKey}→${destinationKey}`;

    if (!edgeMap.has(edgeKey)) {
      edgeMap.set(edgeKey, {
        id: edgeKey,
        source: sourceKey,
        destination: destinationKey,
        count: 0,
        risk: getEventRisk(event),
        port: getEventPort(event),
        protocol: getEventProtocol(event),
      });
    }

    const edge = edgeMap.get(edgeKey);

    edge.count += 1;

    const currentRisk = normalizeSeverity(edge.risk);
    const eventRisk = normalizeSeverity(getEventRisk(event));

    const riskPriority = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      unknown: 0,
    };

    if (
      (riskPriority[eventRisk] || 0) >
      (riskPriority[currentRisk] || 0)
    ) {
      edge.risk = eventRisk;
    }

    const sourceNode = nodeMap.get(sourceKey);
    const destinationNode = nodeMap.get(destinationKey);

    sourceNode.degree += 1;
    sourceNode.outgoing += 1;

    destinationNode.degree += 1;
    destinationNode.incoming += 1;
  });

  const nodes = Array.from(nodeMap.values());
  const edges = Array.from(edgeMap.values());

  const MAX_NODES = 35;

  let visibleNodes = nodes;

  if (nodes.length > MAX_NODES) {
    visibleNodes = [...nodes]
      .sort((a, b) => {
        if (a.suspicious !== b.suspicious) {
          return a.suspicious ? -1 : 1;
        }

        return b.degree - a.degree;
      })
      .slice(0, MAX_NODES);
  }

  const visibleIds = new Set(
    visibleNodes.map((node) => node.id)
  );

  const visibleEdges = edges.filter(
    (edge) =>
      visibleIds.has(edge.source) &&
      visibleIds.has(edge.destination)
  );

  return {
    nodes: visibleNodes,
    edges: visibleEdges,
    totalNodes: nodes.length,
    totalEdges: edges.length,
    hasRelationships: visibleEdges.length > 0,
  };
}

/* =========================================================
   NETWORK MAP
========================================================= */

function NetworkActivityMap({
  graph,
  selectedNode,
  setSelectedNode,
}) {
  const width = 920;
  const height = 500;

  const positions = useMemo(() => {
    if (!graph.nodes.length) {
      return new Map();
    }

    const result = new Map();

    const suspiciousNode =
      graph.nodes.find((node) => node.suspicious) ||
      [...graph.nodes].sort(
        (a, b) => b.degree - a.degree
      )[0];

    const remaining = graph.nodes.filter(
      (node) => node.id !== suspiciousNode.id
    );

    const centerX = width / 2;
    const centerY = height / 2;

    result.set(suspiciousNode.id, {
      x: centerX,
      y: centerY,
    });

    if (remaining.length === 0) {
      return result;
    }

    const ringCount = Math.min(
      3,
      Math.max(1, Math.ceil(remaining.length / 12))
    );

    remaining.forEach((node, index) => {
      const ring = index % ringCount;

      const ringItems = remaining.filter(
        (_, itemIndex) => itemIndex % ringCount === ring
      );

      const positionInRing = ringItems.findIndex(
        (item) => item.id === node.id
      );

      const radius =
        ring === 0
          ? 145
          : ring === 1
            ? 205
            : 255;

      const angle =
        (positionInRing / Math.max(ringItems.length, 1)) *
        Math.PI *
        2 -
        Math.PI / 2;

      result.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius * 0.72,
      });
    });

    return result;
  }, [graph.nodes]);

  const selectedNodeData = selectedNode
    ? graph.nodes.find((node) => node.id === selectedNode)
    : null;

  if (!graph.nodes.length) {
    return (
      <div className="flex min-h-[420px] items-center justify-center rounded-2xl border border-slate-800 bg-slate-950/60 p-8">
        <div className="max-w-md text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700 bg-slate-900">
            <Network className="h-7 w-7 text-slate-500" />
          </div>

          <h3 className="text-lg font-semibold text-white">
            Network map waiting for traffic
          </h3>

          <p className="mt-2 text-sm leading-6 text-slate-400">
            ZeroGuard has not received enough network relationship
            data to draw the activity map yet.
          </p>
        </div>
      </div>
    );
  }

  if (!graph.hasRelationships) {
    return (
      <div className="min-h-[420px] rounded-2xl border border-slate-800 bg-slate-950/60 p-8">
        <div className="flex min-h-[360px] items-center justify-center">
          <div className="max-w-lg text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10">
              <Network className="h-7 w-7 text-cyan-400" />
            </div>

            <h3 className="text-lg font-semibold text-white">
              Network relationships not available
            </h3>

            <p className="mt-2 text-sm leading-6 text-slate-400">
              ZeroGuard received network events, but the current
              records do not contain usable source-to-destination
              relationships.
            </p>

            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-left">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Current activity
              </p>

              <p className="mt-2 text-sm text-slate-300">
                {formatNumber(graph.nodes.length)} network endpoints
                detected from the available event data.
              </p>

              <p className="mt-1 text-xs text-slate-500">
                The visualization will activate when source and
                destination relationships are available.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/60">
      <div className="relative overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-auto min-h-[420px] w-full"
          role="img"
          aria-label="ZeroGuard live network activity map"
        >
          <defs>
            <marker
              id="network-arrow"
              markerWidth="8"
              markerHeight="8"
              refX="7"
              refY="3"
              orient="auto"
              markerUnits="strokeWidth"
            >
              <path
                d="M0,0 L0,6 L7,3 z"
                fill="#64748b"
              />
            </marker>

            <filter
              id="suspicious-glow"
              x="-100%"
              y="-100%"
              width="300%"
              height="300%"
            >
              <feGaussianBlur
                stdDeviation="4"
                result="coloredBlur"
              />

              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <g opacity="0.15">
            {Array.from({ length: 20 }).map((_, index) => (
              <line
                key={`v-${index}`}
                x1={index * 50}
                y1="0"
                x2={index * 50}
                y2={height}
                stroke="#334155"
                strokeWidth="1"
              />
            ))}

            {Array.from({ length: 11 }).map((_, index) => (
              <line
                key={`h-${index}`}
                x1="0"
                y1={index * 50}
                x2={width}
                y2={index * 50}
                stroke="#334155"
                strokeWidth="1"
              />
            ))}
          </g>

          <g>
            {graph.edges.map((edge) => {
              const source = positions.get(edge.source);
              const destination = positions.get(
                edge.destination
              );

              if (!source || !destination) {
                return null;
              }

              const edgeRisk = normalizeSeverity(edge.risk);

              let stroke = "#334155";
              let strokeWidth = 1.5;
              let opacity = 0.55;

              if (edgeRisk === "high") {
                stroke = "#fb923c";
                strokeWidth = 2;
                opacity = 0.8;
              }

              if (edgeRisk === "critical") {
                stroke = "#ef4444";
                strokeWidth = 2.5;
                opacity = 0.9;
              }

              if (edgeRisk === "medium") {
                stroke = "#eab308";
                strokeWidth = 1.8;
                opacity = 0.7;
              }

              return (
                <g key={edge.id}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={destination.x}
                    y2={destination.y}
                    stroke={stroke}
                    strokeWidth={strokeWidth}
                    opacity={opacity}
                    markerEnd="url(#network-arrow)"
                  >
                    <title>
                      {edge.source} → {edge.destination}
                      {"\n"}
                      Connections: {edge.count}
                      {"\n"}
                      Risk: {edge.risk || "Low"}
                    </title>
                  </line>

                  {edge.count > 1 && (
                    <text
                      x={(source.x + destination.x) / 2}
                      y={(source.y + destination.y) / 2 - 5}
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize="9"
                    >
                      {edge.count}x
                    </text>
                  )}
                </g>
              );
            })}
          </g>

          <g>
            {graph.nodes.map((node) => {
              const position = positions.get(node.id);

              if (!position) {
                return null;
              }

              const isSelected = selectedNode === node.id;

              let fill = "#0f172a";
              let stroke = "#475569";
              let radius = 8;

              if (node.private) {
                stroke = "#22d3ee";
              }

              if (node.suspicious) {
                fill = "#431407";
                stroke = "#fb923c";
                radius = 12;
              }

              if (isSelected) {
                stroke = "#f8fafc";
                radius += 3;
              }

              return (
                <g
                  key={node.id}
                  onClick={() => setSelectedNode(node.id)}
                  className="cursor-pointer"
                >
                  {node.suspicious && (
                    <circle
                      cx={position.x}
                      cy={position.y}
                      r="20"
                      fill="none"
                      stroke="#fb923c"
                      strokeWidth="2"
                      opacity="0.25"
                      filter="url(#suspicious-glow)"
                    />
                  )}

                  <circle
                    cx={position.x}
                    cy={position.y}
                    r={radius}
                    fill={fill}
                    stroke={stroke}
                    strokeWidth={isSelected ? 3 : 2}
                  >
                    <title>
                      {node.address}
                      {"\n"}
                      Connections: {node.degree}
                      {"\n"}
                      Incoming: {node.incoming}
                      {"\n"}
                      Outgoing: {node.outgoing}
                      {node.suspicious
                        ? "\nSuspicious activity"
                        : ""}
                    </title>
                  </circle>

                  <text
                    x={position.x}
                    y={position.y + radius + 16}
                    textAnchor="middle"
                    fill={
                      node.suspicious
                        ? "#fdba74"
                        : "#cbd5e1"
                    }
                    fontSize={node.suspicious ? "11" : "9"}
                    fontWeight={
                      node.suspicious ? "600" : "400"
                    }
                  >
                    {node.address.length > 18
                      ? `${node.address.slice(0, 18)}…`
                      : node.address}
                  </text>

                  {node.suspicious && (
                    <text
                      x={position.x}
                      y={position.y - 18}
                      textAnchor="middle"
                      fill="#fb923c"
                      fontSize="9"
                      fontWeight="600"
                    >
                      SUSPICIOUS
                    </text>
                  )}
                </g>
              );
            })}
          </g>

          {graph.nodes.some((node) => node.suspicious) && (
            <g pointerEvents="none">
              <circle
                cx={width / 2}
                cy={height / 2}
                r="38"
                fill="none"
                stroke="#fb923c"
                strokeWidth="1"
                strokeDasharray="4 5"
                opacity="0.4"
              />
            </g>
          )}
        </svg>

        <div className="pointer-events-none absolute left-4 top-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950/90 px-3 py-2 shadow-xl backdrop-blur">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

              <span className="text-xs font-semibold text-white">
                LIVE NETWORK VIEW
              </span>
            </div>

            <p className="mt-1 text-[11px] text-slate-500">
              Based on recent network events
            </p>
          </div>
        </div>

        <div className="absolute bottom-4 left-4 rounded-xl border border-slate-800 bg-slate-950/90 p-3 shadow-xl backdrop-blur">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Legend
          </p>

          <div className="flex flex-wrap gap-3 text-[11px] text-slate-300">
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-cyan-400 bg-slate-950" />
              Private network
            </div>

            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-slate-500 bg-slate-950" />
              External
            </div>

            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-orange-400 bg-orange-950" />
              Suspicious
            </div>

            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 border-b border-slate-500" />
              Traffic
            </div>
          </div>
        </div>

        {selectedNodeData && (
          <div className="absolute right-4 top-4 w-64 rounded-xl border border-slate-700 bg-slate-950/95 p-4 shadow-2xl backdrop-blur">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Selected endpoint
                </p>

                <p className="mt-1 break-all text-sm font-semibold text-white">
                  {selectedNodeData.address}
                </p>
              </div>

              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-slate-500 transition hover:text-white"
              >
                ×
              </button>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2">
              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2">
                <p className="text-[10px] text-slate-500">
                  Connections
                </p>

                <p className="mt-1 text-sm font-semibold text-white">
                  {formatNumber(selectedNodeData.degree)}
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2">
                <p className="text-[10px] text-slate-500">
                  Type
                </p>

                <p className="mt-1 text-sm font-semibold text-white">
                  {selectedNodeData.private
                    ? "Private"
                    : "External"}
                </p>
              </div>
            </div>

            {selectedNodeData.suspicious && (
              <div className="mt-3 rounded-lg border border-orange-500/20 bg-orange-500/10 p-2">
                <div className="flex items-center gap-2 text-xs font-medium text-orange-300">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  Suspicious activity associated
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="border-t border-slate-800 bg-slate-900/40 px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-4 text-xs text-slate-500">
            <span>
              Showing{" "}
              <span className="font-semibold text-slate-300">
                {formatNumber(graph.nodes.length)}
              </span>{" "}
              endpoints
            </span>

            <span>
              <span className="font-semibold text-slate-300">
                {formatNumber(graph.edges.length)}
              </span>{" "}
              active relationships
            </span>
          </div>

          <p className="text-[11px] text-slate-500">
            Click an endpoint for details
          </p>
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   STAT CARD
========================================================= */

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconClass = "text-cyan-400",
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">{title}</p>

          <p className="mt-2 text-3xl font-bold tracking-tight text-white">
            {value}
          </p>

          {subtitle && (
            <p className="mt-1 text-xs text-slate-500">
              {subtitle}
            </p>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
          <Icon className={`h-5 w-5 ${iconClass}`} />
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   SECURITY DETECTION FLOW
========================================================= */

function SecurityDetectionFlow({
  networkEventCount,
  maximumAnomaly,
  riskScore,
  riskLevel,
  threatCount,
  activeThreatCount,
  completedActionCount,
}) {
  const steps = [
    {
      number: "01",
      title: "Network Activity",
      value: formatNumber(networkEventCount),
      subtitle: "events monitored",
      icon: Activity,
      color: "cyan",
    },
    {
      number: "02",
      title: "GNN Analysis",
      value: formatAnomalyPercent(maximumAnomaly),
      subtitle: "maximum anomaly",
      icon: Brain,
      color: "purple",
    },
    {
      number: "03",
      title: "Risk Correlation",
      value: `${Number.isFinite(riskScore)
          ? riskScore.toFixed(0)
          : "0"
        } / 100`,
      subtitle: `${String(riskLevel).toUpperCase()} risk`,
      icon: ShieldAlert,
      color: "yellow",
    },
    {
      number: "04",
      title: "Threat Decision",
      value: formatNumber(threatCount),
      subtitle: `${formatNumber(activeThreatCount)} active`,
      icon: Target,
      color: "orange",
    },
    {
      number: "05",
      title: "Response",
      value: formatNumber(completedActionCount),
      subtitle: "completed actions",
      icon: ShieldCheck,
      color: "emerald",
    },
    {
      number: "06",
      title: "Security Report",
      value: "Evidence",
      subtitle: "available for review",
      icon: FileText,
      color: "blue",
    },
  ];

  const colorMap = {
    cyan: {
      border: "border-cyan-500/20",
      bg: "bg-cyan-500/10",
      icon: "text-cyan-400",
      number: "text-cyan-300",
    },
    purple: {
      border: "border-purple-500/20",
      bg: "bg-purple-500/10",
      icon: "text-purple-400",
      number: "text-purple-300",
    },
    yellow: {
      border: "border-yellow-500/20",
      bg: "bg-yellow-500/10",
      icon: "text-yellow-400",
      number: "text-yellow-300",
    },
    orange: {
      border: "border-orange-500/20",
      bg: "bg-orange-500/10",
      icon: "text-orange-400",
      number: "text-orange-300",
    },
    emerald: {
      border: "border-emerald-500/20",
      bg: "bg-emerald-500/10",
      icon: "text-emerald-400",
      number: "text-emerald-300",
    },
    blue: {
      border: "border-blue-500/20",
      bg: "bg-blue-500/10",
      icon: "text-blue-400",
      number: "text-blue-300",
    },
  };

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70">
      <div className="border-b border-slate-800 px-5 py-4">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-cyan-400" />

              <h2 className="text-lg font-semibold text-white">
                Security Detection & Response Flow
              </h2>
            </div>

            <p className="mt-1 text-sm text-slate-400">
              How ZeroGuard processes network activity from
              detection through security evidence
            </p>
          </div>

          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

            <span className="text-xs font-semibold text-emerald-300">
              PIPELINE ACTIVE
            </span>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto p-5">
        <div className="flex min-w-[1050px] items-stretch gap-3">
          {steps.map((step, index) => {
            const Icon = step.icon;
            const colors = colorMap[step.color];

            return (
              <div
                key={step.number}
                className="flex min-w-[165px] flex-1 items-center"
              >
                <div
                  className={`relative w-full rounded-xl border ${colors.border} bg-slate-950/70 p-4 transition hover:-translate-y-0.5 hover:bg-slate-950`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] font-bold tracking-widest text-slate-600">
                      {step.number}
                    </span>

                    <div
                      className={`flex h-9 w-9 items-center justify-center rounded-lg border ${colors.border} ${colors.bg}`}
                    >
                      <Icon className={`h-4 w-4 ${colors.icon}`} />
                    </div>
                  </div>

                  <p className="mt-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
                    {step.title}
                  </p>

                  <p
                    className={`mt-1 text-xl font-bold ${colors.number}`}
                  >
                    {step.value}
                  </p>

                  <p className="mt-1 text-[11px] text-slate-600">
                    {step.subtitle}
                  </p>
                </div>

                {index < steps.length - 1 && (
                  <div className="mx-2 flex shrink-0 items-center">
                    <div className="h-px w-4 bg-slate-700" />

                    <div className="h-0 w-0 border-y-[4px] border-l-[5px] border-y-transparent border-l-slate-600" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="border-t border-slate-800 bg-slate-950/30 px-5 py-3">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
          <div className="flex items-center gap-2 text-slate-500">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
            Collect
          </div>

          <div className="flex items-center gap-2 text-slate-500">
            <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
            Detect
          </div>

          <div className="flex items-center gap-2 text-slate-500">
            <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
            Correlate
          </div>

          <div className="flex items-center gap-2 text-slate-500">
            <span className="h-1.5 w-1.5 rounded-full bg-orange-400" />
            Decide
          </div>

          <div className="flex items-center gap-2 text-slate-500">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Respond
          </div>

          <div className="flex items-center gap-2 text-slate-500">
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
            Document
          </div>
        </div>
      </div>
    </section>
  );
}

/* =========================================================
   MAIN DASHBOARD
========================================================= */

export default function Dashboard() {
  const { isAdmin } = useAuth();

  const [detection, setDetection] = useState(null);
  const [devices, setDevices] = useState([]);
  const [networkEvents, setNetworkEvents] = useState([]);
  const [threats, setThreats] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [responseActions, setResponseActions] = useState([]);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [selectedNode, setSelectedNode] = useState(null);

  /* =====================================================
     RUN GNN DETECTION
  ===================================================== */

  async function runDetection(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      }

      const result = await analyzeNetwork();

      console.log("ZeroGuard GNN detection result:", result);

      setDetection(result);
      setError("");
    } catch (err) {
      console.error("GNN detection failed:", err);

      setError(
        err?.message ||
        "Unable to run GNN network analysis."
      );
    } finally {
      if (showRefresh) {
        setRefreshing(false);
      }
    }
  }

  /* =====================================================
     LOAD DASHBOARD DATA
  ===================================================== */

  async function loadDashboardData(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const [
        devicesResult,
        networkEventsResult,
        threatsResult,
      ] = await Promise.all([
        getDevices(),
        getNetworkEvents(),
        getThreats(),
      ]);

      setDevices(
        Array.isArray(devicesResult)
          ? devicesResult
          : devicesResult?.devices || []
      );

      setNetworkEvents(
        Array.isArray(networkEventsResult)
          ? networkEventsResult
          : networkEventsResult?.events || []
      );

      setThreats(
        Array.isArray(threatsResult)
          ? threatsResult
          : threatsResult?.threats || []
      );

      if (isAdmin) {
        const [
          incidentsResult,
          responseActionsResult,
        ] = await Promise.all([
          getIncidents(),
          getResponseActions(),
        ]);

        setIncidents(
          Array.isArray(incidentsResult)
            ? incidentsResult
            : incidentsResult?.incidents || []
        );

        setResponseActions(
          Array.isArray(responseActionsResult)
            ? responseActionsResult
            : responseActionsResult?.actions || []
        );
      } else {
        setIncidents([]);
        setResponseActions([]);
      }

      await runDetection(false);
    } catch (err) {
      console.error("Dashboard loading failed:", err);

      setError(
        err?.message ||
        "Unable to load dashboard data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  /* =====================================================
     INITIAL LOAD + AUTO REFRESH
  ===================================================== */

  useEffect(() => {
    loadDashboardData(false);

    const interval = setInterval(() => {
      loadDashboardData(false);
    }, 30000);

    return () => clearInterval(interval);
  }, [isAdmin]);

  /* =====================================================
     DETECTION METRICS
  ===================================================== */

  const suspiciousNodes = useMemo(() => {
    return getSuspiciousNodes(detection);
  }, [detection]);

  const suspiciousNodeCount = useMemo(() => {
    return getSuspiciousNodeCount(detection);
  }, [detection]);

  const maximumAnomaly = Number(
    detection?.maximum_anomaly_score ??
    detection?.maximumAnomalyScore ??
    detection?.max_anomaly_score ??
    detection?.maxAnomalyScore ??
    0
  );

  const averageAnomaly = Number(
    detection?.average_anomaly_score ??
    detection?.averageAnomalyScore ??
    detection?.avg_anomaly_score ??
    detection?.avgAnomalyScore ??
    0
  );

  const totalNodes = Number(
    detection?.total_nodes ??
    detection?.totalNodes ??
    detection?.graph_nodes ??
    detection?.graphNodes ??
    0
  );

  const totalEdges = Number(
    detection?.total_edges ??
    detection?.totalEdges ??
    detection?.graph_edges ??
    detection?.graphEdges ??
    0
  );

  const riskScore = Number(
    detection?.risk_score ??
    detection?.riskScore ??
    0
  );

  const riskLevel =
    detection?.risk_level ??
    detection?.riskLevel ??
    "UNKNOWN";

  const gnnSeverity =
    detection?.gnn_severity ??
    detection?.gnnSeverity ??
    detection?.severity ??
    "UNKNOWN";

  const correlatedEvents = Number(
    detection?.correlated_event_count ??
    detection?.correlatedEventCount ??
    detection?.correlated_events ??
    detection?.correlatedEvents ??
    detection?.linked_events ??
    detection?.linkedEvents ??
    0
  );

  const baselineZScore = Number(
    detection?.baseline_z_score ??
    detection?.baselineZScore ??
    0
  );

  /* =====================================================
     SUSPICIOUS IP INFORMATION
  ===================================================== */

  const detectionSuspiciousIps = useMemo(() => {
    const candidates = [
      detection?.suspicious_ips,
      detection?.suspiciousIps,
      detection?.suspicious_nodes,
      detection?.suspiciousNodes,
    ];

    for (const candidate of candidates) {
      if (Array.isArray(candidate) && candidate.length > 0) {
        return candidate
          .map(
            (item) =>
              getNodeAddress(item) || String(item)
          )
          .filter(Boolean);
      }
    }

    return [];
  }, [detection]);

  const allSuspiciousAddresses = useMemo(() => {
    return [
      ...new Set([
        ...suspiciousNodes,
        ...detectionSuspiciousIps,
      ]),
    ];
  }, [suspiciousNodes, detectionSuspiciousIps]);

  /* =====================================================
     NETWORK GRAPH
  ===================================================== */

  const networkGraph = useMemo(() => {
    return buildNetworkGraph(
      networkEvents,
      allSuspiciousAddresses
    );
  }, [networkEvents, allSuspiciousAddresses]);

  /* =====================================================
     THREAT METRICS
  ===================================================== */

  const activeThreats = useMemo(() => {
  return threats.filter((threat) => {
    const status = String(
      threat?.status || ""
    ).toLowerCase();

    return status === "active";
  }).length;
}, [threats]);

  const criticalThreats = useMemo(() => {
    return threats.filter(
      (threat) =>
        normalizeSeverity(threat?.severity) ===
        "critical"
    ).length;
  }, [threats]);

  const highThreats = useMemo(() => {
    return threats.filter(
      (threat) =>
        normalizeSeverity(threat?.severity) ===
        "high"
    ).length;
  }, [threats]);

  const mediumThreats = useMemo(() => {
    return threats.filter(
      (threat) =>
        normalizeSeverity(threat?.severity) ===
        "medium"
    ).length;
  }, [threats]);

  const resolvedThreats = useMemo(() => {
    return threats.filter((threat) => {
      const status = String(
        threat?.status || ""
      ).toLowerCase();

      return ["resolved", "closed"].includes(status);
    }).length;
  }, [threats]);

  /* =====================================================
     INCIDENT METRICS
  ===================================================== */

  const activeIncidents = useMemo(() => {
    return incidents.filter(isActiveIncident).length;
  }, [incidents]);

  const resolvedIncidents = useMemo(() => {
    return incidents.filter(isResolvedIncident).length;
  }, [incidents]);

  const pendingActions = useMemo(() => {
    return responseActions.filter((action) => {
      const status = String(
        action?.status || ""
      ).toLowerCase();

      return [
        "pending",
        "queued",
        "created",
      ].includes(status);
    }).length;
  }, [responseActions]);

  const completedActions = useMemo(() => {
    return responseActions.filter((action) => {
      const status = String(
        action?.status || ""
      ).toLowerCase();

      return [
        "completed",
        "executed",
      ].includes(status);
    }).length;
  }, [responseActions]);

  /* =====================================================
     RECENT THREATS
  ===================================================== */

  const recentThreats = useMemo(() => {
    return [...threats]
      .sort((a, b) => {
        const dateA = new Date(
          a?.created_at ??
          a?.createdAt ??
          a?.timestamp ??
          0
        ).getTime();

        const dateB = new Date(
          b?.created_at ??
          b?.createdAt ??
          b?.timestamp ??
          0
        ).getTime();

        return dateB - dateA;
      })
      .slice(0, 5);
  }, [threats]);

  /* =====================================================
     SUSPICIOUS NODE DETAILS
  ===================================================== */

  const suspiciousNodeDetails = useMemo(() => {
    return allSuspiciousAddresses.map((address) => {
      const details = findNodeDetails(
        detection,
        address
      );

      const graphNode = networkGraph.nodes.find(
        (node) =>
          node.address.toLowerCase() ===
          String(address).toLowerCase()
      );

      return {
        address,
        anomaly: details
          ? getNodeAnomaly(details)
          : maximumAnomaly,
        reconstructionError: details
          ? getNodeReconstructionError(details)
          : 0,
        baselineZ: details
          ? getNodeBaselineZ(details)
          : baselineZScore,
        connections: graphNode?.degree || 0,
      };
    });
  }, [
    allSuspiciousAddresses,
    detection,
    networkGraph.nodes,
    maximumAnomaly,
    baselineZScore,
  ]);

  /* =====================================================
     REFRESH
  ===================================================== */

  async function handleRefresh() {
    await loadDashboardData(true);
  }

  /* =====================================================
     LOADING
  ===================================================== */

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 p-6 text-white">
        <div className="mx-auto max-w-7xl">
          <div className="flex min-h-[70vh] items-center justify-center">
            <div className="text-center">
              <RefreshCw className="mx-auto h-8 w-8 animate-spin text-cyan-400" />

              <p className="mt-4 text-sm text-slate-400">
                Loading ZeroGuard Security Operations Center...
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  /* =====================================================
     MAIN UI
  ===================================================== */

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="mx-auto max-w-7xl space-y-6 p-4 sm:p-6">

        {/* HEADER */}

        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10">
                <ShieldCheck className="h-6 w-6 text-cyan-400" />
              </div>

              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">
                  Security Operations
                </h1>

                <p className="mt-1 text-sm text-slate-400">
                  ZeroGuard AI-powered network security monitoring
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 sm:flex">
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

              <span className="text-xs font-medium text-emerald-300">
                Backend Online
              </span>
            </div>

            <button
              type="button"
              onClick={handleRefresh}
              disabled={refreshing}
              className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCw
                className={`h-4 w-4 ${refreshing ? "animate-spin" : ""
                  }`}
              />

              {refreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>

        {/* ERROR */}

        {error && (
          <div className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4">
            <CircleAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />

            <div>
              <p className="text-sm font-medium text-red-300">
                Dashboard warning
              </p>

              <p className="mt-1 text-xs text-red-300/80">
                {error}
              </p>
            </div>
          </div>
        )}

        {/* TOP STATS */}

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            title="Devices"
            value={formatNumber(devices.length)}
            subtitle="Registered endpoints"
            icon={Server}
            iconClass="text-cyan-400"
          />

          <StatCard
            title="Network Events"
            value={formatNumber(networkEvents.length)}
            subtitle="Recent traffic records"
            icon={Activity}
            iconClass="text-blue-400"
          />

          <StatCard
            title="Total Threats"
            value={formatNumber(threats.length)}
            subtitle={`${resolvedThreats} resolved`}
            icon={ShieldAlert}
            iconClass="text-orange-400"
          />

          <StatCard
            title="Active Threats"
            value={formatNumber(activeThreats)}
            subtitle={`${highThreats} high severity`}
            icon={AlertTriangle}
            iconClass="text-red-400"
          />
        </div>

        {/* =================================================
            SECURITY DETECTION & RESPONSE FLOW
        ================================================= */}

        <SecurityDetectionFlow
          networkEventCount={networkEvents.length}
          maximumAnomaly={maximumAnomaly}
          riskScore={riskScore}
          riskLevel={riskLevel}
          threatCount={threats.length}
          activeThreatCount={activeThreats}
          completedActionCount={completedActions}
        />

        {/* =================================================
            NETWORK ACTIVITY MAP
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="mb-5 flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
            <div>
              <div className="flex items-center gap-2">
                <Network className="h-5 w-5 text-cyan-400" />

                <h2 className="text-lg font-semibold text-white">
                  Network Activity Map
                </h2>

                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
                  Live
                </span>
              </div>

              <p className="mt-1 text-sm text-slate-400">
                Recent communication relationships detected by ZeroGuard
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
                <span className="text-[10px] uppercase tracking-wider text-slate-500">
                  Visible endpoints
                </span>

                <p className="mt-0.5 text-sm font-semibold text-white">
                  {formatNumber(networkGraph.nodes.length)}
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
                <span className="text-[10px] uppercase tracking-wider text-slate-500">
                  Relationships
                </span>

                <p className="mt-0.5 text-sm font-semibold text-white">
                  {formatNumber(networkGraph.edges.length)}
                </p>
              </div>
            </div>
          </div>

          <NetworkActivityMap
            graph={networkGraph}
            selectedNode={selectedNode}
            setSelectedNode={setSelectedNode}
          />
        </section>

        {/* =================================================
            GNN + RISK OVERVIEW
        ================================================= */}

        <div className="grid gap-6 lg:grid-cols-3">

          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 lg:col-span-2">
            <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
              <div>
                <div className="flex items-center gap-2">
                  <Brain className="h-5 w-5 text-purple-400" />

                  <h2 className="text-lg font-semibold text-white">
                    GNN Detection
                  </h2>
                </div>

                <p className="mt-1 text-sm text-slate-400">
                  Graph Neural Network anomaly analysis
                </p>
              </div>

              <div
                className={`rounded-lg border px-3 py-1.5 text-xs font-semibold uppercase ${getSeverityClass(
                  gnnSeverity
                )}`}
              >
                GNN {gnnSeverity}
              </div>
            </div>

            <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <p className="text-xs text-slate-500">
                  Maximum anomaly
                </p>

                <p className="mt-2 text-xl font-bold text-orange-300">
                  {formatAnomalyPercent(maximumAnomaly)}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <p className="text-xs text-slate-500">
                  Average anomaly
                </p>

                <p className="mt-2 text-xl font-bold text-cyan-300">
                  {formatAnomalyPercent(averageAnomaly)}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <p className="text-xs text-slate-500">
                  Suspicious nodes
                </p>

                <p className="mt-2 text-xl font-bold text-orange-300">
                  {formatNumber(suspiciousNodeCount)}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <p className="text-xs text-slate-500">
                  Correlated events
                </p>

                <p className="mt-2 text-xl font-bold text-yellow-300">
                  {formatNumber(correlatedEvents)}
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-500">
                    GNN graph nodes
                  </span>

                  <Target className="h-4 w-4 text-cyan-400" />
                </div>

                <p className="mt-2 text-2xl font-bold text-white">
                  {formatNumber(totalNodes)}
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  Model graph size
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-500">
                    GNN graph edges
                  </span>

                  <Network className="h-4 w-4 text-blue-400" />
                </div>

                <p className="mt-2 text-2xl font-bold text-white">
                  {formatNumber(totalEdges)}
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  Model relationships
                </p>
              </div>
            </div>
          </section>

          {/* RISK ASSESSMENT */}

          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-orange-400" />

              <h2 className="text-lg font-semibold text-white">
                Risk Assessment
              </h2>
            </div>

            <p className="mt-1 text-sm text-slate-400">
              Contextual risk after correlation
            </p>

            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/60 p-5 text-center">
              <div className="mx-auto flex h-24 w-24 items-center justify-center rounded-full border-8 border-slate-800">
                <div>
                  <p className="text-2xl font-bold text-white">
                    {Number.isFinite(riskScore)
                      ? riskScore.toFixed(0)
                      : "0"}
                  </p>

                  <p className="text-[10px] uppercase tracking-wider text-slate-500">
                    / 100
                  </p>
                </div>
              </div>

              <div
                className={`mx-auto mt-4 inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase ${getSeverityClass(
                  riskLevel
                )}`}
              >
                {riskLevel}
              </div>
            </div>

            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-500">
                  GNN severity
                </span>

                <span className="font-medium text-slate-200">
                  {String(gnnSeverity).toUpperCase()}
                </span>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-500">
                  Baseline Z-score
                </span>

                <span className="font-medium text-slate-200">
                  {Number.isFinite(baselineZScore)
                    ? baselineZScore.toFixed(3)
                    : "0.000"}
                </span>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-500">
                  Correlated events
                </span>

                <span className="font-medium text-slate-200">
                  {formatNumber(correlatedEvents)}
                </span>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-3">
              <div className="flex gap-2">
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-yellow-400" />

                <p className="text-xs leading-5 text-yellow-200/80">
                  GNN anomaly score indicates statistical deviation
                  from learned network behavior. It is not an attack
                  probability.
                </p>
              </div>
            </div>
          </section>
        </div>

        {/* =================================================
            SUSPICIOUS NODES
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
            <div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-orange-400" />

                <h2 className="text-lg font-semibold text-white">
                  Suspicious Network Nodes
                </h2>
              </div>

              <p className="mt-1 text-sm text-slate-400">
                Endpoints requiring investigation based on GNN
                anomaly signals
              </p>
            </div>

            <span className="rounded-lg border border-orange-500/20 bg-orange-500/10 px-3 py-1.5 text-xs font-semibold text-orange-300">
              {formatNumber(suspiciousNodeCount)} detected
            </span>
          </div>

          {suspiciousNodeDetails.length === 0 ? (
            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center">
              <CheckCircle2 className="mx-auto h-7 w-7 text-emerald-400" />

              <p className="mt-3 text-sm font-medium text-slate-300">
                No suspicious nodes currently reported
              </p>

              <p className="mt-1 text-xs text-slate-500">
                ZeroGuard has no explicit suspicious endpoint to
                display.
              </p>
            </div>
          ) : (
            <div className="mt-5 overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full min-w-[760px] text-left">
                <thead className="border-b border-slate-800 bg-slate-950/60">
                  <tr>
                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Endpoint
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Anomaly
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Reconstruction Error
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Baseline Z
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Connections
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Status
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-800">
                  {suspiciousNodeDetails.map((node) => (
                    <tr
                      key={node.address}
                      className="transition hover:bg-slate-950/60"
                    >
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-orange-500/20 bg-orange-500/10">
                            <Target className="h-4 w-4 text-orange-400" />
                          </div>

                          <div>
                            <p className="font-medium text-white">
                              {node.address}
                            </p>

                            <p className="text-xs text-slate-500">
                              Network endpoint
                            </p>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-4 font-semibold text-orange-300">
                        {formatAnomalyPercent(node.anomaly)}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-300">
                        {Number.isFinite(
                          node.reconstructionError
                        )
                          ? node.reconstructionError.toFixed(6)
                          : "0.000000"}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-300">
                        {Number.isFinite(node.baselineZ)
                          ? node.baselineZ.toFixed(3)
                          : "0.000"}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-300">
                        {formatNumber(node.connections)}
                      </td>

                      <td className="px-4 py-4">
                        <span className="rounded-full border border-orange-500/30 bg-orange-500/10 px-2.5 py-1 text-xs font-semibold text-orange-300">
                          Investigate
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* =================================================
            THREAT OVERVIEW
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-red-400" />

            <h2 className="text-lg font-semibold text-white">
              Threat Overview
            </h2>
          </div>

          <p className="mt-1 text-sm text-slate-400">
            Current threat distribution across the monitored environment
          </p>

          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
              <p className="text-xs text-slate-500">
                Critical
              </p>

              <p className="mt-2 text-2xl font-bold text-red-300">
                {formatNumber(criticalThreats)}
              </p>
            </div>

            <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
              <p className="text-xs text-slate-500">
                High
              </p>

              <p className="mt-2 text-2xl font-bold text-orange-300">
                {formatNumber(highThreats)}
              </p>
            </div>

            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
              <p className="text-xs text-slate-500">
                Medium
              </p>

              <p className="mt-2 text-2xl font-bold text-yellow-300">
                {formatNumber(mediumThreats)}
              </p>
            </div>

            <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
              <p className="text-xs text-slate-500">
                Active
              </p>

              <p className="mt-2 text-2xl font-bold text-orange-300">
                {formatNumber(activeThreats)}
              </p>
            </div>

            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
              <p className="text-xs text-slate-500">
                Resolved
              </p>

              <p className="mt-2 text-2xl font-bold text-emerald-300">
                {formatNumber(resolvedThreats)}
              </p>
            </div>
          </div>
        </section>

        {/* =================================================
            RECENT THREATS
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2">
            <FileWarning className="h-5 w-5 text-orange-400" />

            <h2 className="text-lg font-semibold text-white">
              Recent Threats
            </h2>
          </div>

          <p className="mt-1 text-sm text-slate-400">
            Latest detections recorded by ZeroGuard
          </p>

          {recentThreats.length === 0 ? (
            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center">
              <CheckCircle2 className="mx-auto h-7 w-7 text-emerald-400" />

              <p className="mt-3 text-sm text-slate-400">
                No threats recorded yet.
              </p>
            </div>
          ) : (
            <div className="mt-5 overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full min-w-[720px] text-left">
                <thead className="border-b border-slate-800 bg-slate-950/60">
                  <tr>
                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Threat
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Severity
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Status
                    </th>

                    <th className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Created
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-800">
                  {recentThreats.map((threat, index) => {
                    const severity =
                      threat?.severity || "unknown";

                    const status =
                      threat?.status || "unknown";

                    const title =
                      threat?.title ??
                      threat?.name ??
                      threat?.threat_type ??
                      threat?.threatType ??
                      `Threat #${threat?.id ?? index + 1
                      }`;

                    return (
                      <tr
                        key={
                          threat?.id ??
                          threat?.threat_id ??
                          index
                        }
                        className="transition hover:bg-slate-950/60"
                      >
                        <td className="px-4 py-4">
                          <div className="flex items-center gap-3">
                            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-slate-950">
                              <ShieldAlert className="h-4 w-4 text-orange-400" />
                            </div>

                            <div>
                              <p className="font-medium text-white">
                                {title}
                              </p>

                              {threat?.id && (
                                <p className="text-xs text-slate-500">
                                  Threat #{threat.id}
                                </p>
                              )}
                            </div>
                          </div>
                        </td>

                        <td className="px-4 py-4">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${getSeverityClass(
                              severity
                            )}`}
                          >
                            {severity}
                          </span>
                        </td>

                        <td className="px-4 py-4">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${getStatusClass(
                              status
                            )}`}
                          >
                            {status}
                          </span>
                        </td>

                        <td className="px-4 py-4 text-sm text-slate-400">
                          {formatDate(
                            threat?.created_at ??
                            threat?.createdAt ??
                            threat?.detected_at ??
                            threat?.timestamp
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* =================================================
            ADMIN OPERATIONS
        ================================================= */}

        {isAdmin && (
          <div className="grid gap-6 lg:grid-cols-2">
            <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="flex items-center gap-2">
                <CircleAlert className="h-5 w-5 text-orange-400" />

                <h2 className="text-lg font-semibold text-white">
                  Incident Operations
                </h2>
              </div>

              <p className="mt-1 text-sm text-slate-400">
                Administrative incident monitoring
              </p>

              <div className="mt-5 grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
                  <p className="text-xs text-slate-500">
                    Active incidents
                  </p>

                  <p className="mt-2 text-2xl font-bold text-orange-300">
                    {formatNumber(activeIncidents)}
                  </p>
                </div>

                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                  <p className="text-xs text-slate-500">
                    Resolved incidents
                  </p>

                  <p className="mt-2 text-2xl font-bold text-emerald-300">
                    {formatNumber(resolvedIncidents)}
                  </p>
                </div>
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-cyan-400" />

                <h2 className="text-lg font-semibold text-white">
                  Response Operations
                </h2>
              </div>

              <p className="mt-1 text-sm text-slate-400">
                Defensive response action status
              </p>

              <div className="mt-5 grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
                  <p className="text-xs text-slate-500">
                    Pending actions
                  </p>

                  <p className="mt-2 text-2xl font-bold text-yellow-300">
                    {formatNumber(pendingActions)}
                  </p>
                </div>

                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                  <p className="text-xs text-slate-500">
                    Completed actions
                  </p>

                  <p className="mt-2 text-2xl font-bold text-emerald-300">
                    {formatNumber(completedActions)}
                  </p>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* =================================================
            GNN INFORMATION
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-purple-400" />

            <h2 className="text-lg font-semibold text-white">
              GNN Analysis Information
            </h2>
          </div>

          <p className="mt-1 text-sm text-slate-400">
            How ZeroGuard interprets the current network analysis
          </p>

          <div className="mt-5 grid gap-4 md:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-center gap-2">
                <Brain className="h-4 w-4 text-purple-400" />

                <h3 className="text-sm font-semibold text-white">
                  Anomaly Detection
                </h3>
              </div>

              <p className="mt-2 text-xs leading-5 text-slate-500">
                The GNN compares network behavior against learned
                patterns and identifies statistically unusual nodes
                and relationships.
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-orange-400" />

                <h3 className="text-sm font-semibold text-white">
                  Risk Correlation
                </h3>
              </div>

              <p className="mt-2 text-xs leading-5 text-slate-500">
                ZeroGuard combines the GNN signal with contextual
                network evidence before assigning the final risk
                level.
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />

                <h3 className="text-sm font-semibold text-white">
                  Defensive Response
                </h3>
              </div>

              <p className="mt-2 text-xs leading-5 text-slate-500">
                High-risk actions are subject to safety checks.
                ZeroGuard does not automatically block a suspicious
                endpoint merely because the GNN reports an anomaly.
              </p>
            </div>
          </div>
        </section>

        {/* =================================================
            CURRENT SYSTEM SUMMARY
        ================================================= */}

        <section className="rounded-2xl border border-cyan-500/10 bg-cyan-500/[0.03] p-5">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-3">
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-2.5">
                <Info className="h-5 w-5 text-cyan-400" />
              </div>

              <div>
                <p className="text-sm font-semibold text-white">
                  Current ZeroGuard assessment
                </p>

                <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">
                  The GNN has identified statistically unusual
                  network behavior. ZeroGuard combines this signal
                  with contextual evidence before determining the
                  final risk level and recommended response.
                </p>
              </div>
            </div>

            <div className="shrink-0">
              <div
                className={`rounded-xl border px-4 py-2 text-center ${getSeverityClass(
                  riskLevel
                )}`}
              >
                <p className="text-[10px] uppercase tracking-wider opacity-70">
                  Contextual Risk
                </p>

                <p className="mt-0.5 text-sm font-bold uppercase">
                  {riskLevel}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* FOOTER */}

        <div className="flex flex-col justify-between gap-2 border-t border-slate-900 pt-4 text-xs text-slate-600 sm:flex-row">
          <span>
            ZeroGuard Security Operations Center
          </span>

          <span>
            AI-Based Zero-Day Attack Detection Using Graph Neural
            Networks
          </span>
        </div>
      </div>
    </div>
  );
}