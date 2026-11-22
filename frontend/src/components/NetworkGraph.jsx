import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  MarkerType,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

function normalizeEvent(event) {
  const source =
    event?.source_ip ||
    event?.source ||
    event?.src_ip ||
    event?.src ||
    event?.local_ip ||
    "";

  const destination =
    event?.destination_ip ||
    event?.destination ||
    event?.dest_ip ||
    event?.dst_ip ||
    event?.dst ||
    "";

  const sourcePort =
    event?.source_port ||
    event?.src_port ||
    "";

  const destinationPort =
    event?.destination_port ||
    event?.dest_port ||
    event?.dst_port ||
    "";

  const risk = String(
    event?.risk ||
      event?.risk_level ||
      event?.severity ||
      "low"
  ).toLowerCase();

  const threatId =
    event?.threat_id ??
    event?.threatId ??
    null;

  return {
    source: String(source || "").trim(),
    destination: String(destination || "").trim(),
    sourcePort,
    destinationPort,
    risk,
    threatId,
  };
}

function getRiskColor(risk) {
  switch (risk) {
    case "critical":
      return "#ef4444";

    case "high":
      return "#f97316";

    case "medium":
      return "#eab308";

    default:
      return "#22c55e";
  }
}

function getRiskClass(risk) {
  switch (risk) {
    case "critical":
      return "border-red-500/50 bg-red-500/10";

    case "high":
      return "border-orange-500/50 bg-orange-500/10";

    case "medium":
      return "border-yellow-500/50 bg-yellow-500/10";

    default:
      return "border-emerald-500/50 bg-emerald-500/10";
  }
}

function getNodeRisk(ip, events) {
  const related = events.filter(
    (event) =>
      event.source === ip ||
      event.destination === ip
  );

  if (
    related.some(
      (event) =>
        event.risk === "critical"
    )
  ) {
    return "critical";
  }

  if (
    related.some(
      (event) =>
        event.risk === "high"
    )
  ) {
    return "high";
  }

  if (
    related.some(
      (event) =>
        event.risk === "medium"
    )
  ) {
    return "medium";
  }

  return "low";
}

function createNodePosition(index, total) {
  if (total === 1) {
    return {
      x: 450,
      y: 250,
    };
  }

  const centerX = 500;
  const centerY = 300;

  const radius = Math.min(
    350,
    120 + total * 4
  );

  const angle =
    (2 * Math.PI * index) / total;

  return {
    x:
      centerX +
      radius * Math.cos(angle),

    y:
      centerY +
      radius * Math.sin(angle),
  };
}

export default function NetworkGraph({
  networkEvents = [],
  suspiciousIps = [],
}) {
  const normalizedEvents = useMemo(() => {
    return networkEvents
      .map(normalizeEvent)
      .filter(
        (event) =>
          event.source ||
          event.destination
      );
  }, [networkEvents]);

  const suspiciousSet = useMemo(() => {
    return new Set(
      suspiciousIps
        .filter(Boolean)
        .map((ip) =>
          String(ip).trim()
        )
    );
  }, [suspiciousIps]);

  const graph = useMemo(() => {
    const nodeMap = new Map();

    normalizedEvents.forEach((event) => {
      if (event.source) {
        nodeMap.set(event.source, true);
      }

      if (event.destination) {
        nodeMap.set(event.destination, true);
      }
    });

    const nodeIps = Array.from(
      nodeMap.keys()
    );

    const nodes = nodeIps.map(
      (ip, index) => {
        const suspicious =
          suspiciousSet.has(ip);

        const risk = getNodeRisk(
          ip,
          normalizedEvents
        );

        const position =
          createNodePosition(
            index,
            nodeIps.length
          );

        return {
          id: ip,

          position,

          data: {
            label: (
              <div className="min-w-[150px]">
                <div className="font-semibold text-white">
                  {ip}
                </div>

                <div className="mt-1 text-xs uppercase tracking-wider text-slate-400">
                  {suspicious
                    ? "Suspicious Node"
                    : `${risk} risk`}
                </div>
              </div>
            ),
          },

          style: {
            background:
              suspicious
                ? "rgba(239, 68, 68, 0.18)"
                : "rgba(15, 23, 42, 0.95)",

            border:
              suspicious
                ? "2px solid #ef4444"
                : `1px solid ${getRiskColor(
                    risk
                  )}`,

            color: "#fff",

            borderRadius: "12px",

            padding: "12px",

            boxShadow:
              suspicious
                ? "0 0 20px rgba(239,68,68,0.35)"
                : "none",

            minWidth: "150px",
          },

          sourcePosition: "right",

          targetPosition: "left",
        };
      }
    );

    const edgeMap = new Map();

    normalizedEvents.forEach(
      (event) => {
        if (
          !event.source ||
          !event.destination
        ) {
          return;
        }

        if (
          event.source ===
          event.destination
        ) {
          return;
        }

        const key =
          `${event.source}->${event.destination}`;

        if (!edgeMap.has(key)) {
          edgeMap.set(key, {
            source: event.source,
            target: event.destination,
            risk: event.risk,
            count: 1,
          });
        } else {
          const existing =
            edgeMap.get(key);

          existing.count += 1;

          const priority = {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4,
          };

          if (
            priority[event.risk] >
            priority[existing.risk]
          ) {
            existing.risk =
              event.risk;
          }
        }
      }
    );

    const edges = Array.from(
      edgeMap.entries()
    ).map(
      ([key, edge]) => ({
        id: key,

        source: edge.source,

        target: edge.target,

        animated:
          edge.risk === "high" ||
          edge.risk === "critical",

        style: {
          stroke:
            getRiskColor(
              edge.risk
            ),

          strokeWidth:
            edge.risk ===
              "critical"
              ? 3
              : edge.risk ===
                "high"
              ? 2.5
              : 1.5,
        },

        markerEnd: {
          type:
            MarkerType.ArrowClosed,

          color:
            getRiskColor(
              edge.risk
            ),
        },

        label:
          edge.count > 1
            ? `${edge.count} events`
            : undefined,

        labelStyle: {
          fill: "#94a3b8",

          fontSize: 10,

          fontWeight: 500,
        },

        labelBgStyle: {
          fill: "#020617",
        },

        labelBgPadding: [
          4,
          2,
        ],

        labelBgBorderRadius: 4,
      })
    );

    return {
      nodes,
      edges,
    };
  }, [
    normalizedEvents,
    suspiciousSet,
  ]);

  const nodeCount =
    graph.nodes.length;

  const edgeCount =
    graph.edges.length;

  if (!networkEvents.length) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="mb-4">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            GNN Network Topology
          </div>

          <h2 className="mt-1 text-xl font-semibold text-white">
            Live Network Graph
          </h2>
        </div>

        <div className="flex h-[500px] items-center justify-center rounded-xl border border-slate-800 bg-slate-950/60">
          <div className="text-center">
            <div className="text-slate-400">
              No network events available
            </div>

            <div className="mt-1 text-sm text-slate-600">
              Start network collection to build the graph.
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            GNN Network Topology
          </div>

          <h2 className="mt-1 text-xl font-semibold text-white">
            Live Network Graph
          </h2>

          <p className="mt-1 text-sm text-slate-400">
            Real network relationships collected by ZeroGuard.
          </p>
        </div>

        <div className="flex flex-wrap gap-2 text-xs">
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-slate-300">
            Nodes{" "}
            <span className="font-semibold text-white">
              {nodeCount}
            </span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-slate-300">
            Connections{" "}
            <span className="font-semibold text-white">
              {edgeCount}
            </span>
          </div>

          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-red-300">
            Suspicious{" "}
            <span className="font-semibold text-red-200">
              {suspiciousSet.size}
            </span>
          </div>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap gap-4 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
          Low risk
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-yellow-400" />
          Medium risk
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-orange-400" />
          High risk
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
          Suspicious
        </div>
      </div>

      <div className="h-[600px] overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          fitView
          fitViewOptions={{
            padding: 0.25,
          }}
          attributionPosition="bottom-left"
        >
          <Background
            gap={24}
            size={1}
          />

          <Controls />

          <MiniMap
            nodeColor={(node) => {
              if (
                suspiciousSet.has(
                  node.id
                )
              ) {
                return "#ef4444";
              }

              return "#22c55e";
            }}
            maskColor="rgba(2, 6, 23, 0.75)"
          />
        </ReactFlow>
      </div>

      <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div className="text-sm font-medium text-white">
          Graph interpretation
        </div>

        <p className="mt-1 text-xs leading-5 text-slate-400">
          Each node represents an IP address observed in
          ZeroGuard network events. Each connection represents
          an observed source-to-destination relationship.
          Red nodes are the IP addresses identified as
          suspicious by the GNN detection result.
        </p>
      </div>
    </div>
  );
}