import json
import math
from pathlib import Path

import torch
from torch_geometric.data import Data


# ============================================================
# ZERO GUARD BASELINE GRAPH BUILDER
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

BASELINE_FILE = BASE_DIR / "normal_baseline.json"
OUTPUT_FILE = BASE_DIR / "normal_baseline_graphs.pt"


# ============================================================
# FEATURE CONFIGURATION
# ============================================================

INPUT_FEATURES = 6


# ============================================================
# ADD NODE
# ============================================================

def add_node(
    ip_address,
    node_map,
    node_features
):

    if not ip_address:
        return None

    if ip_address not in node_map:

        node_id = len(node_map)

        node_map[ip_address] = node_id

        node_features.append(
            [
                0.0,  # TCP
                0.0,  # UDP
                0.0,  # ESTABLISHED
                0.0,  # LISTEN
                0.0,  # UNIQUE PORTS
                0.0   # HIGH/CRITICAL
            ]
        )

    return node_map[ip_address]


# ============================================================
# BUILD ONE BASELINE GRAPH
# ============================================================

def build_baseline_graph(sample):

    node_map = {}
    node_features = []
    edges = []
    node_ports = {}

    events = sample.get(
        "events",
        []
    )

    for event in events:

        source_ip = (
            event.get("source_ip")
            or ""
        )

        destination_ip = (
            event.get("destination_ip")
            or ""
        )

        protocol = (
            event.get("protocol")
            or ""
        ).upper()

        event_type = (
            event.get("event_type")
            or ""
        ).upper()

        risk = (
            event.get("risk")
            or "low"
        ).lower()

        port = event.get("port")

        # ----------------------------------------------------
        # Source
        # ----------------------------------------------------

        source_node = add_node(
            source_ip,
            node_map,
            node_features
        )

        if source_node is None:
            continue

        # ----------------------------------------------------
        # Destination
        # ----------------------------------------------------

        destination_node = None

        if destination_ip:

            destination_node = add_node(
                destination_ip,
                node_map,
                node_features
            )

        # ----------------------------------------------------
        # Edges
        # ----------------------------------------------------

        if destination_node is not None:

            edges.append(
                [
                    source_node,
                    destination_node
                ]
            )

            edges.append(
                [
                    destination_node,
                    source_node
                ]
            )

        # ----------------------------------------------------
        # Features
        # ----------------------------------------------------

        features = node_features[source_node]

        if protocol == "TCP":
            features[0] += 1.0

        elif protocol == "UDP":
            features[1] += 1.0

        if event_type == "ESTABLISHED":
            features[2] += 1.0

        if event_type == "LISTEN":
            features[3] += 1.0

        if port is not None:

            if source_node not in node_ports:
                node_ports[source_node] = set()

            try:

                node_ports[source_node].add(
                    int(port)
                )

            except (
                ValueError,
                TypeError
            ):

                pass

        if risk in (
            "high",
            "critical"
        ):

            features[5] += 1.0

    # ========================================================
    # UNIQUE PORTS
    # ========================================================

    for node_id, ports in node_ports.items():

        node_features[node_id][4] = float(
            len(ports)
        )

    # ========================================================
    # NORMALIZE
    # ========================================================

    for features in node_features:

        tcp = features[0]
        udp = features[1]
        established = features[2]
        listen = features[3]
        unique_ports = features[4]
        high_critical = features[5]

        features[0] = min(
            math.log1p(tcp)
            / math.log1p(50.0),
            1.0
        )

        features[1] = min(
            math.log1p(udp)
            / math.log1p(50.0),
            1.0
        )

        features[2] = min(
            math.log1p(established)
            / math.log1p(50.0),
            1.0
        )

        features[3] = min(
            math.log1p(listen)
            / math.log1p(20.0),
            1.0
        )

        features[4] = min(
            math.log1p(unique_ports)
            / math.log1p(50.0),
            1.0
        )

        features[5] = min(
            math.log1p(high_critical)
            / math.log1p(20.0),
            1.0
        )

    # ========================================================
    # TENSORS
    # ========================================================

    if node_features:

        x = torch.tensor(
            node_features,
            dtype=torch.float
        )

    else:

        x = torch.empty(
            (0, INPUT_FEATURES),
            dtype=torch.float
        )

    if edges:

        edge_index = torch.tensor(
            edges,
            dtype=torch.long
        ).t().contiguous()

    else:

        edge_index = torch.empty(
            (2, 0),
            dtype=torch.long
        )

    graph = Data(
        x=x,
        edge_index=edge_index
    )

    graph.num_nodes = len(node_map)
    graph.num_edges = edge_index.shape[1]

    graph.event_count = len(events)

    graph.sample_number = sample.get(
        "sample_number"
    )

    graph.timestamp = sample.get(
        "timestamp"
    )

    graph.node_map = node_map

    return graph


# ============================================================
# LOAD BASELINE
# ============================================================

def load_baseline():

    if not BASELINE_FILE.exists():

        raise FileNotFoundError(
            f"Baseline file not found: "
            f"{BASELINE_FILE}"
        )

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# BUILD ALL GRAPHS
# ============================================================

def build_all_baseline_graphs():

    samples = load_baseline()

    graphs = []

    print()
    print("=" * 60)
    print("ZeroGuard Baseline Graph Builder")
    print("=" * 60)

    print(
        f"Baseline samples found: {len(samples)}"
    )

    for sample in samples:

        graph = build_baseline_graph(
            sample
        )

        graphs.append(graph)

        print(
            f"Sample {graph.sample_number}: "
            f"{graph.event_count} events | "
            f"{graph.num_nodes} nodes | "
            f"{graph.num_edges} edges"
        )

    torch.save(
        graphs,
        OUTPUT_FILE
    )

    print()
    print("=" * 60)
    print("BASELINE GRAPHS CREATED")
    print("=" * 60)

    print(
        f"Graphs saved : {len(graphs)}"
    )

    print(
        f"Output file  : {OUTPUT_FILE}"
    )

    print("=" * 60)

    return graphs


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        build_all_baseline_graphs()

    except Exception as error:

        print()
        print("=" * 60)
        print("BASELINE GRAPH ERROR")
        print("=" * 60)

        print(
            f"{type(error).__name__}: {error}"
        )

        print("=" * 60)