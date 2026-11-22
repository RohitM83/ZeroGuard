import sqlite3
from pathlib import Path
from typing import Dict, List
import math

import torch
from torch_geometric.data import Data


# ============================================================
# ZeroGuard Graph Builder
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "zeroguard.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    connection = sqlite3.connect(str(DATABASE_PATH))
    connection.row_factory = sqlite3.Row
    return connection


# ============================================================
# ADD NODE
# ============================================================

def add_node(
    ip_address: str,
    node_map: Dict[str, int],
    node_features: List[List[float]]
):
    """
    Add an IP address to the graph if it does not already exist.

    Each node has 6 features:

    0 = TCP activity
    1 = UDP activity
    2 = ESTABLISHED connections
    3 = LISTEN connections
    4 = UNIQUE ports
    5 = HIGH/CRITICAL risk events
    """

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
                0.0   # HIGH/CRITICAL RISK
            ]
        )

    return node_map[ip_address]


# ============================================================
# BUILD GRAPH
# ============================================================

def build_graph(limit: int = 500):

    connection = get_connection()

    events = connection.execute(
        """
        SELECT
            id,
            source_ip,
            destination_ip,
            protocol,
            port,
            event_type,
            risk,
            timestamp,
            threat_id
        FROM network_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    # --------------------------------------------------------
    # Empty database protection
    # --------------------------------------------------------

    if not events:

        graph = Data(
            x=torch.empty((0, 6), dtype=torch.float),
            edge_index=torch.empty((2, 0), dtype=torch.long)
        )

        graph.num_nodes = 0
        graph.num_edges = 0
        graph.event_count = 0
        graph.node_map = {}
        graph.node_details = []

        return graph

    # --------------------------------------------------------
    # Graph containers
    # --------------------------------------------------------

    node_map = {}
    node_features = []
    edges = []

    # Keep track of unique ports used by each source node
    node_ports = {}

    # --------------------------------------------------------
    # Process network events
    # --------------------------------------------------------

    for event in events:

        source_ip = event["source_ip"] or ""
        destination_ip = event["destination_ip"] or ""

        protocol = (event["protocol"] or "").upper()
        event_type = (event["event_type"] or "").upper()
        risk = (event["risk"] or "low").lower()

        port = event["port"]

        # ----------------------------------------------------
        # Source node
        # ----------------------------------------------------

        source_node = add_node(
            source_ip,
            node_map,
            node_features
        )

        if source_node is None:
            continue

        # ----------------------------------------------------
        # Destination node
        # ----------------------------------------------------

        destination_node = None

        if destination_ip:

            destination_node = add_node(
                destination_ip,
                node_map,
                node_features
            )

        # ----------------------------------------------------
        # Create graph edges
        # ----------------------------------------------------

        if destination_node is not None:

            # Source -> Destination
            edges.append(
                [source_node, destination_node]
            )

            # Destination -> Source
            edges.append(
                [destination_node, source_node]
            )

        # ----------------------------------------------------
        # Source node features
        # ----------------------------------------------------

        features = node_features[source_node]

        # TCP activity
        if protocol == "TCP":
            features[0] += 1.0

        # UDP activity
        elif protocol == "UDP":
            features[1] += 1.0

        # Established connection
        if event_type == "ESTABLISHED":
            features[2] += 1.0

        # Listening service
        if event_type == "LISTEN":
            features[3] += 1.0

        # ----------------------------------------------------
        # Unique ports
        # ----------------------------------------------------

        if port is not None:

            if source_node not in node_ports:
                node_ports[source_node] = set()

            try:
                node_ports[source_node].add(int(port))
            except (ValueError, TypeError):
                pass

        # ----------------------------------------------------
        # High / critical risk
        # ----------------------------------------------------

        if risk in ("high", "critical"):
            features[5] += 1.0

    # ========================================================
    # Calculate unique port feature
    # ========================================================

    for node_id, ports in node_ports.items():

        node_features[node_id][4] = float(len(ports))

    # ========================================================
    # Normalize features
    # ========================================================

    # We use log compression instead of simply dividing by
    # large fixed numbers. This reduces the effect of extremely
    # busy nodes while preserving behavioral differences.

    for features in node_features:

        tcp = features[0]
        udp = features[1]
        established = features[2]
        listen = features[3]
        unique_ports = features[4]
        high_critical = features[5]

        features[0] = min(
            math.log1p(tcp) / math.log1p(50.0),
            1.0
        )

        features[1] = min(
            math.log1p(udp) / math.log1p(50.0),
            1.0
        )

        features[2] = min(
            math.log1p(established) / math.log1p(50.0),
            1.0
        )

        features[3] = min(
            math.log1p(listen) / math.log1p(20.0),
            1.0
        )

        features[4] = min(
            math.log1p(unique_ports) / math.log1p(50.0),
            1.0
        )

        features[5] = min(
            math.log1p(high_critical) / math.log1p(20.0),
            1.0
        )

    # ========================================================
    # Create node feature tensor
    # ========================================================

    x = torch.tensor(
        node_features,
        dtype=torch.float
    )

    # ========================================================
    # Create edge tensor
    # ========================================================

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

    # ========================================================
    # Create PyTorch Geometric graph
    # ========================================================

    graph = Data(
        x=x,
        edge_index=edge_index
    )

    graph.num_nodes = len(node_map)
    graph.num_edges = edge_index.shape[1]
    graph.event_count = len(events)

    # Keep node map available for the detector
    graph.node_map = node_map

    # ========================================================
    # Node details
    # ========================================================

    graph.node_details = []

    for ip_address, node_id in node_map.items():

        graph.node_details.append(
            {
                "node_id": node_id,
                "ip_address": ip_address
            }
        )

    return graph


# ============================================================
# PRINT GRAPH INFORMATION
# ============================================================

def print_graph_information(graph):

    print()
    print("=" * 60)
    print("ZERO GUARD GRAPH")
    print("=" * 60)

    print(
        f"Network Events : "
        f"{getattr(graph, 'event_count', 0)}"
    )

    print(
        f"Graph Nodes    : "
        f"{graph.num_nodes}"
    )

    print(
        f"Graph Edges    : "
        f"{graph.num_edges}"
    )

    print(
        f"Node Features  : "
        f"{graph.x.shape}"
    )

    print(
        f"Edge Index     : "
        f"{graph.edge_index.shape}"
    )

    print("=" * 60)


# ============================================================
# PRINT NODE DETAILS
# ============================================================

def print_node_details(graph):

    print()
    print("=" * 60)
    print("ZERO GUARD NODE DETAILS")
    print("=" * 60)

    if not graph.node_details:

        print("No nodes available.")

        return

    for node in graph.node_details:

        print(
            f"Node {node['node_id']}: "
            f"{node['ip_address']}"
        )

    print("=" * 60)


# ============================================================
# MAIN TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("ZeroGuard Graph Builder")
    print("=" * 60)

    try:

        graph = build_graph(limit=500)

        print_graph_information(graph)

        print_node_details(graph)

        print()
        print("First node features:")

        if graph.x.shape[0] > 0:

            print(
                graph.x[:5]
            )

        else:

            print("No nodes available.")

        print()
        print("Graph building successful.")

    except Exception as error:

        print()
        print("=" * 60)
        print("GRAPH BUILDER ERROR")
        print("=" * 60)

        print(
            type(error).__name__,
            ":",
            error
        )

        print("=" * 60)