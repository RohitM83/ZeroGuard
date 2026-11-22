# ============================================================
# ZERO GUARD - GNN BASELINE-AWARE ANOMALY DETECTION ENGINE
# ============================================================

from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.nn import GCNConv

from graph_builder import build_graph


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FEATURES = 6
HIDDEN_FEATURES = 32
OUTPUT_FEATURES = 16

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR / "trained_gnn.pth"
)

BASELINE_GRAPHS_PATH = (
    BASE_DIR / "normal_baseline_graphs.pt"
)

# ------------------------------------------------------------
# Detection configuration
# ------------------------------------------------------------

SUSPICIOUS_THRESHOLD = 0.80

# Minimum number of standard deviations above
# the normal baseline before a node is considered
# strongly anomalous.
BASELINE_Z_THRESHOLD = 2.0


# ============================================================
# GNN MODEL
# ============================================================

class ZeroGuardGNN(nn.Module):

    def __init__(
        self,
        input_features=INPUT_FEATURES,
        hidden_features=HIDDEN_FEATURES,
        output_features=OUTPUT_FEATURES
    ):

        super().__init__()

        self.conv1 = GCNConv(
            input_features,
            hidden_features
        )

        self.conv2 = GCNConv(
            hidden_features,
            output_features
        )

        self.decoder = nn.Linear(
            output_features,
            input_features
        )

    # ========================================================
    # FORWARD
    # ========================================================

    def forward(
        self,
        x,
        edge_index
    ):

        embedding = self.conv1(
            x,
            edge_index
        )

        embedding = F.relu(
            embedding
        )

        embedding = self.conv2(
            embedding,
            edge_index
        )

        embedding = F.relu(
            embedding
        )

        reconstruction = self.decoder(
            embedding
        )

        return reconstruction, embedding


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

def load_trained_model():

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}"
        )

    model = ZeroGuardGNN()

    checkpoint = torch.load(
        MODEL_PATH,
        map_location="cpu",
        weights_only=False
    )

    if isinstance(
        checkpoint,
        dict
    ):

        if "model_state_dict" in checkpoint:

            checkpoint = checkpoint[
                "model_state_dict"
            ]

    model.load_state_dict(
        checkpoint
    )

    model.eval()

    print(
        "Trained GNN loaded successfully."
    )

    return model


# ============================================================
# LOAD NORMAL BASELINE
# ============================================================

def load_baseline_graphs():

    if not BASELINE_GRAPHS_PATH.exists():

        raise FileNotFoundError(
            "Normal baseline graphs not found: "
            f"{BASELINE_GRAPHS_PATH}"
        )

    graphs = torch.load(
        BASELINE_GRAPHS_PATH,
        map_location="cpu",
        weights_only=False
    )

    if not isinstance(
        graphs,
        list
    ):

        raise RuntimeError(
            "Normal baseline file does not "
            "contain a graph list."
        )

    if not graphs:

        raise RuntimeError(
            "Normal baseline graph list is empty."
        )

    return graphs


# ============================================================
# CALCULATE BASELINE ERROR DISTRIBUTION
# ============================================================

def calculate_baseline_statistics(
    model,
    baseline_graphs
):

    baseline_errors = []

    model.eval()

    with torch.no_grad():

        for graph in baseline_graphs:

            if graph.x.size(0) == 0:

                continue

            reconstruction, embeddings = model(
                graph.x,
                graph.edge_index
            )

            errors = (
                reconstruction - graph.x
            ) ** 2

            node_errors = errors.mean(
                dim=1
            )

            baseline_errors.extend(
                node_errors.tolist()
            )

    if not baseline_errors:

        raise RuntimeError(
            "Could not calculate baseline "
            "reconstruction errors."
        )

    baseline_tensor = torch.tensor(
        baseline_errors,
        dtype=torch.float
    )

    baseline_mean = baseline_tensor.mean()

    baseline_std = baseline_tensor.std(
        unbiased=False
    )

    baseline_max = baseline_tensor.max()

    # --------------------------------------------------------
    # Prevent division by zero
    # --------------------------------------------------------

    if float(baseline_std) < 1e-8:

        baseline_std = torch.tensor(
            1e-8,
            dtype=baseline_tensor.dtype
        )

    return (
        baseline_mean,
        baseline_std,
        baseline_max,
        baseline_tensor
    )


# ============================================================
# CALCULATE BASELINE-AWARE ANOMALY SCORES
# ============================================================

def calculate_anomaly_scores(
    reconstruction,
    original,
    baseline_mean,
    baseline_std
):

    # --------------------------------------------------------
    # Reconstruction error for each feature
    # of every node.
    # --------------------------------------------------------

    errors = (
        reconstruction - original
    ) ** 2

    # --------------------------------------------------------
    # Mean reconstruction error per node.
    # --------------------------------------------------------

    node_errors = errors.mean(
        dim=1
    )

    # --------------------------------------------------------
    # Compare each CURRENT node against the
    # NORMAL baseline distribution.
    # --------------------------------------------------------

    z_scores = (
        node_errors - baseline_mean
    ) / baseline_std

    # --------------------------------------------------------
    # Convert baseline z-score to 0-1 anomaly
    # strength.
    #
    # z <= 0:
    #     normal / better than baseline
    #
    # z around 2:
    #     beginning of strong anomaly
    #
    # z >= 4:
    #     very strong anomaly
    # --------------------------------------------------------

    anomaly_scores = torch.sigmoid(
        z_scores - BASELINE_Z_THRESHOLD
    )

    return (
        anomaly_scores,
        node_errors,
        z_scores
    )


# ============================================================
# ANALYZE CURRENT DATABASE
# ============================================================

def analyze_database():

    print("")
    print("=" * 60)
    print("ZeroGuard GNN Baseline-Aware Analysis")
    print("=" * 60)

    # ========================================================
    # LOAD MODEL
    # ========================================================

    print("")
    print(
        "Loading trained GNN..."
    )

    model = load_trained_model()

    # ========================================================
    # LOAD BASELINE
    # ========================================================

    print("")
    print(
        "Loading normal baseline graphs..."
    )

    baseline_graphs = load_baseline_graphs()

    print(
        f"Baseline graphs : "
        f"{len(baseline_graphs)}"
    )

    # ========================================================
    # CALCULATE BASELINE STATISTICS
    # ========================================================

    print("")
    print(
        "Calculating normal reconstruction "
        "distribution..."
    )

    (
        baseline_mean,
        baseline_std,
        baseline_max,
        baseline_errors
    ) = calculate_baseline_statistics(
        model,
        baseline_graphs
    )

    print("")
    print(
        "Normal baseline statistics:"
    )

    print(
        f"Mean error : "
        f"{float(baseline_mean):.8f}"
    )

    print(
        f"Std error  : "
        f"{float(baseline_std):.8f}"
    )

    print(
        f"Max error  : "
        f"{float(baseline_max):.8f}"
    )

    # ========================================================
    # BUILD CURRENT GRAPH
    # ========================================================

    print("")
    print(
        "Building graph from network database..."
    )

    graph = build_graph(
        limit=500
    )

    if graph is None:

        raise ValueError(
            "Graph builder returned None."
        )

    total_nodes = int(
        graph.x.size(0)
    )

    total_edges = int(
        graph.edge_index.size(1)
    )

    print("")
    print(
        f"Graph Nodes    : {total_nodes}"
    )

    print(
        f"Graph Edges    : {total_edges}"
    )

    print(
        f"Node Features  : {graph.x.shape}"
    )

    # ========================================================
    # EMPTY GRAPH
    # ========================================================

    if total_nodes == 0:

        return {

            "anomaly_score": 0.0,

            "maximum_anomaly_score": 0.0,

            "suspicious_nodes": 0,

            "total_nodes": 0,

            "total_edges": total_edges,

            "severity": "low",

            "node_scores": [],

            "node_details": [],

            "embeddings_shape": [
                0,
                OUTPUT_FEATURES
            ],

            "baseline_mean_error":
                round(
                    float(baseline_mean),
                    8
                ),

            "baseline_std_error":
                round(
                    float(baseline_std),
                    8
                ),

            "baseline_max_error":
                round(
                    float(baseline_max),
                    8
                )

        }

    # ========================================================
    # RUN CURRENT GRAPH THROUGH GNN
    # ========================================================

    print("")
    print(
        "Running GNN reconstruction analysis..."
    )

    with torch.no_grad():

        reconstruction, embeddings = model(
            graph.x,
            graph.edge_index
        )

    # ========================================================
    # CALCULATE BASELINE-AWARE ANOMALY
    # ========================================================

    (
        anomaly_scores,
        node_errors,
        z_scores
    ) = calculate_anomaly_scores(
        reconstruction,
        graph.x,
        baseline_mean,
        baseline_std
    )

    # ========================================================
    # OVERALL SCORES
    # ========================================================

    average_score = (
        anomaly_scores.mean().item()
        * 100
    )

    maximum_score = (
        anomaly_scores.max().item()
        * 100
    )

    # ========================================================
    # SUSPICIOUS NODES
    # ========================================================

    suspicious_mask = (
        anomaly_scores
        >= SUSPICIOUS_THRESHOLD
    )

    suspicious_nodes = int(
        suspicious_mask.sum().item()
    )

    # ========================================================
    # SEVERITY
    # ========================================================

    if maximum_score >= 90:

        severity = "high"

    elif maximum_score >= 80:

        severity = "medium"

    elif maximum_score >= 50:

        severity = "low"

    else:

        severity = "low"

    # ========================================================
    # NODE SCORES
    # ========================================================

    node_scores = [

        round(
            float(score) * 100,
            2
        )

        for score in anomaly_scores

    ]

    # ========================================================
    # NODE IP MAP
    # ========================================================

    node_ip_map = {

        node_id: ip_address

        for ip_address, node_id
        in graph.node_map.items()

    }

    # ========================================================
    # NODE DETAILS
    # ========================================================

    node_details = []

    for index, score in enumerate(
        anomaly_scores
    ):

        ip_address = node_ip_map.get(
            index
        )

        node_details.append({

            "node_id":
                index,

            "ip_address":
                ip_address,

            "score":
                round(
                    float(score) * 100,
                    2
                ),

            "reconstruction_error":
                round(
                    float(node_errors[index]),
                    6
                ),

            "baseline_z_score":
                round(
                    float(z_scores[index]),
                    3
                ),

            "suspicious":
                bool(
                    score.item()
                    >= SUSPICIOUS_THRESHOLD
                )

        })

    # ========================================================
    # EMBEDDINGS
    # ========================================================

    embeddings_shape = list(
        embeddings.shape
    )

    # ========================================================
    # RESULT
    # ========================================================

    result = {

        "anomaly_score":
            round(
                average_score,
                2
            ),

        "maximum_anomaly_score":
            round(
                maximum_score,
                2
            ),

        "suspicious_nodes":
            suspicious_nodes,

        "total_nodes":
            total_nodes,

        "total_edges":
            total_edges,

        "severity":
            severity,

        "node_scores":
            node_scores,

        "node_details":
            node_details,

        "embeddings_shape":
            embeddings_shape,

        # ----------------------------------------------------
        # Baseline information
        # ----------------------------------------------------

        "baseline_mean_error":
            round(
                float(baseline_mean),
                8
            ),

        "baseline_std_error":
            round(
                float(baseline_std),
                8
            ),

        "baseline_max_error":
            round(
                float(baseline_max),
                8
            ),

        "baseline_graphs":
            len(baseline_graphs),

        "detection_method":
            "baseline_relative_gnn_reconstruction"

    }

    # ========================================================
    # PRINT RESULT
    # ========================================================

    print("")
    print("=" * 60)
    print("GNN BASELINE-AWARE ANOMALY RESULT")
    print("=" * 60)

    print(
        "Average Anomaly Score :",
        result["anomaly_score"],
        "%"
    )

    print(
        "Maximum Anomaly Score :",
        result["maximum_anomaly_score"],
        "%"
    )

    print(
        "Suspicious Nodes      :",
        result["suspicious_nodes"]
    )

    print(
        "Total Nodes           :",
        result["total_nodes"]
    )

    print(
        "Total Edges           :",
        result["total_edges"]
    )

    print(
        "Severity              :",
        result["severity"]
    )

    print(
        "Detection Threshold   :",
        int(SUSPICIOUS_THRESHOLD * 100),
        "%"
    )

    print(
        "Baseline Z Threshold  :",
        BASELINE_Z_THRESHOLD
    )

    print(
        "Baseline Mean Error   :",
        result["baseline_mean_error"]
    )

    print(
        "Baseline Std Error    :",
        result["baseline_std_error"]
    )

    print(
        "Baseline Max Error    :",
        result["baseline_max_error"]
    )

    print(
        "Baseline Graphs       :",
        result["baseline_graphs"]
    )

    print(
        "Embeddings Shape      :",
        result["embeddings_shape"]
    )

    print("=" * 60)

    # ========================================================
    # NODE DETAILS
    # ========================================================

    print("")
    print("=" * 60)
    print("NODE ANOMALY DETAILS")
    print("=" * 60)

    sorted_nodes = sorted(
        node_details,
        key=lambda node: node["score"],
        reverse=True
    )

    for node in sorted_nodes:

        print(
            f"Node {node['node_id']} | "
            f"IP: {node['ip_address']} | "
            f"Score: {node['score']}% | "
            f"Error: {node['reconstruction_error']} | "
            f"Baseline Z: {node['baseline_z_score']} | "
            f"Suspicious: {node['suspicious']}"
        )

    print("=" * 60)

    return result


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        result = analyze_database()

        print("")
        print(
            "GNN baseline-aware analysis "
            "completed successfully."
        )
        print("")

    except Exception as error:

        print("")
        print("=" * 60)
        print("GNN ERROR")
        print("=" * 60)

        print(
            type(error).__name__
            + ": "
            + str(error)
        )

        print("=" * 60)
        print("")