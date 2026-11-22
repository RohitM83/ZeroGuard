import os
import time
import numpy as np
from sklearn.neighbors import NearestNeighbors

# ============================================================
# ZERO GUARD - STEP 15.4
# PUBLICATION K-NN GRAPH CONSTRUCTION
# ============================================================
#
# Graph meaning:
# Each node represents one CIC-IDS2017 network flow.
# Edges connect flows with similar feature vectors.
#
# IMPORTANT:
# This is a FEATURE-SIMILARITY GRAPH, not the original
# source-destination communication graph.
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

INPUT_DIR = os.path.join(
    BASE_DIR,
    "processed",
    "evaluation",
    "gnn_ready_publication"
)

OUTPUT_DIR = os.path.join(
    INPUT_DIR,
    "graphs"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

TRAIN_FILE = os.path.join(
    INPUT_DIR,
    "train_gnn.npz"
)

TEST_FILE = os.path.join(
    INPUT_DIR,
    "test_gnn.npz"
)

TRAIN_GRAPH_FILE = os.path.join(
    OUTPUT_DIR,
    "train_graph.npz"
)

TEST_GRAPH_FILE = os.path.join(
    OUTPUT_DIR,
    "test_graph.npz"
)

# Number of nearest neighbours
K = 5

# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.4")
print("PUBLICATION K-NN GRAPH CONSTRUCTION")
print("=" * 70)

print(f"\nK = {K}")

print(
    "\nGraph type:"
)

print(
    "Feature-similarity k-NN graph"
)

print(
    "Node = network flow"
)

print(
    "Edge = similarity between flow feature vectors"
)

# ============================================================
# CHECK INPUT FILES
# ============================================================

if not os.path.exists(TRAIN_FILE):

    raise FileNotFoundError(
        f"Training GNN file not found:\n{TRAIN_FILE}"
    )

if not os.path.exists(TEST_FILE):

    raise FileNotFoundError(
        f"Test GNN file not found:\n{TEST_FILE}"
    )

# ============================================================
# GRAPH BUILDING FUNCTION
# ============================================================

def build_graph(
    input_file,
    output_file,
    graph_name
):

    print("\n" + "=" * 70)
    print(
        f"BUILDING {graph_name.upper()} GRAPH"
    )
    print("=" * 70)

    start_time = time.time()

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    print(
        "\nLoading:"
    )

    print(
        input_file
    )

    data = np.load(
        input_file,
        allow_pickle=True
    )

    X = data["X"].astype(
        np.float32
    )

    y = data["y"].astype(
        np.int64
    )

    print(
        f"Nodes: {X.shape[0]:,}"
    )

    print(
        f"Features per node: {X.shape[1]}"
    )

    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if X.ndim != 2:

        raise ValueError(
            f"{graph_name} feature matrix "
            "must be 2-dimensional."
        )

    if len(X) != len(y):

        raise ValueError(
            f"{graph_name} X/y row count mismatch."
        )

    if np.isnan(X).any():

        raise ValueError(
            f"{graph_name} graph contains NaN values."
        )

    if np.isinf(X).any():

        raise ValueError(
            f"{graph_name} graph contains "
            "infinite values."
        )

    if X.shape[0] <= K:

        raise ValueError(
            f"{graph_name} graph has too few nodes "
            f"for K={K}."
        )

    # --------------------------------------------------------
    # CLASS DISTRIBUTION
    # --------------------------------------------------------

    print(
        "\nNode labels:"
    )

    print(
        f"  BENIGN: "
        f"{np.sum(y == 0):,}"
    )

    print(
        f"  ATTACK: "
        f"{np.sum(y == 1):,}"
    )

    # --------------------------------------------------------
    # K-NN MODEL
    # --------------------------------------------------------
    #
    # K + 1 because the closest returned neighbour
    # is the node itself.
    # --------------------------------------------------------

    print(
        "\nCreating k-NN model..."
    )

    model = NearestNeighbors(
        n_neighbors=K + 1,
        algorithm="auto",
        metric="euclidean",
        n_jobs=-1
    )

    model.fit(X)

    # --------------------------------------------------------
    # FIND NEIGHBOURS
    # --------------------------------------------------------

    print(
        "Finding nearest neighbours..."
    )

    print(
        "This may take some time for the "
        "publication dataset."
    )

    distances, neighbours = model.kneighbors(
        X
    )

    print(
        "Nearest-neighbour search complete."
    )

    # --------------------------------------------------------
    # REMOVE SELF NEIGHBOUR
    # --------------------------------------------------------

    neighbours = neighbours[:, 1:]

    distances = distances[:, 1:]

    num_nodes = X.shape[0]

    # --------------------------------------------------------
    # CREATE DIRECTED EDGES
    # --------------------------------------------------------

    source_nodes = np.repeat(
        np.arange(
            num_nodes,
            dtype=np.int64
        ),
        K
    )

    target_nodes = (
        neighbours
        .reshape(-1)
        .astype(np.int64)
    )

    edge_distances = (
        distances
        .reshape(-1)
        .astype(np.float32)
    )

    # --------------------------------------------------------
    # ADD REVERSE EDGES
    # --------------------------------------------------------

    reverse_sources = target_nodes

    reverse_targets = source_nodes

    reverse_distances = edge_distances

    all_sources = np.concatenate([
        source_nodes,
        reverse_sources
    ])

    all_targets = np.concatenate([
        target_nodes,
        reverse_targets
    ])

    all_distances = np.concatenate([
        edge_distances,
        reverse_distances
    ])

    # --------------------------------------------------------
    # REMOVE SELF LOOPS
    # --------------------------------------------------------

    valid = (
        all_sources != all_targets
    )

    all_sources = (
        all_sources[valid]
    )

    all_targets = (
        all_targets[valid]
    )

    all_distances = (
        all_distances[valid]
    )

    # --------------------------------------------------------
    # REMOVE EXACT DUPLICATE EDGES
    # --------------------------------------------------------

    print(
        "\nRemoving duplicate edges..."
    )

    edges = np.column_stack([
        all_sources,
        all_targets
    ])

    unique_edges, unique_indices = (
        np.unique(
            edges,
            axis=0,
            return_index=True
        )
    )

    all_sources = (
        unique_edges[:, 0]
        .astype(np.int64)
    )

    all_targets = (
        unique_edges[:, 1]
        .astype(np.int64)
    )

    all_distances = (
        all_distances[
            unique_indices
        ]
        .astype(np.float32)
    )

    # --------------------------------------------------------
    # EDGE INDEX
    # --------------------------------------------------------

    edge_index = np.vstack([
        all_sources,
        all_targets
    ])

    # --------------------------------------------------------
    # EDGE WEIGHTS
    #
    # Similarity = 1 / (1 + distance)
    # --------------------------------------------------------

    edge_weight = (
        1.0 /
        (1.0 + all_distances)
    ).astype(
        np.float32
    )

    # --------------------------------------------------------
    # SAVE GRAPH
    # --------------------------------------------------------

    print(
        "\nSaving graph..."
    )

    np.savez_compressed(
        output_file,
        edge_index=edge_index,
        edge_weight=edge_weight,
        y=y
    )

    # --------------------------------------------------------
    # GRAPH STATISTICS
    # --------------------------------------------------------

    num_edges = (
        edge_index.shape[1]
    )

    average_degree = (
        num_edges /
        num_nodes
    )

    self_loops = np.sum(
        edge_index[0] ==
        edge_index[1]
    )

    elapsed = (
        time.time() -
        start_time
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print(
        "\n" + "-" * 70
    )

    print(
        f"{graph_name.upper()} GRAPH CREATED"
    )

    print(
        "-" * 70
    )

    print(
        f"Nodes:                 "
        f"{num_nodes:,}"
    )

    print(
        f"Features per node:     "
        f"{X.shape[1]}"
    )

    print(
        f"Edges:                 "
        f"{num_edges:,}"
    )

    print(
        f"Average degree:        "
        f"{average_degree:.2f}"
    )

    print(
        f"Edge weights:          "
        f"{len(edge_weight):,}"
    )

    print(
        f"Self-loops:            "
        f"{self_loops:,}"
    )

    print(
        f"BENIGN nodes:          "
        f"{np.sum(y == 0):,}"
    )

    print(
        f"ATTACK nodes:          "
        f"{np.sum(y == 1):,}"
    )

    print(
        f"Time taken:            "
        f"{elapsed:.2f} seconds"
    )

    print(
        f"Saved to:\n{output_file}"
    )

    return {
        "nodes": num_nodes,
        "features": X.shape[1],
        "edges": num_edges,
        "average_degree": average_degree,
        "self_loops": int(self_loops)
    }


# ============================================================
# BUILD TRAINING GRAPH
# ============================================================

train_stats = build_graph(
    TRAIN_FILE,
    TRAIN_GRAPH_FILE,
    "Training"
)

# ============================================================
# BUILD TEST GRAPH
# ============================================================

test_stats = build_graph(
    TEST_FILE,
    TEST_GRAPH_FILE,
    "Test"
)

# ============================================================
# FINAL VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("STEP 15.4 FINAL VALIDATION")
print("=" * 70)

print(
    "\nTraining graph:"
)

print(
    f"  Nodes: "
    f"{train_stats['nodes']:,}"
)

print(
    f"  Features: "
    f"{train_stats['features']}"
)

print(
    f"  Edges: "
    f"{train_stats['edges']:,}"
)

print(
    f"  Average degree: "
    f"{train_stats['average_degree']:.2f}"
)

print(
    "\nTest graph:"
)

print(
    f"  Nodes: "
    f"{test_stats['nodes']:,}"
)

print(
    f"  Features: "
    f"{test_stats['features']}"
)

print(
    f"  Edges: "
    f"{test_stats['edges']:,}"
)

print(
    f"  Average degree: "
    f"{test_stats['average_degree']:.2f}"
)

# ============================================================
# GRAPH SEPARATION
# ============================================================

print(
    "\nGraph separation:"
)

print(
    "  Training and test graphs "
    "constructed independently."
)

print(
    "  No train-test graph edges created."
)

# ============================================================
# ZERO-DAY DESIGN
# ============================================================

print(
    "\nZero-day design:"
)

print(
    "  DDoS and PortScan are "
    "test-only attack families."
)

print(
    "  DDoS training rows: 0"
)

print(
    "  PortScan training rows: 0"
)

# ============================================================
# METHODOLOGY NOTE
# ============================================================

print(
    "\nMethodology note:"
)

print(
    "  Nodes represent CIC-IDS2017 flows."
)

print(
    "  Edges represent feature similarity."
)

print(
    "  This is not the original "
    "communication topology."
)

print("\n" + "=" * 70)
print("STEP 15.4 COMPLETE")
print("=" * 70)

print("\nCreated:")

print(
    TRAIN_GRAPH_FILE
)

print(
    TEST_GRAPH_FILE
)

print(
    "\nReady for publication GNN training."
)