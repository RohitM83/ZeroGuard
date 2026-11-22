# ============================================================
# ZERO GUARD - GNN NORMAL BASELINE TRAINING
# ============================================================

from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.nn import GCNConv


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FEATURES = 6
HIDDEN_FEATURES = 32
OUTPUT_FEATURES = 16

EPOCHS = 200
LEARNING_RATE = 0.005

BASE_DIR = Path(__file__).resolve().parent

BASELINE_GRAPHS_PATH = (
    BASE_DIR / "normal_baseline_graphs.pt"
)

MODEL_PATH = (
    BASE_DIR / "trained_gnn.pth"
)


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
# LOAD BASELINE GRAPHS
# ============================================================

def load_baseline_graphs():

    if not BASELINE_GRAPHS_PATH.exists():

        raise FileNotFoundError(
            "Baseline graph file not found: "
            f"{BASELINE_GRAPHS_PATH}"
        )

    print("")
    print(
        f"Loading baseline graphs from:"
    )

    print(
        BASELINE_GRAPHS_PATH
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
            "Baseline graph file does not "
            "contain a graph list."
        )

    if not graphs:

        raise RuntimeError(
            "Baseline graph list is empty."
        )

    return graphs


# ============================================================
# TRAINING
# ============================================================

def train():

    print("")
    print("=" * 60)
    print("ZeroGuard GNN Normal Baseline Training")
    print("=" * 60)

    # --------------------------------------------------------
    # Load baseline graphs
    # --------------------------------------------------------

    graphs = load_baseline_graphs()

    print("")
    print(
        f"Baseline graphs loaded: {len(graphs)}"
    )

    # --------------------------------------------------------
    # Validate graphs
    # --------------------------------------------------------

    valid_graphs = []

    for index, graph in enumerate(
        graphs,
        start=1
    ):

        if graph.x.size(0) == 0:

            print(
                f"Skipping empty graph {index}"
            )

            continue

        if graph.x.size(1) != INPUT_FEATURES:

            raise RuntimeError(
                f"Graph {index} has "
                f"{graph.x.size(1)} features. "
                f"Expected {INPUT_FEATURES}."
            )

        valid_graphs.append(
            graph
        )

    if not valid_graphs:

        raise RuntimeError(
            "No valid baseline graphs available."
        )

    print(
        f"Valid baseline graphs: "
        f"{len(valid_graphs)}"
    )

    # --------------------------------------------------------
    # Display baseline information
    # --------------------------------------------------------

    print("")
    print("Baseline graph information:")
    print("")

    total_nodes = 0
    total_edges = 0

    for index, graph in enumerate(
        valid_graphs,
        start=1
    ):

        nodes = int(
            graph.x.size(0)
        )

        edges = int(
            graph.edge_index.size(1)
        )

        events = int(
            getattr(
                graph,
                "event_count",
                0
            )
        )

        total_nodes += nodes
        total_edges += edges

        print(
            f"Graph {index:02d} | "
            f"Events: {events:03d} | "
            f"Nodes: {nodes:02d} | "
            f"Edges: {edges:03d}"
        )

    print("")
    print(
        f"Total training nodes: {total_nodes}"
    )

    print(
        f"Total training edges: {total_edges}"
    )

    # --------------------------------------------------------
    # Feature information
    # --------------------------------------------------------

    feature_names = [
        "TCP",
        "UDP",
        "ESTABLISHED",
        "LISTEN",
        "UNIQUE_PORTS",
        "HIGH_CRITICAL_RISK"
    ]

    print("")
    print("Training features:")

    for index, name in enumerate(
        feature_names
    ):

        print(
            f"{index}: {name}"
        )

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    model = ZeroGuardGNN()

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE
    )

    loss_function = nn.MSELoss()

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    print("")
    print(
        "Starting training on normal "
        "baseline graphs..."
    )

    print("")

    model.train()

    for epoch in range(
        1,
        EPOCHS + 1
    ):

        total_loss = 0.0

        graph_count = 0

        optimizer.zero_grad()

        for graph in valid_graphs:

            reconstruction, embeddings = model(
                graph.x,
                graph.edge_index
            )

            loss = loss_function(
                reconstruction,
                graph.x
            )

            loss.backward()

            total_loss += loss.item()

            graph_count += 1

        optimizer.step()

        average_loss = (
            total_loss / graph_count
        )

        if (
            epoch == 1
            or epoch % 20 == 0
            or epoch == EPOCHS
        ):

            print(
                f"Epoch {epoch:03d} | "
                f"Average Reconstruction Loss: "
                f"{average_loss:.6f}"
            )

    # --------------------------------------------------------
    # Evaluate baseline reconstruction
    # --------------------------------------------------------

    print("")
    print(
        "Evaluating baseline reconstruction..."
    )

    model.eval()

    baseline_errors = []

    with torch.no_grad():

        for graph in valid_graphs:

            reconstruction, embeddings = model(
                graph.x,
                graph.edge_index
            )

            node_errors = (
                (
                    reconstruction
                    - graph.x
                ) ** 2
            ).mean(dim=1)

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

    baseline_mean = float(
        baseline_tensor.mean()
    )

    baseline_std = float(
        baseline_tensor.std(
            unbiased=False
        )
    )

    baseline_max = float(
        baseline_tensor.max()
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    torch.save(
        model.state_dict(),
        MODEL_PATH
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print("")
    print("=" * 60)
    print("TRAINING COMPLETED")
    print("=" * 60)

    print(
        f"Baseline graphs : "
        f"{len(valid_graphs)}"
    )

    print(
        f"Training epochs : "
        f"{EPOCHS}"
    )

    print(
        f"Final baseline mean error : "
        f"{baseline_mean:.8f}"
    )

    print(
        f"Baseline error std        : "
        f"{baseline_std:.8f}"
    )

    print(
        f"Baseline maximum error   : "
        f"{baseline_max:.8f}"
    )

    print("")
    print(
        f"Model saved to:"
    )

    print(
        MODEL_PATH
    )

    print("")
    print(
        "The GNN has now been trained "
        "using normal baseline graphs."
    )

    print(
        "Future network graphs can be "
        "compared against this learned "
        "normal behavior."
    )

    print("=" * 60)
    print("")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        train()

    except Exception as error:

        print("")
        print("=" * 60)
        print("TRAINING ERROR")
        print("=" * 60)

        print(
            f"{type(error).__name__}: "
            f"{error}"
        )

        print("=" * 60)
        print("")