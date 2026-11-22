import os
import time
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.data import Data
from torch_geometric.nn import GCNConv

# ============================================================
# ZERO GUARD - STEP 15.5
# PUBLICATION GNN TRAINING
# ============================================================
#
# Dataset:
# CIC-IDS2017
#
# Task:
# Binary classification
# BENIGN = 0
# ATTACK = 1
#
# Zero-day-style evaluation:
# DDoS and PortScan are completely excluded from training.
#
# Graph:
# Feature-similarity k-NN graph
#
# Important:
# This graph is NOT the original communication topology.
# Each node represents a network flow.
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "processed",
    "evaluation",
    "gnn_ready_publication"
)

GRAPH_DIR = os.path.join(
    DATA_DIR,
    "graphs"
)

TRAIN_DATA = os.path.join(
    DATA_DIR,
    "train_gnn.npz"
)

TRAIN_GRAPH = os.path.join(
    GRAPH_DIR,
    "train_graph.npz"
)

MODEL_DIR = os.path.join(
    DATA_DIR,
    "models"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "zeroguard_gcn_publication.pt"
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

# ============================================================
# CONFIGURATION
# ============================================================

HIDDEN_CHANNELS = 32

DROPOUT = 0.30

LEARNING_RATE = 0.001

WEIGHT_DECAY = 0.0001

EPOCHS = 20

# CPU is intentionally used because the current
# PyTorch installation is CPU-only.

DEVICE = torch.device(
    "cpu"
)

# ============================================================
# REPRODUCIBILITY
# ============================================================

torch.manual_seed(42)

np.random.seed(42)

# ============================================================
# HEADER
# ============================================================

print("=" * 70)

print(
    "ZERO GUARD - STEP 15.5"
)

print(
    "PUBLICATION GNN TRAINING"
)

print("=" * 70)

print(
    "\nDevice:",
    DEVICE
)

print(
    "PyTorch:",
    torch.__version__
)

# ============================================================
# DATASET INFORMATION
# ============================================================

print(
    "\nDataset: CIC-IDS2017"
)

print(
    "Task: Binary network-flow classification"
)

print(
    "BENIGN = 0"
)

print(
    "ATTACK = 1"
)

print(
    "Unseen attack families: DDoS, PortScan"
)

# ============================================================
# CHECK FILES
# ============================================================

if not os.path.exists(
    TRAIN_DATA
):

    raise FileNotFoundError(
        f"Training data not found:\n{TRAIN_DATA}"
    )

if not os.path.exists(
    TRAIN_GRAPH
):

    raise FileNotFoundError(
        f"Training graph not found:\n{TRAIN_GRAPH}"
    )

# ============================================================
# LOAD FEATURES
# ============================================================

print(
    "\nLoading publication training features..."
)

train_data = np.load(
    TRAIN_DATA,
    allow_pickle=True
)

X_train = train_data[
    "X"
].astype(
    np.float32
)

y_train = train_data[
    "y"
].astype(
    np.int64
)

print(
    f"Training feature matrix: "
    f"{X_train.shape}"
)

print(
    f"Training labels: "
    f"{y_train.shape}"
)

# ============================================================
# LOAD GRAPH
# ============================================================

print(
    "\nLoading publication training graph..."
)

graph_data = np.load(
    TRAIN_GRAPH,
    allow_pickle=True
)

edge_index = graph_data[
    "edge_index"
].astype(
    np.int64
)

edge_weight = graph_data[
    "edge_weight"
].astype(
    np.float32
)

print(
    f"Edge index: "
    f"{edge_index.shape}"
)

print(
    f"Edge weights: "
    f"{edge_weight.shape}"
)

# ============================================================
# VALIDATION
# ============================================================

print(
    "\nValidating training data..."
)

if X_train.shape[0] != y_train.shape[0]:

    raise ValueError(
        "Number of feature rows does not "
        "match number of labels."
    )

if edge_index.ndim != 2:

    raise ValueError(
        "edge_index must be a 2D array."
    )

if edge_index.shape[0] != 2:

    raise ValueError(
        "edge_index must have shape [2, number_of_edges]."
    )

if edge_index.shape[1] != len(edge_weight):

    raise ValueError(
        "Number of edges does not match "
        "number of edge weights."
    )

if edge_index.size == 0:

    raise ValueError(
        "Training graph contains no edges."
    )

if edge_index.max() >= X_train.shape[0]:

    raise ValueError(
        "Graph contains node indices outside "
        "the feature matrix."
    )

if edge_index.min() < 0:

    raise ValueError(
        "Graph contains negative node indices."
    )

if np.isnan(X_train).any():

    raise ValueError(
        "Training features contain NaN."
    )

if np.isinf(X_train).any():

    raise ValueError(
        "Training features contain infinity."
    )

if np.isnan(edge_weight).any():

    raise ValueError(
        "Edge weights contain NaN."
    )

if np.isinf(edge_weight).any():

    raise ValueError(
        "Edge weights contain infinity."
    )

print(
    "Training data validation: PASS"
)

# ============================================================
# CONVERT TO PYTORCH
# ============================================================

print(
    "\nConverting data to PyTorch..."
)

x = torch.from_numpy(
    X_train
)

y = torch.from_numpy(
    y_train
)

edges = torch.from_numpy(
    edge_index
)

weights = torch.from_numpy(
    edge_weight
)

# ============================================================
# CREATE PYTORCH GEOMETRIC DATA
# ============================================================

data = Data(
    x=x,
    edge_index=edges,
    edge_weight=weights,
    y=y
)

data = data.to(
    DEVICE
)

print(
    "\nGraph summary:"
)

print(
    "  Nodes:    ",
    data.num_nodes
)

print(
    "  Edges:    ",
    data.num_edges
)

print(
    "  Features: ",
    data.num_node_features
)

print(
    "  Classes:  ",
    int(
        data.y.max().item()
    ) + 1
)

# ============================================================
# CLASS DISTRIBUTION
# ============================================================

benign_count = int(
    (y == 0).sum().item()
)

attack_count = int(
    (y == 1).sum().item()
)

print(
    "\nClass distribution:"
)

print(
    f"  BENIGN: "
    f"{benign_count:,}"
)

print(
    f"  ATTACK: "
    f"{attack_count:,}"
)

# ============================================================
# SAFETY CHECK
# ============================================================

if benign_count == 0:

    raise ValueError(
        "No BENIGN samples found."
    )

if attack_count == 0:

    raise ValueError(
        "No ATTACK samples found."
    )

# ============================================================
# MODEL
# ============================================================

class ZeroGuardGCN(
    nn.Module
):

    def __init__(
        self,
        input_channels,
        hidden_channels,
        num_classes,
        dropout=0.30
    ):

        super().__init__()

        self.conv1 = GCNConv(
            input_channels,
            hidden_channels
        )

        self.conv2 = GCNConv(
            hidden_channels,
            hidden_channels
        )

        self.classifier = nn.Linear(
            hidden_channels,
            num_classes
        )

        self.dropout = dropout

    def forward(
        self,
        x,
        edge_index,
        edge_weight=None
    ):

        x = self.conv1(
            x,
            edge_index,
            edge_weight
        )

        x = F.relu(
            x
        )

        x = F.dropout(
            x,
            p=self.dropout,
            training=self.training
        )

        x = self.conv2(
            x,
            edge_index,
            edge_weight
        )

        x = F.relu(
            x
        )

        x = F.dropout(
            x,
            p=self.dropout,
            training=self.training
        )

        x = self.classifier(
            x
        )

        return x


model = ZeroGuardGCN(
    input_channels=data.num_node_features,
    hidden_channels=HIDDEN_CHANNELS,
    num_classes=2,
    dropout=DROPOUT
).to(
    DEVICE
)

# ============================================================
# CLASS-WEIGHTED LOSS
# ============================================================
#
# Publication training dataset:
#
# BENIGN = 100,000
# ATTACK = 49,323
#
# Class weighting compensates for the unequal class counts.
# ============================================================

attack_weight = (
    benign_count /
    attack_count
)

class_weights = torch.tensor(
    [
        1.0,
        attack_weight
    ],
    dtype=torch.float32,
    device=DEVICE
)

criterion = nn.CrossEntropyLoss(
    weight=class_weights
)

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE,
    weight_decay=WEIGHT_DECAY
)

# ============================================================
# MODEL INFORMATION
# ============================================================

parameter_count = sum(
    p.numel()
    for p in model.parameters()
    if p.requires_grad
)

print(
    "\n" + "=" * 70
)

print(
    "MODEL CONFIGURATION"
)

print(
    "=" * 70
)

print(
    f"Input features:       "
    f"{data.num_node_features}"
)

print(
    f"Hidden channels:      "
    f"{HIDDEN_CHANNELS}"
)

print(
    "Output classes:       2"
)

print(
    f"Dropout:              "
    f"{DROPOUT}"
)

print(
    f"Learning rate:        "
    f"{LEARNING_RATE}"
)

print(
    f"Weight decay:         "
    f"{WEIGHT_DECAY}"
)

print(
    f"Epochs:               "
    f"{EPOCHS}"
)

print(
    f"Trainable parameters: "
    f"{parameter_count:,}"
)

print(
    "Class weights:        ",
    class_weights.cpu().numpy()
)

# ============================================================
# TRAINING
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "STARTING PUBLICATION GNN TRAINING"
)

print(
    "=" * 70
)

print(
    "\nThe model is trained only on the "
    "publication training graph."
)

print(
    "DDoS and PortScan are NOT present "
    "in training."
)

print(
    "The test graph is NOT used during training."
)

training_start = time.time()

best_loss = float(
    "inf"
)

best_epoch = 0

# ============================================================
# EPOCH LOOP
# ============================================================

for epoch in range(
    1,
    EPOCHS + 1
):

    epoch_start = time.time()

    # --------------------------------------------------------
    # TRAIN MODE
    # --------------------------------------------------------

    model.train()

    optimizer.zero_grad()

    output = model(
        data.x,
        data.edge_index,
        data.edge_weight
    )

    loss = criterion(
        output,
        data.y
    )

    loss.backward()

    optimizer.step()

    # --------------------------------------------------------
    # TRAINING PREDICTIONS
    # --------------------------------------------------------

    model.eval()

    with torch.no_grad():

        predictions = output.argmax(
            dim=1
        )

        correct = (
            predictions ==
            data.y
        ).sum().item()

        train_accuracy = (
            correct /
            data.y.size(0)
        ) * 100

    epoch_time = (
        time.time() -
        epoch_start
    )

    print(
        f"Epoch {epoch:02d}/{EPOCHS} | "
        f"Loss: {loss.item():.6f} | "
        f"Train Accuracy: "
        f"{train_accuracy:.2f}% | "
        f"Time: {epoch_time:.2f}s"
    )

    # --------------------------------------------------------
    # SAVE BEST MODEL
    # --------------------------------------------------------

    if loss.item() < best_loss:

        best_loss = loss.item()

        best_epoch = epoch

        torch.save(
            {
                "model_state_dict":
                    model.state_dict(),

                "input_channels":
                    data.num_node_features,

                "hidden_channels":
                    HIDDEN_CHANNELS,

                "num_classes":
                    2,

                "dropout":
                    DROPOUT,

                "learning_rate":
                    LEARNING_RATE,

                "weight_decay":
                    WEIGHT_DECAY,

                "epoch":
                    epoch,

                "loss":
                    loss.item(),

                "dataset":
                    "CIC-IDS2017",

                "task":
                    "binary_classification",

                "graph_type":
                    "feature_similarity_knn",

                "k":
                    5,

                "random_seed":
                    42
            },
            MODEL_FILE
        )

# ============================================================
# TRAINING TIME
# ============================================================

total_training_time = (
    time.time() -
    training_start
)

# ============================================================
# FINAL SUMMARY
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "PUBLICATION GNN TRAINING COMPLETE"
)

print(
    "=" * 70
)

print(
    f"\nBest epoch:          "
    f"{best_epoch}"
)

print(
    f"Best loss:           "
    f"{best_loss:.6f}"
)

print(
    f"Total training time: "
    f"{total_training_time:.2f} seconds"
)

print(
    f"\nModel saved to:\n"
    f"{MODEL_FILE}"
)

print(
    "\nTraining dataset:"
)

print(
    f"  BENIGN: "
    f"{benign_count:,}"
)

print(
    f"  ATTACK: "
    f"{attack_count:,}"
)

print(
    "\nZero-day design:"
)

print(
    "  DDoS:     unseen during training"
)

print(
    "  PortScan: unseen during training"
)

print(
    "\nIMPORTANT:"
)

print(
    "Training accuracy is NOT the final "
    "paper performance result."
)

print(
    "Final metrics will be calculated on "
    "the independent test dataset."
)

print(
    "The final evaluation will report:"
)

print(
    "  Accuracy"
)

print(
    "  Precision"
)

print(
    "  Recall"
)

print(
    "  F1-score"
)

print(
    "  Specificity"
)

print(
    "  Confusion matrix"
)

print(
    "  DDoS detection rate"
)

print(
    "  PortScan detection rate"
)

print(
    "\n" + "=" * 70
)

print(
    "STEP 15.5 COMPLETE"
)

print(
    "=" * 70
)