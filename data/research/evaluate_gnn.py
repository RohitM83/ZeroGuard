import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv


# ============================================================
# ZERO GUARD - STEP 15.6
# PUBLICATION GNN EVALUATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

EVAL_DIR = os.path.join(
    BASE_DIR,
    "data",
    "research",
    "processed",
    "evaluation",
    "gnn_ready_publication"
)

TRAIN_FEATURES = os.path.join(EVAL_DIR, "train_gnn.npz")
TEST_FEATURES = os.path.join(EVAL_DIR, "test_gnn.npz")

TEST_CSV = os.path.join(
    BASE_DIR,
    "data",
    "research",
    "processed",
    "evaluation",
    "test_zero_day.csv"
)

MODEL_PATH = os.path.join(
    EVAL_DIR,
    "models",
    "zeroguard_gcn_publication.pt"
)

RESULTS_DIR = os.path.join(EVAL_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

RESULTS_FILE = os.path.join(
    RESULTS_DIR,
    "gnn_publication_evaluation_results.txt"
)

PREDICTIONS_FILE = os.path.join(
    RESULTS_DIR,
    "gnn_publication_predictions.npz"
)


# ============================================================
# CONFIGURATION
# ============================================================

DEVICE = torch.device("cpu")

HIDDEN_CHANNELS = 32
DROPOUT = 0.30


# ============================================================
# MODEL
# ============================================================

class ZeroGuardGCN(nn.Module):

    def __init__(self, input_channels, hidden_channels, output_channels):
        super().__init__()

        # First graph convolution
        self.conv1 = GCNConv(
            input_channels,
            hidden_channels
        )

        # Second graph convolution
        self.conv2 = GCNConv(
            hidden_channels,
            hidden_channels
        )

        # Final classifier
        self.classifier = nn.Linear(
            hidden_channels,
            output_channels
        )

        self.dropout = nn.Dropout(DROPOUT)

    def forward(self, x, edge_index, edge_weight=None):

        x = self.conv1(
            x,
            edge_index,
            edge_weight=edge_weight
        )

        x = torch.relu(x)

        x = self.dropout(x)

        x = self.conv2(
            x,
            edge_index,
            edge_weight=edge_weight
        )

        x = torch.relu(x)

        x = self.dropout(x)

        x = self.classifier(x)

        return x


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(y_true, y_pred):

    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))

    total = tn + fp + fn + tp

    accuracy = (
        (tp + tn) / total
        if total > 0
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    specificity = (
        tn / (tn + fp)
        if (tn + fp) > 0
        else 0.0
    )

    return {
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
    }


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.6")
print("PUBLICATION GNN EVALUATION")
print("=" * 70)

print()
print("Device:", DEVICE)
print("Model:", MODEL_PATH)
print()


# ============================================================
# LOAD TEST FEATURES
# ============================================================

print("Loading independent test features...")

if not os.path.exists(TEST_FEATURES):
    raise FileNotFoundError(
        f"Test feature file not found:\n{TEST_FEATURES}"
    )

test_data = np.load(TEST_FEATURES)

X_test = test_data["X"]
y_test_binary = test_data["y"]

print("Test feature matrix:", X_test.shape)
print("Test labels:", y_test_binary.shape)


# ============================================================
# LOAD ORIGINAL TEST DATA
# ============================================================

print()
print("Loading original test dataset labels...")

if not os.path.exists(TEST_CSV):
    raise FileNotFoundError(
        f"Test CSV not found:\n{TEST_CSV}"
    )

test_df = pd.read_csv(TEST_CSV)

print("Original test rows:", len(test_df))

if len(test_df) != len(X_test):
    raise ValueError(
        "ERROR: Test feature rows and original test rows do not match."
    )


# ============================================================
# VERIFY REQUIRED COLUMNS
# ============================================================

required_columns = [
    "binary_label",
    "original_label"
]

for column in required_columns:

    if column not in test_df.columns:

        raise ValueError(
            f"Required column missing from test dataset: {column}"
        )


original_labels = (
    test_df["original_label"]
    .astype(str)
    .str.strip()
)


binary_labels_from_csv = (
    test_df["binary_label"]
    .astype(int)
    .to_numpy()
)


# ============================================================
# ALIGNMENT CHECK
# ============================================================

print()
print("Checking feature/label alignment...")

if not np.array_equal(
    y_test_binary.astype(int),
    binary_labels_from_csv
):

    raise ValueError(
        "ERROR: GNN test labels do not match test_zero_day.csv."
    )

print("Feature/label alignment: PASS")


# ============================================================
# ZERO-DAY VERIFICATION
# ============================================================

print()
print("=" * 70)
print("ZERO-DAY / UNSEEN ATTACK VERIFICATION")
print("=" * 70)

ddos_train_count = 0
portscan_train_count = 0

if os.path.exists(TRAIN_FEATURES):

    train_df = pd.read_csv(
        os.path.join(
            BASE_DIR,
            "data",
            "research",
            "processed",
            "evaluation",
            "train_zero_day_publication.csv"
        ),
        usecols=["original_label"]
    )

    train_labels = (
        train_df["original_label"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    ddos_train_count = int(
        train_labels.str.contains(
            "DDOS",
            regex=False
        ).sum()
    )

    portscan_train_count = int(
        train_labels.str.contains(
            "PORTSCAN",
            regex=False
        ).sum()
    )

print("DDoS training rows:", ddos_train_count)
print("PortScan training rows:", portscan_train_count)

if ddos_train_count != 0:
    raise ValueError(
        "ERROR: DDoS is present in training data."
    )

if portscan_train_count != 0:
    raise ValueError(
        "ERROR: PortScan is present in training data."
    )

print("PASS: DDoS and PortScan are unseen during training.")


# ============================================================
# LOAD TEST GRAPH
# ============================================================

print()
print("Loading independent test graph...")

TEST_GRAPH = os.path.join(
    EVAL_DIR,
    "graphs",
    "test_graph.npz"
)

if not os.path.exists(TEST_GRAPH):
    raise FileNotFoundError(
        f"Test graph not found:\n{TEST_GRAPH}"
    )

graph_data = np.load(TEST_GRAPH)

edge_index = torch.tensor(
    graph_data["edge_index"],
    dtype=torch.long
)

edge_weight = torch.tensor(
    graph_data["edge_weight"],
    dtype=torch.float32
)

print("Test edge index:", tuple(edge_index.shape))
print("Test edge weights:", tuple(edge_weight.shape))


# ============================================================
# GRAPH VALIDATION
# ============================================================

if X_test.shape[0] != len(y_test_binary):
    raise ValueError(
        "ERROR: Test feature and label counts do not match."
    )

if edge_index.shape[0] != 2:
    raise ValueError(
        "ERROR: Edge index must have shape (2, E)."
    )

if edge_index.shape[1] != edge_weight.shape[0]:
    raise ValueError(
        "ERROR: Edge index and edge weights do not match."
    )

if edge_index.numel() > 0:

    if int(edge_index.min()) < 0:
        raise ValueError(
            "ERROR: Negative node index detected."
        )

    if int(edge_index.max()) >= X_test.shape[0]:
        raise ValueError(
            "ERROR: Edge references node outside test graph."
        )

print("Test graph validation: PASS")


# ============================================================
# CONVERT TO PYTORCH
# ============================================================

print()
print("Converting test data to PyTorch...")

x_test = torch.tensor(
    X_test,
    dtype=torch.float32,
    device=DEVICE
)

edge_index = edge_index.to(DEVICE)
edge_weight = edge_weight.to(DEVICE)

data = Data(
    x=x_test,
    edge_index=edge_index,
    edge_weight=edge_weight
)

print("PyTorch test data ready.")


# ============================================================
# LOAD MODEL
# ============================================================

print()
print("Loading trained publication GNN...")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model file not found:\n{MODEL_PATH}"
    )

model = ZeroGuardGCN(
    input_channels=X_test.shape[1],
    hidden_channels=HIDDEN_CHANNELS,
    output_channels=2
).to(DEVICE)

checkpoint = torch.load(
    MODEL_PATH,
    map_location=DEVICE
)

if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

else:

    model.load_state_dict(checkpoint)

model.eval()

print("Model loaded successfully.")


# ============================================================
# INFERENCE
# ============================================================

print()
print("=" * 70)
print("RUNNING INDEPENDENT TEST EVALUATION")
print("=" * 70)

with torch.no_grad():

    logits = model(
        data.x,
        data.edge_index,
        data.edge_weight
    )

    probabilities = torch.softmax(
        logits,
        dim=1
    )

    predictions = torch.argmax(
        probabilities,
        dim=1
    )

y_pred = predictions.cpu().numpy()

attack_scores = (
    probabilities[:, 1]
    .cpu()
    .numpy()
)


# ============================================================
# BASIC PREDICTION VALIDATION
# ============================================================

if len(y_pred) != len(y_test_binary):

    raise ValueError(
        "ERROR: Prediction count does not match test count."
    )

print()
print("Predictions generated:", len(y_pred))

print(
    "Predicted BENIGN:",
    int(np.sum(y_pred == 0))
)

print(
    "Predicted ATTACK:",
    int(np.sum(y_pred == 1))
)


# ============================================================
# OVERALL METRICS
# ============================================================

metrics = calculate_metrics(
    y_test_binary,
    y_pred
)


# ============================================================
# ATTACK FAMILY EVALUATION
# ============================================================

normalized_labels = (
    original_labels
    .str.upper()
    .str.replace(" ", "", regex=False)
    .str.replace("-", "", regex=False)
    .str.replace("_", "", regex=False)
)

ddos_mask = normalized_labels.str.contains(
    "DDOS",
    regex=False
).to_numpy()

portscan_mask = normalized_labels.str.contains(
    "PORTSCAN",
    regex=False
).to_numpy()

benign_mask = (
    test_df["binary_label"].to_numpy() == 0
)


ddos_total = int(np.sum(ddos_mask))
ddos_detected = int(
    np.sum(
        ddos_mask &
        (y_pred == 1)
    )
)

ddos_missed = ddos_total - ddos_detected

ddos_rate = (
    ddos_detected / ddos_total
    if ddos_total > 0
    else 0.0
)


portscan_total = int(np.sum(portscan_mask))
portscan_detected = int(
    np.sum(
        portscan_mask &
        (y_pred == 1)
    )
)

portscan_missed = portscan_total - portscan_detected

portscan_rate = (
    portscan_detected / portscan_total
    if portscan_total > 0
    else 0.0
)


# ============================================================
# PRINT RESULTS
# ============================================================

print()
print("=" * 70)
print("OVERALL CLASSIFICATION RESULTS")
print("=" * 70)

print()
print("Confusion Matrix")
print()
print("                 Predicted")
print("                 BENIGN    ATTACK")
print(
    f"Actual BENIGN   {metrics['TN']:8d}  {metrics['FP']:8d}"
)
print(
    f"Actual ATTACK   {metrics['FN']:8d}  {metrics['TP']:8d}"
)

print()
print("TN:", metrics["TN"])
print("FP:", metrics["FP"])
print("FN:", metrics["FN"])
print("TP:", metrics["TP"])

print()
print(
    f"Accuracy:    {metrics['accuracy'] * 100:.4f}%"
)

print(
    f"Precision:   {metrics['precision'] * 100:.4f}%"
)

print(
    f"Recall:      {metrics['recall'] * 100:.4f}%"
)

print(
    f"F1-score:    {metrics['f1'] * 100:.4f}%"
)

print(
    f"Specificity: {metrics['specificity'] * 100:.4f}%"
)


# ============================================================
# UNSEEN ATTACK RESULTS
# ============================================================

print()
print("=" * 70)
print("UNSEEN ATTACK FAMILY RESULTS")
print("=" * 70)

print()
print("DDoS")
print("  Total:", ddos_total)
print("  Detected:", ddos_detected)
print("  Missed:", ddos_missed)
print(
    f"  Detection rate: {ddos_rate * 100:.4f}%"
)

print()
print("PortScan")
print("  Total:", portscan_total)
print("  Detected:", portscan_detected)
print("  Missed:", portscan_missed)
print(
    f"  Detection rate: {portscan_rate * 100:.4f}%"
)


# ============================================================
# SAVE PREDICTIONS
# ============================================================

np.savez_compressed(
    PREDICTIONS_FILE,
    y_true=y_test_binary,
    y_pred=y_pred,
    attack_score=attack_scores,
    original_label=original_labels.to_numpy()
)

print()
print("Predictions saved to:")
print(PREDICTIONS_FILE)


# ============================================================
# SAVE TEXT RESULTS
# ============================================================

with open(
    RESULTS_FILE,
    "w",
    encoding="utf-8"
) as f:

    f.write("=" * 70 + "\n")
    f.write("ZERO GUARD - PUBLICATION GNN EVALUATION RESULTS\n")
    f.write("=" * 70 + "\n\n")

    f.write("Dataset: CIC-IDS2017\n")
    f.write("Task: Binary network-flow classification\n")
    f.write("BENIGN = 0\n")
    f.write("ATTACK = 1\n\n")

    f.write("Model: 2-layer Graph Convolutional Network (GCN)\n")
    f.write("Input features: 78\n")
    f.write("Hidden channels: 32\n")
    f.write("Output classes: 2\n")
    f.write("Dropout: 0.30\n\n")

    f.write("Evaluation design:\n")
    f.write(
        "DDoS and PortScan were completely excluded from training.\n"
    )
    f.write(
        "They were evaluated as unseen attack families.\n\n"
    )

    f.write("Training unseen-family verification:\n")
    f.write(
        f"DDoS training rows: {ddos_train_count}\n"
    )
    f.write(
        f"PortScan training rows: {portscan_train_count}\n"
    )
    f.write("Verification: PASS\n\n")

    f.write("CONFUSION MATRIX\n")
    f.write("-----------------\n")
    f.write(
        f"TN: {metrics['TN']}\n"
    )
    f.write(
        f"FP: {metrics['FP']}\n"
    )
    f.write(
        f"FN: {metrics['FN']}\n"
    )
    f.write(
        f"TP: {metrics['TP']}\n\n"
    )

    f.write("OVERALL METRICS\n")
    f.write("----------------\n")
    f.write(
        f"Accuracy: {metrics['accuracy'] * 100:.4f}%\n"
    )
    f.write(
        f"Precision: {metrics['precision'] * 100:.4f}%\n"
    )
    f.write(
        f"Recall: {metrics['recall'] * 100:.4f}%\n"
    )
    f.write(
        f"F1-score: {metrics['f1'] * 100:.4f}%\n"
    )
    f.write(
        f"Specificity: {metrics['specificity'] * 100:.4f}%\n\n"
    )

    f.write("UNSEEN ATTACK FAMILY RESULTS\n")
    f.write("----------------------------\n")

    f.write("DDoS:\n")
    f.write(
        f"Total: {ddos_total}\n"
    )
    f.write(
        f"Detected: {ddos_detected}\n"
    )
    f.write(
        f"Missed: {ddos_missed}\n"
    )
    f.write(
        f"Detection rate: {ddos_rate * 100:.4f}%\n\n"
    )

    f.write("PortScan:\n")
    f.write(
        f"Total: {portscan_total}\n"
    )
    f.write(
        f"Detected: {portscan_detected}\n"
    )
    f.write(
        f"Missed: {portscan_missed}\n"
    )
    f.write(
        f"Detection rate: {portscan_rate * 100:.4f}%\n\n"
    )

    f.write("METHODOLOGY NOTE\n")
    f.write("-----------------\n")
    f.write(
        "The graph is a feature-similarity k-NN graph.\n"
    )
    f.write(
        "Each node represents a CIC-IDS2017 network flow.\n"
    )
    f.write(
        "Edges represent similarity between flow feature vectors.\n"
    )
    f.write(
        "The graph is not the original communication topology.\n\n"
    )

    f.write("IMPORTANT INTERPRETATION\n")
    f.write("-------------------------\n")
    f.write(
        "The model prediction score is a classification score, "
        "not a probability that an attack is a real-world zero-day.\n"
    )
    f.write(
        "Unseen DDoS and PortScan performance demonstrates "
        "generalization to attack families excluded from training, "
        "but does not prove detection of every real-world zero-day attack.\n"
    )


# ============================================================
# COMPLETE
# ============================================================

print()
print("=" * 70)
print("PUBLICATION GNN EVALUATION COMPLETE")
print("=" * 70)

print()
print("Results saved to:")
print(RESULTS_FILE)

print()
print("Step 15.6 COMPLETE")
print("=" * 70)