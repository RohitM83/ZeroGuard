import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ============================================================
# ZERO GUARD
# STEP 14 - PUBLICATION RESULTS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RESULT_DIR = os.path.join(
    BASE_DIR,
    "processed",
    "evaluation",
    "gnn_ready",
    "results"
)

PREDICTIONS_FILE = os.path.join(
    RESULT_DIR,
    "gnn_predictions.npz"
)

OUTPUT_DIR = os.path.join(
    RESULT_DIR,
    "publication_figures"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

# ============================================================
# LOAD PREDICTIONS
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 14")
print("PUBLICATION RESULTS GENERATOR")
print("=" * 70)

print("\nLoading saved predictions...")

if not os.path.exists(PREDICTIONS_FILE):
    raise FileNotFoundError(
        f"Prediction file not found:\n{PREDICTIONS_FILE}"
    )

data = np.load(
    PREDICTIONS_FILE,
    allow_pickle=True
)

y_true = data["y_true"].astype(np.int64)
y_pred = data["y_pred"].astype(np.int64)

original_labels = (
    data["original_label"]
    .astype(str)
)

print(
    f"Total predictions: {len(y_true):,}"
)

# ============================================================
# CONFUSION MATRIX
# ============================================================

TN = int(
    ((y_true == 0) & (y_pred == 0)).sum()
)

FP = int(
    ((y_true == 0) & (y_pred == 1)).sum()
)

FN = int(
    ((y_true == 1) & (y_pred == 0)).sum()
)

TP = int(
    ((y_true == 1) & (y_pred == 1)).sum()
)

# ============================================================
# METRICS
# ============================================================

total = len(y_true)

accuracy = (
    (TP + TN) / total
)

precision = (
    TP / (TP + FP)
    if TP + FP > 0
    else 0
)

recall = (
    TP / (TP + FN)
    if TP + FN > 0
    else 0
)

f1 = (
    2 * precision * recall /
    (precision + recall)
    if precision + recall > 0
    else 0
)

specificity = (
    TN / (TN + FP)
    if TN + FP > 0
    else 0
)

print("\nMetrics loaded from saved predictions.")

# ============================================================
# FIGURE 1 - CONFUSION MATRIX
# ============================================================

print("\nGenerating Figure 1 - Confusion Matrix...")

cm = np.array([
    [TN, FP],
    [FN, TP]
])

fig, ax = plt.subplots(
    figsize=(7, 6)
)

image = ax.imshow(
    cm,
    interpolation="nearest"
)

ax.set_title(
    "ZeroGuard GNN Confusion Matrix",
    fontsize=14,
    pad=15
)

ax.set_xlabel(
    "Predicted Class",
    fontsize=11
)

ax.set_ylabel(
    "Actual Class",
    fontsize=11
)

ax.set_xticks(
    [0, 1]
)

ax.set_yticks(
    [0, 1]
)

ax.set_xticklabels(
    ["Benign", "Attack"]
)

ax.set_yticklabels(
    ["Benign", "Attack"]
)

threshold = cm.max() / 2

for i in range(2):

    for j in range(2):

        ax.text(
            j,
            i,
            f"{cm[i, j]:,}",
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold"
        )

plt.tight_layout()

cm_file = os.path.join(
    OUTPUT_DIR,
    "figure_1_confusion_matrix.png"
)

plt.savefig(
    cm_file,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(
    f"Saved: {cm_file}"
)

# ============================================================
# FIGURE 2 - CLASSIFICATION METRICS
# ============================================================

print(
    "\nGenerating Figure 2 - Classification Metrics..."
)

metric_names = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score"
]

metric_values = [
    accuracy * 100,
    precision * 100,
    recall * 100,
    f1 * 100
]

fig, ax = plt.subplots(
    figsize=(8, 6)
)

bars = ax.bar(
    metric_names,
    metric_values
)

ax.set_title(
    "ZeroGuard GNN Classification Performance",
    fontsize=14,
    pad=15
)

ax.set_ylabel(
    "Percentage (%)",
    fontsize=11
)

ax.set_ylim(
    0,
    100
)

for bar, value in zip(
    bars,
    metric_values
):

    ax.text(
        bar.get_x() +
        bar.get_width() / 2,
        value + 1,
        f"{value:.2f}%",
        ha="center",
        va="bottom",
        fontsize=10
    )

plt.tight_layout()

metrics_file = os.path.join(
    OUTPUT_DIR,
    "figure_2_classification_metrics.png"
)

plt.savefig(
    metrics_file,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(
    f"Saved: {metrics_file}"
)

# ============================================================
# ATTACK FAMILY DETECTION
# ============================================================

def family_result(
    family
):

    mask = np.char.find(
        np.char.lower(original_labels),
        family.lower()
    ) >= 0

    indices = np.where(mask)[0]

    family_true = y_true[
        indices
    ]

    family_pred = y_pred[
        indices
    ]

    attack_indices = (
        family_true == 1
    )

    total_attack = int(
        attack_indices.sum()
    )

    detected = int(
        (
            attack_indices &
            (family_pred == 1)
        ).sum()
    )

    missed = int(
        (
            attack_indices &
            (family_pred == 0)
        ).sum()
    )

    detection_rate = (
        detected / total_attack * 100
        if total_attack > 0
        else 0
    )

    return (
        total_attack,
        detected,
        missed,
        detection_rate
    )


ddos_total, ddos_detected, ddos_missed, ddos_rate = (
    family_result("DDoS")
)

portscan_total, portscan_detected, portscan_missed, portscan_rate = (
    family_result("PortScan")
)

# ============================================================
# FIGURE 3 - UNSEEN ATTACK DETECTION
# ============================================================

print(
    "\nGenerating Figure 3 - Unseen Attack Detection..."
)

family_names = [
    "DDoS",
    "PortScan"
]

family_rates = [
    ddos_rate,
    portscan_rate
]

fig, ax = plt.subplots(
    figsize=(8, 6)
)

bars = ax.bar(
    family_names,
    family_rates
)

ax.set_title(
    "ZeroGuard GNN Detection of Unseen Attack Families",
    fontsize=14,
    pad=15
)

ax.set_ylabel(
    "Detection Rate (%)",
    fontsize=11
)

ax.set_ylim(
    0,
    100
)

for bar, value in zip(
    bars,
    family_rates
):

    ax.text(
        bar.get_x() +
        bar.get_width() / 2,
        value + 1,
        f"{value:.2f}%",
        ha="center",
        va="bottom",
        fontsize=10
    )

plt.tight_layout()

family_file = os.path.join(
    OUTPUT_DIR,
    "figure_3_unseen_attack_detection.png"
)

plt.savefig(
    family_file,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(
    f"Saved: {family_file}"
)

# ============================================================
# TABLE 1 - RESULTS CSV
# ============================================================

print(
    "\nGenerating Table 1 - Results..."
)

results_table = pd.DataFrame([
    {
        "Metric": "Accuracy",
        "Value_Percent": accuracy * 100
    },
    {
        "Metric": "Precision",
        "Value_Percent": precision * 100
    },
    {
        "Metric": "Recall",
        "Value_Percent": recall * 100
    },
    {
        "Metric": "F1-score",
        "Value_Percent": f1 * 100
    },
    {
        "Metric": "Specificity",
        "Value_Percent": specificity * 100
    },
    {
        "Metric": "DDoS Detection Rate",
        "Value_Percent": ddos_rate
    },
    {
        "Metric": "PortScan Detection Rate",
        "Value_Percent": portscan_rate
    }
])

table_file = os.path.join(
    OUTPUT_DIR,
    "table_1_gnn_results.csv"
)

results_table.to_csv(
    table_file,
    index=False
)

print(
    f"Saved: {table_file}"
)

# ============================================================
# TABLE 2 - CONFUSION MATRIX CSV
# ============================================================

cm_table = pd.DataFrame(
    [
        {
            "Actual": "Benign",
            "Predicted_Benign": TN,
            "Predicted_Attack": FP
        },
        {
            "Actual": "Attack",
            "Predicted_Benign": FN,
            "Predicted_Attack": TP
        }
    ]
)

cm_table_file = os.path.join(
    OUTPUT_DIR,
    "table_2_confusion_matrix.csv"
)

cm_table.to_csv(
    cm_table_file,
    index=False
)

print(
    f"Saved: {cm_table_file}"
)

# ============================================================
# TEXT SUMMARY
# ============================================================

summary_file = os.path.join(
    OUTPUT_DIR,
    "publication_results_summary.txt"
)

with open(
    summary_file,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "ZERO GUARD GNN PUBLICATION RESULTS\n"
    )

    f.write(
        "=" * 60 + "\n\n"
    )

    f.write(
        "Dataset: CIC-IDS2017\n"
    )

    f.write(
        "Evaluation: Unseen attack-family evaluation\n\n"
    )

    f.write(
        "CONFUSION MATRIX\n"
    )

    f.write(
        f"TN = {TN:,}\n"
    )

    f.write(
        f"FP = {FP:,}\n"
    )

    f.write(
        f"FN = {FN:,}\n"
    )

    f.write(
        f"TP = {TP:,}\n\n"
    )

    f.write(
        "CLASSIFICATION METRICS\n"
    )

    f.write(
        f"Accuracy    = {accuracy * 100:.4f}%\n"
    )

    f.write(
        f"Precision   = {precision * 100:.4f}%\n"
    )

    f.write(
        f"Recall      = {recall * 100:.4f}%\n"
    )

    f.write(
        f"F1-score    = {f1 * 100:.4f}%\n"
    )

    f.write(
        f"Specificity = {specificity * 100:.4f}%\n\n"
    )

    f.write(
        "UNSEEN ATTACK FAMILIES\n"
    )

    f.write(
        f"DDoS: {ddos_detected:,}/{ddos_total:,} "
        f"detected ({ddos_rate:.4f}%)\n"
    )

    f.write(
        f"PortScan: {portscan_detected:,}/{portscan_total:,} "
        f"detected ({portscan_rate:.4f}%)\n"
    )

# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("STEP 14 COMPLETE")
print("=" * 70)

print("\nPublication files created:")

print(
    "\n1. Confusion Matrix:"
)

print(
    cm_file
)

print(
    "\n2. Classification Metrics:"
)

print(
    metrics_file
)

print(
    "\n3. Unseen Attack Detection:"
)

print(
    family_file
)

print(
    "\n4. Results Table:"
)

print(
    table_file
)

print(
    "\n5. Confusion Matrix Table:"
)

print(
    cm_table_file
)

print(
    "\n6. Text Summary:"
)

print(
    summary_file
)

print("\n" + "=" * 70)