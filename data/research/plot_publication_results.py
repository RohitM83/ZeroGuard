import os
import numpy as np
import matplotlib.pyplot as plt


# ============================================================
# ZERO GUARD - STEP 15.7
# PUBLICATION RESULT FIGURE GENERATION
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.7")
print("PUBLICATION FIGURE GENERATION")
print("=" * 70)


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# RESULT PATH
# ============================================================

RESULT_DIR = os.path.join(
    PROJECT_DIR,
    "data",
    "research",
    "processed",
    "evaluation",
    "gnn_ready_publication",
    "results"
)


# ============================================================
# FIGURE OUTPUT PATH
# ============================================================

FIGURE_DIR = os.path.join(
    RESULT_DIR,
    "figures"
)

os.makedirs(FIGURE_DIR, exist_ok=True)


print()
print("Project directory:")
print(PROJECT_DIR)

print()
print("Result directory:")
print(RESULT_DIR)

print()
print("Figure directory:")
print(FIGURE_DIR)


# ============================================================
# VERIFIED RESULTS FROM STEP 15.6
# ============================================================

TN = 29056
FP = 20944
FN = 4784
TP = 45216

ACCURACY = 74.2720
PRECISION = 68.3434
RECALL = 90.4320
F1_SCORE = 77.8512
SPECIFICITY = 58.1120

DDOS_TOTAL = 25000
DDOS_DETECTED = 21668
DDOS_MISSED = 3332
DDOS_DETECTION_RATE = 86.6720

PORTSCAN_TOTAL = 25000
PORTSCAN_DETECTED = 23548
PORTSCAN_MISSED = 1452
PORTSCAN_DETECTION_RATE = 94.1920


# ============================================================
# VERIFY RESULT DIRECTORY
# ============================================================

if not os.path.exists(RESULT_DIR):
    raise FileNotFoundError(
        f"Result directory does not exist:\n{RESULT_DIR}"
    )


# ============================================================
# FIGURE 1
# CONFUSION MATRIX
# ============================================================

print()
print("Generating Figure 1 - Confusion Matrix...")

confusion_matrix = np.array([
    [TN, FP],
    [FN, TP]
])

fig, ax = plt.subplots(figsize=(8, 6))

matrix_image = ax.imshow(confusion_matrix)

ax.set_xticks([0, 1])
ax.set_yticks([0, 1])

ax.set_xticklabels([
    "Benign",
    "Attack"
])

ax.set_yticklabels([
    "Benign",
    "Attack"
])

ax.set_xlabel(
    "Predicted Class",
    fontsize=12
)

ax.set_ylabel(
    "Actual Class",
    fontsize=12
)

ax.set_title(
    "ZeroGuard GNN - Confusion Matrix",
    fontsize=14
)

for i in range(2):
    for j in range(2):

        ax.text(
            j,
            i,
            f"{confusion_matrix[i, j]:,}",
            ha="center",
            va="center",
            fontsize=15
        )


figure_1_path = os.path.join(
    FIGURE_DIR,
    "figure_1_confusion_matrix.png"
)

plt.tight_layout()

plt.savefig(
    figure_1_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# FIGURE 2
# CLASSIFICATION PERFORMANCE METRICS
# ============================================================

print("Generating Figure 2 - Classification Metrics...")

metric_names = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score"
]

metric_values = [
    ACCURACY,
    PRECISION,
    RECALL,
    F1_SCORE
]

fig, ax = plt.subplots(figsize=(9, 6))

bars = ax.bar(
    metric_names,
    metric_values
)

ax.set_ylim(
    0,
    100
)

ax.set_ylabel(
    "Percentage (%)",
    fontsize=12
)

ax.set_xlabel(
    "Evaluation Metric",
    fontsize=12
)

ax.set_title(
    "ZeroGuard GNN - Classification Performance",
    fontsize=14
)

for bar, value in zip(
    bars,
    metric_values
):

    ax.text(
        bar.get_x() + bar.get_width() / 2,
        value + 1,
        f"{value:.2f}%",
        ha="center",
        va="bottom",
        fontsize=11
    )


figure_2_path = os.path.join(
    FIGURE_DIR,
    "figure_2_classification_metrics.png"
)

plt.tight_layout()

plt.savefig(
    figure_2_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# FIGURE 3
# UNSEEN ATTACK DETECTION
# ============================================================

print("Generating Figure 3 - Unseen Attack Detection...")

attack_names = [
    "DDoS",
    "PortScan"
]

detection_rates = [
    DDOS_DETECTION_RATE,
    PORTSCAN_DETECTION_RATE
]

fig, ax = plt.subplots(figsize=(8, 6))

bars = ax.bar(
    attack_names,
    detection_rates
)

ax.set_ylim(
    0,
    100
)

ax.set_xlabel(
    "Unseen Attack Family",
    fontsize=12
)

ax.set_ylabel(
    "Detection Rate (%)",
    fontsize=12
)

ax.set_title(
    "ZeroGuard GNN - Unseen Attack Detection Performance",
    fontsize=14
)

for bar, value in zip(
    bars,
    detection_rates
):

    ax.text(
        bar.get_x() + bar.get_width() / 2,
        value + 1,
        f"{value:.2f}%",
        ha="center",
        va="bottom",
        fontsize=11
    )


figure_3_path = os.path.join(
    FIGURE_DIR,
    "figure_3_unseen_attack_detection.png"
)

plt.tight_layout()

plt.savefig(
    figure_3_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# VERIFY GENERATED FILES
# ============================================================

print()
print("Checking generated figures...")

generated_files = [
    figure_1_path,
    figure_2_path,
    figure_3_path
]

all_files_exist = True

for file_path in generated_files:

    if os.path.exists(file_path):

        file_size = os.path.getsize(file_path)

        print()
        print("PASS:", file_path)
        print("Size:", file_size, "bytes")

    else:

        print()
        print("FAIL:", file_path)

        all_files_exist = False


# ============================================================
# VERIFIED METRICS SUMMARY
# ============================================================

print()
print("=" * 70)
print("VERIFIED CLASSIFICATION RESULTS")
print("=" * 70)

print()
print(f"TN:          {TN}")
print(f"FP:          {FP}")
print(f"FN:          {FN}")
print(f"TP:          {TP}")

print()
print(f"Accuracy:    {ACCURACY:.4f}%")
print(f"Precision:   {PRECISION:.4f}%")
print(f"Recall:      {RECALL:.4f}%")
print(f"F1-score:    {F1_SCORE:.4f}%")
print(f"Specificity: {SPECIFICITY:.4f}%")


# ============================================================
# UNSEEN ATTACK SUMMARY
# ============================================================

print()
print("=" * 70)
print("UNSEEN ATTACK FAMILY RESULTS")
print("=" * 70)

print()
print("DDoS")
print(f"Total:          {DDOS_TOTAL}")
print(f"Detected:       {DDOS_DETECTED}")
print(f"Missed:         {DDOS_MISSED}")
print(f"Detection rate: {DDOS_DETECTION_RATE:.4f}%")

print()
print("PortScan")
print(f"Total:          {PORTSCAN_TOTAL}")
print(f"Detected:       {PORTSCAN_DETECTED}")
print(f"Missed:         {PORTSCAN_MISSED}")
print(f"Detection rate: {PORTSCAN_DETECTION_RATE:.4f}%")


# ============================================================
# FINAL STATUS
# ============================================================

print()

if all_files_exist:

    print("=" * 70)
    print("PUBLICATION FIGURES GENERATED SUCCESSFULLY")
    print("=" * 70)

    print()
    print("Figure 1:")
    print(figure_1_path)

    print()
    print("Figure 2:")
    print(figure_2_path)

    print()
    print("Figure 3:")
    print(figure_3_path)

    print()
    print("STEP 15.7 COMPLETE")
    print("=" * 70)

else:

    print("=" * 70)
    print("STEP 15.7 FAILED - FIGURE VERIFICATION ERROR")
    print("=" * 70)

    raise RuntimeError(
        "One or more publication figures were not generated."
    )