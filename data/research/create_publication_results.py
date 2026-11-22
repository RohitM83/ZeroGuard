import os
from datetime import datetime


# ============================================================
# ZERO GUARD - STEP 15.8
# PUBLICATION RESULTS PACKAGE
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.8")
print("PUBLICATION RESULTS PACKAGE")
print("=" * 70)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULT_DIR = os.path.join(
    PROJECT_DIR,
    "data",
    "research",
    "processed",
    "evaluation",
    "gnn_ready_publication",
    "results"
)

FIGURE_DIR = os.path.join(
    RESULT_DIR,
    "figures"
)

OUTPUT_FILE = os.path.join(
    RESULT_DIR,
    "ZERO_GUARD_PUBLICATION_RESULTS.txt"
)


# ============================================================
# VERIFIED STEP 15.6 RESULTS
# ============================================================

TEST_SAMPLES = 100000

TN = 29056
FP = 20944
FN = 4784
TP = 45216

ACCURACY = 74.2720
PRECISION = 68.3434
RECALL = 90.4320
F1_SCORE = 77.8512
SPECIFICITY = 58.1120


# ============================================================
# UNSEEN ATTACK RESULTS
# ============================================================

DDOS_TOTAL = 25000
DDOS_DETECTED = 21668
DDOS_MISSED = 3332
DDOS_RATE = 86.6720

PORTSCAN_TOTAL = 25000
PORTSCAN_DETECTED = 23548
PORTSCAN_MISSED = 1452
PORTSCAN_RATE = 94.1920


# ============================================================
# EVALUATION INFORMATION
# ============================================================

MODEL_NAME = "ZeroGuard GCN Publication Model"

MODEL_PATH = os.path.join(
    PROJECT_DIR,
    "data",
    "research",
    "processed",
    "evaluation",
    "gnn_ready_publication",
    "models",
    "zeroguard_gcn_publication.pt"
)

FEATURE_SHAPE = "(100000, 78)"

GRAPH_EDGE_SHAPE = "(2, 635700)"

EDGE_WEIGHT_SHAPE = "(635700,)"

DEVICE = "CPU"

FEATURE_ALIGNMENT = "PASS"

GRAPH_VALIDATION = "PASS"

MODEL_LOADED = "PASS"

PREDICTIONS_GENERATED = 100000

PREDICTED_BENIGN = 33840

PREDICTED_ATTACK = 66160


# ============================================================
# UNSEEN TRAINING VERIFICATION
# ============================================================

DDOS_TRAINING_ROWS = 0

PORTSCAN_TRAINING_ROWS = 0

UNSEEN_VERIFICATION = "PASS"


# ============================================================
# FIGURE FILES
# ============================================================

FIGURE_1 = os.path.join(
    FIGURE_DIR,
    "figure_1_confusion_matrix.png"
)

FIGURE_2 = os.path.join(
    FIGURE_DIR,
    "figure_2_classification_metrics.png"
)

FIGURE_3 = os.path.join(
    FIGURE_DIR,
    "figure_3_unseen_attack_detection.png"
)


# ============================================================
# VERIFY REQUIRED FILES
# ============================================================

required_files = [
    MODEL_PATH,
    FIGURE_1,
    FIGURE_2,
    FIGURE_3
]

missing_files = []

for file_path in required_files:

    if not os.path.exists(file_path):
        missing_files.append(file_path)


if missing_files:

    print()
    print("ERROR: Required files are missing.")

    for file_path in missing_files:
        print(file_path)

    raise FileNotFoundError(
        "One or more required publication files are missing."
    )


# ============================================================
# CREATE PUBLICATION RESULTS DOCUMENT
# ============================================================

generated_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)


publication_text = f"""
======================================================================
ZERO GUARD
AI-BASED ZERO-DAY ATTACK DETECTION USING GRAPH NEURAL NETWORKS
======================================================================

PUBLICATION GNN EVALUATION RESULTS

Generated: {generated_time}

======================================================================
1. EVALUATION SUMMARY
======================================================================

Model:
{MODEL_NAME}

Model file:
{MODEL_PATH}

Evaluation device:
{DEVICE}

Independent test samples:
{TEST_SAMPLES:,}

Test feature matrix:
{FEATURE_SHAPE}

Test graph edge index:
{GRAPH_EDGE_SHAPE}

Test edge weights:
{EDGE_WEIGHT_SHAPE}

Feature/label alignment:
{FEATURE_ALIGNMENT}

Test graph validation:
{GRAPH_VALIDATION}

Model loading:
{MODEL_LOADED}

Predictions generated:
{PREDICTIONS_GENERATED:,}

Predicted BENIGN:
{PREDICTED_BENIGN:,}

Predicted ATTACK:
{PREDICTED_ATTACK:,}


======================================================================
2. ZERO-DAY / UNSEEN ATTACK VERIFICATION
======================================================================

DDoS training rows:
{DDOS_TRAINING_ROWS}

PortScan training rows:
{PORTSCAN_TRAINING_ROWS}

Unseen attack verification:
{UNSEEN_VERIFICATION}

The evaluation verified that DDoS and PortScan had zero training
rows in the evaluated training configuration and were therefore
treated as unseen attack families during independent testing.


======================================================================
3. CONFUSION MATRIX
======================================================================

                         Predicted
                    BENIGN       ATTACK

Actual BENIGN       {TN:,}       {FP:,}

Actual ATTACK       {FN:,}       {TP:,}


True Negative (TN):
{TN:,}

False Positive (FP):
{FP:,}

False Negative (FN):
{FN:,}

True Positive (TP):
{TP:,}


======================================================================
4. CLASSIFICATION PERFORMANCE
======================================================================

Accuracy:
{ACCURACY:.4f}%

Precision:
{PRECISION:.4f}%

Recall:
{RECALL:.4f}%

F1-score:
{F1_SCORE:.4f}%

Specificity:
{SPECIFICITY:.4f}%


======================================================================
5. UNSEEN ATTACK FAMILY PERFORMANCE
======================================================================

DDoS
----------------------------------------------------------------------
Total test samples:
{DDOS_TOTAL:,}

Detected:
{DDOS_DETECTED:,}

Missed:
{DDOS_MISSED:,}

Detection rate:
{DDOS_RATE:.4f}%


PortScan
----------------------------------------------------------------------
Total test samples:
{PORTSCAN_TOTAL:,}

Detected:
{PORTSCAN_DETECTED:,}

Missed:
{PORTSCAN_MISSED:,}

Detection rate:
{PORTSCAN_RATE:.4f}%


======================================================================
6. PUBLICATION FIGURES
======================================================================

Figure 1 - Confusion Matrix:
{FIGURE_1}

Figure 2 - Classification Performance:
{FIGURE_2}

Figure 3 - Unseen Attack Detection:
{FIGURE_3}


======================================================================
7. RESULTS INTERPRETATION
======================================================================

The ZeroGuard publication GNN was evaluated using an independent
test set containing 100,000 samples.

The model achieved an accuracy of {ACCURACY:.4f}%, with a precision
of {PRECISION:.4f}%, recall of {RECALL:.4f}%, and F1-score of
{F1_SCORE:.4f}%.

The recall of {RECALL:.4f}% indicates that the model identified a
large proportion of the attack samples present in the independent
test set. The corresponding specificity was {SPECIFICITY:.4f}%,
indicating the proportion of benign samples correctly identified
as benign.

For the unseen attack-family evaluation, the model detected
{DDOS_DETECTED:,} of {DDOS_TOTAL:,} DDoS samples, corresponding to
a detection rate of {DDOS_RATE:.4f}%.

For PortScan, the model detected {PORTSCAN_DETECTED:,} of
{PORTSCAN_TOTAL:,} samples, corresponding to a detection rate of
{PORTSCAN_RATE:.4f}%.

These results provide the quantitative evaluation used for the
ZeroGuard research paper, seminar results, and publication figures.


======================================================================
8. IMPORTANT REPRODUCIBILITY INFORMATION
======================================================================

This document records the results produced by:

Step 15.6 - Independent Publication GNN Evaluation

Step 15.7 - Publication Figure Generation

The numerical values in this document are copied from the verified
evaluation output and should be treated as the current reference
values for the publication results section.

======================================================================
END OF ZERO GUARD PUBLICATION RESULTS
======================================================================
"""


# ============================================================
# WRITE FILE
# ============================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        publication_text.strip() + "\n"
    )


# ============================================================
# VERIFY OUTPUT
# ============================================================

if not os.path.exists(OUTPUT_FILE):

    raise RuntimeError(
        "Publication results file was not created."
    )


file_size = os.path.getsize(
    OUTPUT_FILE
)


# ============================================================
# FINAL OUTPUT
# ============================================================

print()
print("=" * 70)
print("PUBLICATION RESULTS PACKAGE CREATED")
print("=" * 70)

print()
print("Output file:")
print(OUTPUT_FILE)

print()
print("File size:")
print(f"{file_size:,} bytes")

print()
print("Included:")
print("PASS - Evaluation summary")
print("PASS - Confusion matrix")
print("PASS - Accuracy")
print("PASS - Precision")
print("PASS - Recall")
print("PASS - F1-score")
print("PASS - Specificity")
print("PASS - DDoS unseen attack result")
print("PASS - PortScan unseen attack result")
print("PASS - Publication figure references")
print("PASS - Reproducibility information")

print()
print("=" * 70)
print("STEP 15.8 COMPLETE")
print("=" * 70)