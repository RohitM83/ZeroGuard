import os
import csv


# ============================================================
# ZERO GUARD - STEP 15.9
# PUBLICATION TABLE GENERATION
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.9")
print("PUBLICATION TABLE GENERATION")
print("=" * 70)


# ============================================================
# PATHS
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

TABLE_DIR = os.path.join(
    RESULT_DIR,
    "tables"
)

os.makedirs(TABLE_DIR, exist_ok=True)


# ============================================================
# VERIFIED RESULTS
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
DDOS_RATE = 86.6720

PORTSCAN_TOTAL = 25000
PORTSCAN_DETECTED = 23548
PORTSCAN_MISSED = 1452
PORTSCAN_RATE = 94.1920


# ============================================================
# TABLE 1 - CONFUSION MATRIX
# ============================================================

confusion_csv = os.path.join(
    TABLE_DIR,
    "table_1_confusion_matrix.csv"
)

with open(
    confusion_csv,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "Actual / Predicted",
        "Benign",
        "Attack"
    ])

    writer.writerow([
        "Benign",
        TN,
        FP
    ])

    writer.writerow([
        "Attack",
        FN,
        TP
    ])


# ============================================================
# TABLE 2 - OVERALL PERFORMANCE
# ============================================================

performance_csv = os.path.join(
    TABLE_DIR,
    "table_2_overall_performance.csv"
)

with open(
    performance_csv,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "Metric",
        "Value (%)"
    ])

    writer.writerow([
        "Accuracy",
        f"{ACCURACY:.4f}"
    ])

    writer.writerow([
        "Precision",
        f"{PRECISION:.4f}"
    ])

    writer.writerow([
        "Recall",
        f"{RECALL:.4f}"
    ])

    writer.writerow([
        "F1-score",
        f"{F1_SCORE:.4f}"
    ])

    writer.writerow([
        "Specificity",
        f"{SPECIFICITY:.4f}"
    ])


# ============================================================
# TABLE 3 - UNSEEN ATTACK FAMILIES
# ============================================================

unseen_csv = os.path.join(
    TABLE_DIR,
    "table_3_unseen_attack_families.csv"
)

with open(
    unseen_csv,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "Attack Family",
        "Total Samples",
        "Detected",
        "Missed",
        "Detection Rate (%)"
    ])

    writer.writerow([
        "DDoS",
        DDOS_TOTAL,
        DDOS_DETECTED,
        DDOS_MISSED,
        f"{DDOS_RATE:.4f}"
    ])

    writer.writerow([
        "PortScan",
        PORTSCAN_TOTAL,
        PORTSCAN_DETECTED,
        PORTSCAN_MISSED,
        f"{PORTSCAN_RATE:.4f}"
    ])


# ============================================================
# TEXT TABLE DOCUMENT
# ============================================================

text_file = os.path.join(
    TABLE_DIR,
    "ZERO_GUARD_PUBLICATION_TABLES.txt"
)

content = f"""
======================================================================
ZERO GUARD
PUBLICATION TABLES
======================================================================


TABLE 1. CONFUSION MATRIX
----------------------------------------------------------------------

                         Predicted
                    Benign       Attack

Actual Benign       {TN:,}       {FP:,}

Actual Attack       {FN:,}       {TP:,}


TN = {TN:,}
FP = {FP:,}
FN = {FN:,}
TP = {TP:,}


======================================================================
TABLE 2. OVERALL CLASSIFICATION PERFORMANCE
======================================================================

Metric                  Value

Accuracy                {ACCURACY:.4f}%
Precision               {PRECISION:.4f}%
Recall                  {RECALL:.4f}%
F1-score                {F1_SCORE:.4f}%
Specificity             {SPECIFICITY:.4f}%


======================================================================
TABLE 3. UNSEEN ATTACK FAMILY PERFORMANCE
======================================================================

Attack Family    Total       Detected       Missed       Detection Rate

DDoS             {DDOS_TOTAL:,}       {DDOS_DETECTED:,}       {DDOS_MISSED:,}       {DDOS_RATE:.4f}%

PortScan         {PORTSCAN_TOTAL:,}       {PORTSCAN_DETECTED:,}       {PORTSCAN_MISSED:,}       {PORTSCAN_RATE:.4f}%


======================================================================
END OF PUBLICATION TABLES
======================================================================
"""

with open(
    text_file,
    "w",
    encoding="utf-8"
) as file:

    file.write(content.strip() + "\n")


# ============================================================
# VERIFY
# ============================================================

files = [
    confusion_csv,
    performance_csv,
    unseen_csv,
    text_file
]

print()
print("Checking generated table files...")

all_ok = True

for path in files:

    if os.path.exists(path):

        print()
        print("PASS:", path)
        print(
            "Size:",
            os.path.getsize(path),
            "bytes"
        )

    else:

        print()
        print("FAIL:", path)

        all_ok = False


# ============================================================
# FINAL STATUS
# ============================================================

print()

if all_ok:

    print("=" * 70)
    print("PUBLICATION TABLES GENERATED SUCCESSFULLY")
    print("=" * 70)

    print()
    print("Table 1: Confusion Matrix")
    print("Table 2: Overall Performance")
    print("Table 3: Unseen Attack Families")

    print()
    print("STEP 15.9 COMPLETE")
    print("=" * 70)

else:

    raise RuntimeError(
        "One or more publication table files were not created."
    )