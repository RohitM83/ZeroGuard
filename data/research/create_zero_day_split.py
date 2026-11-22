import pandas as pd
from pathlib import Path

# ============================================================
# PATHS
# ============================================================

input_file = Path(
    r"data\research\processed\cic_ids2017_binary.csv"
)

output_folder = Path(
    r"data\research\processed\evaluation"
)

output_folder.mkdir(
    parents=True,
    exist_ok=True
)

train_file = output_folder / "train_zero_day.csv"
test_file = output_folder / "test_zero_day.csv"

# ============================================================
# TARGETS
# ============================================================

TRAIN_BENIGN = 100000
TRAIN_ATTACK = 100000

TEST_BENIGN = 50000
TEST_DDOS = 25000
TEST_PORTSCAN = 25000

# ============================================================
# KNOWN ATTACK FAMILIES
# ============================================================

UNSEEN_ATTACKS = {
    "DDoS",
    "PortScan"
}

# ============================================================
# STORAGE
# ============================================================

train_benign_parts = []
train_attack_parts = []

test_benign_parts = []
test_ddos_parts = []
test_portscan_parts = []

train_benign_count = 0
train_attack_count = 0

test_benign_count = 0
test_ddos_count = 0
test_portscan_count = 0

# ============================================================
# PROCESS DATA
# ============================================================

print("\n" + "=" * 70)
print("CORRECTED ZERO-DAY DATASET SPLIT")
print("=" * 70)

print("\nUnseen attack families:")
print("  DDoS")
print("  PortScan")

print("\nTargets:")
print("  Training BENIGN :", TRAIN_BENIGN)
print("  Training ATTACK :", TRAIN_ATTACK)
print("  Test BENIGN     :", TEST_BENIGN)
print("  Test DDoS       :", TEST_DDOS)
print("  Test PortScan   :", TEST_PORTSCAN)

for chunk_number, chunk in enumerate(
    pd.read_csv(
        input_file,
        chunksize=100000,
        low_memory=False
    ),
    start=1
):

    print(
        f"\nProcessing chunk {chunk_number}"
    )

    chunk["original_label"] = (
        chunk["original_label"]
        .astype(str)
        .str.replace("\ufeff", "", regex=False)
        .str.strip()
    )

    # --------------------------------------------------------
    # BENIGN
    # --------------------------------------------------------

    benign = chunk[
        chunk["original_label"] == "BENIGN"
    ]

    # --------------------------------------------------------
    # KNOWN ATTACKS
    # --------------------------------------------------------

    known_attack = chunk[
        (chunk["binary_label"] == 1)
        &
        (~chunk["original_label"].isin(
            UNSEEN_ATTACKS
        ))
    ]

    # --------------------------------------------------------
    # DDoS
    # --------------------------------------------------------

    ddos = chunk[
        chunk["original_label"] == "DDoS"
    ]

    # --------------------------------------------------------
    # PortScan
    # --------------------------------------------------------

    portscan = chunk[
        chunk["original_label"] == "PortScan"
    ]

    # --------------------------------------------------------
    # TRAIN BENIGN
    # --------------------------------------------------------

    if train_benign_count < TRAIN_BENIGN:

        remaining = (
            TRAIN_BENIGN
            - train_benign_count
        )

        selected = benign.head(remaining)

        if len(selected) > 0:
            train_benign_parts.append(selected)
            train_benign_count += len(selected)

    # --------------------------------------------------------
    # TRAIN KNOWN ATTACK
    # --------------------------------------------------------

    if train_attack_count < TRAIN_ATTACK:

        remaining = (
            TRAIN_ATTACK
            - train_attack_count
        )

        selected = known_attack.head(remaining)

        if len(selected) > 0:
            train_attack_parts.append(selected)
            train_attack_count += len(selected)

    # --------------------------------------------------------
    # TEST BENIGN
    # --------------------------------------------------------

    if test_benign_count < TEST_BENIGN:

        remaining = (
            TEST_BENIGN
            - test_benign_count
        )

        selected = benign.head(remaining)

        if len(selected) > 0:
            test_benign_parts.append(selected)
            test_benign_count += len(selected)

    # --------------------------------------------------------
    # TEST DDoS
    # --------------------------------------------------------

    if test_ddos_count < TEST_DDOS:

        remaining = (
            TEST_DDOS
            - test_ddos_count
        )

        selected = ddos.head(remaining)

        if len(selected) > 0:
            test_ddos_parts.append(selected)
            test_ddos_count += len(selected)

    # --------------------------------------------------------
    # TEST PortScan
    # --------------------------------------------------------

    if test_portscan_count < TEST_PORTSCAN:

        remaining = (
            TEST_PORTSCAN
            - test_portscan_count
        )

        selected = portscan.head(remaining)

        if len(selected) > 0:
            test_portscan_parts.append(selected)
            test_portscan_count += len(selected)

    # --------------------------------------------------------
    # CHECK COMPLETION
    # --------------------------------------------------------

    if (
        train_benign_count >= TRAIN_BENIGN
        and
        train_attack_count >= TRAIN_ATTACK
        and
        test_benign_count >= TEST_BENIGN
        and
        test_ddos_count >= TEST_DDOS
        and
        test_portscan_count >= TEST_PORTSCAN
    ):
        print("\nAll required samples collected.")
        break

# ============================================================
# COMBINE
# ============================================================

print("\n" + "-" * 70)
print("Combining datasets...")
print("-" * 70)

train_benign = pd.concat(
    train_benign_parts,
    ignore_index=True
)

train_attack = pd.concat(
    train_attack_parts,
    ignore_index=True
)

test_benign = pd.concat(
    test_benign_parts,
    ignore_index=True
)

test_ddos = pd.concat(
    test_ddos_parts,
    ignore_index=True
)

test_portscan = pd.concat(
    test_portscan_parts,
    ignore_index=True
)

train_df = pd.concat(
    [
        train_benign,
        train_attack
    ],
    ignore_index=True
)

test_df = pd.concat(
    [
        test_benign,
        test_ddos,
        test_portscan
    ],
    ignore_index=True
)

# ============================================================
# SHUFFLE
# ============================================================

train_df = train_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

test_df = test_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# ============================================================
# SAVE
# ============================================================

train_df.to_csv(
    train_file,
    index=False
)

test_df.to_csv(
    test_file,
    index=False
)

# ============================================================
# FINAL REPORT
# ============================================================

print("\n" + "=" * 70)
print("CORRECTED ZERO-DAY SPLIT COMPLETE")
print("=" * 70)

print("\nTRAINING DATA")
print("-" * 40)

print(
    "Total:",
    f"{len(train_df):,}"
)

print(
    "BENIGN:",
    f"{(train_df['binary_label'] == 0).sum():,}"
)

print(
    "KNOWN ATTACK:",
    f"{(train_df['binary_label'] == 1).sum():,}"
)

print("\nTraining attack distribution:")

training_distribution = (
    train_df[
        train_df["binary_label"] == 1
    ]["original_label"]
    .value_counts()
)

for label, count in training_distribution.items():
    print(
        f"  {label}: {count:,}"
    )

print("\nTEST DATA")
print("-" * 40)

print(
    "Total:",
    f"{len(test_df):,}"
)

print(
    "BENIGN:",
    f"{(test_df['binary_label'] == 0).sum():,}"
)

print(
    "DDoS:",
    f"{(test_df['original_label'] == 'DDoS').sum():,}"
)

print(
    "PortScan:",
    f"{(test_df['original_label'] == 'PortScan').sum():,}"
)

print("\nTest attack distribution:")

test_distribution = (
    test_df[
        test_df["binary_label"] == 1
    ]["original_label"]
    .value_counts()
)

for label, count in test_distribution.items():
    print(
        f"  {label}: {count:,}"
    )

# ============================================================
# VERIFY NO UNSEEN ATTACK IN TRAINING
# ============================================================

print("\n" + "-" * 70)
print("ZERO-DAY SEPARATION CHECK")
print("-" * 70)

train_unseen = train_df[
    train_df["original_label"].isin(
        UNSEEN_ATTACKS
    )
]

if len(train_unseen) == 0:
    print(
        "PASS: DDoS and PortScan are completely absent from training."
    )
else:
    print(
        "ERROR: Unseen attacks found in training:",
        len(train_unseen)
    )

# ============================================================
# FILES
# ============================================================

print("\nTraining file:")
print(train_file)

print("\nTest file:")
print(test_file)

print("\n=== STEP 8 CORRECTED COMPLETE ===")
