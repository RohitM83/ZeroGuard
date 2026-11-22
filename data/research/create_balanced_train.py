import pandas as pd
from pathlib import Path

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

output_file = (
    output_folder /
    "train_zero_day_balanced.csv"
)

# ------------------------------------------------------------
# TARGET
# ------------------------------------------------------------

TARGET_BENIGN = 100000
TARGET_ATTACK = 100000

MAX_PER_ATTACK = 10000

UNSEEN_ATTACKS = {
    "DDoS",
    "PortScan"
}

# ------------------------------------------------------------
# KNOWN ATTACKS
# ------------------------------------------------------------

KNOWN_ATTACKS = [
    "Bot",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "FTP-Patator",
    "Heartbleed",
    "Infiltration",
    "SSH-Patator",
    "Web Attack ? Brute Force",
    "Web Attack ? Sql Injection",
    "Web Attack ? XSS"
]

# ------------------------------------------------------------
# STORAGE
# ------------------------------------------------------------

benign_parts = []
attack_parts = []

benign_count = 0

attack_counts = {
    label: 0
    for label in KNOWN_ATTACKS
}

print("\n" + "=" * 70)
print("BALANCED ZERO-DAY TRAINING DATASET")
print("=" * 70)

print("\nTarget BENIGN:", TARGET_BENIGN)
print("Target ATTACK:", TARGET_ATTACK)

print("\nUnseen attacks excluded:")
print("  DDoS")
print("  PortScan")

# ------------------------------------------------------------
# READ DATA
# ------------------------------------------------------------

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

    if benign_count < TARGET_BENIGN:

        benign = chunk[
            chunk["original_label"] == "BENIGN"
        ]

        remaining = (
            TARGET_BENIGN -
            benign_count
        )

        selected = benign.head(
            remaining
        )

        if len(selected) > 0:
            benign_parts.append(selected)
            benign_count += len(selected)

    # --------------------------------------------------------
    # KNOWN ATTACKS
    # --------------------------------------------------------

    for attack in KNOWN_ATTACKS:

        if attack_counts[attack] >= MAX_PER_ATTACK:
            continue

        attack_rows = chunk[
            chunk["original_label"] == attack
        ]

        remaining = (
            MAX_PER_ATTACK -
            attack_counts[attack]
        )

        selected = attack_rows.head(
            remaining
        )

        if len(selected) > 0:

            attack_parts.append(selected)

            attack_counts[attack] += len(
                selected
            )

    # --------------------------------------------------------
    # STOP IF ENOUGH DATA
    # --------------------------------------------------------

    if (
        benign_count >= TARGET_BENIGN
        and
        sum(attack_counts.values())
        >= TARGET_ATTACK
    ):
        break

# ------------------------------------------------------------
# COMBINE ATTACK DATA
# ------------------------------------------------------------

attack_df = pd.concat(
    attack_parts,
    ignore_index=True
)

# We may have collected more than 100,000 because
# each family was collected independently.
# Randomly select exactly 100,000 attack samples
# using a fixed seed.

if len(attack_df) > TARGET_ATTACK:

    attack_df = attack_df.sample(
        n=TARGET_ATTACK,
        random_state=42
    ).reset_index(drop=True)

# ------------------------------------------------------------
# COMBINE BENIGN + ATTACK
# ------------------------------------------------------------

benign_df = pd.concat(
    benign_parts,
    ignore_index=True
)

train_df = pd.concat(
    [
        benign_df,
        attack_df
    ],
    ignore_index=True
)

# ------------------------------------------------------------
# SHUFFLE
# ------------------------------------------------------------

train_df = train_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# ------------------------------------------------------------
# SAVE
# ------------------------------------------------------------

train_df.to_csv(
    output_file,
    index=False
)

# ------------------------------------------------------------
# REPORT
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("BALANCED TRAINING DATASET CREATED")
print("=" * 70)

print("\nTotal rows:")
print(f"{len(train_df):,}")

print("\nBENIGN:")
print(
    f"{(train_df['binary_label'] == 0).sum():,}"
)

print("\nATTACK:")
print(
    f"{(train_df['binary_label'] == 1).sum():,}"
)

print("\nAttack-family distribution:")

distribution = (
    train_df[
        train_df["binary_label"] == 1
    ]["original_label"]
    .value_counts()
)

for label in KNOWN_ATTACKS:

    count = int(
        distribution.get(label, 0)
    )

    print(
        f"  {label}: {count:,}"
    )

# ------------------------------------------------------------
# ZERO-DAY CHECK
# ------------------------------------------------------------

print("\n" + "-" * 70)
print("ZERO-DAY SEPARATION CHECK")
print("-" * 70)

unseen_rows = train_df[
    train_df["original_label"].isin(
        UNSEEN_ATTACKS
    )
]

if len(unseen_rows) == 0:
    print(
        "PASS: DDoS and PortScan are absent from training."
    )
else:
    print(
        "ERROR: Unseen attack samples found:",
        len(unseen_rows)
    )

print("\nSaved:")
print(output_file)

print("\n=== STEP 9 COMPLETE ===")
