import os
import pandas as pd

# ============================================================
# ZERO GUARD
# STEP 15.2
# PUBLICATION TRAINING DATASET
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROCESSED_DIR = os.path.join(
    BASE_DIR,
    "processed"
)

EVALUATION_DIR = os.path.join(
    PROCESSED_DIR,
    "evaluation"
)

INPUT_FILE = os.path.join(
    PROCESSED_DIR,
    "cic_ids2017_binary.csv"
)

OUTPUT_FILE = os.path.join(
    EVALUATION_DIR,
    "train_zero_day_publication.csv"
)

RANDOM_STATE = 42

BENIGN_TARGET = 100_000

ATTACK_CAP = 10_000

# ============================================================
# CHECK INPUT
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.2")
print("PUBLICATION TRAINING DATASET")
print("=" * 70)

if not os.path.exists(INPUT_FILE):

    raise FileNotFoundError(
        f"Input file not found:\n{INPUT_FILE}"
    )

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading processed CIC-IDS2017 dataset...")

df = pd.read_csv(
    INPUT_FILE
)

print(
    f"Total rows loaded: {len(df):,}"
)

# ============================================================
# CLEAN LABELS
# ============================================================

df["original_label"] = (
    df["original_label"]
    .astype(str)
    .str.strip()
)

df["label_clean"] = (
    df["original_label"]
    .str.lower()
    .str.replace(
        "–",
        "-",
        regex=False
    )
    .str.replace(
        "?",
        "",
        regex=False
    )
    .str.replace(
        "  ",
        " ",
        regex=False
    )
    .str.strip()
)

# ============================================================
# REMOVE UNSEEN ATTACK FAMILIES
# ============================================================

unseen_mask = (
    df["label_clean"]
    .isin(
        [
            "ddos",
            "portscan"
        ]
    )
)

unseen_count = int(
    unseen_mask.sum()
)

print(
    f"\nDDoS + PortScan excluded: "
    f"{unseen_count:,}"
)

known_df = df[
    ~unseen_mask
].copy()

# ============================================================
# BENIGN
# ============================================================

benign_df = known_df[
    known_df["binary_label"] == 0
].copy()

print(
    f"Available BENIGN rows: "
    f"{len(benign_df):,}"
)

if len(benign_df) < BENIGN_TARGET:

    raise ValueError(
        "Not enough benign samples."
    )

benign_sample = benign_df.sample(
    n=BENIGN_TARGET,
    random_state=RANDOM_STATE
)

# ============================================================
# ATTACKS
# ============================================================

attack_df = known_df[
    known_df["binary_label"] == 1
].copy()

print(
    f"Available known attack rows: "
    f"{len(attack_df):,}"
)

# ============================================================
# ATTACK FAMILY NORMALIZATION
# ============================================================

def normalize_family(label):

    label = str(label).strip()

    label_lower = label.lower()

    if "brute force" in label_lower:

        return "Web Attack - Brute Force"

    if "xss" in label_lower:

        return "Web Attack - XSS"

    if "sql injection" in label_lower:

        return "Web Attack - SQL Injection"

    return label

attack_df["attack_family"] = (
    attack_df["original_label"]
    .apply(normalize_family)
)

# ============================================================
# SAMPLE EACH FAMILY
# ============================================================

attack_parts = []

family_counts = (
    attack_df[
        "attack_family"
    ]
    .value_counts()
)

print(
    "\nKnown attack families:"
)

print(
    family_counts.to_string()
)

print(
    "\nSampling up to "
    f"{ATTACK_CAP:,} rows per family..."
)

for family in sorted(
    family_counts.index
):

    family_df = attack_df[
        attack_df["attack_family"] == family
    ]

    sample_count = min(
        ATTACK_CAP,
        len(family_df)
    )

    sampled = family_df.sample(
        n=sample_count,
        random_state=RANDOM_STATE
    )

    attack_parts.append(
        sampled
    )

    print(
        f"{family:35s} "
        f"{sample_count:8,}"
    )

# ============================================================
# COMBINE
# ============================================================

attack_sample = pd.concat(
    attack_parts,
    ignore_index=True
)

print(
    f"\nTotal sampled known attacks: "
    f"{len(attack_sample):,}"
)

# ============================================================
# REMOVE HELPER COLUMN
# ============================================================

benign_sample = benign_sample.drop(
    columns=["label_clean"],
    errors="ignore"
)

attack_sample = attack_sample.drop(
    columns=[
        "label_clean",
        "attack_family"
    ],
    errors="ignore"
)

# ============================================================
# FINAL DATASET
# ============================================================

train_df = pd.concat(
    [
        benign_sample,
        attack_sample
    ],
    ignore_index=True
)

# Shuffle final dataset

train_df = train_df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(
    drop=True
)

# ============================================================
# FINAL CHECKS
# ============================================================

print("\n" + "=" * 70)
print("FINAL DATASET CHECK")
print("=" * 70)

print(
    f"\nTotal rows: "
    f"{len(train_df):,}"
)

print(
    f"BENIGN: "
    f"{(train_df['binary_label'] == 0).sum():,}"
)

print(
    f"ATTACK: "
    f"{(train_df['binary_label'] == 1).sum():,}"
)

print(
    "\nAttack family distribution:"
)

attack_distribution = (
    train_df[
        train_df["binary_label"] == 1
    ]["original_label"]
    .value_counts()
)

print(
    attack_distribution.to_string()
)

# ============================================================
# ZERO-DAY CHECK
# ============================================================

train_labels_lower = (
    train_df["original_label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

ddos_train = int(
    train_labels_lower.str.contains(
        "ddos",
        regex=False
    ).sum()
)

portscan_train = int(
    train_labels_lower.str.contains(
        "portscan",
        regex=False
    ).sum()
)

print("\nZero-day verification:")

print(
    f"DDoS train rows: "
    f"{ddos_train:,}"
)

print(
    f"PortScan train rows: "
    f"{portscan_train:,}"
)

if ddos_train != 0:

    raise ValueError(
        "ERROR: DDoS found in training dataset."
    )

if portscan_train != 0:

    raise ValueError(
        "ERROR: PortScan found in training dataset."
    )

print(
    "\nPASS: DDoS and PortScan remain unseen."
)

# ============================================================
# SAVE
# ============================================================

print(
    f"\nSaving publication training dataset..."
)

os.makedirs(
    EVALUATION_DIR,
    exist_ok=True
)

train_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print(
    f"\nSaved:\n{OUTPUT_FILE}"
)

print("\n" + "=" * 70)
print("STEP 15.2 COMPLETE")
print("=" * 70)