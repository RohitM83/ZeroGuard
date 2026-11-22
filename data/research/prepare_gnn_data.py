import os
import numpy as np
import pandas as pd

# ============================================================
# ZERO GUARD - STEP 15.3
# FEATURE PREPROCESSING FOR PUBLICATION GNN EXPERIMENT
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

TRAIN_FILE = os.path.join(
    BASE_DIR,
    "processed",
    "evaluation",
    "train_zero_day_publication.csv"
)

TEST_FILE = os.path.join(
    BASE_DIR,
    "processed",
    "evaluation",
    "test_zero_day.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "processed",
    "evaluation",
    "gnn_ready_publication"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

TRAIN_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "train_gnn.npz"
)

TEST_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "test_gnn.npz"
)

STATS_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "feature_statistics.csv"
)

# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("ZERO GUARD - STEP 15.3")
print("FEATURE PREPROCESSING FOR PUBLICATION GNN")
print("=" * 70)

# ============================================================
# CHECK FILES
# ============================================================

if not os.path.exists(TRAIN_FILE):

    raise FileNotFoundError(
        f"Training file not found:\n{TRAIN_FILE}"
    )

if not os.path.exists(TEST_FILE):

    raise FileNotFoundError(
        f"Test file not found:\n{TEST_FILE}"
    )

print("\nTraining file:")
print(TRAIN_FILE)

print("\nTest file:")
print(TEST_FILE)

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading publication training data...")

train_df = pd.read_csv(
    TRAIN_FILE
)

print(
    f"Training rows: {len(train_df):,}"
)

print(
    f"Training columns: {len(train_df.columns)}"
)

print("\nLoading test data...")

test_df = pd.read_csv(
    TEST_FILE
)

print(
    f"Test rows: {len(test_df):,}"
)

print(
    f"Test columns: {len(test_df.columns)}"
)

# ============================================================
# VERIFY LABEL COLUMNS
# ============================================================

required_columns = [
    "binary_label",
    "original_label"
]

for column in required_columns:

    if column not in train_df.columns:

        raise ValueError(
            f"Missing column in training data: {column}"
        )

    if column not in test_df.columns:

        raise ValueError(
            f"Missing column in test data: {column}"
        )

# ============================================================
# ZERO-DAY SEPARATION CHECK
# ============================================================

print("\n" + "=" * 70)
print("ZERO-DAY SEPARATION CHECK")
print("=" * 70)

train_labels = (
    train_df["original_label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

test_labels = (
    test_df["original_label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

unseen_attacks = [
    "ddos",
    "portscan"
]

for attack in unseen_attacks:

    train_count = int(
        train_labels.str.contains(
            attack,
            regex=False
        ).sum()
    )

    test_count = int(
        test_labels.str.contains(
            attack,
            regex=False
        ).sum()
    )

    print(
        f"{attack.upper():10s} -> "
        f"TRAIN: {train_count:,} | "
        f"TEST: {test_count:,}"
    )

    if train_count > 0:

        raise ValueError(
            f"ZERO-DAY ERROR: {attack} "
            "found in training data!"
        )

print(
    "\nPASS: DDoS and PortScan remain unseen "
    "during training."
)

# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("TRAINING LABEL DISTRIBUTION")
print("=" * 70)

print(
    train_df["original_label"]
    .value_counts()
    .to_string()
)

print("\nBinary labels:")

print(
    f"BENIGN: "
    f"{(train_df['binary_label'] == 0).sum():,}"
)

print(
    f"ATTACK: "
    f"{(train_df['binary_label'] == 1).sum():,}"
)

# ============================================================
# IDENTIFY FEATURE COLUMNS
# ============================================================

NON_FEATURE_COLUMNS = [
    "binary_label",
    "original_label"
]

feature_columns = [
    column
    for column in train_df.columns
    if column not in NON_FEATURE_COLUMNS
]

print("\n" + "=" * 70)
print("FEATURE INFORMATION")
print("=" * 70)

print(
    f"Total feature columns: "
    f"{len(feature_columns)}"
)

print("\nFirst 10 features:")

for feature in feature_columns[:10]:

    print(
        f"  {feature}"
    )

# ============================================================
# VERIFY TEST FEATURES MATCH TRAIN FEATURES
# ============================================================

test_feature_columns = [
    column
    for column in test_df.columns
    if column not in NON_FEATURE_COLUMNS
]

if feature_columns != test_feature_columns:

    raise ValueError(
        "Training and test feature columns do not match."
    )

print(
    "\nTraining/test feature columns: PASS"
)

# ============================================================
# CONVERT FEATURES TO NUMERIC
# ============================================================

print(
    "\nConverting features to numeric values..."
)

train_features = train_df[
    feature_columns
].apply(
    pd.to_numeric,
    errors="coerce"
)

test_features = test_df[
    feature_columns
].apply(
    pd.to_numeric,
    errors="coerce"
)

# ============================================================
# REPLACE INF VALUES
# ============================================================

print(
    "Checking infinite values..."
)

train_features = train_features.replace(
    [np.inf, -np.inf],
    np.nan
)

test_features = test_features.replace(
    [np.inf, -np.inf],
    np.nan
)

# ============================================================
# TRAINING STATISTICS ONLY
# ============================================================

print(
    "\nCalculating training statistics..."
)

train_means = train_features.mean()

train_stds = train_features.std()

train_stds = train_stds.replace(
    0,
    1
)

train_stds = train_stds.fillna(
    1
)

train_means = train_means.fillna(
    0
)

# ============================================================
# MISSING VALUES
# ============================================================

print(
    "Handling missing values..."
)

train_features = train_features.fillna(
    train_means
)

test_features = test_features.fillna(
    train_means
)

# ============================================================
# STANDARDIZATION
#
# IMPORTANT:
# Statistics come ONLY from training data.
# ============================================================

print(
    "Standardizing features..."
)

train_scaled = (
    train_features - train_means
) / train_stds

test_scaled = (
    test_features - train_means
) / train_stds

# ============================================================
# NUMPY ARRAYS
# ============================================================

X_train = train_scaled.to_numpy(
    dtype=np.float32
)

X_test = test_scaled.to_numpy(
    dtype=np.float32
)

y_train = train_df[
    "binary_label"
].to_numpy(
    dtype=np.int64
)

y_test = test_df[
    "binary_label"
].to_numpy(
    dtype=np.int64
)

# ============================================================
# FINAL NUMERICAL CLEANUP
# ============================================================

X_train = np.nan_to_num(
    X_train,
    nan=0.0,
    posinf=0.0,
    neginf=0.0
)

X_test = np.nan_to_num(
    X_test,
    nan=0.0,
    posinf=0.0,
    neginf=0.0
)

# ============================================================
# SAVE GNN DATA
# ============================================================

print(
    "\nSaving publication GNN-ready datasets..."
)

np.savez_compressed(
    TRAIN_OUTPUT,
    X=X_train,
    y=y_train,
    feature_names=np.array(
        feature_columns
    )
)

np.savez_compressed(
    TEST_OUTPUT,
    X=X_test,
    y=y_test,
    feature_names=np.array(
        feature_columns
    )
)

# ============================================================
# SAVE FEATURE STATISTICS
# ============================================================

stats_df = pd.DataFrame({
    "feature": feature_columns,
    "mean": train_means.values,
    "std": train_stds.values
})

stats_df.to_csv(
    STATS_OUTPUT,
    index=False
)

# ============================================================
# FINAL VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("FINAL VALIDATION")
print("=" * 70)

print(
    f"X_train shape: {X_train.shape}"
)

print(
    f"y_train shape: {y_train.shape}"
)

print(
    f"X_test shape:  {X_test.shape}"
)

print(
    f"y_test shape:  {y_test.shape}"
)

print(
    f"\nTraining BENIGN: "
    f"{(y_train == 0).sum():,}"
)

print(
    f"Training ATTACK: "
    f"{(y_train == 1).sum():,}"
)

print(
    f"Test BENIGN: "
    f"{(y_test == 0).sum():,}"
)

print(
    f"Test ATTACK: "
    f"{(y_test == 1).sum():,}"
)

print(
    f"\nTraining NaN values: "
    f"{np.isnan(X_train).sum():,}"
)

print(
    f"Test NaN values: "
    f"{np.isnan(X_test).sum():,}"
)

print(
    f"Training infinite values: "
    f"{np.isinf(X_train).sum():,}"
)

print(
    f"Test infinite values: "
    f"{np.isinf(X_test).sum():,}"
)

# ============================================================
# TEST ATTACK FAMILIES
# ============================================================

print(
    "\nTest attack families:"
)

test_distribution = (
    test_df["original_label"]
    .value_counts()
)

for label, count in test_distribution.items():

    print(
        f"  {label}: {count:,}"
    )

# ============================================================
# FINAL ZERO-DAY CHECK
# ============================================================

print("\n" + "=" * 70)
print("FINAL ZERO-DAY CHECK")
print("=" * 70)

for attack in unseen_attacks:

    count = int(
        train_labels.str.contains(
            attack,
            regex=False
        ).sum()
    )

    print(
        f"{attack.upper():10s}: "
        f"{count:,} training rows"
    )

    if count != 0:

        raise ValueError(
            f"FAILED: {attack} exists "
            "in training data."
        )

print(
    "\nPASS: Unseen attack families "
    "remain completely excluded."
)

# ============================================================
# COMPLETION
# ============================================================

print("\n" + "=" * 70)
print("STEP 15.3 COMPLETE")
print("=" * 70)

print("\nCreated:")

print(
    TRAIN_OUTPUT
)

print(
    TEST_OUTPUT
)

print(
    STATS_OUTPUT
)

print(
    "\nThe publication dataset is now ready "
    "for graph construction."
)