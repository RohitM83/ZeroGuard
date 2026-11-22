import pandas as pd
from pathlib import Path

file = Path(
    r"data\research\processed\cic_ids2017_binary.csv"
)

print("\n" + "=" * 70)
print("ZERO GUARD RESEARCH DATASET VERIFICATION")
print("=" * 70)

print("\nFile:")
print(file)

print("\nFile exists:", file.exists())

if not file.exists():
    print("\nERROR: Processed dataset not found.")
    raise SystemExit(1)

size_mb = file.stat().st_size / (1024 * 1024)

print(f"File size: {size_mb:.2f} MB")

# --------------------------------------------------
# READ SAMPLE
# --------------------------------------------------

print("\nReading sample...")

sample = pd.read_csv(
    file,
    nrows=1000,
    low_memory=False
)

print("Sample rows:", len(sample))
print("Number of columns:", len(sample.columns))

print("\n=== COLUMN LIST ===")

for i, column in enumerate(sample.columns):
    print(f"{i}: {column}")

# --------------------------------------------------
# CHECK LABEL
# --------------------------------------------------

print("\n=== BINARY LABEL CHECK ===")

print(
    sample["binary_label"]
    .value_counts()
    .sort_index()
)

print("\nUnique binary labels:")
print(
    sorted(
        sample["binary_label"]
        .dropna()
        .unique()
        .tolist()
    )
)

# --------------------------------------------------
# ORIGINAL LABEL CHECK
# --------------------------------------------------

print("\n=== ORIGINAL LABEL SAMPLE ===")

print(
    sample["original_label"]
    .value_counts()
    .head(20)
)

# --------------------------------------------------
# MISSING VALUES
# --------------------------------------------------

print("\n=== MISSING VALUE CHECK ===")

missing = sample.isna().sum()

total_missing = int(missing.sum())

print("Total missing values in sample:", total_missing)

if total_missing == 0:
    print("PASS: No missing values.")
else:
    print("WARNING: Missing values found.")

# --------------------------------------------------
# INFINITE VALUES
# --------------------------------------------------

print("\n=== INFINITE VALUE CHECK ===")

numeric_sample = sample.select_dtypes(
    include="number"
)

infinite_count = 0

for column in numeric_sample.columns:
    infinite_count += int(
        numeric_sample[column]
        .isin([float("inf"), float("-inf")])
        .sum()
    )

print(
    "Infinite values in sample:",
    infinite_count
)

if infinite_count == 0:
    print("PASS: No infinite values.")
else:
    print("WARNING: Infinite values found.")

# --------------------------------------------------
# DATA TYPES
# --------------------------------------------------

print("\n=== DATA TYPES ===")

print(
    sample.dtypes.value_counts()
)

# --------------------------------------------------
# FEATURE COUNT
# --------------------------------------------------

feature_columns = [
    column
    for column in sample.columns
    if column not in [
        "binary_label",
        "original_label"
    ]
]

print("\n=== FEATURE SUMMARY ===")

print(
    "Network features:",
    len(feature_columns)
)

print(
    "Target column:",
    "binary_label"
)

print(
    "Original label column:",
    "original_label"
)

# --------------------------------------------------
# DUPLICATE SAMPLE CHECK
# --------------------------------------------------

print("\n=== DUPLICATE CHECK ===")

duplicates = int(
    sample.duplicated().sum()
)

print(
    "Duplicate rows in 1000-row sample:",
    duplicates
)

# --------------------------------------------------
# FINAL
# --------------------------------------------------

print("\n" + "=" * 70)
print("STEP 7 VERIFICATION COMPLETE")
print("=" * 70)

print("\nDataset is ready for the next research step.")
