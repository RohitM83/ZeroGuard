import pandas as pd
from pathlib import Path

# --------------------------------------------------
# PATHS
# --------------------------------------------------

input_folder = Path(
    r"data\research\raw\CIC-IDS2017\MachineLearningCVE"
)

output_folder = Path(
    r"data\research\processed"
)

output_file = output_folder / "cic_ids2017_binary.csv"

output_folder.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

CHUNK_SIZE = 100000

first_file = True
total_rows = 0
benign_rows = 0
attack_rows = 0

files = sorted(input_folder.glob("*.csv"))

print("\n" + "=" * 70)
print("CIC-IDS2017 BINARY DATASET PREPROCESSING")
print("=" * 70)

print("\nInput folder:")
print(input_folder)

print("\nOutput file:")
print(output_file)

print("\nCSV files found:", len(files))

# --------------------------------------------------
# PROCESS EACH FILE
# --------------------------------------------------

for file in files:

    print("\n" + "-" * 70)
    print("Processing:", file.name)
    print("-" * 70)

    # Read header
    header = pd.read_csv(file, nrows=0)

    # Detect Label column safely
    label_column = None

    for column in header.columns:
        cleaned = (
            str(column)
            .replace("\ufeff", "")
            .strip()
            .lower()
        )

        if cleaned == "label":
            label_column = column
            break

    if label_column is None:
        print("ERROR: Label column not found.")
        continue

    file_rows = 0
    file_benign = 0
    file_attack = 0

    # --------------------------------------------------
    # CHUNK PROCESSING
    # --------------------------------------------------

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ),
        start=1
    ):

        print(
            f"  Chunk {chunk_number}: "
            f"{len(chunk):,} rows"
        )

        # Clean column names
        chunk.columns = [
            str(column)
            .replace("\ufeff", "")
            .strip()
            for column in chunk.columns
        ]

        # Find cleaned label column
        cleaned_label_column = None

        for column in chunk.columns:
            if column.lower() == "label":
                cleaned_label_column = column
                break

        if cleaned_label_column is None:
            print("ERROR: Cleaned Label column not found.")
            continue

        # --------------------------------------------------
        # CLEAN LABELS
        # --------------------------------------------------

        labels = (
            chunk[cleaned_label_column]
            .astype(str)
            .str.replace("\ufeff", "", regex=False)
            .str.strip()
        )

        # Binary classification:
        # BENIGN = 0
        # Everything else = 1

        chunk["binary_label"] = (
            labels != "BENIGN"
        ).astype("int8")

        # Keep original label for verification
        chunk["original_label"] = labels

        # --------------------------------------------------
        # CLEAN NUMERIC FEATURES
        # --------------------------------------------------

        feature_columns = [
            column
            for column in chunk.columns
            if column not in [
                "binary_label",
                "original_label",
                cleaned_label_column
            ]
        ]

        for column in feature_columns:
            chunk[column] = pd.to_numeric(
                chunk[column],
                errors="coerce"
            )

        # Replace infinite values
        chunk[feature_columns] = (
            chunk[feature_columns]
            .replace([float("inf"), float("-inf")], pd.NA)
        )

        # Fill missing numeric values
        chunk[feature_columns] = (
            chunk[feature_columns]
            .fillna(0)
        )

        # --------------------------------------------------
        # WRITE OUTPUT
        # --------------------------------------------------

        # Remove original Label column
        chunk = chunk.drop(
            columns=[cleaned_label_column]
        )

        # Write header only for first chunk
        chunk.to_csv(
            output_file,
            mode="w" if first_file else "a",
            header=first_file,
            index=False
        )

        first_file = False

        # Statistics
        rows = len(chunk)

        benign = int(
            (chunk["binary_label"] == 0).sum()
        )

        attack = int(
            (chunk["binary_label"] == 1).sum()
        )

        total_rows += rows
        benign_rows += benign
        attack_rows += attack

        file_rows += rows
        file_benign += benign
        file_attack += attack

    print("\nFile summary:")
    print("  Rows:", f"{file_rows:,}")
    print("  BENIGN:", f"{file_benign:,}")
    print("  ATTACK:", f"{file_attack:,}")

# --------------------------------------------------
# FINAL SUMMARY
# --------------------------------------------------

print("\n" + "=" * 70)
print("PREPROCESSING COMPLETE")
print("=" * 70)

print("\nTotal rows:", f"{total_rows:,}")
print("BENIGN:", f"{benign_rows:,}")
print("ATTACK:", f"{attack_rows:,}")

if total_rows > 0:
    benign_percentage = (
        benign_rows / total_rows
    ) * 100

    attack_percentage = (
        attack_rows / total_rows
    ) * 100

    print(
        f"\nBENIGN percentage: "
        f"{benign_percentage:.2f}%"
    )

    print(
        f"ATTACK percentage: "
        f"{attack_percentage:.2f}%"
    )

print("\nSaved dataset:")
print(output_file)

if output_file.exists():
    size_mb = output_file.stat().st_size / (
        1024 * 1024
    )

    print(
        f"Output size: {size_mb:.2f} MB"
    )

print("\n=== STEP 6 COMPLETE ===")
