import json
import time
from datetime import datetime
from pathlib import Path

from graph_builder import build_graph
from network_collector import collect_network_connections


# ============================================================
# ZERO GUARD BASELINE COLLECTOR
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
BASELINE_FILE = BASE_DIR / "normal_baseline.json"

NUMBER_OF_SAMPLES = 10
COLLECTION_INTERVAL = 10


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def collect_baseline_sample(sample_number):

    print()
    print("-" * 60)
    print(f"Collecting baseline sample {sample_number}")
    print("-" * 60)

    events = collect_network_connections()

    print(
        f"Current network connections detected: {len(events)}"
    )

    if not events:

        print("No network connections found.")
        return None

    # Convert the current network state into the same graph
    # representation used by the existing GNN.
    #
    # The current graph_builder reads from the database, so
    # this first version records the collected event snapshot.
    sample = {
        "sample_number": sample_number,
        "timestamp": datetime.now().isoformat(),
        "event_count": len(events),
        "events": events,
    }

    return sample


# ============================================================
# SAVE BASELINE DATA
# ============================================================

def save_baseline(samples):

    with open(
        BASELINE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            samples,
            file,
            indent=4
        )

    print()
    print("=" * 60)
    print("BASELINE DATA SAVED")
    print("=" * 60)
    print(f"Samples saved : {len(samples)}")
    print(f"Output file   : {BASELINE_FILE}")
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("ZeroGuard Normal Baseline Collector")
    print("=" * 60)

    print()
    print(
        "This process only records network snapshots."
    )
    print(
        "It does not create threats or execute responses."
    )
    print()
    print(
        f"Samples          : {NUMBER_OF_SAMPLES}"
    )
    print(
        f"Interval         : {COLLECTION_INTERVAL} seconds"
    )

    samples = []

    for sample_number in range(
        1,
        NUMBER_OF_SAMPLES + 1
    ):

        sample = collect_baseline_sample(
            sample_number
        )

        if sample is not None:

            samples.append(sample)

        if sample_number < NUMBER_OF_SAMPLES:

            print()
            print(
                f"Waiting {COLLECTION_INTERVAL} seconds..."
            )

            time.sleep(
                COLLECTION_INTERVAL
            )

    save_baseline(samples)

    print()
    print("Baseline collection completed.")


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()