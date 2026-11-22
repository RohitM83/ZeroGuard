import json
import time
from datetime import datetime

from feature_engineering import get_network_features


OUTPUT_FILE = "training_data.json"

NUMBER_OF_SAMPLES = 20

COLLECTION_INTERVAL = 10


def collect_training_data():

    dataset = []

    print()
    print("========================================")
    print(" ZeroGuard Training Data Collection")
    print("========================================")
    print()

    print(f"Samples: {NUMBER_OF_SAMPLES}")
    print(f"Interval: {COLLECTION_INTERVAL} seconds")
    print()

    print(
        "Keep your computer running normally while "
        "this collection is happening."
    )

    print()

    for sample_number in range(1, NUMBER_OF_SAMPLES + 1):

        try:

            features = get_network_features()

            sample = {
                "timestamp": datetime.now().isoformat(),
                "features": features,
                "label": 0
            }

            dataset.append(sample)

            print(
                f"[{sample_number}/{NUMBER_OF_SAMPLES}] "
                f"Connections: "
                f"{features['total_connections']} | "
                f"Destinations: "
                f"{features['unique_destinations']} | "
                f"Ports: "
                f"{features['unique_ports']}"
            )

        except Exception as error:

            print(
                f"[ERROR] {error}"
            )

        if sample_number < NUMBER_OF_SAMPLES:

            time.sleep(COLLECTION_INTERVAL)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            dataset,
            file,
            indent=4
        )

    print()
    print("========================================")
    print(" Collection Complete")
    print("========================================")
    print()

    print(
        f"Saved {len(dataset)} samples to "
        f"{OUTPUT_FILE}"
    )

    print()

    print(
        "These samples represent your normal "
        "network behavior baseline."
    )

    print()


if __name__ == "__main__":

    collect_training_data()