import time
import requests
from datetime import datetime


API_URL = "http://127.0.0.1:8000"


def analyze_network():

    try:

        response = requests.get(
            f"{API_URL}/api/detection/analyze",
            timeout=10
        )

        if response.status_code != 200:

            print(
                f"[{datetime.now()}] "
                f"Detection API error: "
                f"{response.status_code}"
            )

            return None

        result = response.json()

        return result

    except requests.exceptions.ConnectionError:

        print(
            f"[{datetime.now()}] "
            "Backend is not running."
        )

        return None

    except requests.exceptions.Timeout:

        print(
            f"[{datetime.now()}] "
            "Detection request timed out."
        )

        return None

    except Exception as error:

        print(
            f"[{datetime.now()}] "
            f"Detection error: {error}"
        )

        return None


def print_detection_result(result):

    if result is None:
        return

    print()
    print("=" * 60)
    print("ZERO GUARD AUTOMATIC DETECTION")
    print("=" * 60)

    print(
        f"Time           : {datetime.now()}"
    )

    print(
        f"Anomaly Score  : "
        f"{result.get('anomaly_score', 'N/A')}"
    )

    print(
        f"Status         : "
        f"{result.get('status', 'N/A')}"
    )

    print(
        f"Threat Saved   : "
        f"{result.get('threat_saved', False)}"
    )

    print(
        f"Threat ID      : "
        f"{result.get('threat_id', 'N/A')}"
    )

    print(
        f"Incident ID    : "
        f"{result.get('incident_id', 'N/A')}"
    )

    print(
        f"Linked Events  : "
        f"{result.get('linked_events', 0)}"
    )

    print(
        f"Message        : "
        f"{result.get('message', '')}"
    )

    print("=" * 60)


def main():

    print()
    print("=" * 60)
    print("ZeroGuard Automatic Detection Service")
    print("=" * 60)
    print(
        f"Backend: {API_URL}"
    )
    print(
        "Detection interval: 10 seconds"
    )
    print("Press CTRL+C to stop.")
    print("=" * 60)

    while True:

        result = analyze_network()

        print_detection_result(result)

        time.sleep(10)


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        print("=" * 60)
        print("Automatic Detection Service Stopped")
        print("=" * 60)