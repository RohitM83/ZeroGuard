import time

from network_collector import (
    collect_network_connections,
    save_network_events,
)


COLLECTION_INTERVAL = 30


def start_collector():

    print("========================================")
    print(" ZeroGuard Network Collector")
    print("========================================")
    print(f"Collection interval: {COLLECTION_INTERVAL} seconds")
    print()

    while True:

        try:

            events = collect_network_connections()

            saved = save_network_events(events)

            print(
                f"[Collector] "
                f"Collected: {len(events)} | "
                f"Saved: {saved}"
            )

        except Exception as error:

            print(
                f"[Collector Error] {error}"
            )

        time.sleep(COLLECTION_INTERVAL)


if __name__ == "__main__":
    start_collector()