from collections import Counter

from database import get_connection


# Number of most recent network events
# used for current GNN analysis.
WINDOW_SIZE = 100


def get_network_features():

    connection = get_connection()

    events = connection.execute(
        """
        SELECT
            source_ip,
            destination_ip,
            protocol,
            port,
            event_type
        FROM network_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (WINDOW_SIZE,)
    ).fetchall()

    connection.close()

    if not events:
        return {
            "total_connections": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "unique_ports": 0,
            "tcp_connections": 0,
            "udp_connections": 0,
            "established_connections": 0,
            "listening_connections": 0,
        }

    sources = Counter()
    destinations = Counter()
    ports = Counter()

    tcp_connections = 0
    udp_connections = 0
    established_connections = 0
    listening_connections = 0

    for event in events:

        sources[event["source_ip"]] += 1

        if event["destination_ip"]:
            destinations[event["destination_ip"]] += 1

        if event["port"] is not None:
            ports[event["port"]] += 1

        if event["protocol"] == "TCP":
            tcp_connections += 1

        elif event["protocol"] == "UDP":
            udp_connections += 1

        if event["event_type"] == "ESTABLISHED":
            established_connections += 1

        elif event["event_type"] == "LISTEN":
            listening_connections += 1

    features = {
        "total_connections": len(events),
        "unique_sources": len(sources),
        "unique_destinations": len(destinations),
        "unique_ports": len(ports),
        "tcp_connections": tcp_connections,
        "udp_connections": udp_connections,
        "established_connections": established_connections,
        "listening_connections": listening_connections,
    }

    return features


if __name__ == "__main__":

    print()
    print("========================================")
    print(" ZeroGuard Feature Extraction")
    print("========================================")

    print(f"Analyzing latest {WINDOW_SIZE} events")

    features = get_network_features()

    print()

    for name, value in features.items():
        print(f"{name}: {value}")

    print()