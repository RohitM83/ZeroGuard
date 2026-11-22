from collections import Counter
from datetime import datetime, timedelta

from database import get_connection


# ============================================================
# CONFIGURATION
# ============================================================

WINDOW_MINUTES = 5

HIGH_CONNECTION_COUNT = 50
HIGH_PORT_COUNT = 20
HIGH_DESTINATION_COUNT = 30


# ============================================================
# GET RECENT NETWORK EVENTS
# ============================================================

def get_recent_events():

    connection = get_connection()

    events = connection.execute(
        """
        SELECT
            id,
            source_ip,
            destination_ip,
            protocol,
            port,
            event_type,
            risk,
            timestamp
        FROM network_events
        WHERE timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
        """,
        (f"-{WINDOW_MINUTES} minutes",),
    ).fetchall()

    connection.close()

    return [dict(event) for event in events]


# ============================================================
# ANALYZE NETWORK BEHAVIOR
# ============================================================

def analyze_behavior(events):

    if not events:
        return {
            "status": "normal",
            "risk_score": 0,
            "reasons": [],
            "recommended_action": "No action required"
        }

    reasons = []
    risk_score = 0

    source_ips = Counter()
    destination_ips = Counter()
    ports = Counter()

    for event in events:

        source_ips[event["source_ip"]] += 1

        if event["destination_ip"]:
            destination_ips[event["destination_ip"]] += 1

        ports[event["port"]] += 1

    # --------------------------------------------------------
    # Rule 1: High connection volume
    # --------------------------------------------------------

    total_connections = len(events)

    if total_connections >= HIGH_CONNECTION_COUNT:

        risk_score += 30

        reasons.append(
            f"High network activity detected: "
            f"{total_connections} connections in "
            f"{WINDOW_MINUTES} minutes."
        )

    # --------------------------------------------------------
    # Rule 2: Many different ports
    # --------------------------------------------------------

    unique_ports = len(ports)

    if unique_ports >= HIGH_PORT_COUNT:

        risk_score += 30

        reasons.append(
            f"Unusually high number of destination/source ports: "
            f"{unique_ports}."
        )

    # --------------------------------------------------------
    # Rule 3: Many different destinations
    # --------------------------------------------------------

    unique_destinations = len(destination_ips)

    if unique_destinations >= HIGH_DESTINATION_COUNT:

        risk_score += 40

        reasons.append(
            f"Large number of different destinations detected: "
            f"{unique_destinations}."
        )

    # --------------------------------------------------------
    # Determine final risk
    # --------------------------------------------------------

    if risk_score >= 70:

        status = "critical"

    elif risk_score >= 50:

        status = "high"

    elif risk_score >= 30:

        status = "medium"

    else:

        status = "low"

    # --------------------------------------------------------
    # Recommended response
    # --------------------------------------------------------

    if status == "critical":

        recommended_action = (
            "Isolate the affected device and investigate "
            "the network activity immediately."
        )

    elif status == "high":

        recommended_action = (
            "Investigate the source device and monitor "
            "the suspicious connections."
        )

    elif status == "medium":

        recommended_action = (
            "Continue monitoring the activity."
        )

    else:

        recommended_action = (
            "No immediate action required."
        )

    return {
        "status": status,
        "risk_score": risk_score,
        "reasons": reasons,
        "recommended_action": recommended_action,
        "total_connections": total_connections,
        "unique_destinations": unique_destinations,
        "unique_ports": unique_ports,
    }


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def detect_threats():

    events = get_recent_events()

    result = analyze_behavior(events)

    return {
        "timestamp": datetime.now().isoformat(),
        **result
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("========================================")
    print(" ZeroGuard Detection Engine")
    print("========================================")

    result = detect_threats()

    print()
    print("Detection Result")
    print("----------------")
    print(f"Status: {result['status']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Connections: {result.get('total_connections', 0)}")
    print(f"Unique Destinations: {result.get('unique_destinations', 0)}")
    print(f"Unique Ports: {result.get('unique_ports', 0)}")

    print()

    if result["reasons"]:

        print("Reasons:")

        for reason in result["reasons"]:
            print(f"- {reason}")

    else:

        print("No suspicious behavior detected.")

    print()
    print("Recommended Action:")
    print(result["recommended_action"])
    print()