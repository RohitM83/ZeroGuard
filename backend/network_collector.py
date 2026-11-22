import socket
from datetime import datetime

import psutil

from database import get_connection


# ============================================================
# ZERO GUARD NETWORK COLLECTOR
# ============================================================


# ============================================================
# PROTOCOL
# ============================================================

def get_protocol(connection):

    if connection.type == socket.SOCK_STREAM:

        return "TCP"

    if connection.type == socket.SOCK_DGRAM:

        return "UDP"

    return "OTHER"


# ============================================================
# RISK ASSESSMENT
# ============================================================

def assess_risk(
    protocol,
    port,
    event_type
):

    protocol = (
        protocol or ""
    ).upper()

    event_type = (
        event_type or ""
    ).upper()

    try:

        port = int(port)

    except (
        TypeError,
        ValueError
    ):

        port = None

    # --------------------------------------------------------
    # High-risk ports
    # --------------------------------------------------------

    high_risk_ports = {

        23,      # Telnet
        135,
        139,
        445,     # SMB
        1433,    # MSSQL
        3389,    # RDP
        5900,    # VNC
        6379,    # Redis
        27017    # MongoDB

    }

    if port in high_risk_ports:

        return "high"

    # --------------------------------------------------------
    # Suspicious connection states
    # --------------------------------------------------------

    if event_type in (
        "SYN_SENT",
        "SYN_RECV"
    ):

        return "medium"

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if protocol == "UDP" and port is not None:

        if port > 40000:

            return "medium"

    return "low"


# ============================================================
# LOCAL DEVICE
# ============================================================

def get_local_device():

    hostname = socket.gethostname()

    try:

        local_ip = socket.gethostbyname(
            hostname
        )

    except Exception:

        local_ip = "127.0.0.1"

    now = datetime.now().isoformat()

    return {

        "name": hostname,

        "ip_address": local_ip,

        "status": "online",

        "risk_level": "low",

        "last_seen": now,

        "device_name": hostname,

        "mac_address": None,

        "device_type": "Computer",

        "created_at": now

    }


# ============================================================
# SAVE DEVICE
# ============================================================

def save_device():

    device = get_local_device()

    connection = get_connection()

    cursor = connection.cursor()

    try:

        existing = cursor.execute(
            """
            SELECT id

            FROM devices

            WHERE ip_address = ?

            LIMIT 1
            """,
            (
                device["ip_address"],
            )
        ).fetchone()

        if existing:

            cursor.execute(
                """
                UPDATE devices

                SET

                    name = ?,

                    status = ?,

                    risk_level = ?,

                    last_seen = ?,

                    device_name = ?,

                    device_type = ?

                WHERE id = ?
                """,
                (

                    device["name"],

                    device["status"],

                    device["risk_level"],

                    device["last_seen"],

                    device["device_name"],

                    device["device_type"],

                    existing["id"]

                )
            )

            device_id = existing["id"]

        else:

            cursor.execute(
                """
                INSERT INTO devices
                (
                    name,
                    ip_address,
                    status,
                    risk_level,
                    last_seen,
                    device_name,
                    mac_address,
                    device_type,
                    created_at
                )

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (

                    device["name"],

                    device["ip_address"],

                    device["status"],

                    device["risk_level"],

                    device["last_seen"],

                    device["device_name"],

                    device["mac_address"],

                    device["device_type"],

                    device["created_at"]

                )
            )

            device_id = cursor.lastrowid

        connection.commit()

        return device_id

    finally:

        connection.close()


# ============================================================
# COLLECT NETWORK CONNECTIONS
# ============================================================

def collect_network_connections():

    connections = []

    try:

        system_connections = (
            psutil.net_connections(
                kind="inet"
            )
        )

    except Exception as error:

        print(
            "Unable to read network connections:",
            error
        )

        return connections

    timestamp = datetime.now().isoformat()

    for connection in system_connections:

        if not connection.laddr:

            continue

        source_ip = connection.laddr.ip

        source_port = connection.laddr.port

        destination_ip = ""

        destination_port = None

        if connection.raddr:

            destination_ip = connection.raddr.ip

            destination_port = connection.raddr.port

        protocol = get_protocol(
            connection
        )

        port = (
            destination_port
            if destination_port is not None
            else source_port
        )

        event_type = (
            connection.status
            if connection.status
            else "NETWORK_CONNECTION"
        )

        risk = assess_risk(
            protocol,
            port,
            event_type
        )

        event = {

            "source_ip":
                source_ip,

            "destination_ip":
                destination_ip,

            "protocol":
                protocol,

            "port":
                port,

            "event_type":
                event_type,

            "risk":
                risk,

            "timestamp":
                timestamp

        }

        connections.append(event)

    return connections


# ============================================================
# SAVE NETWORK EVENTS
# ============================================================

def save_network_events(events):

    connection = get_connection()

    cursor = connection.cursor()

    saved_count = 0

    try:

        for event in events:

            # ------------------------------------------------
            # Only suppress an identical event recorded
            # during the last 30 seconds.
            # ------------------------------------------------

            existing = cursor.execute(
                """
                SELECT id

                FROM network_events

                WHERE source_ip = ?

                AND destination_ip = ?

                AND protocol = ?

                AND port = ?

                AND event_type = ?

                AND timestamp >= datetime(
                    'now',
                    '-30 seconds'
                )

                LIMIT 1
                """,
                (

                    event["source_ip"],

                    event["destination_ip"],

                    event["protocol"],

                    event["port"],

                    event["event_type"]

                )
            ).fetchone()

            if existing is not None:

                continue

            cursor.execute(
                """
                INSERT INTO network_events
                (
                    source_ip,
                    destination_ip,
                    protocol,
                    port,
                    event_type,
                    risk,
                    timestamp,
                    threat_id
                )

                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (

                    event["source_ip"],

                    event["destination_ip"],

                    event["protocol"],

                    event["port"],

                    event["event_type"],

                    event["risk"],

                    event["timestamp"],

                    None

                )
            )

            saved_count += 1

        connection.commit()

    finally:

        connection.close()

    return saved_count


# ============================================================
# MAIN
# ============================================================

def main():

    print()

    print("=" * 60)
    print("ZeroGuard Network Collector")
    print("=" * 60)

    try:

        # ----------------------------------------------------
        # DEVICE
        # ----------------------------------------------------

        device_id = save_device()

        print(
            f"Local device registered successfully. "
            f"Device ID: {device_id}"
        )

        # ----------------------------------------------------
        # NETWORK
        # ----------------------------------------------------

        events = collect_network_connections()

        print(
            f"Collected {len(events)} network connections."
        )

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        saved = save_network_events(
            events
        )

        print(
            f"Saved {saved} new network events."
        )

        print()

        print("=" * 60)
        print("COLLECTION COMPLETE")
        print("=" * 60)

    except Exception as error:

        print()

        print("=" * 60)
        print("COLLECTOR ERROR")
        print("=" * 60)

        print(
            f"{type(error).__name__}: {error}"
        )

        print("=" * 60)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()