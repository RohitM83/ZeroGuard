import json
import os
import platform
import socket
import time
import uuid
from datetime import datetime

import psutil
import requests


# ============================================================
# ZeroGuard Endpoint Agent
# ============================================================

BACKEND_URL = "http://127.0.0.1:8000"

REGISTER_ENDPOINT = f"{BACKEND_URL}/api/agents/register"
HEARTBEAT_ENDPOINT = f"{BACKEND_URL}/api/agents/heartbeat"
EVENTS_ENDPOINT = f"{BACKEND_URL}/api/agents/events"

HEARTBEAT_INTERVAL = 30
EVENT_COLLECTION_INTERVAL = 30

TOKEN_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    ".zeroguard_agent_token.json",
)


# ============================================================
# DEVICE INFORMATION
# ============================================================

def get_hostname():
    return socket.gethostname()


def get_local_ip():
    """
    Detect the local LAN IP without requiring an external
    internet request.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]

    except Exception:
        try:
            return socket.gethostbyname(
                socket.gethostname()
            )
        except Exception:
            return "127.0.0.1"

    finally:
        sock.close()


def get_mac_address():
    mac = uuid.getnode()

    return ":".join(
        f"{(mac >> shift) & 0xff:02x}"
        for shift in range(40, -1, -8)
    )


def get_operating_system():
    return (
        f"{platform.system()} "
        f"{platform.release()} "
        f"({platform.version()})"
    )


def get_device_information():
    hostname = get_hostname()

    return {
        "agent_name": f"ZeroGuard-{hostname}",
        "device_name": hostname,
        "mac_address": get_mac_address(),
        "device_type": "Computer",
        "ip_address": get_local_ip(),
        "operating_system": get_operating_system(),
    }


# ============================================================
# TOKEN STORAGE
# ============================================================

def save_token(data):
    with open(
        TOKEN_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
        )


def load_token():
    if not os.path.exists(TOKEN_FILE):
        return None

    try:
        with open(
            TOKEN_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    except Exception as error:
        print(
            f"[Agent] Could not read token file: {error}"
        )

        return None


# ============================================================
# SERVER COMMUNICATION
# ============================================================

def register_agent():
    device = get_device_information()

    print()
    print("========================================")
    print(" ZeroGuard Endpoint Agent")
    print("========================================")
    print(
        f"Device      : {device['device_name']}"
    )
    print(
        f"IP Address  : {device['ip_address']}"
    )
    print(
        f"MAC Address : {device['mac_address']}"
    )
    print(
        f"Operating System: {device['operating_system']}"
    )
    print()

    existing_token = load_token()

    if existing_token:
        print(
            "[Agent] Existing agent token found."
        )

        return existing_token

    print(
        "[Agent] Registering device with ZeroGuard..."
    )

    response = requests.post(
        REGISTER_ENDPOINT,
        json=device,
        timeout=10,
    )

    response.raise_for_status()

    data = response.json()

    save_token(data)

    print(
        "[Agent] Device registered successfully."
    )

    print(
        f"[Agent] Device ID: {data.get('device_id')}"
    )

    print(
        f"[Agent] Agent ID: {data.get('agent_id')}"
    )

    return data


def get_token():
    data = load_token()

    if not data:
        return None

    return data.get("agent_token")


def agent_headers():
    token = get_token()

    if not token:
        raise RuntimeError(
            "Agent token not available."
        )

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


# ============================================================
# HEARTBEAT
# ============================================================

def send_heartbeat():
    response = requests.post(
        HEARTBEAT_ENDPOINT,
        headers=agent_headers(),
        timeout=10,
    )

    response.raise_for_status()

    data = response.json()

    print(
        f"[Heartbeat] OK | "
        f"Device ID: {data.get('device_id')} | "
        f"{data.get('timestamp')}"
    )

    return data


# ============================================================
# NETWORK RISK
# ============================================================

HIGH_RISK_PORTS = {
    23,
    135,
    139,
    445,
    1433,
    3389,
    5900,
    6379,
    27017,
}


def assess_risk(
    protocol,
    port,
    status,
):
    if port in HIGH_RISK_PORTS:
        return "high"

    if status in {
        "SYN_SENT",
        "SYN_RECV",
    }:
        return "medium"

    if (
        protocol == "UDP"
        and port
        and port > 40000
    ):
        return "medium"

    return "low"


# ============================================================
# NETWORK COLLECTION
# ============================================================

def get_protocol(connection):
    if connection.type == socket.SOCK_STREAM:
        return "TCP"

    if connection.type == socket.SOCK_DGRAM:
        return "UDP"

    return "OTHER"


def collect_network_events():
    local_ip = get_local_ip()

    events = []

    try:
        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception as error:
        print(
            f"[Collector Error] {error}"
        )

        return events

    for connection in connections:

        try:
            protocol = get_protocol(connection)

            source_ip = ""

            source_port = None

            destination_ip = ""

            destination_port = None

            if connection.laddr:
                source_ip = connection.laddr.ip
                source_port = connection.laddr.port

            if connection.raddr:
                destination_ip = connection.raddr.ip
                destination_port = connection.raddr.port

            port = (
                destination_port
                if destination_port is not None
                else source_port
            )

            status = (
                connection.status
                if connection.status
                else "UNKNOWN"
            )

            risk = assess_risk(
                protocol,
                port,
                status,
            )

            if not source_ip:
                source_ip = local_ip

            events.append(
                {
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "protocol": protocol,
                    "port": port,
                    "event_type": status,
                    "risk": risk,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception:
            continue

    return events


# ============================================================
# EVENT UPLOAD
# ============================================================

def upload_network_events(events):
    if not events:
        print(
            "[Events] No network connections detected."
        )

        return None

    payload = {
        "events": events
    }

    response = requests.post(
        EVENTS_ENDPOINT,
        headers=agent_headers(),
        json=payload,
        timeout=20,
    )

    response.raise_for_status()

    data = response.json()

    print(
        f"[Events] Received: "
        f"{data.get('received', len(events))} | "
        f"Saved: {data.get('saved', '?')} | "
        f"Duplicates: {data.get('duplicates', 0)}"
    )

    return data


# ============================================================
# MAIN AGENT LOOP
# ============================================================

def run_agent():
    print()
    print("========================================")
    print("       ZEROGUARD ENDPOINT AGENT")
    print("========================================")
    print()

    try:
        requests.get(
            f"{BACKEND_URL}/api/health",
            timeout=5,
        )

    except Exception as error:
        print()
        print(
            "[Agent Error] ZeroGuard backend is not reachable."
        )
        print(
            f"[Agent Error] {error}"
        )
        print()
        print(
            "Start FastAPI first:"
        )
        print(
            "python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000"
        )

        return

    try:
        registration = register_agent()

    except Exception as error:
        print()
        print(
            f"[Registration Error] {error}"
        )
        print()

        return

    token = registration.get("agent_token")

    if not token:
        token = get_token()

    if not token:
        print(
            "[Agent Error] No agent token available."
        )

        return

    print()
    print(
        "[Agent] ZeroGuard endpoint connection ACTIVE."
    )
    print(
        f"[Agent] Heartbeat interval: "
        f"{HEARTBEAT_INTERVAL} seconds"
    )
    print(
        f"[Agent] Event interval: "
        f"{EVENT_COLLECTION_INTERVAL} seconds"
    )
    print()
    print(
        "Press CTRL+C to stop the agent."
    )
    print()

    last_heartbeat = 0
    last_event_collection = 0

    while True:

        current_time = time.time()

        # ----------------------------------------------------
        # HEARTBEAT
        # ----------------------------------------------------

        if (
            current_time - last_heartbeat
            >= HEARTBEAT_INTERVAL
        ):

            try:
                send_heartbeat()

            except Exception as error:
                print(
                    f"[Heartbeat Error] {error}"
                )

            last_heartbeat = current_time

        # ----------------------------------------------------
        # NETWORK EVENTS
        # ----------------------------------------------------

        if (
            current_time - last_event_collection
            >= EVENT_COLLECTION_INTERVAL
        ):

            try:
                events = collect_network_events()

                print(
                    f"[Collector] Collected: "
                    f"{len(events)} network connections"
                )

                upload_network_events(events)

            except Exception as error:
                print(
                    f"[Events Error] {error}"
                )

            last_event_collection = current_time

        time.sleep(2)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        run_agent()

    except KeyboardInterrupt:
        print()
        print(
            "[Agent] ZeroGuard endpoint agent stopped."
        )

    except Exception as error:
        print()
        print(
            f"[Agent Fatal Error] {error}"
        )