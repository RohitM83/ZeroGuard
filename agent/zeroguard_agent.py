import ctypes
import json
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

import psutil
import requests


# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_URL = "http://127.0.0.1:8000"

CONFIG_FILE = Path(__file__).with_name("config.json")
TOKEN_FILE = Path(__file__).with_name("agent_token.json")

HEARTBEAT_INTERVAL = 30
NETWORK_SCAN_INTERVAL = 15

DEVICE_TYPE = "Computer"


# ============================================================
# CONSOLE
# ============================================================

def print_banner():
    print()
    print("=" * 70)
    print("                 ZEROGUARD WINDOWS AGENT")
    print("=" * 70)
    print()
    print(f"Backend: {BACKEND_URL}")
    print()


# ============================================================
# LOCAL SYSTEM INFORMATION
# ============================================================

def get_computer_name():
    return socket.gethostname()


def get_windows_version():
    try:
        return platform.platform()
    except Exception:
        return "Windows"


def get_local_ip():
    try:
        hostname = socket.gethostname()

        addresses = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET,
        )

        for item in addresses:
            ip = item[4][0]

            if ip and not ip.startswith("127."):
                return ip

    except Exception:
        pass

    try:
        connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        connection.connect(("8.8.8.8", 80))

        ip = connection.getsockname()[0]

        connection.close()

        return ip

    except Exception:
        return "127.0.0.1"


def get_mac_address():
    try:
        mac = uuid.getnode()

        mac_address = ":".join(
            f"{(mac >> element) & 0xff:02x}"
            for element in range(40, -1, -8)
        )

        return mac_address

    except Exception:
        return "unknown"


def get_system_information():

    computer_name = get_computer_name()
    ip_address = get_local_ip()
    mac_address = get_mac_address()
    operating_system = get_windows_version()

    return {
        "device_name": computer_name,
        "agent_name": f"ZeroGuard-{computer_name}",
        "mac_address": mac_address,
        "device_type": DEVICE_TYPE,
        "ip_address": ip_address,
        "operating_system": operating_system,
    }


# ============================================================
# CONFIG FILE
# ============================================================

def load_config():

    if not CONFIG_FILE.exists():
        return {}

    try:
        with open(
            CONFIG_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            f"[WARNING] Could not read config.json: {error}"
        )

        return {}


def save_config(data):

    try:

        with open(
            CONFIG_FILE,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                data,
                file,
                indent=4,
            )

    except Exception as error:

        print(
            f"[ERROR] Could not save config.json: {error}"
        )


# ============================================================
# AGENT TOKEN
# ============================================================

def load_agent_token():

    if not TOKEN_FILE.exists():
        return None

    try:

        with open(
            TOKEN_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        return data.get("agent_token")

    except Exception as error:

        print(
            f"[WARNING] Could not read agent token: {error}"
        )

        return None


def save_agent_token(token):

    try:

        with open(
            TOKEN_FILE,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                {
                    "agent_token": token
                },
                file,
                indent=4,
            )

        print("[OK] Agent token saved.")

    except Exception as error:

        print(
            f"[ERROR] Could not save agent token: {error}"
        )


# ============================================================
# HTTP HELPERS
# ============================================================

def api_request(
    method,
    endpoint,
    token=None,
    payload=None,
):

    url = f"{BACKEND_URL}{endpoint}"

    headers = {
        "Content-Type": "application/json",
    }

    if token:

        headers["Authorization"] = (
            f"Bearer {token}"
        )

    try:

        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=payload,
            timeout=10,
        )

        try:
            data = response.json()
        except Exception:
            data = {}

        if not response.ok:

            detail = data.get(
                "detail",
                f"HTTP {response.status_code}",
            )

            return False, detail

        return True, data

    except requests.RequestException as error:

        return False, str(error)


# ============================================================
# DEVICE PAIRING
# ============================================================

def register_device(pairing_code):

    system = get_system_information()

    print()
    print("Registering this computer...")
    print()

    print(
        f"Device Name      : {system['device_name']}"
    )

    print(
        f"IP Address       : {system['ip_address']}"
    )

    print(
        f"MAC Address      : {system['mac_address']}"
    )

    print(
        f"Operating System : {system['operating_system']}"
    )

    print()

    success, response = api_request(
        "POST",
        "/api/device-pairings/register",
        payload={
            "pairing_code": pairing_code.strip(),
            "agent_name": system["agent_name"],
            "device_name": system["device_name"],
            "mac_address": system["mac_address"],
            "device_type": system["device_type"],
            "ip_address": system["ip_address"],
            "operating_system": system["operating_system"],
        },
    )

    if not success:

        print(
            f"[ERROR] Pairing failed: {response}"
        )

        return None

    print()
    print("[SUCCESS] Device paired successfully.")
    print()

    print(
        f"Device ID : {response.get('device_id')}"
    )

    print(
        f"Agent ID  : {response.get('agent_id')}"
    )

    token = response.get("agent_token")

    if not token:

        print(
            "[ERROR] Backend did not return an agent token."
        )

        return None

    save_agent_token(token)

    print()

    print(
        "The agent token has been stored locally."
    )

    print(
        "You do not need to enter the pairing code again."
    )

    print()

    return token


# ============================================================
# AGENT INFORMATION
# ============================================================

def get_agent_information(token):

    success, response = api_request(
        "GET",
        "/api/agents/me",
        token=token,
    )

    if not success:

        print(
            f"[ERROR] Agent authentication failed: {response}"
        )

        return None

    return response


# ============================================================
# HEARTBEAT
# ============================================================


def send_heartbeat(token):

    system = get_system_information()

    success, response = api_request(
        "POST",
        "/api/agents/heartbeat",
        token=token,
        payload={
            "ip_address": system["ip_address"],
        },
    )

    if not success:
        print(
            f"[WARNING] Heartbeat failed: {response}"
        )
        return False

    timestamp = response.get(
        "timestamp",
        datetime.now().isoformat(),
    )

    print(
        f"[HEARTBEAT] Device online | "
        f"IP: {system['ip_address']} | {timestamp}"
    )

    return True



# ============================================================
# NETWORK CONNECTION COLLECTION
# ============================================================

def get_network_events():

    events = []

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception as error:

        print(
            f"[WARNING] Could not read network connections: {error}"
        )

        return events

    timestamp = datetime.now().isoformat()
    local_ip = get_local_ip()

    for connection in connections:

        try:

            # Determine protocol
            if connection.type == socket.SOCK_STREAM:
                protocol = "TCP"

            elif connection.type == socket.SOCK_DGRAM:
                protocol = "UDP"

            else:
                continue

            # Read local endpoint
            local_address = (
                connection.laddr.ip
                if connection.laddr
                else local_ip
            )

            local_port = (
                connection.laddr.port
                if connection.laddr
                else None
            )

            # Replace wildcard local addresses with the
            # computer's detected IP address.
            if local_address in ("0.0.0.0", "::", ""):
                local_address = local_ip

            # Read remote endpoint when available
            if connection.raddr:

                destination_ip = connection.raddr.ip
                destination_port = connection.raddr.port

            else:

                destination_ip = ""
                destination_port = None

            # Preserve actual TCP connection states.
            status = (
                connection.status or ""
            ).upper()

            if protocol == "UDP":

                event_type = "UDP_SOCKET"

                event_port = (
                    destination_port
                    if destination_port is not None
                    else local_port
                )

            elif status in (
                "ESTABLISHED",
                "LISTEN",
                "TIME_WAIT",
                "CLOSE_WAIT",
                "FIN_WAIT1",
                "FIN_WAIT2",
                "SYN_SENT",
                "SYN_RECV",
                "CLOSING",
                "LAST_ACK",
            ):

                event_type = status

                # Listening sockets use their local port.
                if status == "LISTEN":
                    event_port = local_port
                else:
                    event_port = (
                        destination_port
                        if destination_port is not None
                        else local_port
                    )

            else:

                event_type = "TCP_CONNECTION"

                event_port = (
                    destination_port
                    if destination_port is not None
                    else local_port
                )

            events.append(
                {
                    "source_ip": local_address,
                    "destination_ip": destination_ip,
                    "protocol": protocol,
                    "port": event_port,
                    "event_type": event_type,
                    "risk": (
                        "high"
                        if event_port in {
                            23, 135, 139, 445, 1433,
                            3389, 5900, 6379, 27017
                        }
                        else "medium"
                        if event_type in ("SYN_SENT", "SYN_RECV")
                        or (
                            protocol == "UDP"
                            and event_port is not None
                            and event_port > 40000
                        )
                        else "low"
                    ),
                    "timestamp": timestamp,
                }
            )

        except Exception:
            continue

    return events


# ============================================================
# UPLOAD NETWORK EVENTS
# ============================================================

def upload_network_events(
    token,
    events,
):

    if not events:

        print(
            "[NETWORK] No external connections detected."
        )

        return

    # Avoid sending an unnecessarily large payload.
    events = events[:250]

    success, response = api_request(
        "POST",
        "/api/agents/events",
        token=token,
        payload={
            "events": events
        },
    )

    if not success:

        print(
            f"[WARNING] Network event upload failed: {response}"
        )

        return

    print(
        "[NETWORK] "
        f"Detected {response.get('received', 0)} | "
        f"Saved {response.get('saved', 0)} | "
        f"Duplicates {response.get('duplicates', 0)}"
    )


# ============================================================
# PAIRING MODE
# ============================================================

def pairing_mode():

    print()
    print("=" * 70)
    print("DEVICE PAIRING")
    print("=" * 70)
    print()

    pairing_code = input(
        "Enter the ZeroGuard pairing code: "
    ).strip()

    if not pairing_code:

        print(
            "[ERROR] Pairing code cannot be empty."
        )

        return None

    return register_device(pairing_code)


# ============================================================
# AGENT MAIN LOOP
# ============================================================

def run_agent(token):

    print()
    print("=" * 70)
    print("ZERO GUARD AGENT STARTED")
    print("=" * 70)
    print()

    information = get_agent_information(token)

    if information is None:

        print()
        print(
            "The stored agent token is invalid or inactive."
        )

        print(
            "You will need to pair this computer again."
        )

        return False

    print(
        f"Agent ID   : {information.get('agent_id')}"
    )

    print(
        f"Device ID  : {information.get('device_id')}"
    )

    print(
        f"Agent Name : {information.get('agent_name')}"
    )

    device = information.get(
        "device",
        {},
    )

    print(
        f"Device     : {device.get('name')}"
    )

    print(
        f"IP         : {device.get('ip_address')}"
    )

    print()

    last_heartbeat = 0
    last_network_scan = 0

    while True:

        current_time = time.time()

        # ----------------------------------------------------
        # HEARTBEAT
        # ----------------------------------------------------

        if (
            current_time - last_heartbeat
            >= HEARTBEAT_INTERVAL
        ):

            heartbeat_ok = send_heartbeat(
                token
            )

            last_heartbeat = current_time

            if not heartbeat_ok:

                print(
                    "[WARNING] Backend may be unavailable."
                )

        # ----------------------------------------------------
        # NETWORK SCAN
        # ----------------------------------------------------

        if (
            current_time - last_network_scan
            >= NETWORK_SCAN_INTERVAL
        ):

            events = get_network_events()

            upload_network_events(
                token,
                events,
            )

            last_network_scan = current_time

        time.sleep(2)


# ============================================================
# MAIN
# ============================================================

def main():

    print_banner()

    print("Checking local system...")
    print()

    system = get_system_information()

    print(
        f"Computer Name    : {system['device_name']}"
    )

    print(
        f"IP Address       : {system['ip_address']}"
    )

    print(
        f"MAC Address      : {system['mac_address']}"
    )

    print(
        f"Operating System : {system['operating_system']}"
    )

    print()

    token = load_agent_token()

    if token:

        print(
            "[OK] Existing ZeroGuard agent token found."
        )

        print(
            "Attempting to reconnect..."
        )

        success = run_agent(token)

        if success is not False:

            return

        print()

        print(
            "Stored agent token could not be used."
        )

        print(
            "Starting pairing mode..."
        )

        print()

        token = pairing_mode()

    else:

        print(
            "[INFO] This computer is not paired yet."
        )

        token = pairing_mode()

    if not token:

        print()
        print(
            "Agent could not be started."
        )

        input(
            "Press Enter to exit..."
        )

        return

    run_agent(token)


if __name__ == "__main__":
    main()