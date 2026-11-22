from datetime import datetime
import ipaddress
import platform
import subprocess


SUPPORTED_ACTIONS = {
    "Alert Generated",
    "Block Source",
    "Isolate Device",
    "Terminate Connection",
    "Network Quarantine",
}


def is_valid_ip(value: str) -> bool:
    """
    Return True when value is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_safe_to_block(ip_address: str):
    """
    Safety checks before creating a Windows Firewall block rule.

    ZeroGuard must never block:

    - localhost
    - loopback addresses
    - unspecified addresses
    - multicast addresses
    - reserved addresses
    - IPv4 broadcast address
    """

    value = str(ip_address or "").strip()

    if not value:
        return False, "IP address is required."

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False, "Invalid IP address."

    if ip.is_loopback:
        return False, "Loopback addresses cannot be blocked."

    if ip.is_unspecified:
        return False, "Unspecified addresses cannot be blocked."

    if ip.is_multicast:
        return False, "Multicast addresses cannot be blocked."

    if ip.is_reserved:
        return False, "Reserved addresses cannot be blocked."

    if ip.version == 4 and str(ip) == "255.255.255.255":
        return False, "Broadcast address cannot be blocked."

    return True, "IP address passed safety checks."


def execute_firewall_block(ip_address: str):
    """
    Create and verify Windows Firewall inbound and outbound
    block rules for a source IP.

    IMPORTANT:
    This function performs an actual firewall modification.

    Risk authorization must be performed by the API layer before
    this function is called.
    """

    value = str(ip_address or "").strip()

    if platform.system().lower() != "windows":
        return {
            "success": False,
            "status": "failed",
            "message": (
                "Windows Firewall blocking is available only on Windows."
            ),
        }

    valid, safety_message = is_safe_to_block(value)

    if not valid:
        return {
            "success": False,
            "status": "failed",
            "message": safety_message,
        }

    rule_name = "ZeroGuard Block " + value

    commands = [
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=" + rule_name,
            "dir=in",
            "action=block",
            "remoteip=" + value,
            "enable=yes",
        ],
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=" + rule_name + " OUT",
            "dir=out",
            "action=block",
            "remoteip=" + value,
            "enable=yes",
        ],
    ]

    try:
        for command in commands:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            if result.returncode != 0:
                error_message = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "Windows Firewall command failed."
                )

                return {
                    "success": False,
                    "status": "failed",
                    "message": error_message,
                }

        verification = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=" + rule_name,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        verification_text = (
            verification.stdout + "\n" + verification.stderr
        ).lower()

        if verification.returncode != 0:
            return {
                "success": False,
                "status": "failed",
                "message": (
                    "Firewall rule creation was attempted, "
                    "but verification failed."
                ),
            }

        if rule_name.lower() not in verification_text:
            return {
                "success": False,
                "status": "failed",
                "message": (
                    "Firewall rule could not be verified after creation."
                ),
            }

        return {
            "success": True,
            "status": "completed",
            "message": (
                "Windows Firewall successfully blocked source IP "
                + value
                + "."
            ),
            "executed_at": datetime.now().isoformat(),
            "action_type": "Block Source",
            "target": value,
            "rule_name": rule_name,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "status": "failed",
            "message": "Windows Firewall operation timed out.",
        }

    except Exception as error:
        return {
            "success": False,
            "status": "failed",
            "message": str(error),
        }


def execute_response_action(
    action_type: str,
    target: str,
    reason: str,
):
    """
    Execute a ZeroGuard response action.

    Supported actions:

    Alert Generated
        Safe notification-only action.

    Block Source
        Performs a real Windows Firewall block.
        The API layer must authorize this action before calling
        this executor.

    Isolate Device
    Terminate Connection
    Network Quarantine
        Currently validated only and remain pending until their
        dedicated safe executors are implemented.
    """

    action = str(action_type or "").strip()
    target_value = str(target or "").strip()
    reason_value = str(reason or "").strip()

    if not action:
        return {
            "success": False,
            "status": "failed",
            "message": "Action type is required.",
        }

    if action not in SUPPORTED_ACTIONS:
        return {
            "success": False,
            "status": "failed",
            "message": "Unsupported response action: " + action,
        }

    if not target_value:
        return {
            "success": False,
            "status": "failed",
            "message": "Response target is required.",
        }

    # ------------------------------------------------------------
    # ALERT
    # ------------------------------------------------------------

    if action == "Alert Generated":
        return {
            "success": True,
            "status": "completed",
            "message": "Security alert generated successfully.",
            "executed_at": datetime.now().isoformat(),
            "action_type": action,
            "target": target_value,
            "reason": reason_value,
        }

    # ------------------------------------------------------------
    # BLOCK SOURCE
    # ------------------------------------------------------------

    if action == "Block Source":

        if not is_valid_ip(target_value):
            return {
                "success": False,
                "status": "failed",
                "message": (
                    "Block Source requires a valid source IP address."
                ),
            }

        valid, safety_message = is_safe_to_block(target_value)

        if not valid:
            return {
                "success": False,
                "status": "failed",
                "message": safety_message,
            }

        result = execute_firewall_block(target_value)

        result["reason"] = reason_value

        return result

    # ------------------------------------------------------------
    # OTHER DEFENSIVE ACTIONS
    # ------------------------------------------------------------

    return {
            "success": False,
            "status": "pending",
            "message": (
                "Action validated but not executed. "
                "Manual execution is required for this defensive action."
            ),
            "executed_at": None,
            "action_type": action,
            "target": target_value,
            "reason": reason_value,
    }
