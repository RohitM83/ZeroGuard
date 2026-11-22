"""
ZeroGuard Risk Correlator
-------------------------

Converts statistical GNN anomalies into a contextual security
risk assessment.

IMPORTANT:
- GNN anomaly score is NOT attack probability.
- This module does not execute any response action.
- It only evaluates evidence and produces a risk assessment.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List


# ============================================================
# CONFIGURATION
# ============================================================

HIGH_RISK_PORTS = {
    23,       # Telnet
    135,      # RPC
    139,      # NetBIOS Session Service
    445,      # SMB
    1433,     # MSSQL
    3389,     # RDP
    5900,     # VNC
    6379,     # Redis
    27017,    # MongoDB
}

MEDIUM_RISK_PORTS = {
    21,
    22,
    25,
    53,
    110,
    143,
    389,
    443,
    3306,
    5432,
    8080,
    8443,
}

WINDOWS_COMMON_PORTS = {
    53,
    80,
    123,
    135,
    137,
    138,
    139,
    443,
    445,
}


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_ip(value: Any) -> str | None:
    """
    Return a normalized IP string.

    Invalid or empty values return None.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def is_private_ip(value: Any) -> bool:
    """
    Determine whether an IP belongs to a private network.
    """

    normalized = normalize_ip(value)

    if not normalized:
        return False

    try:
        return ipaddress.ip_address(normalized).is_private
    except ValueError:
        return False


def is_loopback_ip(value: Any) -> bool:
    """
    Determine whether an IP is loopback.
    """

    normalized = normalize_ip(value)

    if not normalized:
        return False

    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def is_local_host_ip(
    ip_address: Any,
    local_ips: List[str] | None = None,
) -> bool:
    """
    Determine whether an IP belongs to the monitored host.

    This is intentionally dynamic.
    We do NOT hard-code the user's current IP.
    """

    normalized = normalize_ip(ip_address)

    if not normalized:
        return False

    if is_loopback_ip(normalized):
        return True

    if not local_ips:
        return False

    normalized_local_ips = {
        normalize_ip(ip)
        for ip in local_ips
        if normalize_ip(ip)
    }

    return normalized in normalized_local_ips


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert a value to float.
    """

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert a value to int.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ============================================================
# PORT CLASSIFICATION
# ============================================================

def classify_port(port: Any) -> str:
    """
    Classify a network port.

    This is evidence only.
    A high-risk port does NOT mean the connection is malicious.
    """

    port_number = safe_int(port)

    if port_number <= 0:
        return "unknown"

    if port_number in HIGH_RISK_PORTS:
        return "high_risk"

    if port_number in MEDIUM_RISK_PORTS:
        return "medium_risk"

    return "normal"


# ============================================================
# EVENT ANALYSIS
# ============================================================

def analyze_network_events(
    events: List[Dict[str, Any]],
    local_ips: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Analyze network events associated with a suspicious GNN node.
    """

    total_events = len(events)

    high_risk_port_events = 0
    medium_risk_port_events = 0

    established_events = 0
    listen_events = 0
    syn_events = 0

    tcp_events = 0
    udp_events = 0

    local_host_events = 0
    private_network_events = 0

    suspicious_ports = set()

    source_ips = set()
    destination_ips = set()

    for event in events:

        source_ip = normalize_ip(
            event.get("source_ip")
        )

        destination_ip = normalize_ip(
            event.get("destination_ip")
        )

        protocol = str(
            event.get("protocol") or ""
        ).upper()

        event_type = str(
            event.get("event_type") or ""
        ).upper()

        port = safe_int(
            event.get("port")
        )

        # ----------------------------------------------------
        # PROTOCOL
        # ----------------------------------------------------

        if protocol == "TCP":
            tcp_events += 1

        elif protocol == "UDP":
            udp_events += 1

        # ----------------------------------------------------
        # EVENT STATE
        # ----------------------------------------------------

        if "ESTABLISHED" in event_type:
            established_events += 1

        if "LISTEN" in event_type:
            listen_events += 1

        if "SYN" in event_type:
            syn_events += 1

        # ----------------------------------------------------
        # PORT RISK
        # ----------------------------------------------------

        port_class = classify_port(port)

        if port_class == "high_risk":

            high_risk_port_events += 1

            if port > 0:
                suspicious_ports.add(port)

        elif port_class == "medium_risk":

            medium_risk_port_events += 1

        # ----------------------------------------------------
        # HOST CONTEXT
        # ----------------------------------------------------

        if (
            is_local_host_ip(source_ip, local_ips)
            or is_local_host_ip(destination_ip, local_ips)
        ):
            local_host_events += 1

        # ----------------------------------------------------
        # PRIVATE NETWORK
        # ----------------------------------------------------

        if (
            is_private_ip(source_ip)
            or is_private_ip(destination_ip)
        ):
            private_network_events += 1

        if source_ip:
            source_ips.add(source_ip)

        if destination_ip:
            destination_ips.add(destination_ip)

    return {
        "total_events": total_events,
        "tcp_events": tcp_events,
        "udp_events": udp_events,
        "established_events": established_events,
        "listen_events": listen_events,
        "syn_events": syn_events,
        "high_risk_port_events": high_risk_port_events,
        "medium_risk_port_events": medium_risk_port_events,
        "local_host_events": local_host_events,
        "private_network_events": private_network_events,
        "suspicious_ports": sorted(suspicious_ports),
        "source_ips": sorted(source_ips),
        "destination_ips": sorted(destination_ips),
    }


# ============================================================
# RISK CORRELATION
# ============================================================

def correlate_risk(
    *,
    anomaly_score: float,
    baseline_z_score: float,
    suspicious_nodes: int,
    events: List[Dict[str, Any]] | None = None,
    local_ips: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Correlate GNN anomaly evidence with network context.

    The final score is a SECURITY RISK SCORE, not an attack
    probability.

    The function intentionally gives contextual evidence weight.
    """

    events = events or []
    local_ips = local_ips or []

    anomaly_score = max(
        0.0,
        min(100.0, safe_float(anomaly_score))
    )

    baseline_z_score = safe_float(
        baseline_z_score
    )

    suspicious_nodes = max(
        0,
        safe_int(suspicious_nodes)
    )

    event_analysis = analyze_network_events(
        events,
        local_ips
    )

    # ========================================================
    # EVIDENCE SCORE
    # ========================================================

    evidence_score = 0.0

    reasons: List[str] = []
    warnings: List[str] = []
    positive_context: List[str] = []

    # --------------------------------------------------------
    # GNN ANOMALY
    # --------------------------------------------------------

    if anomaly_score >= 90:

        evidence_score += 25

        reasons.append(
            "GNN detected an extremely unusual network pattern."
        )

    elif anomaly_score >= 80:

        evidence_score += 20

        reasons.append(
            "GNN detected a highly unusual network pattern."
        )

    elif anomaly_score >= 60:

        evidence_score += 12

        reasons.append(
            "GNN detected a moderately unusual network pattern."
        )

    elif anomaly_score >= 40:

        evidence_score += 6

        reasons.append(
            "GNN detected some deviation from normal behavior."
        )

    # --------------------------------------------------------
    # BASELINE DEVIATION
    # --------------------------------------------------------

    if baseline_z_score >= 8:

        evidence_score += 20

        reasons.append(
            "Behavior is extremely far from the learned normal baseline."
        )

    elif baseline_z_score >= 5:

        evidence_score += 15

        reasons.append(
            "Behavior is significantly above the normal baseline."
        )

    elif baseline_z_score >= 3:

        evidence_score += 10

        reasons.append(
            "Behavior is noticeably above the normal baseline."
        )

    elif baseline_z_score >= 2:

        evidence_score += 5

        reasons.append(
            "Behavior is above the normal baseline."
        )

    # --------------------------------------------------------
    # SUSPICIOUS NODE COUNT
    # --------------------------------------------------------

    if suspicious_nodes >= 3:

        evidence_score += 10

        reasons.append(
            f"{suspicious_nodes} suspicious network nodes were identified."
        )

    elif suspicious_nodes == 2:

        evidence_score += 7

        reasons.append(
            "Multiple suspicious network nodes were identified."
        )

    elif suspicious_nodes == 1:

        evidence_score += 3

        reasons.append(
            "One suspicious network node was identified."
        )

    # --------------------------------------------------------
    # HIGH-RISK PORTS
    # --------------------------------------------------------

    high_risk_ports = event_analysis[
        "high_risk_port_events"
    ]

    if high_risk_ports >= 10:

        evidence_score += 20

        reasons.append(
            "Multiple events involve high-risk service ports."
        )

    elif high_risk_ports >= 5:

        evidence_score += 12

        reasons.append(
            "Several events involve high-risk service ports."
        )

    elif high_risk_ports >= 1:

        evidence_score += 6

        reasons.append(
            "Some events involve ports commonly associated with "
            "security-sensitive services."
        )

    # --------------------------------------------------------
    # SYN ACTIVITY
    # --------------------------------------------------------

    syn_events = event_analysis["syn_events"]

    if syn_events >= 20:

        evidence_score += 12

        reasons.append(
            "High SYN activity was observed."
        )

    elif syn_events >= 5:

        evidence_score += 6

        reasons.append(
            "Elevated SYN activity was observed."
        )

    # --------------------------------------------------------
    # ESTABLISHED CONNECTIONS
    # --------------------------------------------------------

    established_events = event_analysis[
        "established_events"
    ]

    if established_events >= 20:

        evidence_score += 8

        reasons.append(
            "A large number of established connections were observed."
        )

    # --------------------------------------------------------
    # LOCAL HOST CONTEXT
    # --------------------------------------------------------

    local_host_events = event_analysis[
        "local_host_events"
    ]

    if local_host_events > 0:

        # Local activity is NOT automatically malicious.
        # It reduces the confidence that the anomaly represents
        # an external attack.

        evidence_score -= 15

        positive_context.append(
            "The observed activity involves the monitored local host."
        )

        warnings.append(
            "Local-host activity can represent legitimate operating "
            "system or application behavior."
        )

    # --------------------------------------------------------
    # WINDOWS / NETBIOS CONTEXT
    # --------------------------------------------------------

    suspicious_ports = set(
        event_analysis["suspicious_ports"]
    )

    if suspicious_ports.intersection(
        {135, 137, 138, 139, 445}
    ):

        positive_context.append(
            "Windows/NetBIOS/SMB-related ports are present."
        )

        warnings.append(
            "Windows networking services can legitimately use "
            "ports 135, 137, 138, 139 and 445."
        )

        # These ports alone should not cause a critical verdict.
        evidence_score -= 8

    # --------------------------------------------------------
    # LISTENING CONTEXT
    # --------------------------------------------------------

    listen_events = event_analysis[
        "listen_events"
    ]

    if listen_events > 0:

        warnings.append(
            "Listening services were observed; listening alone "
            "does not establish malicious activity."
        )

    # --------------------------------------------------------
    # PRIVATE NETWORK CONTEXT
    # --------------------------------------------------------

    if event_analysis["private_network_events"] > 0:

        positive_context.append(
            "Network activity includes private/internal addresses."
        )

    # ========================================================
    # FINAL RISK SCORE
    # ========================================================

    risk_score = max(
        0.0,
        min(100.0, evidence_score)
    )

    # --------------------------------------------------------
    # FINAL RISK LEVEL
    # --------------------------------------------------------

    if risk_score >= 80:

        final_risk = "critical"

    elif risk_score >= 60:

        final_risk = "high"

    elif risk_score >= 35:

        final_risk = "medium"

    else:

        final_risk = "low"

    # ========================================================
    # INVESTIGATION STATUS
    # ========================================================

    if final_risk in {"high", "critical"}:

        recommended_action = (
            "Investigate immediately. "
            "Consider containment only after confirming "
            "independent malicious evidence."
        )

    elif final_risk == "medium":

        recommended_action = (
            "Continue monitoring and investigate the "
            "associated network evidence."
        )

    else:

        recommended_action = (
            "Monitor the activity. No automatic blocking "
            "is recommended from GNN anomaly alone."
        )

    # ========================================================
    # RESPONSE SAFETY
    # ========================================================

    automatic_response_allowed = (
        final_risk == "critical"
        and high_risk_ports >= 5
        and syn_events >= 5
        and local_host_events == 0
    )

    if not automatic_response_allowed:

        warnings.append(
            "Automatic blocking is not recommended from the "
            "current evidence alone."
        )

    # ========================================================
    # RETURN
    # ========================================================

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": final_risk,

        "anomaly_score": round(
            anomaly_score,
            2
        ),

        "baseline_z_score": round(
            baseline_z_score,
            3
        ),

        "suspicious_nodes": suspicious_nodes,

        "event_analysis": event_analysis,

        "reasons": reasons,

        "positive_context": positive_context,

        "warnings": warnings,

        "recommended_action": recommended_action,

        "automatic_response_allowed": (
            automatic_response_allowed
        ),

        "detection_interpretation": (
            "The GNN anomaly score measures deviation "
            "from learned network behavior. It is not "
            "an attack probability."
        ),
    }


# ============================================================
# SIMPLE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("ZeroGuard Risk Correlator Test")
    print("=" * 60)

    sample_events = [
        {
            "source_ip": "192.0.2.10",
            "destination_ip": "0.0.0.0",
            "protocol": "TCP",
            "port": 139,
            "event_type": "LISTEN",
        },
        {
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "protocol": "UDP",
            "port": 137,
            "event_type": "ESTABLISHED",
        },
        {
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "protocol": "UDP",
            "port": 138,
            "event_type": "ESTABLISHED",
        },
    ]

    result = correlate_risk(
        anomaly_score=99.96,
        baseline_z_score=9.743,
        suspicious_nodes=1,
        events=sample_events,
        local_ips=[
            "192.0.2.10"
        ],
    )

    print()
    print(
        f"Anomaly Score       : "
        f"{result['anomaly_score']}%"
    )

    print(
        f"Baseline Z-Score    : "
        f"{result['baseline_z_score']}"
    )

    print(
        f"Risk Score          : "
        f"{result['risk_score']}"
    )

    print(
        f"Final Risk          : "
        f"{result['risk_level'].upper()}"
    )

    print(
        f"Auto Response       : "
        f"{result['automatic_response_allowed']}"
    )

    print()
    print("Reasons:")

    for reason in result["reasons"]:
        print(f"  - {reason}")

    print()
    print("Context:")

    for context in result["positive_context"]:
        print(f"  + {context}")

    print()
    print("Warnings:")

    for warning in result["warnings"]:
        print(f"  ! {warning}")

    print()
    print(
        "Recommended Action:"
    )

    print(
        f"  {result['recommended_action']}"
    )

    print()
    print("=" * 60)