"""Data model shared by capture, analysis, storage and the dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ("info", "low", "medium", "high", "critical").index(self.value)


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertType(str, Enum):
    NEW_DEVICE = "new_device"
    PORT_SCAN = "port_scan"
    MIRAI_SCAN = "mirai_scan"
    FLOOD = "flood"
    DNS_TUNNEL = "dns_tunnel"
    EXFILTRATION = "exfiltration"
    BLOCKLISTED = "blocklisted_destination"
    NEW_DESTINATIONS = "new_destinations"
    LATERAL_MOVEMENT = "lateral_movement"
    INSECURE_PROTOCOL = "insecure_protocol"
    ARP_SPOOF = "arp_spoofing"
    BEHAVIOUR_ANOMALY = "behaviour_anomaly"
    MAC_FLOOD = "mac_flood"

    @property
    def title(self) -> str:
        return _TITLES[self]


_TITLES = {
    AlertType.NEW_DEVICE: "Unknown device joined the network",
    AlertType.PORT_SCAN: "Port / host scan",
    AlertType.MIRAI_SCAN: "Mirai-style Telnet scanning",
    AlertType.FLOOD: "Traffic flood (possible DDoS participation)",
    AlertType.DNS_TUNNEL: "Suspicious DNS (tunnelling / DGA)",
    AlertType.EXFILTRATION: "Unusual outbound data volume",
    AlertType.BLOCKLISTED: "Contact with blocklisted destination",
    AlertType.NEW_DESTINATIONS: "Contact with new destinations",
    AlertType.LATERAL_MOVEMENT: "Connection to internal admin services",
    AlertType.INSECURE_PROTOCOL: "Insecure protocol in use",
    AlertType.ARP_SPOOF: "ARP spoofing / IP conflict",
    AlertType.BEHAVIOUR_ANOMALY: "Behaviour deviates from baseline",
    AlertType.MAC_FLOOD: "MAC flooding (device table exhaustion attempt)",
}


@dataclass(slots=True)
class PacketRecord:
    """Metadata of one packet. Payloads are never stored."""

    ts: float
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    proto: str = "other"             # tcp | udp | icmp | arp | other
    sport: int | None = None
    dport: int | None = None
    length: int = 0
    tcp_flags: int | None = None
    dns_qname: str | None = None
    dns_qtype: int | None = None
    dns_rcode: int | None = None
    dns_response: bool = False
    dns_label_entropy: float = 0.0
    tls_sni: str | None = None
    http_host: str | None = None
    arp_op: int | None = None
    dhcp_hostname: str | None = None
    dhcp_vendor: str | None = None
    mdns_names: tuple[str, ...] = ()
    ssdp_server: str | None = None

    @property
    def is_syn(self) -> bool:
        return bool(self.tcp_flags is not None and self.tcp_flags & 0x02
                    and not self.tcp_flags & 0x10)

    @property
    def is_rst(self) -> bool:
        return self.tcp_flags is not None and bool(self.tcp_flags & 0x04)


@dataclass
class Device:
    mac: str
    ip: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    label: str | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    approved: bool = False
    randomized_mac: bool = False
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    dhcp_vendor: str | None = None

    @property
    def display_name(self) -> str:
        return self.label or self.hostname or self.vendor or self.mac


@dataclass
class Alert:
    device_mac: str | None
    alert_type: AlertType
    severity: Severity
    details: dict[str, Any] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    count: int = 1
    status: AlertStatus = AlertStatus.OPEN
    id: int | None = None
    notes: str = ""

    @property
    def title(self) -> str:
        return self.alert_type.title
