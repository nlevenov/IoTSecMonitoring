"""Active discovery: ARP sweep and a TCP connect probe of common IoT ports.

Both only ever target addresses inside the configured monitored networks.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..sanitize import normalize_mac, valid_interface, valid_ip
from .scope import NetworkScope


def arp_sweep(cidr: str, scope: NetworkScope, iface: str | None = None,
              timeout: float = 2.0) -> list[tuple[str, str]]:
    """Return ``(ip, mac)`` for every host answering ARP. Needs CAP_NET_RAW."""
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    target = scope.check_target(cidr)
    if target.version != 4:
        raise ValueError("ARP sweeps are IPv4 only")
    kwargs = {"iface": valid_interface(iface)} if iface else {}
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target)),
                      timeout=timeout, verbose=False, **kwargs)
    hosts = {}
    for _, reply in answered:
        ip, mac = valid_ip(reply[ARP].psrc), normalize_mac(reply[ARP].hwsrc)
        if ip and mac and scope.contains(ip):
            hosts[ip] = mac
    return sorted(hosts.items(), key=lambda item: tuple(int(p) for p in item[0].split(".")))


def probe_ports(ip: str, ports: list[int], scope: NetworkScope,
                timeout: float = 0.5) -> list[int]:
    """TCP connect probe - no raw packets, no banner grabbing, no payloads."""
    if not scope.contains(ip):
        raise PermissionError(f"{ip} is outside the monitored networks; refusing to probe it")

    def is_open(port: int) -> int | None:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=min(16, len(ports) or 1)) as pool:
        return sorted(p for p in pool.map(is_open, ports) if p is not None)
