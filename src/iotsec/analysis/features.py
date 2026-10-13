"""Per-device traffic windows.

Packets are attributed to the local endpoint(s) of the conversation: the
sender if its IP is in a monitored network (outbound) and the receiver if
its IP is (inbound). Every device gets one window of counters per
``window_seconds``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache

from ..discovery.scope import NetworkScope
from ..models import PacketRecord
from ..sanitize import is_unicast_mac
from ..threatintel import Blocklist

FEATURES = (
    "pkts_out", "pkts_in", "bytes_out", "bytes_in", "uniq_dst_ips", "uniq_dst_ports",
    "uniq_ext_ips", "uniq_int_peers", "syn_out", "rst_in", "dns_queries", "uniq_domains",
    "nxdomain", "dns_txt", "max_dns_entropy", "long_dns_labels", "arp_targets",
    "telnet_hosts", "tcp_frac", "udp_frac", "mean_pkt_size",
)
TELNET_PORTS = {23, 2323}
INSECURE_PORTS = {21: "ftp", 23: "telnet", 2323: "telnet", 69: "tftp", 513: "rlogin"}
MAX_TRACKED = 4096  # per set per window - bounds memory under scans and floods


def _bounded_add(target: set, value: object) -> None:
    if len(target) < MAX_TRACKED:
        target.add(value)


@lru_cache(maxsize=65_536)
def _address_kind(ip: str) -> tuple[bool, bool]:
    """(is_multicast_or_broadcast, is_global) for a destination address."""
    address = ipaddress.ip_address(ip)
    broadcast = address.version == 4 and str(address).endswith(".255")
    return address.is_multicast or broadcast, address.is_global


def _prefix(ip: str) -> str:
    network = ipaddress.ip_network(f"{ip}/{24 if ':' not in ip else 64}", strict=False)
    return str(network)


@dataclass
class DeviceWindow:
    mac: str
    start: float
    pkts_out: int = 0
    pkts_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    tcp: int = 0
    udp: int = 0
    syn_out: int = 0
    rst_in: int = 0
    dns_queries: int = 0
    nxdomain: int = 0
    dns_txt: int = 0
    max_dns_entropy: float = 0.0
    long_dns_labels: int = 0
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    ext_ips: set[str] = field(default_factory=set)
    int_peers: set[str] = field(default_factory=set)
    syn_ports: set[int] = field(default_factory=set)
    syn_hosts: set[str] = field(default_factory=set)
    arp_targets: set[str] = field(default_factory=set)
    telnet_hosts: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    prefixes: set[str] = field(default_factory=set)
    admin_targets: set[str] = field(default_factory=set)
    insecure_out: set[str] = field(default_factory=set)
    insecure_in: set[str] = field(default_factory=set)
    blocklisted: dict[str, str] = field(default_factory=dict)
    syn_by_target: dict[str, int] = field(default_factory=dict)

    @property
    def packets(self) -> int:
        return self.pkts_out + self.pkts_in

    def features(self) -> dict[str, float]:
        total = max(self.packets, 1)
        return {
            "pkts_out": self.pkts_out, "pkts_in": self.pkts_in,
            "bytes_out": self.bytes_out, "bytes_in": self.bytes_in,
            "uniq_dst_ips": len(self.dst_ips), "uniq_dst_ports": len(self.dst_ports),
            "uniq_ext_ips": len(self.ext_ips), "uniq_int_peers": len(self.int_peers),
            "syn_out": self.syn_out, "rst_in": self.rst_in,
            "dns_queries": self.dns_queries, "uniq_domains": len(self.domains),
            "nxdomain": self.nxdomain, "dns_txt": self.dns_txt,
            "max_dns_entropy": round(self.max_dns_entropy, 3),
            "long_dns_labels": self.long_dns_labels,
            "arp_targets": len(self.arp_targets), "telnet_hosts": len(self.telnet_hosts),
            "tcp_frac": round(self.tcp / total, 4), "udp_frac": round(self.udp / total, 4),
            "mean_pkt_size": round((self.bytes_out + self.bytes_in) / total, 1),
        }


class WindowAggregator:
    def __init__(self, scope: NetworkScope, blocklist: Blocklist, window_seconds: int,
                 admin_ports: list[int], dns_label_length: int,
                 tracked: Mapping[str, object] | None = None) -> None:
        self.scope = scope
        self.blocklist = blocklist
        self.window = window_seconds
        self.admin_ports = set(admin_ports)
        self.dns_label_length = dns_label_length
        self.current_start: float | None = None
        self.windows: dict[str, DeviceWindow] = {}
        # When given (the inventory), only devices it accepted get windows, so
        # forged MACs rejected by the inventory cap cannot grow this either.
        self.tracked = tracked

    def _tracked(self, mac: str | None) -> bool:
        if not is_unicast_mac(mac):
            return False
        return self.tracked is None or mac in self.tracked

    def _window(self, mac: str) -> DeviceWindow:
        win = self.windows.get(mac)
        if win is None:
            if self.current_start is None:
                raise RuntimeError("window accessed before the first packet")
            win = self.windows[mac] = DeviceWindow(mac, self.current_start)
        return win

    def add(self, record: PacketRecord) -> list[DeviceWindow]:
        """Account one packet. Returns windows completed by moving past them."""
        finished = self.advance(record.ts)
        if self.current_start is None:
            self.current_start = record.ts - record.ts % self.window

        if record.proto == "arp":
            if self._tracked(record.src_mac) and record.arp_op == 1 and record.dst_ip:
                win = self._window(record.src_mac)  # type: ignore[arg-type]
                win.pkts_out += 1
                _bounded_add(win.arp_targets, record.dst_ip)
            return finished

        src_local = self.scope.contains(record.src_ip) and self._tracked(record.src_mac)
        dst_local = self.scope.contains(record.dst_ip) and self._tracked(record.dst_mac)
        if src_local:
            self._outbound(self._window(record.src_mac), record, dst_local)  # type: ignore[arg-type]
        if dst_local:
            self._inbound(self._window(record.dst_mac), record)  # type: ignore[arg-type]
        return finished

    def _outbound(self, win: DeviceWindow, r: PacketRecord, dst_local: bool) -> None:
        win.pkts_out += 1
        win.bytes_out += r.length
        win.tcp += r.proto == "tcp"
        win.udp += r.proto == "udp"
        if r.dst_ip:
            _bounded_add(win.dst_ips, r.dst_ip)
            if dst_local:
                _bounded_add(win.int_peers, r.dst_ip)
            elif not _address_kind(r.dst_ip)[0]:
                _bounded_add(win.ext_ips, r.dst_ip)
                if _address_kind(r.dst_ip)[1]:
                    _bounded_add(win.prefixes, _prefix(r.dst_ip))
                reason = self.blocklist.match_ip(r.dst_ip)
                if reason and len(win.blocklisted) < 64:
                    win.blocklisted[r.dst_ip] = reason
        if r.dport is not None:
            _bounded_add(win.dst_ports, r.dport)
        if r.is_syn and r.dst_ip:
            win.syn_out += 1
            _bounded_add(win.syn_ports, r.dport)
            if dst_local:
                _bounded_add(win.syn_hosts, r.dst_ip)
            if len(win.syn_by_target) < MAX_TRACKED or r.dst_ip in win.syn_by_target:
                win.syn_by_target[r.dst_ip] = win.syn_by_target.get(r.dst_ip, 0) + 1
            if r.dport in TELNET_PORTS:
                _bounded_add(win.telnet_hosts, r.dst_ip)
            if dst_local and r.dport in self.admin_ports:
                _bounded_add(win.admin_targets, f"{r.dst_ip}:{r.dport}")
        if r.dport in INSECURE_PORTS and r.dst_ip and not r.is_syn:
            _bounded_add(win.insecure_out, f"{INSECURE_PORTS[r.dport]}:{r.dst_ip}")
        if r.dns_qname and not r.dns_response and r.dport == 53:  # unicast DNS only
            win.dns_queries += 1
            _bounded_add(win.domains, r.dns_qname)
            win.dns_txt += r.dns_qtype == 16
            win.max_dns_entropy = max(win.max_dns_entropy, r.dns_label_entropy)
            longest = max((len(label) for label in r.dns_qname.split(".")), default=0)
            win.long_dns_labels += longest >= self.dns_label_length
        for name in (r.dns_qname if r.dport == 53 else None, r.tls_sni, r.http_host):
            if name:
                reason = self.blocklist.match_domain(name)
                if reason and len(win.blocklisted) < 64:
                    win.blocklisted[name] = reason
        if r.tls_sni:
            _bounded_add(win.domains, r.tls_sni)

    def _inbound(self, win: DeviceWindow, r: PacketRecord) -> None:
        win.pkts_in += 1
        win.bytes_in += r.length
        win.tcp += r.proto == "tcp"
        win.udp += r.proto == "udp"
        if r.is_rst:
            win.rst_in += 1
        if r.dns_response and r.dns_rcode == 3 and r.sport == 53:
            win.nxdomain += 1
        if r.dport in INSECURE_PORTS and r.src_ip and not r.is_syn and r.proto == "tcp":
            _bounded_add(win.insecure_in, f"{INSECURE_PORTS[r.dport]}:{r.src_ip}")

    def advance(self, now: float) -> list[DeviceWindow]:
        """Close the current window if ``now`` lies beyond it."""
        if self.current_start is None or now < self.current_start + self.window:
            return []
        finished = list(self.windows.values())
        self.windows = {}
        self.current_start = now - now % self.window
        return finished

    def drain(self) -> list[DeviceWindow]:
        finished = list(self.windows.values())
        self.windows = {}
        return finished
