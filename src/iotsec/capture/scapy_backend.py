"""Scapy backend: live sniffing and pcap reading."""

from __future__ import annotations

import logging
import os
import pwd
import queue
import threading
from collections.abc import Iterator
from pathlib import Path

from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapReader

from ..models import PacketRecord
from ..sanitize import (
    clean_domain,
    clean_text,
    domain_label_entropy,
    normalize_mac,
    valid_interface,
    valid_ip,
)
from .parsing import http_host, ssdp_server, tls_sni

log = logging.getLogger(__name__)


def _records(section: object) -> list[object]:
    """DNS sections are lists in recent scapy and linked records in older ones."""
    if section is None:
        return []
    if isinstance(section, list):
        return section
    items, node, guard = [], section, 0
    while node is not None and getattr(node, "name", None) and guard < 64:
        items.append(node)
        node = getattr(node, "payload", None)
        guard += 1
        if node is not None and node.__class__.__name__ == "NoPayload":
            break
    return items


def _dhcp_options(pkt: Packet) -> tuple[str | None, str | None]:
    hostname = vendor = None
    for option in pkt[DHCP].options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        if option[0] == "hostname":
            hostname = clean_text(option[1], 64)
        elif option[0] == "vendor_class_id":
            vendor = clean_text(option[1], 64)
    return hostname, vendor


def to_record(pkt: Packet) -> PacketRecord | None:
    """Convert a scapy packet into metadata. Returns None for unusable frames."""
    # wire length, not captured length: captures are often truncated (snaplen)
    record = PacketRecord(ts=float(pkt.time), length=int(getattr(pkt, "wirelen", None) or len(pkt)))
    if Ether in pkt:
        record.src_mac = normalize_mac(pkt[Ether].src)
        record.dst_mac = normalize_mac(pkt[Ether].dst)

    if ARP in pkt:
        arp = pkt[ARP]
        record.proto, record.arp_op = "arp", int(arp.op)
        record.src_mac = normalize_mac(arp.hwsrc) or record.src_mac
        record.src_ip, record.dst_ip = valid_ip(arp.psrc), valid_ip(arp.pdst)
        return record

    if IP in pkt:
        record.src_ip, record.dst_ip = valid_ip(pkt[IP].src), valid_ip(pkt[IP].dst)
    elif IPv6 in pkt:
        record.src_ip, record.dst_ip = valid_ip(pkt[IPv6].src), valid_ip(pkt[IPv6].dst)
    else:
        return record if record.src_mac else None

    payload = b""
    if TCP in pkt:
        tcp = pkt[TCP]
        record.proto, record.sport, record.dport = "tcp", int(tcp.sport), int(tcp.dport)
        record.tcp_flags = int(tcp.flags)
        payload = bytes(tcp.payload) if Raw in pkt else b""
    elif UDP in pkt:
        udp = pkt[UDP]
        record.proto, record.sport, record.dport = "udp", int(udp.sport), int(udp.dport)
        payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    elif ICMP in pkt:
        record.proto = "icmp"

    if DNS in pkt:
        _dns(pkt[DNS], record)
    if DHCP in pkt:
        record.dhcp_hostname, record.dhcp_vendor = _dhcp_options(pkt)
    if payload:
        if record.proto == "tcp":
            record.tls_sni = tls_sni(payload) if record.dport in (443, 8443, 8883) else None
            record.http_host = http_host(payload)
        elif 1900 in (record.sport, record.dport):
            record.ssdp_server = ssdp_server(payload)
    return record


def _dns(dns: Packet, record: PacketRecord) -> None:
    record.dns_response = bool(dns.qr)
    record.dns_rcode = int(dns.rcode) if dns.qr else None  # only meaningful in responses
    questions = _records(dns.qd)
    if questions:
        raw_name = bytes(getattr(questions[0], "qname", b"") or b"")[:253]
        record.dns_qname = clean_domain(raw_name)
        record.dns_qtype = int(getattr(questions[0], "qtype", 0) or 0)
        if record.dns_qname:
            record.dns_label_entropy = round(domain_label_entropy(record.dns_qname), 3)
    if 5353 in (record.sport, record.dport):  # mDNS service announcements
        names = []
        for answer in _records(dns.an)[:16]:
            if getattr(answer, "type", None) == 12:  # PTR
                value = getattr(answer, "rdata", b"")
                name = clean_text(value if isinstance(value, (bytes, str)) else str(value), 96)
                if name:
                    names.append(name.rstrip("."))
        record.mdns_names = tuple(dict.fromkeys(names))


def read_pcap(path: str | Path) -> Iterator[PacketRecord]:
    errors = 0
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            try:
                record = to_record(pkt)
            except Exception as exc:  # malformed frames must never stop the monitor
                errors += 1
                log.debug("skipping unparsable packet: %s", exc)
                continue
            if record is not None:
                yield record
    if errors:
        log.info("%d packets could not be parsed", errors)


def drop_privileges(username: str) -> None:
    """Switch to an unprivileged user once the capture socket is open."""
    entry = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("failed to drop root privileges")
    log.info("dropped privileges to %s", username)


class LiveCapture:
    """Sniff an interface on a background thread and yield records."""

    def __init__(self, iface: str | None = None, bpf_filter: str = "",
                 drop_to: str = "", queue_size: int = 50_000) -> None:
        self.iface = valid_interface(iface) if iface else None
        self.bpf_filter = bpf_filter
        self.drop_to = drop_to
        self._queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self.dropped = 0
        self._sniffer = None

    def _handle(self, pkt: Packet) -> None:
        try:
            record = to_record(pkt)
        except Exception as exc:  # see read_pcap
            log.debug("skipping unparsable packet: %s", exc)
            return
        if record is None:
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self.dropped += 1  # back-pressure: never block the capture thread

    def start(self) -> None:
        from scapy.config import conf
        from scapy.sendrecv import AsyncSniffer

        kwargs = {"iface": self.iface} if self.iface else {}
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        # open the raw socket while still privileged ...
        sock = conf.L2listen(**kwargs)
        # ... then give the privileges up before touching any packet
        if self.drop_to:
            drop_privileges(self.drop_to)
        self._sniffer = AsyncSniffer(opened_socket=sock, prn=self._handle, store=False)
        self._sniffer.start()

    def records(self, poll: float = 0.5) -> Iterator[PacketRecord | None]:
        """Yield records; yields None every ``poll`` seconds when idle."""
        while not self._stop.is_set():
            try:
                yield self._queue.get(timeout=poll)
            except queue.Empty:
                yield None

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:  # sniffer may already be gone on shutdown
                log.debug("sniffer stop: %s", exc)
