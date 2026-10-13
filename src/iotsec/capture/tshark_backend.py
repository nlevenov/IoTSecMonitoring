"""tshark backend.

Recommended for production: dumpcap (shipped with Wireshark) holds the
capture privileges, so this process can run as an unprivileged user. tshark
is always started without a shell and with name resolution disabled.
"""

from __future__ import annotations

import logging
import shutil
import subprocess  # nosec B404 - fixed argv, no shell, validated arguments
import threading
from collections.abc import Iterator
from pathlib import Path

from ..models import PacketRecord
from ..sanitize import (
    clean_domain,
    clean_text,
    domain_label_entropy,
    normalize_mac,
    valid_interface,
    valid_ip,
)

log = logging.getLogger(__name__)

FIELDS = (
    "frame.time_epoch", "frame.len", "eth.src", "eth.dst",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.proto", "ipv6.nxt",
    "tcp.srcport", "tcp.dstport", "tcp.flags", "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.flags.response", "dns.ptr.domain_name",
    "tls.handshake.extensions_server_name", "http.host", "http.server",
    "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "dhcp.option.hostname", "dhcp.option.vendor_class_id",
)
_INDEX = {name: i for i, name in enumerate(FIELDS)}
_PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp"}


def tshark_path() -> str:
    path = shutil.which("tshark")
    if path is None:
        raise RuntimeError("tshark not found - install Wireshark/tshark or use the scapy backend")
    return path


def _validate_filter(bpf: str) -> str:
    if len(bpf) > 512 or bpf.startswith("-") or not bpf.isprintable():
        raise ValueError("invalid capture filter")
    return bpf


def build_command(*, iface: str | None = None, pcap: str | Path | None = None,
                  bpf_filter: str = "") -> list[str]:
    command = [tshark_path(), "-n", "-l", "-Q", "-T", "fields", "-E", "separator=/t",
               "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n"]
    if pcap is not None:
        path = Path(pcap).resolve(strict=True)  # absolute: can never look like an option
        command += ["-r", str(path)]
    elif iface:
        command += ["-i", valid_interface(iface)]
    if bpf_filter:
        if pcap is not None:
            raise ValueError("capture filters only apply to live capture")
        command += ["-f", _validate_filter(bpf_filter)]
    for field in FIELDS:
        command += ["-e", field]
    return command


def _first(value: str) -> str:
    return value.split(",", 1)[0] if value else ""


def _int(value: str, base: int = 10) -> int | None:
    try:
        return int(_first(value), base)
    except ValueError:
        return None


def parse_line(line: str) -> PacketRecord | None:
    cols = line.rstrip("\n").split("\t")
    if len(cols) != len(FIELDS):
        return None

    def col(name: str) -> str:
        return cols[_INDEX[name]]

    try:
        ts = float(col("frame.time_epoch"))
    except ValueError:
        return None
    record = PacketRecord(ts=ts, length=_int(col("frame.len")) or 0,
                          src_mac=normalize_mac(_first(col("eth.src"))),
                          dst_mac=normalize_mac(_first(col("eth.dst"))))
    if col("arp.opcode"):
        record.proto, record.arp_op = "arp", _int(col("arp.opcode"))
        record.src_mac = normalize_mac(col("arp.src.hw_mac")) or record.src_mac
        record.src_ip = valid_ip(col("arp.src.proto_ipv4"))
        record.dst_ip = valid_ip(col("arp.dst.proto_ipv4"))
        return record

    record.src_ip = valid_ip(_first(col("ip.src")) or _first(col("ipv6.src")))
    record.dst_ip = valid_ip(_first(col("ip.dst")) or _first(col("ipv6.dst")))
    if record.src_ip is None and record.dst_ip is None:
        return record if record.src_mac else None
    record.proto = _PROTOCOLS.get(_first(col("ip.proto")) or _first(col("ipv6.nxt")), "other")
    if col("tcp.srcport"):
        record.proto = "tcp"
        record.sport, record.dport = _int(col("tcp.srcport")), _int(col("tcp.dstport"))
        record.tcp_flags = _int(col("tcp.flags"), 16)
    elif col("udp.srcport"):
        record.proto = "udp"
        record.sport, record.dport = _int(col("udp.srcport")), _int(col("udp.dstport"))

    if col("dns.qry.name"):
        record.dns_qname = clean_domain(_first(col("dns.qry.name")))
        record.dns_qtype = _int(col("dns.qry.type"))
        record.dns_rcode = _int(col("dns.flags.rcode"))
        record.dns_response = _first(col("dns.flags.response")).lower() in ("1", "true")
        if record.dns_qname:
            record.dns_label_entropy = round(domain_label_entropy(record.dns_qname), 3)
    if col("dns.ptr.domain_name") and 5353 in (record.sport, record.dport):
        names = (clean_text(n, 96) for n in col("dns.ptr.domain_name").split(",")[:16])
        record.mdns_names = tuple(dict.fromkeys(n.rstrip(".") for n in names if n))
    record.tls_sni = clean_domain(_first(col("tls.handshake.extensions_server_name")))
    if 1900 in (record.sport, record.dport):  # SSDP reuses HTTP headers
        record.ssdp_server = clean_text(_first(col("http.server")), 96)
    elif record.proto == "tcp":
        record.http_host = clean_domain(_first(col("http.host")).split(":", 1)[0])
    record.dhcp_hostname = clean_text(_first(col("dhcp.option.hostname")), 64)
    record.dhcp_vendor = clean_text(_first(col("dhcp.option.vendor_class_id")), 64)
    return record


def _run(command: list[str]) -> Iterator[PacketRecord]:
    # argv list built by build_command: absolute tshark path, validated interface,
    # resolved pcap path, validated filter - never passed through a shell
    process = subprocess.Popen(  # nosec B603
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1)
    stderr: list[str] = []
    drain = threading.Thread(target=lambda: stderr.extend(process.stderr), daemon=True)
    drain.start()
    try:
        if process.stdout is None:
            raise RuntimeError("tshark produced no output stream")
        for line in process.stdout:
            record = parse_line(line)
            if record is not None:
                yield record
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        drain.join(timeout=1)
    if process.returncode not in (0, None, -15):
        raise RuntimeError(f"tshark failed: {''.join(stderr[-5:]).strip()}")


def read_pcap(path: str | Path) -> Iterator[PacketRecord]:
    return _run(build_command(pcap=path))


def live(iface: str | None, bpf_filter: str = "") -> Iterator[PacketRecord]:
    return _run(build_command(iface=iface, bpf_filter=bpf_filter))
