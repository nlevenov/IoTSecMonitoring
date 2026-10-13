from __future__ import annotations

import contextlib
import ssl

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from iotsec.models import PacketRecord

NET = "192.168.50"
CAMERA = ("44:19:b6:50:00:10", f"{NET}.10")
BULB = ("00:17:88:50:00:11", f"{NET}.11")
LAPTOP = ("3a:1c:5e:50:00:20", f"{NET}.20")
ROUTER = ("a0:40:a0:50:00:01", f"{NET}.1")


def client_hello(server_name: str) -> bytes:
    """A genuine TLS ClientHello produced by Python's own TLS stack."""
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    with contextlib.suppress(ssl.SSLWantReadError):  # waits for a server that never answers
        tls.do_handshake()
    return outgoing.read()


def record(ts: float = 1000.0, src=CAMERA, dst=("ff:ee:dd:00:00:01", "203.0.113.10"),
           **fields) -> PacketRecord:
    defaults = {"proto": "tcp", "sport": 40000, "dport": 443, "length": 100}
    defaults.update(fields)
    return PacketRecord(ts=ts, src_mac=src[0], src_ip=src[1], dst_mac=dst[0], dst_ip=dst[1],
                        **defaults)


def tcp(src, dst_ip: str, dport: int, flags: str = "PA", dst_mac: str = ROUTER[0]):
    return Ether(src=src[0], dst=dst_mac) / IP(src=src[1], dst=dst_ip) / \
        TCP(sport=40000, dport=dport, flags=flags)


def udp(src, dst_ip: str, dport: int, dst_mac: str = ROUTER[0]):
    return Ether(src=src[0], dst=dst_mac) / IP(src=src[1], dst=dst_ip) / \
        UDP(sport=40000, dport=dport)
