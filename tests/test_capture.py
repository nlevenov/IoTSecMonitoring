import random

import pytest
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from iotsec.capture import tshark_backend
from iotsec.capture.parsing import http_host, ssdp_server, tls_sni
from iotsec.capture.scapy_backend import read_pcap, to_record

from conftest import requires_tshark
from helpers import CAMERA, ROUTER, client_hello, tcp, udp


def test_tls_sni_from_real_client_hello():
    assert tls_sni(client_hello("api.camera-cloud.example")) == "api.camera-cloud.example"


def test_tls_sni_never_raises_on_truncated_or_random_input():
    hello = client_hello("x.example")
    for i in range(len(hello)):
        assert tls_sni(hello[:i]) in (None, "x.example")
    rng = random.Random(1)
    for _ in range(2000):
        blob = bytes([0x16, 3, 1, 0, 200, 1]) + rng.randbytes(rng.randint(0, 300))
        tls_sni(blob)


def test_http_and_ssdp_headers():
    assert http_host(b"GET / HTTP/1.1\r\nHost: Cam.Example.com:8080\r\n\r\n") == "cam.example.com"
    assert http_host(b"\x00\x01binary") is None
    banner = b"NOTIFY * HTTP/1.1\r\nSERVER: Linux UPnP/1.0 <b>Roku</b>\r\n\r\n"
    assert ssdp_server(banner) == "Linux UPnP/1.0 bRoku/b"


def test_dns_record():
    pkt = udp(CAMERA, ROUTER[1], 53) / DNS(rd=1, qd=DNSQR(qname="a1b2.Example.com", qtype=16))
    record = to_record(pkt)
    assert record.dns_qname == "a1b2.example.com" and record.dns_qtype == 16
    assert record.dns_rcode is None and not record.dns_response


def test_dhcp_hostname_is_sanitized():
    pkt = Ether(src=CAMERA[0], dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") \
        / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[
            ("message-type", "request"), ("hostname", b"cam<img src=x onerror=alert(1)>"),
            ("vendor_class_id", b"udhcp 1.30"), "end"])
    record = to_record(pkt)
    assert record.dhcp_hostname == "camimg src=x onerror=alert(1)"
    assert "<" not in record.dhcp_hostname and record.dhcp_vendor == "udhcp 1.30"


def test_mdns_and_arp():
    pkt = Ether(src=CAMERA[0], dst="01:00:5e:00:00:fb") / IP(src=CAMERA[1], dst="224.0.0.251") / \
        UDP(sport=5353, dport=5353) / DNS(qr=1, an=DNSRR(rrname="_hue._tcp.local", type="PTR",
                                                       rdata="Hue._hue._tcp.local"))
    assert to_record(pkt).mdns_names == ("Hue._hue._tcp.local",)
    arp = Ether(src=CAMERA[0], dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=CAMERA[0],
                                                             psrc=CAMERA[1], pdst=CAMERA[1])
    record = to_record(arp)
    assert (record.proto, record.arp_op, record.src_ip) == ("arp", 2, CAMERA[1])


def test_wire_length_is_used():
    pkt = tcp(CAMERA, "203.0.113.5", 443) / Raw(b"\0" * 10)
    pkt.wirelen = 1514
    assert to_record(pkt).length == 1514


def _sample_packets():
    return [
        udp(CAMERA, ROUTER[1], 53) / DNS(rd=1, qd=DNSQR(qname="x9f.evil.test", qtype=16)),
        tcp(CAMERA, "203.0.113.10", 443) / Raw(client_hello("cloud.example.net")),
        tcp(CAMERA, f"{ROUTER[1][:-1]}77", 23, flags="S"),
        Ether(src=CAMERA[0], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=CAMERA[0], psrc=CAMERA[1],
                                                           pdst=ROUTER[1]),
        Ether(src=CAMERA[0], dst="01:00:5e:7f:ff:fa") / IP(src=CAMERA[1], dst="239.255.255.250") /
        UDP(sport=1900, dport=1900) / Raw(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                                          b"SERVER: Roku/12 UPnP/1.0\r\n\r\n"),
        Ether(src=CAMERA[0]) / Raw(b"\x00" * 30),  # unparsable frame
    ]


def test_scapy_reader_skips_garbage(tmp_path):
    path = tmp_path / "s.pcap"
    wrpcap(str(path), _sample_packets())
    records = list(read_pcap(path))
    assert len(records) == 6 and records[1].tls_sni == "cloud.example.net"


@requires_tshark
def test_tshark_and_scapy_backends_agree(tmp_path):
    path = tmp_path / "s.pcap"
    wrpcap(str(path), _sample_packets())
    for a, b in zip(tshark_backend.read_pcap(path), read_pcap(path), strict=False):
        differences = {name for name in a.__slots__ if name != "ts"
                       and getattr(a, name) != getattr(b, name)}
        assert not differences, differences


@requires_tshark
def test_tshark_command_is_safe(tmp_path):
    path = tmp_path / "x.pcap"
    wrpcap(str(path), _sample_packets()[:1])
    command = tshark_backend.build_command(pcap=path)
    assert command[command.index("-r") + 1].startswith("/") and "-n" in command
    with pytest.raises(ValueError):
        tshark_backend.build_command(iface="eth0 -w /tmp/out")
    with pytest.raises(ValueError):
        tshark_backend.build_command(iface="eth0", bpf_filter="-w /tmp/out")
    with pytest.raises(FileNotFoundError):
        tshark_backend.build_command(pcap=tmp_path / "missing.pcap")


def test_tshark_parser_rejects_malformed_lines():
    assert tshark_backend.parse_line("too\tfew\tcolumns") is None
    columns = [""] * len(tshark_backend.FIELDS)
    columns[0] = "not-a-time"
    assert tshark_backend.parse_line("\t".join(columns)) is None
