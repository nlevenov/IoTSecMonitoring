"""Synthetic smart-home traffic with labelled attacks, written as a real pcap.

The first part of the capture is normal behaviour (the learning period),
then a sequence of attacks is staged. Ground truth is written next to the
pcap so detections can be scored. External infrastructure uses the
documentation ranges (RFC 5737) and the reserved .test / .example TLDs.
"""

from __future__ import annotations

import json
import random
import string
import time
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter

NET = "192.168.50"
UNSPECIFIED = ".".join("0" * 4)  # DHCP clients have no address yet
ROUTER = (f"{NET}.1", "a0:40:a0:50:00:01")


@dataclass
class SimDevice:
    name: str
    ip: str
    mac: str
    hostname: str
    cloud: list[tuple[str, str, int]]  # (domain, ip, port)
    rate: float                         # sessions per minute
    upload: tuple[int, int]             # bytes per session (min, max)
    download: tuple[int, int]


DEVICES = [
    SimDevice("camera", f"{NET}.10", "44:19:b6:50:00:10", "ipcam-frontdoor",
              [("cam-cloud.example.net", "203.0.113.10", 443)], 6, (4000, 12000), (300, 1000)),
    SimDevice("bulb", f"{NET}.11", "00:17:88:50:00:11", "hue-bridge",
              [("mqtt.lights.example.com", "198.51.100.20", 8883)], 2, (200, 400), (200, 400)),
    SimDevice("plug", f"{NET}.12", "94:10:3e:50:00:12", "wemo-plug-kitchen",
              [("api.plug.example.com", "198.51.100.30", 443)], 1, (300, 600), (300, 900)),
    SimDevice("tv", f"{NET}.13", "b0:a7:37:50:00:13", "roku-livingroom",
              [("video.stream.example.net", "192.0.2.50", 443),
               ("api.tv.example.com", "192.0.2.60", 443)], 4, (1000, 4000), (30000, 120000)),
    SimDevice("thermostat", f"{NET}.14", "44:61:32:50:00:14", "ecobee-hallway",
              [("api.thermo.example.com", "198.51.100.40", 443)], 1, (500, 1500), (500, 1500)),
    SimDevice("speaker", f"{NET}.15", "00:0e:58:50:00:15", "sonos-kitchen",
              [("music.audio.example.com", "192.0.2.70", 443),
               ("time.audio.example.com", "192.0.2.71", 443)], 3, (800, 2500), (8000, 30000)),
    SimDevice("laptop", f"{NET}.20", "3a:1c:5e:50:00:20", "nikola-laptop",
              [(f"site{i}.example.org", f"192.0.2.{100 + i}", 443) for i in range(40)],
              8, (1000, 5000), (5000, 60000)),
]
INTRUDER = SimDevice("intruder", f"{NET}.66", "24:0a:c4:50:00:66", "esp-device",
                     [], 0, (0, 0), (0, 0))


@dataclass
class Scenario:
    packets: list[Packet] = field(default_factory=list)
    labels: list[dict] = field(default_factory=list)


class Generator:
    def __init__(self, seed: int) -> None:
        # seeded PRNG on purpose: lab captures must be reproducible (not crypto)
        self.rng = random.Random(seed)  # noqa: S311  # nosec B311
        self.out = Scenario()
        self.sport = 40000

    def _port(self) -> int:
        self.sport = 40000 + (self.sport - 39999) % 20000
        return self.sport

    def _emit(self, ts: float, pkt: Packet) -> None:
        pkt.time = ts
        self.out.packets.append(pkt)

    def _data(self, ts: float, headers: Packet, size: int) -> None:
        """A data segment stored truncated, like a capture with a short snaplen.

        Only the first bytes of the payload are written; the pcap records the
        full on-the-wire length, which is what the analysis uses.
        """
        pkt = headers / Raw(b"\0" * min(size, 32))
        pkt.wirelen = len(headers) + size
        self._emit(ts, pkt)

    def eth(self, src: SimDevice | tuple[str, str], dst_mac: str) -> Ether:
        mac = src.mac if isinstance(src, SimDevice) else src[1]
        return Ether(src=mac, dst=dst_mac)

    # ------------------------------------------------------------- building
    def dns(self, ts: float, dev: SimDevice, name: str, answer: str | None, qtype: str = "A",
            rcode: int = 0) -> None:
        sport = self._port()
        self._emit(ts, self.eth(dev, ROUTER[1]) / IP(src=dev.ip, dst=ROUTER[0]) /
                   UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype)))
        reply = DNS(id=0, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype))
        if answer and rcode == 0:
            reply.an = DNSRR(rrname=name, type="A", ttl=300, rdata=answer)
        self._emit(ts + 0.01, Ether(src=ROUTER[1], dst=dev.mac) / IP(src=ROUTER[0], dst=dev.ip) /
                   UDP(sport=53, dport=sport) / reply)

    def session(self, ts: float, dev: SimDevice, dst_ip: str, dport: int, up: int, down: int,
                dst_mac: str = ROUTER[1]) -> float:
        """A TCP connection with handshake, data in both directions and teardown."""
        sport = self._port()
        out = self.eth(dev, dst_mac) / IP(src=dev.ip, dst=dst_ip)
        back = Ether(src=dst_mac, dst=dev.mac) / IP(src=dst_ip, dst=dev.ip)
        self._emit(ts, out / TCP(sport=sport, dport=dport, flags="S"))
        self._emit(ts + 0.02, back / TCP(sport=dport, dport=sport, flags="SA"))
        self._emit(ts + 0.03, out / TCP(sport=sport, dport=dport, flags="A"))
        t = ts + 0.05
        for chunk in _chunks(up):
            self._data(t, out / TCP(sport=sport, dport=dport, flags="PA"), chunk)
            t += 0.002
        for chunk in _chunks(down):
            self._data(t, back / TCP(sport=dport, dport=sport, flags="PA"), chunk)
            t += 0.002
        self._emit(t, out / TCP(sport=sport, dport=dport, flags="FA"))
        self._emit(t + 0.01, back / TCP(sport=dport, dport=sport, flags="FA"))
        return t

    def dhcp(self, ts: float, dev: SimDevice) -> None:
        self._emit(ts, Ether(src=dev.mac, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=UNSPECIFIED, dst="255.255.255.255") / UDP(sport=68, dport=67) /
                   BOOTP(chaddr=bytes.fromhex(dev.mac.replace(":", "")),
                         xid=self.rng.getrandbits(32)) /
                   DHCP(options=[("message-type", "request"), ("requested_addr", dev.ip),
                                 ("hostname", dev.hostname.encode()),
                                 ("vendor_class_id", b"udhcp 1.31.1"), "end"]))

    def arp_announce(self, ts: float, dev: SimDevice | tuple[str, str], claim_ip: str | None = None,
                     op: int = 2) -> None:
        mac = dev.mac if isinstance(dev, SimDevice) else dev[1]
        ip = claim_ip or (dev.ip if isinstance(dev, SimDevice) else dev[0])
        self._emit(ts, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                   ARP(op=op, hwsrc=mac, psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip))

    def mdns(self, ts: float, dev: SimDevice, service: str) -> None:
        self._emit(ts, Ether(src=dev.mac, dst="01:00:5e:00:00:fb") /
                   IP(src=dev.ip, dst="224.0.0.251") / UDP(sport=5353, dport=5353) /
                   DNS(qr=1, aa=1, an=DNSRR(rrname=service, type="PTR", ttl=120,
                                            rdata=f"{dev.hostname}.{service}")))

    def ssdp(self, ts: float, dev: SimDevice) -> None:
        payload = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   b"NT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\n"
                   b"SERVER: Roku/12.5 UPnP/1.0 MiniUPnPd/1.4\r\n\r\n")
        self._emit(ts, Ether(src=dev.mac, dst="01:00:5e:7f:ff:fa") /
                   IP(src=dev.ip, dst="239.255.255.250") / UDP(sport=1900, dport=1900) /
                   Raw(payload))

    # ------------------------------------------------------------ behaviour
    def normal_minute(self, minute_start: float) -> None:
        for dev in DEVICES:
            sessions = self._poisson(dev.rate)
            for _ in range(sessions):
                ts = minute_start + self.rng.uniform(0, 58)
                domain, ip, port = self.rng.choice(dev.cloud)
                if self.rng.random() < 0.25:
                    self.dns(ts - 0.2, dev, domain, ip)
                self.session(ts, dev, ip, port, self.rng.randint(*dev.upload),
                             self.rng.randint(*dev.download))

    def _poisson(self, rate: float) -> int:
        count, threshold, product = 0, pow(2.718281828, -rate), self.rng.random()
        while product > threshold and count < 50:
            count += 1
            product *= self.rng.random()
        return count

    def label(self, kind: str, dev: SimDevice, start: float, end: float) -> None:
        self.out.labels.append({"alert_type": kind, "device_mac": dev.mac,
                                "start": start, "end": end})


def _chunks(total: int, size: int = 1400) -> list[int]:
    full, rest = divmod(total, size)
    return [size] * full + ([rest] if rest else [])


def generate(start: float | None = None, learning_minutes: int = 40, attack_minutes: int = 30,
             seed: int = 7) -> Scenario:
    gen = Generator(seed)
    rng = gen.rng
    start = start if start is not None else time.time() - (learning_minutes + attack_minutes) * 60
    start -= start % 60

    for i, dev in enumerate(DEVICES):  # devices come online
        t = start + 1 + i
        gen.dhcp(t, dev)
        gen.arp_announce(t + 0.5, dev)
    gen.arp_announce(start + 0.2, ROUTER)
    for minute in range(learning_minutes + attack_minutes):
        m = start + minute * 60
        gen.normal_minute(m)
        if minute % 5 == 0:
            gen.mdns(m + 3, DEVICES[1], "_hue._tcp.local")
            gen.mdns(m + 4, DEVICES[5], "_sonos._tcp.local")
            gen.ssdp(m + 5, DEVICES[3])
            for dev in DEVICES:
                gen.arp_announce(m + 6 + rng.random(), dev, op=1)

    attack = start + learning_minutes * 60
    cam, bulb, plug, tv, thermo, _speaker, laptop = DEVICES

    # 1. an unknown device joins
    t = attack + 30
    gen.dhcp(t, INTRUDER)
    gen.arp_announce(t + 1, INTRUDER)
    gen.label("new_device", INTRUDER, t, t + 60)

    # 2. Mirai-style telnet scanning from the camera
    t = attack + 3 * 60
    for i in range(80):
        target = f"{NET}.{100 + i}" if i < 40 else f"198.51.100.{100 + i}"
        gen._emit(t + i * 0.5, gen.eth(cam, ROUTER[1]) / IP(src=cam.ip, dst=target) /
                  TCP(sport=gen._port(), dport=rng.choice([23, 2323]), flags="S"))
    gen.label("mirai_scan", cam, t, t + 60)

    # 3. the bulb joins a SYN flood
    t = attack + 7 * 60
    for i in range(4500):
        gen._emit(t + i * 0.012, gen.eth(bulb, ROUTER[1]) / IP(src=bulb.ip, dst="198.51.100.200") /
                  TCP(sport=rng.randint(1024, 65535), dport=80, flags="S"))
    gen.label("flood", bulb, t, t + 60)

    # 4. DNS tunnelling from the plug
    t = attack + 11 * 60
    for i in range(40):
        label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(48))
        gen.dns(t + i * 1.2, plug, f"{label}.tunnel.evil-dns.test", None, qtype="TXT",
                rcode=3 if i % 3 == 0 else 0)
    gen.label("dns_tunnel", plug, t, t + 60)

    # 5. the intruder claims the gateway's IP (ARP spoofing)
    t = attack + 15 * 60
    for i in range(10):
        gen.arp_announce(t + i * 2, INTRUDER, claim_ip=ROUTER[0])
    gen.label("arp_spoofing", INTRUDER, t, t + 60)

    # 6. the thermostat uploads far more than usual
    t = attack + 19 * 60
    gen.session(t, thermo, "203.0.113.99", 443, 3_000_000, 2000)
    gen.label("exfiltration", thermo, t, t + 60)

    # 7. the camera contacts known C2 infrastructure
    t = attack + 23 * 60
    gen.dns(t, cam, "c2.botnet-example.test", "203.0.113.66")
    gen.session(t + 1, cam, "203.0.113.66", 443, 1200, 800)
    gen.label("blocklisted_destination", cam, t, t + 60)

    # 8. the TV opens SMB to the laptop (lateral movement)
    t = attack + 27 * 60
    for port in (445, 445, 3389):
        gen.session(t + rng.random() * 10, tv, laptop.ip, port, 600, 400, dst_mac=laptop.mac)
    gen.label("lateral_movement", tv, t, t + 60)

    gen.out.packets.sort(key=lambda p: float(p.time))
    return gen.out


def write(scenario: Scenario, pcap_path: str | Path) -> Path:
    pcap_path = Path(pcap_path)
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(str(pcap_path), linktype=1, sync=False) as writer:
        for packet in scenario.packets:
            writer.write(packet)
    labels = pcap_path.with_suffix(".labels.json")
    labels.write_text(json.dumps({"devices": {d.mac: d.name for d in DEVICES + [INTRUDER]},
                                  "attacks": scenario.labels}, indent=2), encoding="utf-8")
    return labels
