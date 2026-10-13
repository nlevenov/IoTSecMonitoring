"""Normalization of untrusted values.

Everything this tool reads off the wire - DHCP host names, mDNS service
names, SSDP banners, DNS queries, TLS SNI - is chosen by whoever sent the
packet. Values are normalized here once, at ingestion, so the rest of the
code (database, dashboard, e-mail) only ever handles bounded, printable
text without markup characters.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter

_MAC = re.compile(r"^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?"
                  r"([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$")
_IFACE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_DOMAIN_CHARS = re.compile(r"[^a-z0-9._-]")
# characters that carry meaning in HTML, Markdown, shells or SQL literals
_UNSAFE_CHARS = str.maketrans("", "", "<>\"'`&\\|$;{}[]")
_SPACES = re.compile(r"\s+")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def clean_text(value: object, max_len: int = 128) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = "".join(ch for ch in str(value) if ch.isprintable())
    text = _SPACES.sub(" ", text.translate(_UNSAFE_CHARS)).strip()
    return text[:max_len] or None


def clean_domain(value: object) -> str | None:
    """Lower-cased DNS name restricted to LDH characters, at most 253 chars."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    text = str(value).strip().lower().rstrip(".")
    text = _DOMAIN_CHARS.sub("", text)[:253]
    return text or None


def normalize_mac(value: object) -> str | None:
    if value is None:
        return None
    match = _MAC.match(str(value).strip().lower())
    if not match:
        return None
    return ":".join(match.groups())


def valid_ip(value: object) -> str | None:
    if value is None or value == "":
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def is_unicast_mac(mac: str | None) -> bool:
    if not mac or mac == BROADCAST_MAC or mac == "00:00:00:00:00:00":
        return False
    return not int(mac[:2], 16) & 0x01  # multicast bit


def is_randomized_mac(mac: str | None) -> bool:
    """Locally administered addresses - used by phones and some IoT for privacy."""
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


def valid_interface(name: str) -> str:
    """Interface names are passed to capture tools - reject anything unusual."""
    if not _IFACE.match(name or "") or name.startswith("-"):
        raise ValueError(f"invalid interface name: {name!r}")
    return name


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def domain_label_entropy(domain: str) -> float:
    """Entropy of the longest label, the part DGA and tunnelling tools randomize."""
    labels = [label for label in domain.split(".") if label]
    if len(labels) > 2:
        labels = labels[:-2]  # ignore the registered domain and TLD
    longest = max(labels, key=len, default="")
    return shannon_entropy(longest)
