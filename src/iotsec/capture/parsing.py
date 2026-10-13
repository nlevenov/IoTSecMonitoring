"""Small, defensive parsers for application metadata in raw payloads.

Every read is bounds-checked: malformed or hostile packets yield ``None``,
never an exception.
"""

from __future__ import annotations

import struct

from ..sanitize import clean_domain, clean_text

MAX_SCAN = 2048


def tls_sni(payload: bytes) -> str | None:
    """Server name from a TLS ClientHello, if this payload starts with one."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None  # not handshake / not ClientHello
        pos = 9 + 2 + 32  # record + handshake headers, client version, random
        session_len = payload[pos]
        pos += 1 + session_len
        (cipher_len,) = struct.unpack_from("!H", payload, pos)
        pos += 2 + cipher_len
        compression_len = payload[pos]
        pos += 1 + compression_len
        (ext_total,) = struct.unpack_from("!H", payload, pos)
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", payload, pos)
            pos += 4
            if ext_type == 0x0000:  # server_name
                # list length (2), name type (1), name length (2), name
                name_type = payload[pos + 2]
                (name_len,) = struct.unpack_from("!H", payload, pos + 3)
                if name_type != 0 or pos + 5 + name_len > len(payload):
                    return None
                return clean_domain(payload[pos + 5:pos + 5 + name_len])
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def http_host(payload: bytes) -> str | None:
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload[:MAX_SCAN]
    for line in head.split(b"\r\n")[1:]:
        if not line:
            break
        if line[:5].lower() == b"host:":
            host = line[5:].strip().split(b":", 1)[0]
            return clean_domain(host)
    return None


def ssdp_server(payload: bytes) -> str | None:
    """SERVER / NT / ST header of an SSDP announcement - describes the device."""
    head = payload[:MAX_SCAN]
    found = None
    for line in head.split(b"\r\n"):
        key, _, value = line.partition(b":")
        key = key.strip().lower()
        if key == b"server":
            return clean_text(value, 96)
        if key in (b"nt", b"st") and b"urn:" in value and found is None:
            found = clean_text(value, 96)
    return found
