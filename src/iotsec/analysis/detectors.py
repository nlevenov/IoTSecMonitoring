"""Rule-based detectors over one device window.

Detectors that recognise attack *patterns* (scans, Mirai, floods, DNS
tunnelling, blocklisted contacts) run from the first window. Detectors that
compare against learned behaviour only run once the device's baseline has
finished learning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import DetectionSettings
from ..models import AlertType, Device, Severity
from .baseline import Baseline
from .features import DeviceWindow

# Devices with one job; anything outside their routine deserves attention.
SINGLE_PURPOSE = {"camera", "smart-bulb", "smart-plug", "thermostat", "smart-speaker",
                  "hub", "appliance", "iot-module", "printer"}
# Devices where admin connections to other hosts are expected.
ADMIN_CAPABLE = {"computer", "phone", "router", "nas"}


@dataclass
class Finding:
    alert_type: AlertType
    severity: Severity
    details: dict[str, Any] = field(default_factory=dict)


def _sample(values: set | dict | list, limit: int = 10) -> list:
    return sorted(map(str, values))[:limit]


def detect(window: DeviceWindow, baseline: Baseline | None, learning: bool,
           device: Device | None, settings: DetectionSettings) -> list[Finding]:
    findings: list[Finding] = []
    device_type = device.device_type if device else "unknown"

    # -------------------------------------------------- pattern detectors
    if len(window.telnet_hosts) >= settings.telnet_hosts:
        findings.append(Finding(AlertType.MIRAI_SCAN, Severity.CRITICAL, {
            "telnet_targets": len(window.telnet_hosts),
            "sample": _sample(window.telnet_hosts)}))
    elif len(window.syn_ports) >= settings.scan_ports or \
            len(window.syn_hosts) >= settings.scan_hosts or \
            len(window.arp_targets) >= settings.scan_hosts * 3:
        findings.append(Finding(AlertType.PORT_SCAN, Severity.HIGH, {
            "ports_probed": len(window.syn_ports), "hosts_probed": len(window.syn_hosts),
            "arp_targets": len(window.arp_targets), "sample_ports": _sample(window.syn_ports)}))

    flood_z = baseline.zscore("pkts_out", window.pkts_out) if baseline and not learning else None
    top_target, top_syns = max(window.syn_by_target.items(), key=lambda kv: kv[1],
                               default=(None, 0))
    if window.pkts_out >= settings.flood_packets and (
            flood_z is None or flood_z >= settings.flood_sigma):
        findings.append(Finding(AlertType.FLOOD, Severity.CRITICAL, {
            "packets_out": window.pkts_out,
            "zscore": round(flood_z, 1) if flood_z is not None else None,
            "top_target": top_target, "syn_to_top_target": top_syns}))

    if (window.max_dns_entropy >= settings.dns_entropy and window.long_dns_labels >= 3) or \
            window.nxdomain >= settings.dns_nxdomain or window.dns_txt >= settings.dns_txt:
        findings.append(Finding(AlertType.DNS_TUNNEL, Severity.HIGH, {
            "queries": window.dns_queries, "long_labels": window.long_dns_labels,
            "max_entropy": round(window.max_dns_entropy, 2), "nxdomain": window.nxdomain,
            "txt_queries": window.dns_txt, "sample": _sample(window.domains, 5)}))

    if window.blocklisted:
        findings.append(Finding(AlertType.BLOCKLISTED, Severity.CRITICAL, {
            "matches": dict(sorted(window.blocklisted.items())[:10])}))

    if window.insecure_in:
        findings.append(Finding(AlertType.INSECURE_PROTOCOL, Severity.MEDIUM, {
            "direction": "inbound - the device exposes a cleartext service",
            "sessions": _sample(window.insecure_in)}))
    elif window.insecure_out and len(window.telnet_hosts) < settings.telnet_hosts:
        findings.append(Finding(AlertType.INSECURE_PROTOCOL, Severity.LOW, {
            "direction": "outbound", "sessions": _sample(window.insecure_out)}))

    # ------------------------------------------------ baseline detectors
    if baseline is None or learning:
        return findings

    exfil_z = baseline.zscore("bytes_out", window.bytes_out)
    if window.bytes_out >= settings.exfil_bytes and exfil_z >= settings.exfil_sigma:
        findings.append(Finding(AlertType.EXFILTRATION, Severity.HIGH, {
            "bytes_out": window.bytes_out, "zscore": round(exfil_z, 1),
            "typical_bytes_out": round(baseline.stats["bytes_out"].mean),
            "destinations": _sample(window.ext_ips, 5)}))

    new_admin = window.admin_targets - baseline.admin_targets
    scanning = any(f.alert_type in (AlertType.MIRAI_SCAN, AlertType.PORT_SCAN) for f in findings)
    if new_admin and device_type not in ADMIN_CAPABLE and not scanning:
        findings.append(Finding(AlertType.LATERAL_MOVEMENT, Severity.HIGH, {
            "targets": _sample(new_admin)}))

    new = baseline.new_destinations(window)
    if len(new) >= settings.new_destinations:
        severity = Severity.MEDIUM if device_type in SINGLE_PURPOSE else Severity.LOW
        findings.append(Finding(AlertType.NEW_DESTINATIONS, severity, {
            "count": len(new), "sample": new[:10]}))
    return findings
