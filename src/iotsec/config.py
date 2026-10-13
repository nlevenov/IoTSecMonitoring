"""Settings loaded from YAML with ${ENV_VAR} / ${ENV_VAR:-default} expansion.

Lookup order: explicit path, ``IOTSEC_CONFIG``, ``config/settings.yaml``.
Unknown keys are errors, so a typo never silently disables a control.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class CaptureSettings:
    backend: str = "scapy"           # scapy | tshark
    interface: str = ""              # empty = system default
    bpf_filter: str = ""
    window_seconds: int = 60
    drop_privileges_to: str = ""     # user to switch to after opening the capture socket


@dataclass
class DiscoverySettings:
    arp_timeout: float = 2.0
    active_probe: bool = False       # TCP connect probe of common IoT ports
    probe_ports: list[int] = field(default_factory=lambda: [
        22, 23, 53, 80, 443, 554, 1883, 5000, 7547, 8008, 8080, 8443, 8883, 9999])
    probe_timeout: float = 0.5
    online_minutes: int = 5
    max_devices: int = 2048          # inventory cap - protects against MAC flooding


@dataclass
class BaselineSettings:
    learning_hours: float = 24.0
    min_windows: int = 30
    max_destinations: int = 500


@dataclass
class DetectionSettings:
    scan_ports: int = 20             # distinct destination ports in one window
    scan_hosts: int = 20             # distinct internal hosts probed in one window
    telnet_hosts: int = 5            # distinct hosts contacted on 23/2323
    flood_packets: int = 3000        # absolute floor for flood detection per window
    flood_sigma: float = 6.0
    exfil_bytes: int = 1_000_000     # absolute floor for exfiltration per window
    exfil_sigma: float = 6.0
    dns_entropy: float = 3.8
    dns_label_length: int = 30
    dns_nxdomain: int = 10
    dns_txt: int = 15
    new_destinations: int = 5
    lateral_ports: list[int] = field(default_factory=lambda: [22, 23, 135, 139, 445, 3389, 5900])


@dataclass
class MlSettings:
    enabled: bool = True
    contamination: float = 0.01
    min_windows: int = 50
    retrain_hours: float = 24.0
    margin: float = 0.05             # extra score required beyond the model threshold


@dataclass
class EmailSettings:
    enabled: bool = False
    host: str = ""
    port: int = 465
    security: str = "ssl"            # ssl (implicit TLS) | starttls - plaintext is not offered
    username: str = ""
    password: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)


@dataclass
class NotifySettings:
    min_severity: str = "high"
    cooldown_minutes: int = 30
    email: EmailSettings = field(default_factory=EmailSettings)
    webhook_url: str = ""


@dataclass
class DashboardSettings:
    password_hash: str = ""
    session_minutes: int = 720
    refresh_seconds: int = 10
    # Host names browsers use to reach the dashboard (DNS-rebinding protection).
    # Empty = loopback names only.
    allowed_hosts: list[str] = field(default_factory=list)


@dataclass
class Settings:
    database: str = "var/iotsec.db"
    model_path: str = "models/anomaly.joblib"
    model_signing_key: str = ""
    feeds_dir: str = "feeds"
    oui_file: str = ""
    monitored_networks: list[str] = field(default_factory=lambda: ["192.168.0.0/16"])
    gateway_ip: str = ""
    retention_days: int = 30
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    discovery: DiscoverySettings = field(default_factory=DiscoverySettings)
    baseline: BaselineSettings = field(default_factory=BaselineSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    ml: MlSettings = field(default_factory=MlSettings)
    notify: NotifySettings = field(default_factory=NotifySettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)

    def validate(self) -> Settings:
        for net in self.monitored_networks:
            ipaddress.ip_network(net, strict=False)
        if self.gateway_ip:
            ipaddress.ip_address(self.gateway_ip)
        if self.capture.backend not in ("scapy", "tshark"):
            raise ValueError("capture.backend must be 'scapy' or 'tshark'")
        if not 5 <= self.capture.window_seconds <= 3600:
            raise ValueError("capture.window_seconds must be between 5 and 3600")
        if self.notify.min_severity not in SEVERITIES:
            raise ValueError(f"notify.min_severity must be one of {SEVERITIES}")
        if self.notify.email.security not in ("ssl", "starttls"):
            raise ValueError("notify.email.security must be 'ssl' or 'starttls'")
        if self.notify.webhook_url and not self.notify.webhook_url.startswith("https://"):
            raise ValueError("notify.webhook_url must use https://")
        email = self.notify.email
        if email.enabled and not (email.host and email.sender and email.recipients):
            raise ValueError("notify.email needs host, sender and recipients when enabled")
        if not 0 < self.ml.contamination < 0.5:
            raise ValueError("ml.contamination must be between 0 and 0.5")
        for port in self.discovery.probe_ports + self.detection.lateral_ports:
            if not 0 < int(port) < 65536:
                raise ValueError(f"invalid port {port}")
        return self


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _coerce(value: str, type_name: str) -> Any:
    """Env-expanded values arrive as strings; convert them to the declared type."""
    if type_name == "bool":
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if type_name == "int":
        return int(value)
    if type_name == "float":
        return float(value)
    if type_name.startswith("list"):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _build(cls: type, data: dict[str, Any], section: str = "") -> Any:
    if not isinstance(data, dict):
        raise ValueError(f"section '{section or 'root'}' must be a mapping")
    known = {f.name: f for f in fields(cls)}
    kwargs = {}
    for key, value in data.items():
        if key not in known:
            raise ValueError(f"unknown setting '{section + key}'")
        spec = known[key]
        default = spec.default_factory() if callable(spec.default_factory) else None
        if is_dataclass(default):
            value = _build(type(default), value or {}, f"{section}{key}.")
        elif isinstance(value, str):
            value = _coerce(value, str(spec.type))
        kwargs[key] = value
    return cls(**kwargs)


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    candidate = path or os.environ.get("IOTSEC_CONFIG") or "config/settings.yaml"
    config_path = Path(candidate)
    if not config_path.exists():
        if path or os.environ.get("IOTSEC_CONFIG"):
            raise FileNotFoundError(config_path)
        return Settings().validate()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    settings = _build(Settings, _expand_env(raw))
    if os.environ.get("IOTSEC_DATABASE"):
        settings.database = os.environ["IOTSEC_DATABASE"]
    return settings.validate()
