"""Learned per-device behaviour profile.

During the learning period every clean window updates running statistics
(Welford's algorithm) and the sets of destinations, ports and internal
admin services the device normally uses. Afterwards deviations from this
profile drive the volume and new-destination detectors.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .features import FEATURES, DeviceWindow

MAX_SAMPLES = 10_000  # caps the weight of history so the profile can follow drift


@dataclass
class RunningStat:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, value: float) -> None:
        if self.n >= MAX_SAMPLES:
            self.n = MAX_SAMPLES - 1
            self.m2 *= (MAX_SAMPLES - 1) / MAX_SAMPLES
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    def zscore(self, value: float) -> float:
        # a floor on the spread stops perfectly regular devices (std ~ 0)
        # from alerting on trivial changes
        spread = max(self.std, 0.1 * abs(self.mean), 1.0)
        return (value - self.mean) / spread


@dataclass
class Baseline:
    mac: str
    started_at: float
    windows: int = 0
    stats: dict[str, RunningStat] = field(default_factory=dict)
    domains: set[str] = field(default_factory=set)
    prefixes: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    admin_targets: set[str] = field(default_factory=set)
    saturated: bool = False  # too many destinations to track (phones, laptops)

    def is_learning(self, now: float, learning_seconds: float, min_windows: int) -> bool:
        return now - self.started_at < learning_seconds or self.windows < min_windows

    def update(self, window: DeviceWindow, max_destinations: int) -> None:
        self.windows += 1
        features = window.features()
        for name in FEATURES:
            self.stats.setdefault(name, RunningStat()).add(float(features[name]))
        self.admin_targets |= window.admin_targets
        self.ports |= {p for p in window.dst_ports if p < 49152}  # skip ephemeral ports
        if not self.saturated:
            self.domains |= window.domains
            self.prefixes |= window.prefixes
            if len(self.domains) + len(self.prefixes) > max_destinations:
                self.saturated = True
                self.domains.clear()
                self.prefixes.clear()

    def zscore(self, name: str, value: float) -> float:
        stat = self.stats.get(name)
        return stat.zscore(value) if stat and stat.n > 1 else 0.0

    def new_destinations(self, window: DeviceWindow) -> list[str]:
        if self.saturated:
            return []
        return sorted((window.domains - self.domains) | (window.prefixes - self.prefixes))

    # ------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac, "started_at": self.started_at, "windows": self.windows,
            "stats": {k: [v.n, v.mean, v.m2] for k, v in self.stats.items()},
            "domains": sorted(self.domains), "prefixes": sorted(self.prefixes),
            "ports": sorted(self.ports), "admin_targets": sorted(self.admin_targets),
            "saturated": self.saturated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        return cls(
            mac=data["mac"], started_at=float(data["started_at"]), windows=int(data["windows"]),
            stats={k: RunningStat(int(v[0]), float(v[1]), float(v[2]))
                   for k, v in data.get("stats", {}).items()},
            domains=set(data.get("domains", [])), prefixes=set(data.get("prefixes", [])),
            ports={int(p) for p in data.get("ports", [])},
            admin_targets=set(data.get("admin_targets", [])),
            saturated=bool(data.get("saturated", False)),
        )
