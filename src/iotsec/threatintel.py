"""Local blocklists: IPs, CIDR ranges and domains (parent domains match too)."""

from __future__ import annotations

import csv
import ipaddress
from pathlib import Path

from .sanitize import clean_domain, clean_text


class Blocklist:
    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self.domains: dict[str, str] = {}
        self.files: list[str] = []

    @classmethod
    def from_dir(cls, directory: str | Path) -> Blocklist:
        blocklist = cls()
        path = Path(directory)
        if path.is_dir():
            for file in sorted(path.iterdir()):
                if file.suffix == ".txt":
                    blocklist._load_txt(file)
                elif file.suffix == ".csv":
                    blocklist._load_csv(file)
        return blocklist

    def add(self, indicator: str, reason: str) -> None:
        indicator = indicator.strip()
        try:
            network = ipaddress.ip_network(indicator, strict=False)
        except ValueError:
            domain = clean_domain(indicator)
            if domain and "." in domain:
                self.domains[domain] = reason
            return
        if network.num_addresses == 1:
            self.ips[str(network.network_address)] = reason
        else:
            self.networks.append((network, reason))

    def _load_txt(self, file: Path) -> None:
        reason = file.stem.replace("_", " ")
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                self.add(value, reason)
        self.files.append(file.name)

    def _load_csv(self, file: Path) -> None:
        with file.open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(line for line in fh if not line.startswith("#")):
                value = (row.get("indicator") or "").strip()
                if value:
                    self.add(value, clean_text(row.get("description"), 96) or file.stem)
        self.files.append(file.name)

    def match_ip(self, ip: str | None) -> str | None:
        if not ip:
            return None
        if ip in self.ips:
            return self.ips[ip]
        if self.networks:
            address = ipaddress.ip_address(ip)
            for network, reason in self.networks:
                if address.version == network.version and address in network:
                    return reason
        return None

    def match_domain(self, domain: str | None) -> str | None:
        if not domain or not self.domains:
            return None
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            reason = self.domains.get(".".join(labels[i:]))
            if reason:
                return reason
        return None

    def __len__(self) -> int:
        return len(self.ips) + len(self.networks) + len(self.domains)
