"""The set of networks this deployment is allowed to monitor and probe."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

MAX_SWEEP_HOSTS = 65_536  # a /16 - anything larger is almost certainly a mistake


class NetworkScope:
    def __init__(self, networks: list[str]) -> None:
        self.networks = [ipaddress.ip_network(n, strict=False) for n in networks]

    @lru_cache(maxsize=65_536)  # noqa: B019 - one instance per process, bounded cache
    def contains(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address.version == net.version and address in net for net in self.networks)

    def check_target(self, cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """Refuse active scans outside the monitored networks."""
        target = ipaddress.ip_network(cidr, strict=False)
        if not any(target.version == net.version and target.subnet_of(net)  # type: ignore[arg-type]
                   for net in self.networks):
            raise PermissionError(
                f"{target} is outside the monitored networks "
                f"({', '.join(map(str, self.networks))}); refusing to scan it")
        if target.num_addresses > MAX_SWEEP_HOSTS:
            raise ValueError(f"{target} is too large to sweep (max /16)")
        return target
