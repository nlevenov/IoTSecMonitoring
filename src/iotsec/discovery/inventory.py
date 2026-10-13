"""Passive device inventory built from observed traffic.

Updates are kept in memory and written to the database in batches, so the
inventory keeps up with packet rates without a write per packet.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..models import AlertType, Device, PacketRecord, Severity
from ..sanitize import is_randomized_mac, is_unicast_mac
from ..storage import Store
from .classify import classify
from .oui import OuiDatabase
from .scope import NetworkScope

# How long a MAC must have held an IP before a different MAC claiming it
# counts as a conflict rather than a normal DHCP re-assignment.
BINDING_STABLE_SECONDS = 120
# A conflicting claim while the current owner was seen this recently is a
# conflict / spoofing attempt rather than a legitimate re-assignment.
OWNER_ACTIVE_SECONDS = 600
FLOOD_ALERT_SECONDS = 300
MAX_BINDINGS = 65_536


@dataclass
class InventoryEvent:
    alert_type: AlertType
    severity: Severity
    device_mac: str
    details: dict[str, object]
    ts: float


class Inventory:
    def __init__(self, store: Store, scope: NetworkScope, oui: OuiDatabase,
                 gateway_ip: str = "", max_devices: int = 2048) -> None:
        self.store = store
        self.scope = scope
        self.oui = oui
        self.gateway_ip = gateway_ip
        self.devices: dict[str, Device] = {d.mac: d for d in store.list_devices()}
        self._dirty: set[str] = set()
        self._bindings: dict[str, tuple[str, float]] = {}
        self._contacted_ports: dict[str, set[int]] = {}
        self._last_flush = time.monotonic()
        self.max_devices = max_devices
        self.rejected_macs = 0
        self._last_flood_alert = float("-inf")

    # ---------------------------------------------------------------- observe
    def observe(self, record: PacketRecord) -> list[InventoryEvent]:
        events: list[InventoryEvent] = []
        if record.proto == "arp":
            # ARP is the authoritative IP-to-MAC claim on the segment; routed IP
            # traffic carries the router's MAC and must not be used for this.
            if record.arp_op in (1, 2):
                events += self._binding(record.src_ip, record.src_mac, record.ts,
                                        is_reply=record.arp_op == 2)
            # a conflicting claim must not overwrite the claimant's real address
            spoofed = any(e.alert_type is AlertType.ARP_SPOOF for e in events)
            return events + self._touch(record.src_mac, None if spoofed else record.src_ip,
                                        record)

        if record.dhcp_hostname or record.dhcp_vendor:
            # DHCP requests come from 0.0.0.0 before the device has an address
            events += self._touch(record.src_mac, None, record)

        if self.scope.contains(record.src_ip):
            events += self._touch(record.src_mac, record.src_ip, record)
            if record.dport is not None and record.src_mac in self._contacted_ports:
                ports = self._contacted_ports[record.src_mac]
                if len(ports) < 64:
                    ports.add(record.dport)
        if self.scope.contains(record.dst_ip) and is_unicast_mac(record.dst_mac):
            events += self._touch(record.dst_mac, record.dst_ip, None, ts=record.ts)
        return events

    def _touch(self, mac: str | None, ip: str | None, record: PacketRecord | None,
               ts: float | None = None) -> list[InventoryEvent]:
        if not is_unicast_mac(mac):
            return []
        now = record.ts if record else (ts or time.time())
        device = self.devices.get(mac)
        events: list[InventoryEvent] = []
        if device is None and len(self.devices) >= self.max_devices:
            # a flood of forged source MACs must not exhaust memory or the database
            self.rejected_macs += 1
            if now - self._last_flood_alert >= FLOOD_ALERT_SECONDS:
                self._last_flood_alert = now
                return [InventoryEvent(AlertType.MAC_FLOOD, Severity.CRITICAL, mac, {
                    "inventory_size": len(self.devices), "rejected_macs": self.rejected_macs,
                    "example_mac": mac}, now)]
            return []
        if device is None:
            device = Device(mac=mac, ip=ip if self.scope.contains(ip) else None,
                            vendor=self.oui.vendor(mac), first_seen=now, last_seen=now,
                            randomized_mac=is_randomized_mac(mac))
            self.devices[mac] = device
            self._contacted_ports[mac] = set()
            events.append(InventoryEvent(
                AlertType.NEW_DEVICE, Severity.MEDIUM, mac,
                {"ip": device.ip, "vendor": device.vendor,
                 "randomized_mac": device.randomized_mac}, now))
        self._contacted_ports.setdefault(mac, set())
        device.last_seen = max(device.last_seen, now)
        if ip and self.scope.contains(ip):
            device.ip = ip
        if record is not None:
            if record.dhcp_hostname:
                device.hostname = record.dhcp_hostname
            if record.dhcp_vendor:
                device.dhcp_vendor = record.dhcp_vendor
            for name in record.mdns_names:
                if name not in device.services and len(device.services) < 50:
                    device.services.append(name)
            if record.ssdp_server and record.ssdp_server not in device.services \
                    and len(device.services) < 50:
                device.services.append(record.ssdp_server)
        self._dirty.add(mac)
        return events

    def _binding(self, ip: str | None, mac: str | None, ts: float,
                 is_reply: bool) -> list[InventoryEvent]:
        if not ip or not is_unicast_mac(mac) or not self.scope.contains(ip):
            return []
        current = self._bindings.get(ip)
        if current is None:
            stored = self.store.get_binding(ip)
            current = (stored[0], stored[1]) if stored else None
        if current is None and len(self._bindings) >= MAX_BINDINGS:
            return []
        if current is None or current[0] == mac:
            self._bindings[ip] = (mac, current[1] if current else ts)
            if current is None:
                self.store.set_binding(ip, mac, ts)
            return []
        previous_mac, since = current
        previous = self.devices.get(previous_mac)
        owner_active = previous is not None and ts - previous.last_seen < OWNER_ACTIVE_SECONDS
        if ts - since < BINDING_STABLE_SECONDS or not owner_active:
            # fresh lease churn, or the old owner left and the address was reassigned
            self._bindings[ip] = (mac, ts)
            self.store.set_binding(ip, mac, ts)
            return []
        # The owner is still on the network: keep the binding with it, so every
        # further forged claim is reported, not just the first one.
        is_gateway = ip == self.gateway_ip
        severity = Severity.CRITICAL if is_gateway else (
            Severity.HIGH if is_reply else Severity.MEDIUM)
        return [InventoryEvent(
            AlertType.ARP_SPOOF, severity, mac,
            {"ip": ip, "previous_mac": previous_mac, "new_mac": mac,
             "gateway": is_gateway, "arp": "reply" if is_reply else "request"}, ts)]

    # ------------------------------------------------------------------ write
    def flush(self, force: bool = False) -> None:
        if not force and time.monotonic() - self._last_flush < 5:
            return
        for mac in list(self._dirty):
            device = self.devices[mac]
            stored = self.store.get_device(mac)
            if stored is not None:
                # analyst decisions made in the dashboard win over our cache
                device.approved, device.label = stored.approved, stored.label
                device.open_ports = sorted(set(device.open_ports) | set(stored.open_ports))
            if stored is not None and stored.label is not None:
                device.device_type = stored.device_type  # set by an analyst
            else:
                device.device_type = classify(device, self.oui.hint(mac),
                                              self._contacted_ports.get(mac))
            self.store.save_device(device)
        self._dirty.clear()
        self._last_flush = time.monotonic()

    def record_scan(self, hosts: list[tuple[str, str]], ts: float | None = None) -> int:
        """Merge ARP sweep results. Returns the number of new devices."""
        now = ts or time.time()
        new = 0
        for ip, mac in hosts:
            new += len(self._touch(mac, ip, None, ts=now))
            self._binding(ip, mac, now, is_reply=True)
        self.flush(force=True)
        return new

    def record_ports(self, mac: str, ports: list[int]) -> None:
        device = self.devices.get(mac)
        if device is not None:
            device.open_ports = sorted(set(device.open_ports) | set(ports))
            self._dirty.add(mac)
