import socket

import pytest

from iotsec.discovery.active import probe_ports
from iotsec.discovery.classify import classify
from iotsec.discovery.inventory import Inventory
from iotsec.discovery.oui import OuiDatabase
from iotsec.discovery.scope import NetworkScope
from iotsec.models import AlertType, Device, PacketRecord, Severity
from iotsec.storage import Store

from helpers import CAMERA, LAPTOP, ROUTER

SCOPE = NetworkScope(["192.168.50.0/24", "127.0.0.0/8"])


def test_oui_lookup_and_ieee_import(tmp_path):
    db = OuiDatabase.load()
    assert db.vendor("44:19:b6:00:00:01") == "Hikvision"
    assert db.hint("44:19:b6:00:00:01") == "camera"
    assert db.vendor("3a:00:00:00:00:01") == "Private (randomized) address"
    assert db.vendor("00:00:5e:00:00:00") is None  # unknown, universally administered
    registry = tmp_path / "oui.csv"
    registry.write_text("Registry,Assignment,Organization Name,Organization Address\n"
                        "MA-L,001122,Example <Corp>,Somewhere\nMA-L,44:19:B6,Other,X\n")
    assert db.load_ieee(registry) == 1
    assert db.vendor("00:11:22:00:00:01") == "Example Corp"
    assert db.vendor("44:19:b6:00:00:01") == "Hikvision"  # curated name kept


@pytest.mark.parametrize("device,hint,expected", [
    (Device(mac="x", hostname="ipcam-front"), None, "camera"),
    (Device(mac="x", services=["Living._googlecast._tcp.local"]), None, "smart-tv"),
    (Device(mac="x", open_ports=[554]), None, "camera"),
    (Device(mac="x"), "smart-bulb", "smart-bulb"),
    (Device(mac="x", hostname="nikola-laptop", dhcp_vendor="MSFT 5.0"), None, "computer"),
    (Device(mac="x"), None, "unknown"),
])
def test_classification(device, hint, expected):
    assert classify(device, hint) == expected


def test_scope_refuses_targets_outside_monitored_networks():
    assert SCOPE.check_target("192.168.50.0/25")
    with pytest.raises(PermissionError):
        SCOPE.check_target("10.0.0.0/24")
    with pytest.raises(PermissionError):
        SCOPE.check_target("192.168.0.0/16")  # larger than what is monitored
    with pytest.raises(ValueError):
        NetworkScope(["10.0.0.0/8"]).check_target("10.0.0.0/8")  # too large to sweep


def test_probe_ports_finds_open_port_and_respects_scope():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    try:
        assert probe_ports("127.0.0.1", [port, 1], SCOPE, timeout=0.5) == [port]
    finally:
        server.close()
    with pytest.raises(PermissionError):
        probe_ports("8.8.8.8", [53], SCOPE)


def _arp(ts, mac, ip, op=2):
    return PacketRecord(ts=ts, src_mac=mac, proto="arp", arp_op=op, src_ip=ip, dst_ip=ip)


@pytest.fixture
def inventory():
    return Inventory(Store(":memory:"), NetworkScope(["192.168.50.0/24"]), OuiDatabase.load(),
                     gateway_ip=ROUTER[1])


def test_new_devices_and_dhcp_names(inventory):
    events = inventory.observe(PacketRecord(ts=1, src_mac=CAMERA[0], src_ip="0.0.0.0",
                                            dst_ip="255.255.255.255", proto="udp",
                                            dhcp_hostname="ipcam-front"))
    assert [e.alert_type for e in events] == [AlertType.NEW_DEVICE]
    inventory.flush(force=True)
    device = inventory.store.get_device(CAMERA[0])
    assert device.hostname == "ipcam-front" and device.device_type == "camera"
    assert device.vendor == "Hikvision"


def test_arp_spoofing_of_active_gateway(inventory):
    first = inventory.observe(_arp(0, ROUTER[0], ROUTER[1]))
    assert [e.alert_type for e in first] == [AlertType.NEW_DEVICE]
    inventory.observe(_arp(500, ROUTER[0], ROUTER[1]))      # gateway is alive
    events = [e for e in inventory.observe(_arp(510, CAMERA[0], ROUTER[1]))
              if e.alert_type is AlertType.ARP_SPOOF]
    assert events and events[0].severity is Severity.CRITICAL
    assert events[0].details["previous_mac"] == ROUTER[0]
    # the binding stays with the real owner, so repeats are reported too
    again = inventory.observe(_arp(512, CAMERA[0], ROUTER[1]))
    assert any(e.alert_type is AlertType.ARP_SPOOF for e in again)
    # and the attacker's inventory entry keeps its own address
    assert inventory.devices[CAMERA[0]].ip != ROUTER[1]


def test_reassigned_address_is_not_spoofing(inventory):
    inventory.observe(_arp(0, LAPTOP[0], f"{LAPTOP[1]}"))
    # the laptop leaves; an hour later the address is leased to someone else
    events = inventory.observe(_arp(3600, CAMERA[0], LAPTOP[1]))
    assert not any(e.alert_type is AlertType.ARP_SPOOF for e in events)


def test_lease_churn_is_not_spoofing(inventory):
    inventory.observe(_arp(0, LAPTOP[0], LAPTOP[1]))
    events = inventory.observe(_arp(30, CAMERA[0], LAPTOP[1]))
    assert not any(e.alert_type is AlertType.ARP_SPOOF for e in events)


def test_analyst_label_survives_inventory_updates(inventory):
    inventory.observe(PacketRecord(ts=1, src_mac=CAMERA[0], src_ip=CAMERA[1], proto="udp",
                                   dst_ip="203.0.113.1"))
    inventory.flush(force=True)
    inventory.store.set_device_label(CAMERA[0], "Front door", "smart-plug")
    inventory.store.set_device_approval(CAMERA[0], True)
    inventory.observe(PacketRecord(ts=2, src_mac=CAMERA[0], src_ip=CAMERA[1], proto="udp",
                                   dst_ip="203.0.113.1"))
    inventory.flush(force=True)
    device = inventory.store.get_device(CAMERA[0])
    assert (device.label, device.device_type, device.approved) == ("Front door", "smart-plug", True)


def test_mac_flood_is_capped_and_reported():
    inventory = Inventory(Store(":memory:"), NetworkScope(["192.168.50.0/24"]),
                          OuiDatabase.load(), max_devices=50)
    events = []
    for i in range(5000):
        mac = f"02:00:00:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}"
        events += inventory.observe(PacketRecord(ts=1 + i * 0.001, src_mac=mac,
                                                 src_ip=f"192.168.50.{i % 250 + 1}",
                                                 dst_ip="203.0.113.1", proto="udp"))
    floods = [e for e in events if e.alert_type is AlertType.MAC_FLOOD]
    assert len(inventory.devices) == 50 and inventory.rejected_macs == 4950
    assert len(floods) == 1 and floods[0].severity is Severity.CRITICAL
