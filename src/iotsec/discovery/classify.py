"""Best-effort device type inference from everything observed about a device.

Each clue adds weight to a category; the strongest category wins. Analysts
can always override the result from the dashboard.
"""

from __future__ import annotations

from collections import Counter

from ..models import Device

DEVICE_TYPES = (
    "camera", "smart-speaker", "smart-tv", "smart-bulb", "smart-plug", "thermostat",
    "hub", "appliance", "iot-module", "router", "nas", "printer", "computer", "phone",
    "unknown",
)

_HOSTNAME_HINTS = {
    "camera": ("cam", "ipc", "nvr", "dvr", "doorbell"),
    "smart-speaker": ("echo", "alexa", "sonos", "homepod", "nest-mini", "google-home"),
    "smart-tv": ("tv", "roku", "chromecast", "firetv", "bravia", "appletv"),
    "smart-bulb": ("bulb", "hue", "lifx", "light", "lamp"),
    "smart-plug": ("plug", "wemo", "kasa", "outlet", "shelly", "tasmota", "sonoff"),
    "thermostat": ("thermostat", "nest", "ecobee"),
    "printer": ("printer", "laserjet", "officejet", "epson", "brother"),
    "phone": ("iphone", "android", "galaxy", "pixel"),
    "computer": ("desktop", "laptop", "macbook", "pc-", "workstation", "raspberrypi"),
    "router": ("router", "gateway", "fritz", "openwrt", "unifi"),
    "nas": ("nas", "synology", "diskstation", "qnap"),
}
_SERVICE_HINTS = {
    "_googlecast._tcp": "smart-tv",
    "_airplay._tcp": "smart-tv",
    "_raop._tcp": "smart-speaker",
    "_spotify-connect._tcp": "smart-speaker",
    "_sonos._tcp": "smart-speaker",
    "_hap._tcp": "hub",
    "_hue._tcp": "smart-bulb",
    "_ipp._tcp": "printer",
    "_printer._tcp": "printer",
    "_pdl-datastream._tcp": "printer",
    "_smb._tcp": "nas",
    "_afpovertcp._tcp": "nas",
    "_rtsp._tcp": "camera",
    "_companion-link._tcp": "phone",
}
_PORT_HINTS = {
    554: "camera", 8554: "camera", 37777: "camera", 34567: "camera",
    1883: "hub", 8883: "hub", 9999: "smart-plug", 8008: "smart-tv", 8009: "smart-tv",
    631: "printer", 9100: "printer", 5000: "nas", 548: "nas", 53: "router", 7547: "router",
}
_SSDP_HINTS = {
    "mediarenderer": "smart-tv", "dial": "smart-tv", "camera": "camera",
    "printer": "printer", "internetgatewaydevice": "router", "hue": "smart-bulb",
}
_DHCP_VENDOR_HINTS = {"android": "phone", "msft": "computer", "dhcpcd": "computer",
                      "udhcp": "iot-module"}


def classify(device: Device, vendor_hint: str | None = None,
             contacted_ports: set[int] | None = None) -> str:
    scores: Counter[str] = Counter()
    if vendor_hint:
        scores[vendor_hint] += 3
    hostname = (device.hostname or "").lower()
    for category, words in _HOSTNAME_HINTS.items():
        if any(word in hostname for word in words):
            scores[category] += 4
    for service in device.services:
        lowered = service.lower()
        for marker, category in _SERVICE_HINTS.items():
            if marker in lowered:
                scores[category] += 5
        for marker, category in _SSDP_HINTS.items():
            if marker in lowered:
                scores[category] += 3
    for port in device.open_ports:
        if port in _PORT_HINTS:
            scores[_PORT_HINTS[port]] += 3
    for port in contacted_ports or ():
        if port in (554, 8554):  # streams video to an NVR or the cloud
            scores["camera"] += 2
        elif port in (1883, 8883):
            scores["iot-module"] += 1
    dhcp_vendor = (device.dhcp_vendor or "").lower()
    for marker, category in _DHCP_VENDOR_HINTS.items():
        if marker in dhcp_vendor:
            scores[category] += 2
    if not scores:
        return "unknown"
    return scores.most_common(1)[0][0]
