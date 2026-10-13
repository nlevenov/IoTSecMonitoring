"""Read models for the dashboard, shaped as pandas frames."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pandas as pd

from ..models import Alert, Device
from ..storage import Store


def utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def devices_frame(devices: list[Device], online_after: float,
                  suspicious: set[str]) -> pd.DataFrame:
    rows = [{
        "Status": ("Suspicious" if d.mac in suspicious else
                   "Online" if d.last_seen >= online_after else "Offline"),
        "Name": d.display_name, "IP address": d.ip or "", "Device type": d.device_type,
        "Vendor": d.vendor or "", "MAC": d.mac, "Approved": d.approved,
        "First seen": utc(d.first_seen), "Last seen": utc(d.last_seen),
    } for d in devices]
    return pd.DataFrame(rows, columns=["Status", "Name", "IP address", "Device type", "Vendor",
                                       "MAC", "Approved", "First seen", "Last seen"])


def alerts_frame(alerts: list[Alert], devices: dict[str, Device]) -> pd.DataFrame:
    rows = [{
        "ID": a.id, "Last seen": utc(a.last_seen), "Severity": a.severity.value,
        "Alert": a.title,
        "Device": devices[a.device_mac].display_name if a.device_mac in devices
        else (a.device_mac or "network"),
        "IP": devices[a.device_mac].ip if a.device_mac in devices else "",
        "Count": a.count, "Status": a.status.value.replace("_", " "),
    } for a in alerts]
    return pd.DataFrame(rows, columns=["ID", "Last seen", "Severity", "Alert", "Device", "IP",
                                       "Count", "Status"])


def traffic_frame(store: Store, hours: float) -> pd.DataFrame:
    rows = store.traffic_since(_since(store, hours))
    frame = pd.DataFrame(rows, columns=["window_start", "packets", "bytes",
                                        "suspicious_packets"])
    frame["time"] = pd.to_datetime(frame["window_start"], unit="s", utc=True)
    frame["normal"] = frame["packets"] - frame["suspicious_packets"]
    return frame


def device_windows_frame(store: Store, mac: str, hours: float) -> pd.DataFrame:
    windows = store.device_windows(mac, _since(store, hours))
    frame = pd.DataFrame([{"time": utc(w["window_start"]), **w["features"],
                           "anomaly_score": w["anomaly_score"], "flagged": w["flagged"]}
                          for w in windows])
    return frame


def _since(store: Store, hours: float) -> float:
    """Start of the chart range, relative to the newest data (so replays display)."""
    return (store.latest_traffic() or time.time()) - hours * 3600
