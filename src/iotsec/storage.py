"""SQLite persistence: devices, IP bindings, traffic windows, baselines, alerts."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import Alert, AlertStatus, AlertType, Device, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac            TEXT PRIMARY KEY,
    ip             TEXT,
    vendor         TEXT,
    hostname       TEXT,
    device_type    TEXT NOT NULL DEFAULT 'unknown',
    label          TEXT,
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    approved       INTEGER NOT NULL DEFAULT 0,
    randomized_mac INTEGER NOT NULL DEFAULT 0,
    open_ports     TEXT NOT NULL DEFAULT '[]',
    services       TEXT NOT NULL DEFAULT '[]',
    dhcp_vendor    TEXT
);
CREATE TABLE IF NOT EXISTS ip_bindings (
    ip         TEXT PRIMARY KEY,
    mac        TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS windows (
    device_mac    TEXT NOT NULL,
    window_start  REAL NOT NULL,
    features      TEXT NOT NULL,
    anomaly_score REAL,
    flagged       INTEGER NOT NULL DEFAULT 0,
    learning      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_mac, window_start)
);
CREATE INDEX IF NOT EXISTS ix_windows_start ON windows (window_start);
CREATE TABLE IF NOT EXISTS traffic (
    window_start       REAL PRIMARY KEY,
    packets            INTEGER NOT NULL,
    bytes              INTEGER NOT NULL,
    suspicious_packets INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS baselines (
    device_mac TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac  TEXT,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '{}',
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'open',
    notes       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_alerts_open ON alerts (status, last_seen);
CREATE INDEX IF NOT EXISTS ix_alerts_device ON alerts (device_mac, alert_type, status);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_SEVERITY_RANK_SQL = ("CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                      "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END")
_OPEN = (AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value)
_SUSPICIOUS_SQL = (
    "SELECT COUNT(DISTINCT device_mac) FROM alerts WHERE status IN (?, ?) AND"
    " severity IN ('medium', 'high', 'critical')"
)


class Store:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            Path(path).chmod(0o600)  # inventory and alerts are sensitive
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------------- meta
    def get_meta(self, key: str) -> str | None:
        row = self._one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._tx() as conn:
            conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    # ------------------------------------------------------------- devices
    def get_device(self, mac: str) -> Device | None:
        row = self._one("SELECT * FROM devices WHERE mac = ?", (mac,))
        return _device(row) if row else None

    def list_devices(self) -> list[Device]:
        return [_device(r) for r in self._all("SELECT * FROM devices ORDER BY last_seen DESC")]

    def save_device(self, device: Device) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO devices (mac, ip, vendor, hostname, device_type, label, first_seen,"
                " last_seen, approved, randomized_mac, open_ports, services, dhcp_vendor)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, vendor=excluded.vendor,"
                " hostname=excluded.hostname, device_type=excluded.device_type,"
                " label=excluded.label, last_seen=excluded.last_seen,"
                " approved=excluded.approved, randomized_mac=excluded.randomized_mac,"
                " open_ports=excluded.open_ports, services=excluded.services,"
                " dhcp_vendor=excluded.dhcp_vendor",
                (device.mac, device.ip, device.vendor, device.hostname, device.device_type,
                 device.label, device.first_seen, device.last_seen, int(device.approved),
                 int(device.randomized_mac), json.dumps(sorted(set(device.open_ports))),
                 json.dumps(sorted(set(device.services))[:50]), device.dhcp_vendor),
            )

    def set_device_approval(self, mac: str, approved: bool) -> bool:
        with self._tx() as conn:
            return conn.execute("UPDATE devices SET approved = ? WHERE mac = ?",
                                (int(approved), mac)).rowcount == 1

    def set_device_label(self, mac: str, label: str | None,
                         device_type: str | None = None) -> bool:
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE devices SET label = ?, device_type = COALESCE(?, device_type)"
                " WHERE mac = ?", (label, device_type, mac))
            return cursor.rowcount == 1

    # ---------------------------------------------------------- IP bindings
    def get_binding(self, ip: str) -> tuple[str, float, float] | None:
        row = self._one("SELECT mac, first_seen, last_seen FROM ip_bindings WHERE ip = ?", (ip,))
        return (row["mac"], row["first_seen"], row["last_seen"]) if row else None

    def set_binding(self, ip: str, mac: str, ts: float) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO ip_bindings VALUES (?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET"
                " mac=excluded.mac, last_seen=excluded.last_seen,"
                " first_seen=CASE WHEN ip_bindings.mac = excluded.mac"
                " THEN ip_bindings.first_seen ELSE excluded.first_seen END",
                (ip, mac, ts, ts))

    # -------------------------------------------------------------- windows
    def save_window(self, mac: str, start: float, features: dict[str, float],
                    anomaly_score: float | None, flagged: bool, learning: bool) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO windows VALUES (?, ?, ?, ?, ?, ?)",
                (mac, start, json.dumps(features), anomaly_score, int(flagged), int(learning)))

    def device_windows(self, mac: str, since: float = 0.0,
                       limit: int = 10_000) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT * FROM windows WHERE device_mac = ? AND window_start >= ?"
            " ORDER BY window_start DESC LIMIT ?", (mac, since, limit))
        return [_window(r) for r in reversed(rows)]

    def training_windows(self, max_per_device: int = 5000) -> dict[str, list[dict[str, float]]]:
        """Unflagged windows per device - the behaviour considered normal."""
        result: dict[str, list[dict[str, float]]] = {}
        for row in self._all("SELECT device_mac, features FROM windows WHERE flagged = 0"
                             " ORDER BY window_start DESC"):
            bucket = result.setdefault(row["device_mac"], [])
            if len(bucket) < max_per_device:
                bucket.append(json.loads(row["features"]))
        return result

    def add_traffic(self, start: float, packets: int, nbytes: int, suspicious: int) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO traffic VALUES (?, ?, ?, ?) ON CONFLICT(window_start) DO UPDATE SET"
                " packets=traffic.packets+excluded.packets, bytes=traffic.bytes+excluded.bytes,"
                " suspicious_packets=traffic.suspicious_packets+excluded.suspicious_packets",
                (start, packets, nbytes, suspicious))

    def latest_traffic(self) -> float | None:
        row = self._one("SELECT MAX(window_start) FROM traffic")
        return row[0] if row else None

    def traffic_since(self, since: float) -> list[dict[str, Any]]:
        return [dict(r) for r in self._all(
            "SELECT * FROM traffic WHERE window_start >= ? ORDER BY window_start", (since,))]

    # ------------------------------------------------------------ baselines
    def get_baseline(self, mac: str) -> dict[str, Any] | None:
        row = self._one("SELECT data FROM baselines WHERE device_mac = ?", (mac,))
        return json.loads(row["data"]) if row else None

    def save_baseline(self, mac: str, data: dict[str, Any]) -> None:
        with self._tx() as conn:
            conn.execute("INSERT OR REPLACE INTO baselines VALUES (?, ?, ?)",
                         (mac, json.dumps(data), time.time()))

    # --------------------------------------------------------------- alerts
    def record_alert(self, alert: Alert, cooldown_seconds: float) -> tuple[Alert, bool]:
        """Insert an alert, or fold it into an open one of the same kind.

        Returns the stored alert and whether it is new (or escalated), which
        decides whether a notification goes out.
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_type = ? AND device_mac IS ? AND status IN"
                " (?, ?) AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1",
                (alert.alert_type.value, alert.device_mac, *_OPEN,
                 alert.last_seen - cooldown_seconds)).fetchone()
            if row is not None:
                existing = _alert(row)
                escalated = alert.severity.rank > existing.severity.rank
                severity = alert.severity if escalated else existing.severity
                details = {**existing.details, **alert.details}
                conn.execute(
                    "UPDATE alerts SET last_seen = ?, count = count + 1, severity = ?,"
                    " details = ? WHERE id = ?",
                    (max(existing.last_seen, alert.last_seen), severity.value,
                     json.dumps(details), existing.id))
                existing.count += 1
                existing.severity, existing.details = severity, details
                existing.last_seen = max(existing.last_seen, alert.last_seen)
                return existing, escalated
            cursor = conn.execute(
                "INSERT INTO alerts (device_mac, alert_type, severity, details, first_seen,"
                " last_seen, count, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (alert.device_mac, alert.alert_type.value, alert.severity.value,
                 json.dumps(alert.details), alert.first_seen, alert.last_seen, alert.count,
                 alert.status.value))
            alert.id = cursor.lastrowid
            return alert, True

    def get_alert(self, alert_id: int) -> Alert | None:
        row = self._one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return _alert(row) if row else None

    def list_alerts(self, *, statuses: list[str] | None = None, device_mac: str | None = None,
                    min_severity: Severity | None = None, since: float = 0.0,
                    limit: int = 500) -> list[Alert]:
        clauses, params = ["last_seen >= ?"], [since]
        if statuses:
            clauses.append(f"status IN ({','.join('?' * len(statuses))})")
            params += [AlertStatus(s).value for s in statuses]
        if device_mac:
            clauses.append("device_mac = ?")
            params.append(device_mac)
        if min_severity is not None:
            clauses.append(f"{_SEVERITY_RANK_SQL} >= ?")
            params.append(min_severity.rank)
        # clauses are fixed strings from this function; all values are bound
        sql = ("SELECT * FROM alerts WHERE " + " AND ".join(clauses)  # noqa: S608  # nosec B608
               + " ORDER BY status = 'open' DESC, " + _SEVERITY_RANK_SQL
               + " DESC, last_seen DESC LIMIT ?")
        return [_alert(r) for r in self._all(sql, (*params, limit))]

    def update_alert(self, alert_id: int, status: AlertStatus, notes: str | None = None) -> bool:
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE alerts SET status = ?, notes = COALESCE(?, notes) WHERE id = ?",
                (status.value, notes, alert_id))
            return cursor.rowcount == 1

    # ---------------------------------------------------------------- stats
    def summary(self, online_seconds: float) -> dict[str, int]:
        now = time.time()
        row = self._one(
            "SELECT COUNT(*) AS devices, SUM(last_seen >= ?) AS online,"
            " SUM(approved = 0) AS unapproved FROM devices", (now - online_seconds,))
        suspicious = self._one(_SUSPICIOUS_SQL, _OPEN)[0]
        open_alerts = self._one(
            "SELECT COUNT(*) FROM alerts WHERE status IN (?, ?)", _OPEN)[0]
        return {"devices": row["devices"] or 0, "online": row["online"] or 0,
                "unapproved": row["unapproved"] or 0, "suspicious": suspicious or 0,
                "alerts": open_alerts or 0}

    def prune(self, retention_days: int, now: float | None = None) -> int:
        """Drop history older than the retention period, relative to ``now``
        (the time of the newest data, so replays of old captures keep theirs)."""
        cutoff = (now if now is not None else time.time()) - retention_days * 86400
        with self._tx() as conn:
            removed = conn.execute("DELETE FROM windows WHERE window_start < ?",
                                   (cutoff,)).rowcount
            removed += conn.execute("DELETE FROM traffic WHERE window_start < ?",
                                    (cutoff,)).rowcount
            removed += conn.execute(
                "DELETE FROM alerts WHERE last_seen < ? AND status NOT IN (?, ?)",
                (cutoff, *_OPEN)).rowcount
        return removed


def _device(row: sqlite3.Row) -> Device:
    return Device(
        mac=row["mac"], ip=row["ip"], vendor=row["vendor"], hostname=row["hostname"],
        device_type=row["device_type"], label=row["label"], first_seen=row["first_seen"],
        last_seen=row["last_seen"], approved=bool(row["approved"]),
        randomized_mac=bool(row["randomized_mac"]), open_ports=json.loads(row["open_ports"]),
        services=json.loads(row["services"]), dhcp_vendor=row["dhcp_vendor"])


def _alert(row: sqlite3.Row) -> Alert:
    return Alert(
        id=row["id"], device_mac=row["device_mac"], alert_type=AlertType(row["alert_type"]),
        severity=Severity(row["severity"]), details=json.loads(row["details"]),
        first_seen=row["first_seen"], last_seen=row["last_seen"], count=row["count"],
        status=AlertStatus(row["status"]), notes=row["notes"])


def _window(row: sqlite3.Row) -> dict[str, Any]:
    return {"window_start": row["window_start"], "features": json.loads(row["features"]),
            "anomaly_score": row["anomaly_score"], "flagged": bool(row["flagged"]),
            "learning": bool(row["learning"])}
