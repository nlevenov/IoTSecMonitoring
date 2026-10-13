"""Score detections against the ground truth written by the simulator."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Alert, AlertType, Severity
from .storage import Store


@dataclass
class Evaluation:
    attacks: int
    detected: int
    detected_exact: int
    alerts: int
    true_alerts: int
    window_precision: float
    window_recall: float
    window_f1: float
    actionable_alerts: int
    actionable_true: int
    per_attack: list[dict[str, Any]]
    false_alerts: list[dict[str, Any]]

    @property
    def alert_precision(self) -> float:
        return self.true_alerts / self.alerts if self.alerts else 0.0

    @property
    def actionable_precision(self) -> float:
        """Precision of the alerts an analyst is asked to act on (medium and above)."""
        return self.actionable_true / self.actionable_alerts if self.actionable_alerts else 0.0

    def as_dict(self) -> dict[str, Any]:
        data = self.__dict__.copy()
        data["alert_precision"] = round(self.alert_precision, 3)
        data["actionable_precision"] = round(self.actionable_precision, 3)
        return data


def _overlaps(alert: Alert, start: float, end: float, slack: float) -> bool:
    return alert.first_seen <= end + slack and alert.last_seen >= start - slack


def evaluate(store: Store, labels_path: str | Path, window_seconds: int) -> Evaluation:
    truth = json.loads(Path(labels_path).read_text(encoding="utf-8"))["attacks"]
    alerts = store.list_alerts(limit=100_000)
    slack = window_seconds

    per_attack, matched_alerts = [], set()
    for label in truth:
        related = [a for a in alerts if a.device_mac == label["device_mac"]
                   and _overlaps(a, label["start"], label["end"], slack)]
        exact = [a for a in related if a.alert_type == AlertType(label["alert_type"])]
        matched_alerts |= {a.id for a in related}
        per_attack.append({"attack": label["alert_type"], "device": label["device_mac"],
                           "detected": bool(related), "exact_type": bool(exact),
                           "alerts": sorted({a.alert_type.value for a in related})})
    false_alerts = [{"type": a.alert_type.value, "device": a.device_mac,
                     "severity": a.severity.value} for a in alerts if a.id not in matched_alerts]
    actionable = [a for a in alerts if a.severity.rank >= Severity.MEDIUM.rank]

    # window level: was each device-minute flagged when (and only when) it was attacked?
    attacked = {(label["device_mac"], int(label["start"] // window_seconds))
                for label in truth}
    tp = fp = fn = 0
    for mac in {d.mac for d in store.list_devices()}:
        for window in store.device_windows(mac):
            key = (mac, int(window["window_start"] // window_seconds))
            if window["flagged"] and key in attacked:
                tp += 1
            elif window["flagged"]:
                fp += 1
            elif key in attacked:
                fn += 1
    # attacks visible only to the inventory (new device, ARP) have no window
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Evaluation(
        attacks=len(truth), detected=sum(p["detected"] for p in per_attack),
        detected_exact=sum(p["exact_type"] for p in per_attack), alerts=len(alerts),
        true_alerts=len(alerts) - len(false_alerts), window_precision=round(precision, 3),
        window_recall=round(recall, 3), window_f1=round(f1, 3),
        actionable_alerts=len(actionable),
        actionable_true=sum(a.id in matched_alerts for a in actionable), per_attack=per_attack,
        false_alerts=false_alerts)
