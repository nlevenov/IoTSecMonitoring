"""The monitor: packets in, inventory + windows + alerts out.

Time is taken from packet timestamps, so a pcap replay behaves exactly like
the live traffic it was recorded from.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from .analysis.baseline import Baseline
from .analysis.detectors import Finding, detect
from .analysis.features import DeviceWindow, WindowAggregator
from .analysis.ml import AnomalyModel
from .config import Settings
from .discovery.inventory import Inventory
from .discovery.oui import OuiDatabase
from .discovery.scope import NetworkScope
from .models import Alert, AlertType, PacketRecord, Severity
from .notify import Notifier
from .storage import Store
from .threatintel import Blocklist

log = logging.getLogger(__name__)
HOUSEKEEPING_SECONDS = 300
ANOMALY_STREAK = 2  # consecutive anomalous windows before an ML alert is medium


@dataclass
class RunStats:
    packets: int = 0
    windows: int = 0
    alerts: int = 0
    notified: int = 0
    by_type: dict[str, int] = field(default_factory=dict)


class Monitor:
    def __init__(self, settings: Settings, store: Store | None = None,
                 notifier: Notifier | None = None) -> None:
        self.settings = settings
        self.store = store or Store(settings.database)
        self.scope = NetworkScope(settings.monitored_networks)
        self.blocklist = Blocklist.from_dir(settings.feeds_dir)
        self.inventory = Inventory(self.store, self.scope, OuiDatabase.load(settings.oui_file),
                                   settings.gateway_ip, settings.discovery.max_devices)
        self.aggregator = WindowAggregator(
            self.scope, self.blocklist, settings.capture.window_seconds,
            settings.detection.lateral_ports, settings.detection.dns_label_length,
            tracked=self.inventory.devices)
        self.notifier = notifier if notifier is not None else Notifier(settings.notify)
        self.model = AnomalyModel.load(settings.model_path, settings.model_signing_key,
                                       settings.ml.margin) if settings.ml.enabled else None
        if settings.ml.enabled and not settings.model_signing_key:
            log.warning("IOTSEC_MODEL_KEY is not set: the model file is only checksummed, "
                        "not authenticated - anyone able to write it could replace both")
        self.baselines: dict[str, Baseline] = {}
        self._anomaly_streak: dict[str, int] = {}
        self.stats = RunStats()
        self.clock = 0.0
        self._lock = threading.Lock()
        self._last_housekeeping = 0.0
        started = self.store.get_meta("started_at")
        self.started_at = float(started) if started else None
        trained = self.store.get_meta("model_trained_at")
        self._model_trained_at = float(trained) if trained else 0.0

    # ----------------------------------------------------------------- input
    def process(self, record: PacketRecord) -> None:
        with self._lock:
            self.stats.packets += 1
            self.clock = max(self.clock, record.ts)
            if self.started_at is None:
                self.started_at = record.ts
                self.store.set_meta("started_at", str(record.ts))
            for event in self.inventory.observe(record):
                if event.alert_type is AlertType.NEW_DEVICE and self._initial_learning():
                    # devices present while the deployment learns are the
                    # existing inventory, not intruders
                    self._auto_approve(event.device_mac)
                    continue
                mac = None if event.alert_type is AlertType.MAC_FLOOD else event.device_mac
                self._raise(mac, Finding(event.alert_type, event.severity, event.details),
                            event.ts)
            finished = self.aggregator.add(record)
            if finished:
                self._analyze(finished)
            self._housekeeping()

    def tick(self, now: float | None = None) -> None:
        """Close windows on a quiet network (live mode calls this periodically)."""
        with self._lock:
            now = now if now is not None else time.time()
            self.clock = max(self.clock, now)
            finished = self.aggregator.advance(now)
            if finished:
                self._analyze(finished)
            self.inventory.flush()
            self._housekeeping()

    def run(self, records: Iterable[PacketRecord | None], live: bool = False) -> RunStats:
        for record in records:
            if record is None:
                if live:
                    self.tick()
                continue
            self.process(record)
            if live and self.stats.packets % 1000 == 0:
                self.tick()
        self.finish()
        return self.stats

    def finish(self) -> None:
        with self._lock:
            remaining = self.aggregator.drain()
            if remaining:
                self._analyze(remaining)
            self.inventory.flush(force=True)
            for mac, baseline in self.baselines.items():
                self.store.save_baseline(mac, baseline.to_dict())
            self._maybe_train(force=False)

    def close(self) -> None:
        self.finish()
        self.notifier.close()

    # --------------------------------------------------------------- analyze
    def _initial_learning(self) -> bool:
        if self.started_at is None:
            return True
        return self.clock - self.started_at < self.settings.baseline.learning_hours * 3600

    def _auto_approve(self, mac: str) -> None:
        device = self.inventory.devices.get(mac)
        if device is not None:
            device.approved = True
            self.store.save_device(device)

    def _baseline(self, mac: str, start: float) -> Baseline:
        baseline = self.baselines.get(mac)
        if baseline is None:
            stored = self.store.get_baseline(mac)
            baseline = Baseline.from_dict(stored) if stored else Baseline(mac, start)
            self.baselines[mac] = baseline
        return baseline

    def _analyze(self, windows: list[DeviceWindow]) -> None:
        settings = self.settings
        learning_seconds = settings.baseline.learning_hours * 3600
        total_packets = total_bytes = suspicious_packets = 0
        self.inventory.flush(force=True)
        for window in windows:
            self.stats.windows += 1
            baseline = self._baseline(window.mac, window.start)
            learning = baseline.is_learning(window.start, learning_seconds,
                                            settings.baseline.min_windows)
            device = self.inventory.devices.get(window.mac)
            findings = detect(window, baseline, learning, device, settings.detection)

            features = window.features()
            score, anomalous = (None, False)
            if self.model is not None and not learning:
                score, anomalous = self.model.score(features, baseline)
                streak = self._anomaly_streak[window.mac] = \
                    self._anomaly_streak.get(window.mac, 0) + 1 if anomalous else 0
                if anomalous and not findings:
                    # one unusual minute is weak evidence; a deviation that
                    # persists across windows is worth an analyst's time
                    severity = Severity.MEDIUM if streak >= ANOMALY_STREAK else Severity.LOW
                    findings.append(Finding(AlertType.BEHAVIOUR_ANOMALY, severity, {
                        "anomaly_score": score, "consecutive_windows": streak,
                        "packets_out": window.pkts_out, "bytes_out": window.bytes_out,
                        "external_hosts": len(window.ext_ips)}))

            flagged = any(f.severity.rank >= Severity.MEDIUM.rank for f in findings)
            if not flagged:
                # only clean behaviour teaches the baseline
                baseline.update(window, settings.baseline.max_destinations)
            for finding in findings:
                self._raise(window.mac, finding, window.start + settings.capture.window_seconds)
            self.store.save_window(window.mac, window.start, features, score, flagged, learning)

            total_packets += window.packets
            total_bytes += window.bytes_out + window.bytes_in
            suspicious_packets += window.packets if flagged else 0
        if windows:
            self.store.add_traffic(windows[0].start, total_packets, total_bytes,
                                   suspicious_packets)

    def _raise(self, mac: str | None, finding: Finding, ts: float) -> None:
        alert = Alert(device_mac=mac, alert_type=finding.alert_type, severity=finding.severity,
                      details=finding.details, first_seen=ts, last_seen=ts)
        stored, is_new = self.store.record_alert(
            alert, self.settings.notify.cooldown_minutes * 60)
        self.stats.alerts += 1
        key = finding.alert_type.value
        self.stats.by_type[key] = self.stats.by_type.get(key, 0) + 1
        if is_new and self.notifier.submit(stored, self.inventory.devices.get(mac or "")):
            self.stats.notified += 1

    # ---------------------------------------------------------- housekeeping
    def _housekeeping(self) -> None:
        if self.clock - self._last_housekeeping < HOUSEKEEPING_SECONDS:
            return
        self._last_housekeeping = self.clock
        for mac, baseline in self.baselines.items():
            self.store.save_baseline(mac, baseline.to_dict())
        removed = self.store.prune(self.settings.retention_days, now=self.clock)
        if removed:
            log.info("pruned %d expired rows", removed)
        self._maybe_train(force=False)

    def _maybe_train(self, force: bool) -> None:
        ml = self.settings.ml
        if not ml.enabled:
            return
        due = self.clock - self._model_trained_at >= ml.retrain_hours * 3600
        learned = [m for m, b in self.baselines.items() if not b.is_learning(
            self.clock, self.settings.baseline.learning_hours * 3600,
            self.settings.baseline.min_windows)]
        if not learned or not (force or due or self.model is None):
            return
        windows = self.store.training_windows()
        model = AnomalyModel.train({m: windows.get(m, []) for m in learned}, self.baselines,
                                   ml.min_windows, ml.contamination)
        if not model.ready:
            return
        model.margin = ml.margin
        model.save(self.settings.model_path, self.settings.model_signing_key)
        self.model = model
        self._model_trained_at = self.clock
        self.store.set_meta("model_trained_at", str(self.clock))
        log.info("anomaly model trained on %d windows from %d devices",
                 model.metadata["windows"], model.metadata["devices"])

    def train_now(self) -> AnomalyModel | None:
        with self._lock:
            for mac, stored in ((d.mac, self.store.get_baseline(d.mac))
                                for d in self.store.list_devices()):
                if stored and mac not in self.baselines:
                    self.baselines[mac] = Baseline.from_dict(stored)
            self._model_trained_at = 0.0
            self._maybe_train(force=True)
            return self.model
