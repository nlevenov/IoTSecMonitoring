"""End-to-end: replay the simulated lab capture through the whole pipeline."""

import pytest

from iotsec.capture import scapy_backend, tshark_backend
from iotsec.engine import Monitor
from iotsec.evaluation import evaluate
from iotsec.models import AlertType
from iotsec.notify import Notifier
from iotsec.storage import Store

from conftest import requires_tshark


class RecordingNotifier(Notifier):
    def __init__(self, settings):
        super().__init__(settings)
        self.submitted = []

    @property
    def enabled(self):
        return True

    def submit(self, alert, device):
        if alert.severity.rank < self.min_severity.rank:
            return False
        self.submitted.append(alert)
        return True


def _replay(settings, reader, lab_pcap):
    notifier = RecordingNotifier(settings.notify)
    monitor = Monitor(settings, Store(":memory:"), notifier)
    monitor.run(reader(lab_pcap))
    return monitor, notifier


@pytest.fixture(scope="module")
def scapy_run(lab_pcap, tmp_path_factory):
    from iotsec.config import load_settings

    from conftest import ROOT

    settings = load_settings(ROOT / "config" / "lab.yaml")
    settings.model_path = str(tmp_path_factory.mktemp("m") / "model.joblib")
    settings.feeds_dir = str(ROOT / "feeds")
    return settings, *_replay(settings, scapy_backend.read_pcap, lab_pcap)


def test_every_staged_attack_is_detected(scapy_run, lab_pcap):
    settings, monitor, _ = scapy_run
    result = evaluate(monitor.store, lab_pcap.with_suffix(".labels.json"), 60)
    missed = [p for p in result.per_attack if not p["exact_type"]]
    assert result.detected == result.attacks == 8 and not missed, missed
    assert result.alert_precision >= 0.9, result.false_alerts
    assert result.window_recall == 1.0 and result.window_precision >= 0.8


def test_inventory_from_passive_discovery(scapy_run):
    _, monitor, _ = scapy_run
    devices = {d.hostname: d for d in monitor.store.list_devices() if d.hostname}
    assert devices["ipcam-frontdoor"].device_type == "camera"
    assert devices["hue-bridge"].device_type == "smart-bulb"
    assert devices["nikola-laptop"].device_type == "computer"
    # present during learning -> trusted inventory; the intruder is not
    assert devices["ipcam-frontdoor"].approved and not devices["esp-device"].approved
    assert devices["esp-device"].ip == "192.168.50.66"


def test_notifications_only_for_high_severity_and_once(scapy_run):
    _, _, notifier = scapy_run
    kinds = [a.alert_type for a in notifier.submitted]
    assert AlertType.MIRAI_SCAN in kinds and AlertType.NEW_DEVICE not in kinds
    assert kinds.count(AlertType.ARP_SPOOF) == 1  # repeats fold into one alert


def test_model_was_trained_and_signed(scapy_run):
    settings, monitor, _ = scapy_run
    assert monitor.model is not None and monitor.model.ready
    assert monitor.store.get_meta("model_trained_at")


@requires_tshark
def test_tshark_backend_gives_identical_results(scapy_run, lab_pcap, tmp_path):
    settings, scapy_monitor, _ = scapy_run
    settings.model_path = str(tmp_path / "t.joblib")
    tshark_monitor, _ = _replay(settings, tshark_backend.read_pcap, lab_pcap)

    def summary(monitor):
        return sorted((a.alert_type.value, a.device_mac, a.count)
                      for a in monitor.store.list_alerts())

    assert summary(tshark_monitor) == summary(scapy_monitor)


def test_ml_anomaly_escalates_only_when_it_persists(settings):
    from iotsec.analysis.baseline import Baseline
    from iotsec.analysis.features import DeviceWindow

    class AlwaysAnomalous:
        ready = True

        def score(self, features, baseline):
            return 0.3, True

    monitor = Monitor(settings, Store(":memory:"), Notifier(settings.notify))
    monitor.model = AlwaysAnomalous()
    mac = "44:19:b6:50:00:10"
    baseline = monitor.baselines[mac] = Baseline(mac, started_at=0)
    for i in range(40):
        baseline.update(DeviceWindow(mac, i * 60.0, pkts_out=10), 500)
    for minute in (100, 101):
        monitor._analyze([DeviceWindow(mac, minute * 60.0, pkts_out=10)])
    alert = monitor.store.list_alerts()[0]
    assert alert.alert_type is AlertType.BEHAVIOUR_ANOMALY
    assert alert.severity.value == "medium" and alert.count == 2
    assert alert.details["consecutive_windows"] == 2
