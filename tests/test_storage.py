import os
import stat

from iotsec.models import Alert, AlertStatus, AlertType, Device, Severity
from iotsec.storage import Store


def _alert(ts, severity=Severity.HIGH, kind=AlertType.PORT_SCAN, mac="aa:bb:cc:00:00:01"):
    return Alert(mac, kind, severity, {"t": ts}, ts, ts)


def test_alerts_fold_and_escalate():
    store = Store(":memory:")
    first, new = store.record_alert(_alert(100), cooldown_seconds=600)
    again, new_again = store.record_alert(_alert(200), cooldown_seconds=600)
    escalated, is_escalation = store.record_alert(_alert(300, Severity.CRITICAL), 600)
    assert new and not new_again and is_escalation
    assert escalated.id == first.id and escalated.count == 3
    assert escalated.severity is Severity.CRITICAL
    later, new_later = store.record_alert(_alert(2000), cooldown_seconds=600)
    assert new_later and later.id != first.id


def test_closed_alerts_are_not_reopened():
    store = Store(":memory:")
    alert, _ = store.record_alert(_alert(100), 600)
    store.update_alert(alert.id, AlertStatus.RESOLVED, "fixed")
    _, new = store.record_alert(_alert(150), 600)
    assert new
    assert store.get_alert(alert.id).notes == "fixed"


def test_filters_and_summary():
    store = Store(":memory:")
    store.save_device(Device(mac="aa:bb:cc:00:00:01", first_seen=0, last_seen=10**10))
    store.record_alert(_alert(100, Severity.LOW, AlertType.INSECURE_PROTOCOL), 600)
    store.record_alert(_alert(100, Severity.CRITICAL), 600)
    assert [a.severity for a in store.list_alerts(min_severity=Severity.HIGH)] == \
        [Severity.CRITICAL]
    summary = store.summary(online_seconds=60)
    assert summary == {"devices": 1, "online": 1, "unapproved": 1, "suspicious": 1, "alerts": 2}


def test_prune_is_relative_to_data_time():
    store = Store(":memory:")
    store.save_window("m", 1000.0, {"pkts_out": 1}, None, False, True)
    store.save_window("m", 1000.0 + 40 * 86400, {"pkts_out": 1}, None, False, True)
    assert store.prune(30, now=1000.0 + 40 * 86400) == 1
    assert len(store.device_windows("m")) == 1


def test_database_file_is_private(tmp_path):
    path = tmp_path / "x.db"
    Store(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_hostile_values_are_stored_verbatim_as_data():
    store = Store(":memory:")
    name = "x'); DROP TABLE devices; --"
    store.save_device(Device(mac="aa:bb:cc:00:00:02", hostname=name, first_seen=0, last_seen=0))
    assert store.get_device("aa:bb:cc:00:00:02").hostname == name
    assert len(store.list_devices()) == 1
