import time

import pytest

from iotsec import cli
from iotsec.models import Alert, AlertType, Device, Severity
from iotsec.storage import Store

from conftest import ROOT


@pytest.fixture
def config(tmp_path, monkeypatch):
    db = tmp_path / "cli.db"
    store = Store(str(db))
    now = time.time()
    store.save_device(Device(mac="44:19:b6:50:00:10", ip="192.168.50.10", hostname="ipcam",
                             device_type="camera", first_seen=now, last_seen=now))
    store.record_alert(Alert("44:19:b6:50:00:10", AlertType.PORT_SCAN, Severity.HIGH, {},
                             now, now), 600)
    store.close()
    path = tmp_path / "cli.yaml"
    path.write_text(f"database: {db}\nmodel_path: {tmp_path}/m.joblib\n"
                    f"feeds_dir: {ROOT / 'feeds'}\nmonitored_networks: [192.168.50.0/24]\n"
                    "dashboard:\n  password_hash: ${IOTSEC_TEST_HASH:-}\n")
    monkeypatch.delenv("IOTSEC_DASHBOARD_PASSWORD_HASH", raising=False)
    return str(path), db


def run(config, *args):
    return cli.main(["-c", config, *args])


def test_devices_and_triage(config, capsys):
    path, db = config
    assert run(path, "devices") == 0
    assert "ipcam" in capsys.readouterr().out
    assert run(path, "devices", "--approve", "44-19-B6-50-00-10") == 0
    assert Store(str(db)).get_device("44:19:b6:50:00:10").approved
    assert run(path, "devices", "--label", "44:19:b6:50:00:10", "Front <door>",
               "--type", "camera") == 0
    assert Store(str(db)).get_device("44:19:b6:50:00:10").label == "Front door"
    assert run(path, "devices", "--label", "44:19:b6:50:00:10", "x", "--type", "toaster") == 2
    assert run(path, "devices", "--approve", "00:00:00:00:00:01") == 1
    with pytest.raises(SystemExit):
        run(path, "devices", "--approve", "not-a-mac")


def test_alert_commands(config, capsys):
    path, db = config
    assert run(path, "alerts") == 0 and "Port / host scan" in capsys.readouterr().out
    assert run(path, "alerts", "--ack", "1") == 0
    assert Store(str(db)).get_alert(1).status.value == "acknowledged"
    assert run(path, "alerts", "--resolve", "999") == 0
    assert "not found" in capsys.readouterr().out
    assert run(path, "status") == 0


def test_dashboard_refuses_unsafe_starts(config, capsys, monkeypatch):
    path, _ = config
    assert run(path, "dashboard") == 2
    assert "no dashboard password" in capsys.readouterr().out
    from iotsec.passwords import hash_password

    monkeypatch.setenv("IOTSEC_TEST_HASH", hash_password("long-enough-password"))
    assert run(path, "dashboard", "--host", "0.0.0.0") == 2
    assert "allowed_hosts" in capsys.readouterr().out


def test_discover_refuses_foreign_networks(config, capsys):
    path, _ = config
    assert run(path, "discover", "--cidr", "10.0.0.0/24") == 1
    assert "outside the monitored networks" in capsys.readouterr().out


def test_hash_password(monkeypatch, capsys, config):
    path, _ = config
    answers = iter(["long-enough-password", "long-enough-password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    assert run(path, "hash-password") == 0
    assert "IOTSEC_DASHBOARD_PASSWORD_HASH='scrypt$" in capsys.readouterr().out
    answers = iter(["long-enough-password", "different-password"])
    assert run(path, "hash-password") == 2
    answers = iter(["short", "short"])
    assert run(path, "hash-password") == 2


def test_import_oui(tmp_path, config, capsys):
    path, _ = config
    small = tmp_path / "small.csv"
    small.write_text("Registry,Assignment,Organization Name,Organization Address\n"
                     "MA-L,001122,Example,X\n")
    assert run(path, "import-oui", str(small)) == 1
    full = tmp_path / "oui.csv"
    full.write_text("Registry,Assignment,Organization Name,Organization Address\n" + "".join(
        f"MA-L,{i:06X},Vendor {i},X\n" for i in range(1200)))
    assert run(path, "import-oui", str(full)) == 0


def test_invalid_config_is_reported(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("capture:\n  backend: pcap-magic\n")
    assert cli.main(["-c", str(bad), "status"]) == 2
    assert "invalid configuration" in capsys.readouterr().out


def test_monitor_and_evaluate_on_lab_capture(lab_pcap, config, capsys, tmp_path):
    path = tmp_path / "lab.yaml"
    path.write_text((ROOT / "config" / "lab.yaml").read_text()
                    .replace("${IOTSEC_DATABASE:-var/lab.db}", str(tmp_path / "lab.db"))
                    .replace("models/lab-anomaly.joblib", str(tmp_path / "lab.joblib"))
                    .replace("feeds_dir: feeds", f"feeds_dir: {ROOT / 'feeds'}"))
    assert cli.main(["-c", str(path), "evaluate", "--pcap", str(lab_pcap)]) == 0
    out = capsys.readouterr().out
    assert "attacks detected        8/8 (8 with the exact alert type)" in out
