"""Dashboard tests with Streamlit's AppTest harness (no browser needed)."""

import time

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from iotsec.dashboard import auth
from iotsec.models import Alert, AlertType, Device, Severity
from iotsec.passwords import hash_password
from iotsec.storage import Store

from conftest import ROOT

APP = str(ROOT / "src" / "iotsec" / "dashboard" / "app.py")
PASSWORD = "dashboard-test-password"
HASH = hash_password(PASSWORD)


@pytest.fixture
def app(tmp_path, monkeypatch):
    db = tmp_path / "dash.db"
    store = Store(str(db))
    now = time.time()
    store.save_device(Device(mac="44:19:b6:50:00:10", ip="192.168.50.10", hostname="ipcam",
                             device_type="camera", first_seen=now - 600, last_seen=now,
                             approved=True))
    store.save_device(Device(mac="24:0a:c4:50:00:66", ip="192.168.50.66",
                             hostname="<img src=x onerror=alert(1)>", first_seen=now,
                             last_seen=now))
    store.record_alert(Alert("44:19:b6:50:00:10", AlertType.MIRAI_SCAN, Severity.CRITICAL,
                             {"telnet_targets": 80}, now, now), 600)
    store.add_traffic(now - now % 60, 500, 90_000, 120)
    store.close()
    config = tmp_path / "dash.yaml"
    config.write_text(f"database: {db}\nmonitored_networks: [192.168.50.0/24]\n"
                      "dashboard:\n  password_hash: ${IOTSEC_TEST_HASH:-}\n")
    monkeypatch.setenv("IOTSEC_CONFIG", str(config))
    monkeypatch.setenv("IOTSEC_TEST_HASH", HASH)
    monkeypatch.delenv("IOTSEC_DASHBOARD_PASSWORD_HASH", raising=False)
    monkeypatch.setattr(auth, "FAILURE_DELAY", 0)  # skip the anti-guessing delay in tests
    st.cache_resource.clear()
    yield AppTest.from_file(APP, default_timeout=30)
    st.cache_resource.clear()


def _login(at, password=PASSWORD):
    at.run()
    at.text_input[0].input(password)
    at.button[0].click().run()
    return at


def test_dashboard_fails_closed_without_password(app, monkeypatch):
    monkeypatch.setenv("IOTSEC_TEST_HASH", "")
    app.run()
    assert "dashboard is locked" in app.error[0].value
    assert not app.metric


def test_login_page_shows_no_data(app):
    app.run()
    assert app.title[0].value == "IoT Security Monitor" and not app.metric
    assert not app.dataframe


def test_wrong_password_is_rejected(app):
    _login(app, "not-the-password")
    assert app.error[0].value == "Invalid password." and not app.metric


def test_correct_password_shows_overview(app):
    _login(app)
    values = {m.label: m.value for m in app.metric}
    assert values == {"Devices": "2", "Online": "2", "Suspicious": "1", "Open alerts": "1"}


def test_session_expires(app):
    _login(app)
    app.session_state["auth_until"] = time.time() - 1
    app.run()
    assert not app.metric and app.text_input[0].label == "Password"


def test_brute_force_lockout(app):
    app.run()
    for _ in range(auth.SESSION_MAX_FAILURES):
        app.text_input[0].input("guess-guess-guess")
        app.button[0].click().run()
    app.run()  # the next render of this session
    assert "Too many failed sign-in attempts" in app.error[0].value
    assert not app.text_input  # the form is gone for this session


def test_global_limiter():
    limiter = auth.LoginLimiter()
    for _ in range(auth.GLOBAL_MAX_FAILURES):
        limiter.failure()
    assert limiter.locked()


def test_alert_triage_and_device_approval(app, tmp_path):
    _login(app)
    app.sidebar.radio[0].set_value("Alerts").run()
    [b for b in app.button if b.label == "Acknowledge"][0].click().run()
    store = Store(str(tmp_path / "dash.db"))
    assert store.list_alerts()[0].status.value == "acknowledged"

    app.sidebar.radio[0].set_value("Devices").run()
    app.selectbox[0].set_value("24:0a:c4:50:00:66").run()
    [b for b in app.button if b.label == "Approve device"][0].click().run()
    assert store.get_device("24:0a:c4:50:00:66").approved
