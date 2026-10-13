import pytest

from iotsec.config import load_settings

from conftest import ROOT


def test_defaults_without_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("IOTSEC_CONFIG", raising=False)
    settings = load_settings()
    assert settings.capture.window_seconds == 60 and settings.notify.min_severity == "high"


def test_env_expansion_and_coercion(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_ON", "yes")
    monkeypatch.setenv("RCPT", "soc@example.com, oncall@example.com")
    path = tmp_path / "s.yaml"
    path.write_text(
        "retention_days: ${DAYS:-7}\n"
        "notify:\n  email:\n    enabled: ${SMTP_ON:-false}\n    host: smtp.example.com\n"
        "    sender: iot@example.com\n    recipients: ${RCPT}\n"
        "    port: ${PORT:-587}\n    security: starttls\n")
    settings = load_settings(path)
    assert settings.retention_days == 7
    assert settings.notify.email.enabled is True and settings.notify.email.port == 587
    assert settings.notify.email.recipients == ["soc@example.com", "oncall@example.com"]


@pytest.mark.parametrize("content,message", [
    ("capture:\n  backnd: scapy\n", "capture.backnd"),
    ("notify:\n  webhook_url: http://hooks.example.com/x\n", "https"),
    ("notify:\n  email:\n    security: none\n", "ssl"),
    ("notify:\n  email:\n    enabled: true\n", "host, sender"),
    ("monitored_networks: [not-a-network]\n", "does not appear"),
    ("capture:\n  window_seconds: 1\n", "window_seconds"),
    ("detection:\n  lateral_ports: [70000]\n", "invalid port"),
    ("ml:\n  contamination: 0.9\n", "contamination"),
])
def test_invalid_settings_are_rejected(tmp_path, content, message):
    path = tmp_path / "bad.yaml"
    path.write_text(content)
    with pytest.raises(ValueError, match=message):
        load_settings(path)


@pytest.mark.parametrize("name", ["settings.yaml", "lab.yaml"])
def test_shipped_configs_are_valid(name):
    settings = load_settings(ROOT / "config" / name)
    assert settings.monitored_networks
