import smtplib

import pytest

from iotsec.config import EmailSettings, NotifySettings
from iotsec.models import Alert, AlertType, Device, Severity
from iotsec.notify import MAX_PER_HOUR, Notifier, render


def _alert(severity=Severity.CRITICAL):
    return Alert("44:19:b6:50:00:10", AlertType.MIRAI_SCAN, severity,
                 {"sample": ["192.168.50.100"], "evil\r\nBcc: x@evil.test": "<b>x</b>"}, 1e9, 1e9)


def _settings(**email):
    return NotifySettings(min_severity="high", email=EmailSettings(
        enabled=True, host="smtp.example.com", port=465, sender="iot@example.com",
        recipients=["soc@example.com"], username="u", password="p", **email))


def test_hostile_device_names_cannot_inject_headers(monkeypatch):
    device = Device(mac="44:19:b6:50:00:10", hostname="cam\r\nBcc: attacker@evil.test",
                    ip="192.168.50.10", device_type="camera")
    subject, body = render(_alert(), device)
    assert subject.startswith("[IoT CRITICAL] Mirai-style Telnet scanning")
    assert "\n" not in subject and "\r" not in subject and "<" not in body
    FakeSMTP.sent = []
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    Notifier(_settings(security="ssl")).send_email(subject, body)
    message = FakeSMTP.sent[0]
    assert message["Bcc"] is None and message["To"] == "soc@example.com"


class FakeSMTP:
    sent: list = []
    instances: list = []

    def __init__(self, host, port, context=None, timeout=None):
        self.context = context
        self.tls = False
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.tls = context is not None

    def login(self, user, password):
        self.user = user

    def send_message(self, message):
        FakeSMTP.sent.append(message)


@pytest.mark.parametrize("security,cls", [("ssl", "SMTP_SSL"), ("starttls", "SMTP")])
def test_email_always_uses_verified_tls(monkeypatch, security, cls):
    FakeSMTP.sent, FakeSMTP.instances = [], []
    monkeypatch.setattr(smtplib, cls, FakeSMTP)
    notifier = Notifier(_settings(security=security))
    notifier.send_email("subject", "body")
    smtp = FakeSMTP.instances[0]
    context = smtp.context if security == "ssl" else None
    if security == "starttls":
        assert smtp.tls
    else:
        assert context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
    assert FakeSMTP.sent[0]["To"] == "soc@example.com"


def test_background_delivery_rate_limit_and_failures(monkeypatch):
    calls = []
    notifier = Notifier(_settings())
    monkeypatch.setattr(notifier, "send_email", lambda s, b: calls.append(s))
    assert not notifier.submit(_alert(Severity.MEDIUM), None)  # below min severity
    results = [notifier.submit(_alert(), None) for _ in range(MAX_PER_HOUR + 5)]
    notifier.close()
    assert sum(results) == MAX_PER_HOUR and notifier.suppressed == 5
    assert len(calls) == MAX_PER_HOUR

    def broken(subject, body):
        raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    failing = Notifier(_settings())
    monkeypatch.setattr(failing, "send_email", broken)
    failing.submit(_alert(), None)
    failing.close()  # must not raise
    assert failing.failed == 1


def test_disabled_notifier_sends_nothing():
    notifier = Notifier(NotifySettings())
    assert not notifier.enabled and not notifier.submit(_alert(), None)
