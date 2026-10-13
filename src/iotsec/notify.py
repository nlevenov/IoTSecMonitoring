"""Alert delivery by e-mail (smtplib over TLS) and webhook.

Delivery runs on a background thread so a slow mail server never stalls
packet processing, and is rate limited so an attacker who can trigger
alerts cannot use the monitor to flood the analysts' inboxes.
"""

from __future__ import annotations

import logging
import queue
import smtplib
import ssl
import threading
import time
from collections import deque
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import make_msgid

import httpx

from .config import NotifySettings
from .models import Alert, Device, Severity
from .sanitize import clean_text

log = logging.getLogger(__name__)
MAX_PER_HOUR = 30


def render(alert: Alert, device: Device | None) -> tuple[str, str]:
    """Subject and plain-text body. All values are already sanitized text."""
    name = clean_text(device.display_name if device else alert.device_mac or "network", 64)
    subject = f"[IoT {alert.severity.value.upper()}] {alert.title} - {name}"
    # header safety: no CR/LF or other control characters can reach the Subject
    subject = "".join(ch for ch in subject if ch.isprintable())[:150]
    when = datetime.fromtimestamp(alert.last_seen, tz=timezone.utc)
    lines = [
        f"{alert.title}",
        "",
        f"Severity : {alert.severity.value}",
        f"Device   : {name} ({alert.device_mac or '-'})",
        f"IP       : {device.ip if device and device.ip else '-'}",
        f"Type     : {device.device_type if device else '-'}",
        f"Seen     : {when:%Y-%m-%d %H:%M:%S} UTC (x{alert.count})",
        "",
        "Details:",
    ]
    for key, value in alert.details.items():
        lines.append(f"  {clean_text(key, 40)}: {clean_text(value, 300)}")
    return subject or "IoT security alert", "\n".join(lines)


class Notifier:
    def __init__(self, settings: NotifySettings) -> None:
        self.settings = settings
        self.min_severity = Severity(settings.min_severity)
        self.sent = 0
        self.failed = 0
        self.suppressed = 0
        self._recent: deque[float] = deque()
        self._queue: queue.Queue[tuple[Alert, Device | None] | None] = queue.Queue(maxsize=500)
        self._worker: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.settings.email.enabled or self.settings.webhook_url)

    def submit(self, alert: Alert, device: Device | None) -> bool:
        if not self.enabled or alert.severity.rank < self.min_severity.rank:
            return False
        now = time.monotonic()
        while self._recent and now - self._recent[0] > 3600:
            self._recent.popleft()
        if len(self._recent) >= MAX_PER_HOUR:
            self.suppressed += 1
            return False
        self._recent.append(now)
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, name="notifier", daemon=True)
            self._worker.start()
        try:
            self._queue.put_nowait((alert, device))
        except queue.Full:
            self.suppressed += 1
            return False
        return True

    def _run(self) -> None:
        while (item := self._queue.get()) is not None:
            subject, body = render(*item)
            if self.settings.email.enabled:
                self._deliver(self.send_email, subject, body)
            if self.settings.webhook_url:
                self._deliver(self.send_webhook, subject, body)
            self._queue.task_done()
        self._queue.task_done()

    def _deliver(self, channel, subject: str, body: str) -> None:
        try:
            channel(subject, body)
            self.sent += 1
        except (OSError, smtplib.SMTPException, httpx.HTTPError) as exc:
            self.failed += 1
            # never log credentials or the webhook URL, only the failure type
            log.warning("alert delivery via %s failed: %s", channel.__name__,
                        type(exc).__name__)

    def send_email(self, subject: str, body: str) -> None:
        cfg = self.settings.email
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = cfg.sender
        message["To"] = ", ".join(cfg.recipients)
        message["Message-ID"] = make_msgid(domain=cfg.sender.split("@")[-1] or None)
        message.set_content(body)
        context = ssl.create_default_context()  # verifies certificate and host name
        if cfg.security == "ssl":
            with smtplib.SMTP_SSL(cfg.host, cfg.port, context=context, timeout=15) as smtp:
                self._login_and_send(smtp, message)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=15) as smtp:
                smtp.starttls(context=context)  # raises if the server cannot do TLS
                self._login_and_send(smtp, message)

    def _login_and_send(self, smtp: smtplib.SMTP, message: EmailMessage) -> None:
        cfg = self.settings.email
        if cfg.username:
            smtp.login(cfg.username, cfg.password)
        smtp.send_message(message)

    def send_webhook(self, subject: str, body: str) -> None:
        # Slack / Mattermost / Teams style payload; markup characters were
        # stripped from all values during sanitization
        response = httpx.post(self.settings.webhook_url, json={"text": f"*{subject}*\n{body}"},
                              timeout=10, follow_redirects=False)
        response.raise_for_status()

    def flush(self, timeout: float = 30) -> None:
        if self._worker is None:
            return
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.05)

    def close(self) -> None:
        if self._worker is not None:
            self.flush()
            self._queue.put(None)
            self._worker.join(timeout=5)
            self._worker = None
