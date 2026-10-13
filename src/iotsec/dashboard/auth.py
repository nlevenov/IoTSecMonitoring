"""Login gate for the dashboard.

Streamlit has no authentication of its own, so every page render goes
through ``require_login`` first. The gate fails closed: without a valid
password hash configured nothing but an error is shown.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque

import streamlit as st

from ..passwords import is_valid_hash, verify_password

GLOBAL_MAX_FAILURES = 10      # across all sessions ...
GLOBAL_WINDOW = 300           # ... within five minutes locks the login for five minutes
SESSION_MAX_FAILURES = 5
FAILURE_DELAY = 1.0           # seconds; slows down guessing on top of the scrypt cost


class LoginLimiter:
    def __init__(self) -> None:
        self._failures: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        while self._failures and now - self._failures[0] > GLOBAL_WINDOW:
            self._failures.popleft()

    def locked(self) -> bool:
        with self._lock:
            self._prune(time.monotonic())
            return len(self._failures) >= GLOBAL_MAX_FAILURES

    def failure(self) -> None:
        with self._lock:
            self._failures.append(time.monotonic())


@st.cache_resource
def _limiter() -> LoginLimiter:
    return LoginLimiter()  # one per server process, shared by all sessions


def _password_hash(configured: str) -> str:
    return configured or os.environ.get("IOTSEC_DASHBOARD_PASSWORD_HASH", "")


def require_login(configured_hash: str, session_minutes: int) -> None:
    """Render the login form and stop the script unless the session is signed in."""
    state = st.session_state
    now = time.time()
    if state.get("auth_until", 0) > now:
        state["auth_until"] = now + session_minutes * 60  # sliding idle timeout
        return
    state.pop("auth_until", None)

    password_hash = _password_hash(configured_hash)
    if not is_valid_hash(password_hash):
        st.error("The dashboard is locked: no password is configured. "
                 "Run `iotsec hash-password` and set IOTSEC_DASHBOARD_PASSWORD_HASH.")
        st.stop()

    _, center, _ = st.columns([1, 1.2, 1])
    with center:
        st.title("IoT Security Monitor")
        limiter = _limiter()
        if limiter.locked() or state.get("failures", 0) >= SESSION_MAX_FAILURES:
            st.error("Too many failed sign-in attempts. Try again in a few minutes.")
            st.stop()
        with st.form("login", clear_on_submit=True):
            password = st.text_input("Password", type="password", max_chars=256)
            submitted = st.form_submit_button("Sign in", use_container_width=True)
        if submitted:
            if password and verify_password(password, password_hash):
                state["auth_until"] = now + session_minutes * 60
                state["failures"] = 0
                st.rerun()
            limiter.failure()
            state["failures"] = state.get("failures", 0) + 1
            time.sleep(FAILURE_DELAY)
            st.error("Invalid password.")
    st.stop()


def logout() -> None:
    st.session_state.clear()
    st.rerun()
