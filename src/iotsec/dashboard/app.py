"""IoT Security Monitor - Streamlit dashboard.

Run through ``iotsec dashboard``, which applies the hardened server options.
Everything shown here was sanitized when it was captured; nothing is
rendered as raw HTML.
"""

from __future__ import annotations

import time

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from iotsec.config import load_settings
from iotsec.dashboard.auth import logout, require_login
from iotsec.dashboard.data import (
    alerts_frame,
    device_windows_frame,
    devices_frame,
    traffic_frame,
)
from iotsec.discovery.classify import DEVICE_TYPES
from iotsec.models import AlertStatus, Severity
from iotsec.sanitize import clean_text
from iotsec.storage import Store

st.set_page_config(page_title="IoT Security Monitor", page_icon=":material/router:",
                   layout="wide", menu_items={})

SEVERITY_COLORS = {"critical": "#d62728", "high": "#ff7f0e", "medium": "#e6b800",
                   "low": "#1f77b4", "info": "#7f7f7f"}
TYPE_ICONS = {"camera": "📷", "smart-speaker": "🔊", "smart-tv": "📺", "smart-bulb": "💡",
              "smart-plug": "🔌", "thermostat": "🌡️", "router": "📡", "computer": "💻",
              "phone": "📱", "hub": "🏠", "nas": "🗄️", "printer": "🖨️"}


@st.cache_resource
def _settings():
    return load_settings()


@st.cache_resource
def _store(path: str) -> Store:
    return Store(path)


settings = _settings()
require_login(settings.dashboard.password_hash, settings.dashboard.session_minutes)
store = _store(settings.database)

# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("IoT Security Monitor")
    page = st.radio("View", ["Overview", "Devices", "Alerts"], label_visibility="collapsed")
    hours = st.select_slider("Time range", options=[1, 3, 6, 12, 24, 72, 168], value=6,
                             format_func=lambda h: f"{h} h" if h < 24 else f"{h // 24} d")
    st.caption(f"Networks: {', '.join(settings.monitored_networks)}")
    if st.button("Sign out", use_container_width=True):
        logout()


def _context():
    devices = store.list_devices()
    by_mac = {d.mac: d for d in devices}
    open_alerts = store.list_alerts(statuses=["open", "acknowledged"], limit=1000)
    suspicious = {a.device_mac for a in open_alerts
                  if a.device_mac and a.severity.rank >= Severity.MEDIUM.rank}
    online_after = (store.latest_traffic() or time.time()) - \
        settings.discovery.online_minutes * 60
    return devices, by_mac, open_alerts, suspicious, online_after


TIME_FORMAT = "YYYY-MM-DD HH:mm:ss"
COLUMNS = {
    "Last seen": st.column_config.DatetimeColumn("Last seen (UTC)", format=TIME_FORMAT),
    "First seen": st.column_config.DatetimeColumn("First seen (UTC)", format=TIME_FORMAT),
    "Approved": st.column_config.CheckboxColumn("Approved"),
}


def _table(frame, style_severity: bool = False) -> None:
    data = frame.style.apply(_severity_style, subset=["Severity"]) if style_severity else frame
    st.dataframe(data, hide_index=True, use_container_width=True, column_config=COLUMNS)


def _facts(rows: dict) -> None:
    """Key/value table - rendered as data, never as markup."""
    st.dataframe([{"Field": k, "Value": "" if v is None else str(v)} for k, v in rows.items()],
                 hide_index=True, use_container_width=True)


def _severity_style(column):
    return [f"color: {SEVERITY_COLORS.get(v, '')}; font-weight: 600" for v in column]


# ---------------------------------------------------------------- overview
@st.fragment(run_every=settings.dashboard.refresh_seconds)
def overview() -> None:
    devices, by_mac, open_alerts, suspicious, online_after = _context()
    summary = store.summary(settings.discovery.online_minutes * 60)
    online = sum(d.last_seen >= online_after for d in devices)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Devices", summary["devices"], border=True)
    k2.metric("Online", online, border=True)
    k3.metric("Suspicious", len(suspicious), border=True)
    k4.metric("Open alerts", len(open_alerts), border=True)

    left, right = st.columns([2, 1])
    with left, st.container(border=True):
        st.subheader("Network activity")
        traffic = traffic_frame(store, hours)
        if traffic.empty:
            st.info("No traffic recorded yet.")
        else:
            figure = go.Figure()
            figure.add_scatter(x=traffic["time"], y=traffic["normal"], name="Normal traffic",
                               line={"color": "#1f77b4"})
            figure.add_scatter(x=traffic["time"], y=traffic["suspicious_packets"],
                               name="Suspicious activity", line={"color": "#d62728"},
                               fill="tozeroy")
            figure.update_layout(height=320, margin={"l": 10, "r": 10, "t": 10, "b": 10},
                                 yaxis_title="Packets per window",
                                 legend={"orientation": "h", "y": 1.1})
            st.plotly_chart(figure, use_container_width=True)
    with right, st.container(border=True):
        st.subheader("Device types")
        if devices:
            types = devices_frame(devices, online_after, suspicious)["Device type"] \
                .value_counts().rename_axis("type").reset_index(name="devices")
            donut = px.pie(types, names="type", values="devices", hole=0.55)
            donut.update_layout(height=320, margin={"l": 10, "r": 10, "t": 10, "b": 10})
            st.plotly_chart(donut, use_container_width=True)
        else:
            st.info("No devices discovered yet.")

    left, right = st.columns([3, 2])
    with left, st.container(border=True):
        st.subheader("Recent alerts")
        _table(alerts_frame(open_alerts[:15], by_mac), style_severity=True)
    with right, st.container(border=True):
        st.subheader("Top devices")
        frame = devices_frame(devices, online_after, suspicious)
        frame["Type"] = frame["Device type"].map(lambda t: f"{TYPE_ICONS.get(t, '❔')} {t}")
        st.dataframe(frame[["IP address", "Type", "Name", "Status"]].head(15),
                     hide_index=True, use_container_width=True)


# ---------------------------------------------------------------- devices
def devices_page() -> None:
    devices, by_mac, open_alerts, suspicious, online_after = _context()
    st.header("Devices")
    if not devices:
        st.info("No devices yet - start `iotsec monitor` or run `iotsec discover`.")
        return
    frame = devices_frame(devices, online_after, suspicious)
    only_unapproved = st.toggle("Only unapproved devices")
    if only_unapproved:
        frame = frame[~frame["Approved"]]
    _table(frame)

    options = {d.mac: f"{d.display_name} ({d.ip or d.mac})" for d in devices}
    mac = st.selectbox("Device details", list(options), format_func=options.get)
    device = by_mac[mac]

    info, actions = st.columns([2, 1])
    with info, st.container(border=True):
        st.subheader(device.display_name)
        _facts({"MAC": device.mac, "IP": device.ip, "Vendor": device.vendor,
                "Hostname": device.hostname, "Type": device.device_type,
                "Randomized MAC": "yes" if device.randomized_mac else "no",
                "Approved": "yes" if device.approved else "no",
                "Open ports": ", ".join(map(str, device.open_ports)) or "-",
                "Services": "; ".join(device.services[:10]) or "-"})
        baseline = store.get_baseline(mac)
        if baseline:
            st.caption(f"Baseline: {baseline['windows']} windows learned, "
                       f"{len(baseline['domains'])} known domains, "
                       f"{len(baseline['prefixes'])} known networks"
                       + (" (too many destinations to track)" if baseline["saturated"] else ""))
    with actions, st.container(border=True):
        st.subheader("Actions")
        if device.approved:
            if st.button("Revoke approval", use_container_width=True):
                store.set_device_approval(mac, False)
                st.rerun()
        elif st.button("Approve device", type="primary", use_container_width=True):
            store.set_device_approval(mac, True)
            st.rerun()
        with st.form(f"label-{mac}"):
            label = st.text_input("Label", value=device.label or "", max_chars=64)
            types = list(DEVICE_TYPES)
            device_type = st.selectbox("Type", types, index=types.index(device.device_type)
                                       if device.device_type in types else len(types) - 1)
            if st.form_submit_button("Save"):
                store.set_device_label(mac, clean_text(label, 64), device_type)
                st.rerun()

    windows = device_windows_frame(store, mac, hours)
    if not windows.empty:
        with st.container(border=True):
            st.subheader("Traffic")
            chart = px.bar(windows, x="time", y=["pkts_out", "pkts_in"], barmode="stack",
                           labels={"value": "packets", "variable": ""})
            chart.update_layout(height=260, margin={"l": 10, "r": 10, "t": 10, "b": 10})
            st.plotly_chart(chart, use_container_width=True)
            if windows["anomaly_score"].notna().any():
                score = px.line(windows, x="time", y="anomaly_score")
                score.add_hline(y=settings.ml.margin, line_dash="dot", line_color="#d62728")
                score.update_layout(height=200, margin={"l": 10, "r": 10, "t": 10, "b": 10})
                st.caption("Anomaly score (above the dotted line = anomalous)")
                st.plotly_chart(score, use_container_width=True)
    device_alerts = store.list_alerts(device_mac=mac, limit=100)
    if device_alerts:
        st.subheader("Alerts for this device")
        _table(alerts_frame(device_alerts, by_mac), style_severity=True)


# ----------------------------------------------------------------- alerts
def alerts_page() -> None:
    devices, by_mac, *_ = _context()
    st.header("Alerts")
    c1, c2 = st.columns(2)
    statuses = c1.multiselect("Status", [s.value for s in AlertStatus],
                              default=["open", "acknowledged"])
    minimum = c2.selectbox("Minimum severity", [s.value for s in Severity], index=0)
    alerts = store.list_alerts(statuses=statuses or None, min_severity=Severity(minimum),
                               limit=1000)
    if not alerts:
        st.success("No alerts match the filters.")
        return
    _table(alerts_frame(alerts, by_mac), style_severity=True)

    options = {a.id: f"#{a.id} {a.severity.value.upper()} - {a.title}" for a in alerts}
    alert_id = st.selectbox("Alert details", list(options), format_func=options.get)
    alert = store.get_alert(alert_id)
    if alert is None:
        return
    with st.container(border=True):
        device = by_mac.get(alert.device_mac or "")
        st.subheader(alert.title)
        _facts({"Device": device.display_name if device else alert.device_mac,
                "IP": device.ip if device else None, "Severity": alert.severity.value,
                "Status": alert.status.value.replace("_", " "), "Occurrences": alert.count})
        st.json(alert.details, expanded=True)
        notes = st.text_area("Analyst notes", value=alert.notes, max_chars=1000)
        b1, b2, b3 = st.columns(3)
        for column, status, text in ((b1, AlertStatus.ACKNOWLEDGED, "Acknowledge"),
                                     (b2, AlertStatus.RESOLVED, "Resolve"),
                                     (b3, AlertStatus.FALSE_POSITIVE, "False positive")):
            if column.button(text, use_container_width=True):
                store.update_alert(alert.id, status, clean_text(notes, 1000) or "")
                st.rerun()


try:
    {"Overview": overview, "Devices": devices_page, "Alerts": alerts_page}[page]()
except Exception:  # never show internals; details go to the server log only
    import logging

    logging.getLogger("iotsec.dashboard").exception("dashboard error")
    st.error("Something went wrong while loading this view.")
