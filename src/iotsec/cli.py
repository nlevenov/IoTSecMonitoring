"""Command line interface: ``iotsec <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import secrets
import signal
import subprocess  # nosec B404 - launches streamlit with a fixed argv, no shell
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Settings, load_settings
from .models import AlertStatus, Severity
from .sanitize import normalize_mac

log = logging.getLogger("iotsec")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_COLORS = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[36m",
           "info": "\033[37m"}


def _color(text: str, severity: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{_COLORS.get(severity, '')}{text}\033[0m"


def _ts(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _mac(value: str) -> str:
    mac = normalize_mac(value)
    if mac is None:
        raise argparse.ArgumentTypeError(f"not a MAC address: {value}")
    return mac


def _print_alerts(store, limit: int = 20, statuses: list[str] | None = None) -> None:
    alerts = store.list_alerts(statuses=statuses, limit=limit)
    devices = {d.mac: d for d in store.list_devices()}
    if not alerts:
        print("no alerts")
        return
    print(f"{'ID':>4}  {'Last seen (UTC)':<19}  {'Severity':<8}  {'Alert':<40}  {'Device':<24}  "
          f"{'Count':>5}  Status")
    for a in alerts:
        device = devices.get(a.device_mac or "")
        name = (device.display_name if device else a.device_mac or "-")[:24]
        print(f"{a.id:>4}  {_ts(a.last_seen):<19}  "
              f"{_color(f'{a.severity.value:<8}', a.severity.value)}  {a.title[:40]:<40}  "
              f"{name:<24}  {a.count:>5}  {a.status.value}")


# ---------------------------------------------------------------- commands

def cmd_monitor(args: argparse.Namespace, settings: Settings) -> int:
    from .engine import Monitor

    backend = args.backend or settings.capture.backend
    stop = threading.Event()

    def _stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        if args.pcap:
            if backend == "tshark":
                from .capture.tshark_backend import read_pcap
            else:
                from .capture.scapy_backend import read_pcap
            source, close_source, live = read_pcap(args.pcap), (lambda: None), False
            print(f"replaying {args.pcap} with the {backend} backend ...")
        else:
            iface = args.iface or settings.capture.interface or None
            # The capture is opened (and root dropped) before any file is
            # created, so the database never ends up owned by root.
            source, close_source = _open_live(backend, iface, settings, stop)
            live = True
            print(f"monitoring {iface or 'default interface'} with the {backend} backend "
                  f"({', '.join(settings.monitored_networks)}) - Ctrl+C to stop")
    except PermissionError:
        print("error: capturing needs CAP_NET_RAW. Use the tshark backend (dumpcap holds the "
              "privilege) or run the scapy backend as root with capture.drop_privileges_to.")
        return 1
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}")
        return 1

    monitor = Monitor(settings)
    print(f"threat intel: {len(monitor.blocklist)} indicators from "
          f"{len(monitor.blocklist.files)} feed files")
    started = time.monotonic()
    try:
        stats = monitor.run(source, live=live)
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}")
        return 1
    finally:
        close_source()
        monitor.close()
    elapsed = time.monotonic() - started
    print(f"processed {stats.packets:,} packets into {stats.windows:,} device windows "
          f"in {elapsed:.1f}s; {stats.alerts} detections")
    notifier = monitor.notifier
    if notifier.enabled:
        print(f"notifications: {notifier.sent} delivered, {notifier.failed} failed, "
              f"{notifier.suppressed} suppressed by the rate limit")
    if args.show > 0:
        _print_alerts(monitor.store, limit=args.show, statuses=["open", "acknowledged"])
    return 0


def _open_live(backend: str, iface: str | None, settings: Settings, stop: threading.Event):
    """Start capturing now; return (record iterator, close function)."""
    if backend == "tshark":
        from .capture.live import with_ticks
        from .capture.tshark_backend import live

        return with_ticks(live(iface, settings.capture.bpf_filter), stop), stop.set
    from .capture.scapy_backend import LiveCapture

    capture = LiveCapture(iface, settings.capture.bpf_filter,
                          settings.capture.drop_privileges_to)
    capture.start()

    def records():
        for record in capture.records():
            if stop.is_set():
                break
            yield record

    def close() -> None:
        capture.stop()
        if capture.dropped:
            log.warning("dropped %d packets because analysis fell behind", capture.dropped)

    return records(), close


def cmd_discover(args: argparse.Namespace, settings: Settings) -> int:
    from .discovery.active import arp_sweep, probe_ports
    from .discovery.inventory import Inventory
    from .discovery.oui import OuiDatabase
    from .discovery.scope import NetworkScope
    from .storage import Store

    scope = NetworkScope(settings.monitored_networks)
    store = Store(settings.database)
    inventory = Inventory(store, scope, OuiDatabase.load(settings.oui_file), settings.gateway_ip)
    targets = args.cidr or [n for n in settings.monitored_networks if ":" not in n]
    iface = args.iface or settings.capture.interface or None
    try:
        hosts = []
        for cidr in targets:
            print(f"ARP sweep of {cidr} ...")
            hosts += arp_sweep(cidr, scope, iface, settings.discovery.arp_timeout)
    except PermissionError as exc:
        message = str(exc) if "outside" in str(exc) else "ARP sweeps need root / CAP_NET_RAW"
        print(f"error: {message}")
        return 1
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    new = inventory.record_scan(hosts)
    if args.probe or settings.discovery.active_probe:
        for ip, mac in hosts:
            ports = probe_ports(ip, settings.discovery.probe_ports, scope,
                                settings.discovery.probe_timeout)
            inventory.record_ports(mac, ports)
        inventory.flush(force=True)
    print(f"{len(hosts)} hosts answered, {new} not seen before")
    return cmd_devices(argparse.Namespace(approve=None, revoke=None, label=None, type=None),
                       settings)


def cmd_devices(args: argparse.Namespace, settings: Settings) -> int:
    from .discovery.classify import DEVICE_TYPES
    from .sanitize import clean_text
    from .storage import Store

    store = Store(settings.database)
    if args.approve or args.revoke:
        mac = args.approve or args.revoke
        if not store.set_device_approval(mac, bool(args.approve)):
            print(f"error: unknown device {mac}")
            return 1
        print(f"{mac} {'approved' if args.approve else 'no longer approved'}")
        return 0
    if args.label:
        mac, label = args.label
        if args.type and args.type not in DEVICE_TYPES:
            print(f"error: type must be one of {', '.join(DEVICE_TYPES)}")
            return 2
        if not store.set_device_label(mac, clean_text(label, 64), args.type):
            print(f"error: unknown device {mac}")
            return 1
        print(f"{mac} labelled")
        return 0
    devices = store.list_devices()
    online_after = time.time() - settings.discovery.online_minutes * 60
    print(f"{'MAC':<17}  {'IP':<15}  {'Type':<13}  {'Vendor':<24}  {'Name':<24}  "
          f"{'Approved':<8}  Last seen (UTC)")
    for d in devices:
        state = "online " if d.last_seen >= online_after else ""
        print(f"{d.mac:<17}  {d.ip or '-':<15}  {d.device_type:<13}  {(d.vendor or '-')[:24]:<24}  "
              f"{(d.label or d.hostname or '-')[:24]:<24}  {'yes' if d.approved else 'NO':<8}  "
              f"{state}{_ts(d.last_seen)}")
    print(f"\n{len(devices)} devices")
    return 0


def cmd_alerts(args: argparse.Namespace, settings: Settings) -> int:
    from .storage import Store

    store = Store(settings.database)
    for status, ids in ((AlertStatus.ACKNOWLEDGED, args.ack), (AlertStatus.RESOLVED, args.resolve),
                        (AlertStatus.FALSE_POSITIVE, args.false_positive)):
        for alert_id in ids or []:
            ok = store.update_alert(alert_id, status)
            print(f"alert {alert_id}: {status.value if ok else 'not found'}")
    if args.ack or args.resolve or args.false_positive:
        return 0
    statuses = None if args.all else ["open", "acknowledged"]
    _print_alerts(store, limit=args.limit, statuses=statuses)
    return 0


def cmd_train(args: argparse.Namespace, settings: Settings) -> int:
    from .engine import Monitor

    monitor = Monitor(settings)
    model = monitor.train_now()
    if model is None or not model.ready:
        print("not enough learned behaviour yet - keep the monitor running until devices "
              "finish their learning period")
        return 1
    print(f"model trained on {model.metadata['windows']} windows from "
          f"{model.metadata['devices']} devices -> {settings.model_path}")
    return 0


def cmd_simulate(args: argparse.Namespace, settings: Settings) -> int:
    from .simulate import generate, write

    print("generating lab traffic ...")
    scenario = generate(learning_minutes=args.learning_minutes, attack_minutes=30, seed=args.seed)
    labels = write(scenario, args.out)
    print(f"wrote {len(scenario.packets):,} packets to {args.out} and ground truth to {labels}")
    return 0


def cmd_evaluate(args: argparse.Namespace, settings: Settings) -> int:
    from .engine import Monitor
    from .evaluation import evaluate
    from .notify import Notifier
    from .storage import Store

    if args.backend == "tshark":
        from .capture.tshark_backend import read_pcap
    else:
        from .capture.scapy_backend import read_pcap
    settings.notify.email.enabled, settings.notify.webhook_url = False, ""
    settings.model_path = str(Path(args.pcap).with_suffix(".eval-model.joblib"))
    for leftover in (Path(settings.model_path), Path(settings.model_path + ".sig")):
        leftover.unlink(missing_ok=True)
    monitor = Monitor(settings, Store(":memory:"), Notifier(settings.notify))
    monitor.run(read_pcap(args.pcap))
    labels = args.labels or str(Path(args.pcap).with_suffix(".labels.json"))
    result = evaluate(monitor.store, labels, settings.capture.window_seconds)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
        return 0
    print(f"attacks detected        {result.detected}/{result.attacks} "
          f"({result.detected_exact} with the exact alert type)")
    print(f"alerts                  {result.alerts} ({result.true_alerts} true, "
          f"precision {result.alert_precision:.3f})")
    print(f"actionable (>= medium)  {result.actionable_alerts} "
          f"(precision {result.actionable_precision:.3f})")
    print(f"window precision/recall {result.window_precision:.3f} / {result.window_recall:.3f} "
          f"(F1 {result.window_f1:.3f})\n")
    for row in result.per_attack:
        mark = "ok  " if row["exact_type"] else ("part" if row["detected"] else "MISS")
        print(f"  [{mark}] {row['attack']:<24} {row['device']}  -> {', '.join(row['alerts'])}")
    for row in result.false_alerts:
        print(f"  [FP  ] {row['type']:<24} {row['device']}  ({row['severity']})")
    return 0


def cmd_dashboard(args: argparse.Namespace, settings: Settings,
                  extra_env: dict | None = None) -> int:
    from .passwords import is_valid_hash

    password_hash = (extra_env or {}).get("IOTSEC_DASHBOARD_PASSWORD_HASH") \
        or settings.dashboard.password_hash
    if not is_valid_hash(password_hash):
        print("error: no dashboard password configured. Create one with `iotsec hash-password` "
              "and set IOTSEC_DASHBOARD_PASSWORD_HASH.")
        return 2
    allowed_hosts = settings.dashboard.allowed_hosts or ["localhost", "127.0.0.1", "::1"]
    if args.host not in LOOPBACK:
        if not settings.dashboard.allowed_hosts:
            print("error: set dashboard.allowed_hosts to the host name(s) used to reach the "
                  "dashboard before serving it beyond localhost")
            return 2
        print(f"warning: serving on {args.host}. Put a TLS reverse proxy in front - the "
              "password would otherwise cross the network in clear text.")
    app = Path(__file__).parent / "dashboard" / "app.py"
    command = [
        sys.executable, "-m", "streamlit", "run", str(app),
        "--server.address", args.host, "--server.port", str(args.port),
        "--server.headless", "true", "--server.enableXsrfProtection", "true",
        "--server.xsrfCookieSameSite", "strict",
        "--server.enableCORS", "true", "--server.enableStaticServing", "false",
        "--server.fileWatcherType", "none", "--server.runOnSave", "false",
        "--server.maxUploadSize", "1", "--server.maxMessageSize", "50",
        "--browser.gatherUsageStats", "false", "--client.showErrorDetails", "none",
        "--client.toolbarMode", "minimal", "--global.developmentMode", "false",
    ]
    for host in allowed_hosts:
        command += ["--server.allowedHosts", host]
    env = {**os.environ, **(extra_env or {}),
           "IOTSEC_CONFIG": str(Path(args.config_path).resolve()) if args.config_path else
           os.environ.get("IOTSEC_CONFIG", ""),
           "IOTSEC_DATABASE": settings.database}
    print(f"dashboard on http://{args.host}:{args.port}")
    try:
        return subprocess.call(command, env=env)  # nosec B603 - fixed argv, no shell
    except KeyboardInterrupt:
        return 0


def cmd_hash_password(args: argparse.Namespace, settings: Settings) -> int:
    from .passwords import MIN_LENGTH, hash_password

    password = getpass.getpass("Dashboard password: ")
    if password != getpass.getpass("Repeat: "):
        print("error: passwords do not match")
        return 2
    try:
        encoded = hash_password(password)
    except ValueError as exc:
        print(f"error: {exc} (minimum {MIN_LENGTH})")
        return 2
    print("\nAdd this to your environment (.env):\n")
    print(f"IOTSEC_DASHBOARD_PASSWORD_HASH='{encoded}'")
    return 0


def cmd_import_oui(args: argparse.Namespace, settings: Settings) -> int:
    import shutil

    from .discovery.oui import OuiDatabase

    count = OuiDatabase().load_ieee(args.source)
    if count < 1000:
        print("error: that does not look like the IEEE MA-L registry (oui.csv)")
        return 1
    destination = Path(settings.oui_file or "var/oui.csv")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.source, destination)
    print(f"imported {count:,} vendor prefixes to {destination}")
    if not settings.oui_file:
        print(f"set `oui_file: {destination}` in your settings to use it")
    return 0


def cmd_status(args: argparse.Namespace, settings: Settings) -> int:
    from .storage import Store

    store = Store(settings.database)
    summary = store.summary(settings.discovery.online_minutes * 60)
    for key, value in summary.items():
        print(f"{key:<11} {value}")
    critical = store.list_alerts(statuses=["open"], min_severity=Severity.HIGH, limit=5)
    if critical:
        print()
        _print_alerts(store, limit=5, statuses=["open"])
    return 0


def cmd_demo(args: argparse.Namespace, settings: Settings) -> int:
    from .passwords import hash_password

    pcap = Path(args.pcap)
    if not pcap.exists():
        cmd_simulate(argparse.Namespace(out=str(pcap), seed=7, learning_minutes=40), settings)
    db = Path(settings.database)
    for leftover in (db, Path(f"{db}-wal"), Path(f"{db}-shm"),
                     Path(settings.model_path), Path(settings.model_path + ".sig")):
        leftover.unlink(missing_ok=True)
    cmd_monitor(argparse.Namespace(pcap=str(pcap), iface=None, backend=None, show=10), settings)
    if args.no_dashboard:
        return 0
    password = secrets.token_urlsafe(12)
    print(f"\ndemo dashboard login password (valid for this run only): {password}\n")
    return cmd_dashboard(args, settings,
                         extra_env={"IOTSEC_DASHBOARD_PASSWORD_HASH": hash_password(password)})


# ------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iotsec", description="IoT security monitoring platform")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", dest="config_path", help="settings YAML file")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("monitor", help="capture and analyse traffic (live or from a pcap)")
    p.add_argument("--pcap", help="replay a capture file instead of sniffing")
    p.add_argument("-i", "--iface", help="interface to capture on")
    p.add_argument("--backend", choices=["scapy", "tshark"])
    p.add_argument("--show", type=int, default=15, help="alerts to print when finished")
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("discover", help="ARP sweep (and optionally port probe) the network")
    p.add_argument("--cidr", action="append", help="subnet to sweep (must be monitored)")
    p.add_argument("-i", "--iface")
    p.add_argument("--probe", action="store_true", help="TCP connect probe of IoT ports")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("devices", help="list, approve or label devices")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--approve", type=_mac, metavar="MAC")
    group.add_argument("--revoke", type=_mac, metavar="MAC")
    group.add_argument("--label", nargs=2, metavar=("MAC", "NAME"))
    p.add_argument("--type", help="device type to set together with --label")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("alerts", help="list or triage alerts")
    p.add_argument("--all", action="store_true", help="include resolved alerts")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.add_argument("--ack", type=int, nargs="+", metavar="ID")
    p.add_argument("--resolve", type=int, nargs="+", metavar="ID")
    p.add_argument("--false-positive", type=int, nargs="+", metavar="ID")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("train", help="(re)train the anomaly model from stored behaviour")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("simulate", help="write a lab pcap with labelled attacks")
    p.add_argument("-o", "--out", default="data/lab.pcap")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--learning-minutes", type=int, default=40)
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("evaluate", help="score detection on a labelled pcap")
    p.add_argument("--pcap", default="data/lab.pcap")
    p.add_argument("--labels", help="ground truth JSON (default: <pcap>.labels.json)")
    p.add_argument("--backend", choices=["scapy", "tshark"], default="scapy")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_evaluate)

    for name, func, helptext in (("dashboard", cmd_dashboard, "start the web dashboard"),
                                 ("demo", cmd_demo, "simulate, analyse and open the dashboard")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=8501)
        if name == "demo":
            p.add_argument("--pcap", default="data/lab.pcap")
            p.add_argument("--no-dashboard", action="store_true")
        p.set_defaults(func=func)

    p = sub.add_parser("hash-password", help="create a dashboard password hash")
    p.set_defaults(func=cmd_hash_password)

    p = sub.add_parser("import-oui", help="import the IEEE OUI registry for vendor names")
    p.add_argument("source", help="oui.csv from standards-oui.ieee.org")
    p.set_defaults(func=cmd_import_oui)

    p = sub.add_parser("status", help="inventory and alert summary")
    p.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)  # database, models and reports are readable by this user only
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.command == "demo" and not args.config_path:
        args.config_path = "config/lab.yaml"
    try:
        settings = load_settings(args.config_path)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: invalid configuration: {exc}")
        return 2
    return args.func(args, settings)


if __name__ == "__main__":
    sys.exit(main())
