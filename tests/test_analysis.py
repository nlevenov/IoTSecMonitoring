import pytest

from iotsec.analysis.baseline import Baseline, RunningStat
from iotsec.analysis.detectors import detect
from iotsec.analysis.features import DeviceWindow, WindowAggregator
from iotsec.analysis.ml import AnomalyModel
from iotsec.config import DetectionSettings
from iotsec.discovery.scope import NetworkScope
from iotsec.models import AlertType, Device, Severity
from iotsec.threatintel import Blocklist

from helpers import CAMERA, LAPTOP, ROUTER, record

SCOPE = NetworkScope(["192.168.50.0/24"])
RULES = DetectionSettings()


def _aggregator(blocklist=None):
    return WindowAggregator(SCOPE, blocklist or Blocklist(), 60, RULES.lateral_ports,
                            RULES.dns_label_length)


def _types(findings):
    return {f.alert_type for f in findings}


def test_packets_are_attributed_to_local_endpoints():
    agg = _aggregator()
    agg.add(record(ts=0, length=500))                                   # camera -> internet
    agg.add(record(ts=1, src=("ff:ee:dd:00:00:01", "203.0.113.10"),
                   dst=CAMERA, length=900))                             # internet -> camera
    agg.add(record(ts=2, src=CAMERA, dst=LAPTOP, dport=445, tcp_flags=0x02))  # camera -> laptop
    windows = {w.mac: w for w in agg.add(record(ts=61))}
    camera, laptop = windows[CAMERA[0]], windows[LAPTOP[0]]
    assert (camera.pkts_out, camera.bytes_out, camera.pkts_in, camera.bytes_in) == (2, 600, 1, 900)
    assert camera.ext_ips == {"203.0.113.10"} and camera.int_peers == {LAPTOP[1]}
    assert camera.admin_targets == {f"{LAPTOP[1]}:445"}
    assert laptop.pkts_in == 1 and laptop.pkts_out == 0
    assert not agg.windows or all(w.start == 60 for w in agg.windows.values())


def test_sets_are_bounded_under_floods():
    agg = _aggregator()
    for i in range(10_000):
        agg.add(record(ts=1, dst=("ff:ee:dd:00:00:01", f"198.51.{i // 250}.{i % 250}"),
                       dport=i % 65535, tcp_flags=0x02))
    window = agg.drain()[0]
    assert len(window.dst_ips) <= 4096 and len(window.syn_ports) <= 4096
    assert window.syn_out == 10_000


def _window(**values):
    window = DeviceWindow(CAMERA[0], 0.0)
    for key, value in values.items():
        setattr(window, key, value)
    return window


@pytest.mark.parametrize("window,expected", [
    (_window(telnet_hosts={f"10.0.0.{i}" for i in range(6)}), AlertType.MIRAI_SCAN),
    (_window(syn_ports=set(range(25))), AlertType.PORT_SCAN),
    (_window(syn_hosts={f"192.168.50.{i}" for i in range(25)}), AlertType.PORT_SCAN),
    (_window(pkts_out=5000), AlertType.FLOOD),
    (_window(max_dns_entropy=4.2, long_dns_labels=5), AlertType.DNS_TUNNEL),
    (_window(nxdomain=20), AlertType.DNS_TUNNEL),
    (_window(blocklisted={"203.0.113.66": "C2"}), AlertType.BLOCKLISTED),
    (_window(insecure_in={"telnet:192.168.50.20"}), AlertType.INSECURE_PROTOCOL),
])
def test_pattern_detectors_fire_without_a_baseline(window, expected):
    assert expected in _types(detect(window, None, True, None, RULES))


def test_quiet_window_raises_nothing():
    assert detect(_window(pkts_out=20, bytes_out=4000), None, True, None, RULES) == []


def _learned_baseline(**overrides):
    baseline = Baseline(CAMERA[0], started_at=0)
    for i in range(40):
        window = _window(pkts_out=100 + i % 5, bytes_out=20_000 + i * 10, pkts_in=50,
                         domains={"cloud.example.net"}, prefixes={"203.0.113.0/24"})
        baseline.update(window, max_destinations=500)
    for key, value in overrides.items():
        setattr(baseline, key, value)
    return baseline


def test_baseline_detectors_only_after_learning():
    baseline = _learned_baseline()
    big = _window(pkts_out=300, bytes_out=5_000_000, ext_ips={"198.51.100.9"})
    assert AlertType.EXFILTRATION in _types(detect(big, baseline, False, None, RULES))
    assert AlertType.EXFILTRATION not in _types(detect(big, baseline, True, None, RULES))


def test_flood_needs_deviation_once_learned():
    baseline = _learned_baseline()
    busy_tv = Baseline("tv", 0)
    for _ in range(40):
        busy_tv.update(_window(pkts_out=4000), 500)
    flood = _window(pkts_out=4100)
    assert AlertType.FLOOD not in _types(detect(flood, busy_tv, False, None, RULES))
    assert AlertType.FLOOD in _types(detect(flood, baseline, False, None, RULES))


def test_new_destinations_and_lateral_movement():
    baseline = _learned_baseline()
    camera = Device(mac=CAMERA[0], device_type="camera")
    window = _window(domains={f"new{i}.example.org" for i in range(6)},
                     admin_targets={f"{LAPTOP[1]}:445"})
    findings = {f.alert_type: f for f in detect(window, baseline, False, camera, RULES)}
    assert findings[AlertType.NEW_DESTINATIONS].severity is Severity.MEDIUM
    assert AlertType.LATERAL_MOVEMENT in findings
    laptop = Device(mac=LAPTOP[0], device_type="computer")
    assert AlertType.LATERAL_MOVEMENT not in _types(detect(window, baseline, False, laptop, RULES))


def test_baseline_saturation_and_roundtrip():
    baseline = Baseline("m", 0)
    baseline.update(_window(domains={f"d{i}.example" for i in range(600)}), 500)
    assert baseline.saturated and baseline.new_destinations(_window(domains={"x.y"})) == []
    learned = _learned_baseline()
    restored = Baseline.from_dict(learned.to_dict())
    assert restored.to_dict() == learned.to_dict()
    assert restored.zscore("pkts_out", 102) == pytest.approx(learned.zscore("pkts_out", 102))


def test_running_stat_matches_textbook_values():
    stat = RunningStat()
    for value in (2, 4, 4, 4, 5, 5, 7, 9):
        stat.add(value)
    assert stat.mean == 5 and stat.std == pytest.approx(2.138, abs=1e-3)


def test_blocklist_matching(tmp_path):
    (tmp_path / "bad.txt").write_text("# comment\n203.0.113.66\n198.51.100.0/24\nevil.test\n")
    (tmp_path / "more.csv").write_text("indicator,description\nc2.example.org,Botnet <C2>\n")
    blocklist = Blocklist.from_dir(tmp_path)
    assert blocklist.match_ip("203.0.113.66") == "bad"
    assert blocklist.match_ip("198.51.100.200") == "bad" and not blocklist.match_ip("192.0.2.1")
    assert blocklist.match_domain("a.b.evil.test") == "bad"
    assert blocklist.match_domain("c2.example.org") == "Botnet C2"
    assert not blocklist.match_domain("example.org")
    agg = _aggregator(blocklist)
    agg.add(record(ts=0, dst=("ff:ee:dd:00:00:01", "203.0.113.66")))
    agg.add(record(ts=1, dst=ROUTER, proto="udp", dport=53, dns_qname="x.evil.test"))
    assert set(agg.drain()[0].blocklisted) == {"203.0.113.66", "x.evil.test"}


def _trained_model():
    baselines, windows = {}, {}
    for d in range(3):
        mac = f"aa:00:00:00:00:0{d}"
        baseline = Baseline(mac, 0)
        rows = []
        for i in range(60):
            window = _window(pkts_out=100 * (d + 1) + i % 7, bytes_out=10_000 * (d + 1) + i,
                             pkts_in=50 + i % 3)
            baseline.update(window, 500)
            rows.append(window.features())
        baselines[mac], windows[mac] = baseline, rows
    return AnomalyModel.train(windows, baselines, 50, 0.01), baselines


def test_model_flags_deviation_relative_to_the_device():
    model, baselines = _trained_model()
    normal = _window(pkts_out=103, bytes_out=10_030, pkts_in=51).features()
    attack = _window(pkts_out=9000, bytes_out=9_000_000, pkts_in=1).features()
    baseline = baselines["aa:00:00:00:00:00"]
    assert not model.score(normal, baseline)[1]
    assert model.score(attack, baseline)[1]


def test_model_signature_is_enforced(tmp_path):
    model, _ = _trained_model()
    path = tmp_path / "m.joblib"
    model.save(path, signing_key="k1")
    assert AnomalyModel.load(path, "k1").ready
    assert AnomalyModel.load(path, "k2") is None
    assert AnomalyModel.load(path) is None
    path.write_bytes(path.read_bytes() + b"x")
    assert AnomalyModel.load(path, "k1") is None
    model.save(path)
    (tmp_path / "m.joblib.sig").unlink()
    assert AnomalyModel.load(path) is None
