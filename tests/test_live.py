import os
import subprocess
import sys
import threading
import time

import pytest

from iotsec.capture.live import with_ticks
from iotsec.models import PacketRecord

needs_root = pytest.mark.skipif(os.geteuid() != 0, reason="live capture needs root")


def test_with_ticks_yields_idle_ticks_and_records():
    stop = threading.Event()

    def slow():
        time.sleep(0.3)
        yield PacketRecord(ts=1.0)

    items = list(with_ticks(slow(), stop, poll=0.05))
    assert items[-1] == PacketRecord(ts=1.0) and None in items


def test_with_ticks_surfaces_source_errors():
    def broken():
        yield PacketRecord(ts=1.0)
        raise RuntimeError("tshark failed: permission denied")

    with pytest.raises(RuntimeError, match="permission denied"):
        list(with_ticks(broken(), threading.Event(), poll=0.05))


@needs_root
def test_scapy_capture_keeps_running_after_dropping_root():
    # runs in a child process: dropping privileges cannot be undone
    script = """
import os, socket, threading, time
from iotsec.capture.scapy_backend import LiveCapture
capture = LiveCapture("lo", drop_to="nobody")
capture.start()
assert os.getuid() == os.geteuid() == 65534
def send():
    time.sleep(0.5)
    for i in range(5):
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 41000 + i))
threading.Thread(target=send).start()
ports, deadline = set(), time.time() + 10
for record in capture.records(0.2):
    if record is not None and record.proto == "udp":
        ports.add(record.dport)
    if len(ports) == 5 or time.time() > deadline:
        break
capture.stop()
print(sorted(ports))
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[41000, 41001, 41002, 41003, 41004]"
