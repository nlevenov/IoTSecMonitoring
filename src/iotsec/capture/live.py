"""Turn a blocking packet source into one that also yields idle ticks."""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Iterable, Iterator

from ..models import PacketRecord

log = logging.getLogger(__name__)
_END = object()


def with_ticks(source: Iterable[PacketRecord], stop: threading.Event,
               poll: float = 0.5, max_queue: int = 50_000) -> Iterator[PacketRecord | None]:
    """Yield records from ``source``; yield None at least every ``poll`` seconds.

    The reader runs on a thread so windows still close when the network is
    quiet. A full queue drops packets instead of blocking the capture tool.
    """
    buffer: queue.Queue = queue.Queue(maxsize=max_queue)
    errors: list[BaseException] = []
    dropped = 0

    def reader() -> None:
        nonlocal dropped
        try:
            for record in source:
                if stop.is_set():
                    break
                try:
                    buffer.put_nowait(record)
                except queue.Full:
                    dropped += 1
        except Exception as exc:  # surfaced to the caller below
            errors.append(exc)
        finally:
            buffer.put(_END)

    thread = threading.Thread(target=reader, name="capture-reader", daemon=True)
    thread.start()
    while not stop.is_set():
        try:
            item = buffer.get(timeout=poll)
        except queue.Empty:
            yield None
            continue
        if item is _END:
            break
        yield item
    if dropped:
        log.warning("dropped %d packets because analysis fell behind", dropped)
    if errors:
        raise errors[0]
