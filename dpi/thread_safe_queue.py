"""
dpi/thread_safe_queue.py
========================
Python equivalent of include/thread_safe_queue.h.

The standard queue.Queue already provides locking and blocking semantics. This
wrapper adds the shutdown behavior used by the C++ ThreadSafeQueue class.
"""

from __future__ import annotations

import queue
import threading
from typing import Generic, Optional, TypeVar


T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    def __init__(self, max_size: int = 10_000):
        self._queue: queue.Queue[T] = queue.Queue(maxsize=max_size)
        self._shutdown = False
        self._lock = threading.Lock()

    def push(self, item: T, timeout: Optional[float] = None) -> bool:
        with self._lock:
            if self._shutdown:
                return False
        try:
            self._queue.put(item, timeout=timeout)
            return True
        except queue.Full:
            return False

    def try_push(self, item: T) -> bool:
        with self._lock:
            if self._shutdown:
                return False
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            return False

    def pop(self, timeout: Optional[float] = None) -> Optional[T]:
        with self._lock:
            if self._shutdown and self._queue.empty():
                return None
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def pop_with_timeout(self, timeout_seconds: float) -> Optional[T]:
        return self.pop(timeout=timeout_seconds)

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True

    def is_shutdown(self) -> bool:
        with self._lock:
            return self._shutdown
