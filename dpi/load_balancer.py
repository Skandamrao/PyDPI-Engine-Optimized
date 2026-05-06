"""
dpi/load_balancer.py
====================
Python port of src/load_balancer.cpp + include/load_balancer.h

LoadBalancer  — one thread that distributes packets to FP queues using
                5-tuple hashing.
LBManager     — manages a pool of LoadBalancer threads.
"""

from __future__ import annotations
import threading
import queue
from dataclasses import dataclass, field
from typing import List, Optional

from .types import FiveTuple, PacketJob


# ─────────────────────────────────────────────────────────────
# LBStats
# ─────────────────────────────────────────────────────────────

@dataclass
class LBStats:
    packets_received:  int = 0
    packets_dispatched: int = 0
    per_fp_packets:    List[int] = field(default_factory=list)


@dataclass
class AggregatedLBStats:
    total_received:   int = 0
    total_dispatched: int = 0


# ─────────────────────────────────────────────────────────────
# LoadBalancer
# ─────────────────────────────────────────────────────────────

class LoadBalancer:
    """
    Single load-balancer thread that hashes the 5-tuple and forwards
    each PacketJob to the appropriate FP queue.

    Mirrors DPI::LoadBalancer from load_balancer.cpp.
    """

    def __init__(self, lb_id: int,
                 fp_queues: List["queue.Queue[Optional[PacketJob]]"],
                 fp_start_id: int = 0):
        self._lb_id       = lb_id
        self._fp_start_id = fp_start_id
        self._num_fps     = len(fp_queues)
        self._fp_queues   = fp_queues

        # Input queue (replaces ThreadSafeQueue<PacketJob> with capacity 10000)
        self.input_queue: queue.Queue[Optional[PacketJob]] = queue.Queue(maxsize=10_000)

        self._per_fp_counts = [0] * self._num_fps
        self._packets_received   = 0
        self._packets_dispatched = 0

        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                         name=f"LB-{self._lb_id}")
        self._thread.start()
        fp_end = self._fp_start_id + self._num_fps - 1
        print(f"[LB{self._lb_id}] Started (serving FP{self._fp_start_id}-FP{fp_end})")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        try:
            self.input_queue.put(None, timeout=1)  # sentinel to unblock
        except queue.Full:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print(f"[LB{self._lb_id}] Stopped")

    # ── Worker loop ───────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            try:
                job = self.input_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if job is None:   # shutdown sentinel
                break

            self._packets_received += 1
            fp_index = self._select_fp(job.tuple)

            try:
                self._fp_queues[fp_index].put(job, timeout=1)
                self._packets_dispatched += 1
                self._per_fp_counts[fp_index] += 1
            except queue.Full:
                pass  # drop on back-pressure

    # ── Selection ─────────────────────────────────────────────

    def _select_fp(self, tuple_: FiveTuple) -> int:
        """Hash the 5-tuple and pick an FP index."""
        return hash(tuple_) % self._num_fps

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> LBStats:
        return LBStats(
            packets_received   = self._packets_received,
            packets_dispatched = self._packets_dispatched,
            per_fp_packets     = list(self._per_fp_counts),
        )


# ─────────────────────────────────────────────────────────────
# LBManager
# ─────────────────────────────────────────────────────────────

class LBManager:
    """
    Manages a pool of LoadBalancer threads.
    Mirrors DPI::LBManager from load_balancer.cpp.
    """

    def __init__(self, num_lbs: int, fps_per_lb: int,
                 fp_queues: "List[queue.Queue[Optional[PacketJob]]]"):
        if num_lbs <= 0:
            raise ValueError("num_lbs must be greater than zero")
        if fps_per_lb <= 0:
            raise ValueError("fps_per_lb must be greater than zero")
        if len(fp_queues) < num_lbs * fps_per_lb:
            raise ValueError("not enough FP queues for the requested LB layout")

        self._fps_per_lb = fps_per_lb
        self._lbs: List[LoadBalancer] = []

        for lb_id in range(num_lbs):
            fp_start = lb_id * fps_per_lb
            lb_fp_queues = fp_queues[fp_start: fp_start + fps_per_lb]
            self._lbs.append(LoadBalancer(lb_id, lb_fp_queues, fp_start))

        print(f"[LBManager] Created {num_lbs} load balancers, {fps_per_lb} FPs each")

    def start_all(self) -> None:
        for lb in self._lbs:
            lb.start()

    def stop_all(self) -> None:
        for lb in self._lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_: FiveTuple) -> LoadBalancer:
        """Select LB using 5-tuple hash (mirrors getLBForPacket())."""
        lb_index = hash(tuple_) % len(self._lbs)
        return self._lbs[lb_index]

    def get_aggregated_stats(self) -> AggregatedLBStats:
        stats = AggregatedLBStats()
        for lb in self._lbs:
            s = lb.get_stats()
            stats.total_received   += s.packets_received
            stats.total_dispatched += s.packets_dispatched
        return stats
