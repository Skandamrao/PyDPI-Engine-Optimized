"""
dpi/fast_path.py
================
Python port of src/fast_path.cpp + include/fast_path.h

FastPathProcessor  — one FP worker thread: DPI, classification, rule-check.
FPManager          — pool of FastPathProcessor threads + reporting.
"""

from __future__ import annotations
import threading
import queue
from dataclasses import dataclass
from typing import Optional, Callable, List
from collections import defaultdict

from .types import (
    FiveTuple, Connection, ConnectionState,
    PacketAction, PacketJob, AppType,
    app_type_to_string, sni_to_app_type,
)
from .connection_tracker import ConnectionTracker
from .rule_manager import RuleManager, BlockType
from .sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor


# ─────────────────────────────────────────────────────────────
# Type alias for output callback
# ─────────────────────────────────────────────────────────────

PacketOutputCallback = Callable[[PacketJob, PacketAction], None]


# ─────────────────────────────────────────────────────────────
# FPStats
# ─────────────────────────────────────────────────────────────

@dataclass
class FPStats:
    packets_processed:   int = 0
    packets_forwarded:   int = 0
    packets_dropped:     int = 0
    connections_tracked: int = 0
    sni_extractions:     int = 0
    classification_hits: int = 0


# ─────────────────────────────────────────────────────────────
# FastPathProcessor
# ─────────────────────────────────────────────────────────────

class FastPathProcessor:
    """
    One FP worker thread that inspects payloads, tracks connections,
    and applies blocking rules.

    Mirrors DPI::FastPathProcessor from fast_path.cpp.
    """

    _SYN = 0x02
    _ACK = 0x10
    _FIN = 0x01
    _RST = 0x04

    def __init__(self, fp_id: int,
                 rule_manager: Optional[RuleManager],
                 output_callback: Optional[PacketOutputCallback] = None):
        self._fp_id           = fp_id
        self._rule_manager    = rule_manager
        self._output_callback = output_callback

        # Input queue (capacity 10 000, mirrors ThreadSafeQueue)
        self.input_queue: "queue.Queue[Optional[PacketJob]]" = queue.Queue(maxsize=10_000)

        self._conn_tracker = ConnectionTracker(fp_id)

        # Counters (thread-safe via GIL on CPython int ops)
        self._packets_processed   = 0
        self._packets_forwarded   = 0
        self._packets_dropped     = 0
        self._sni_extractions     = 0
        self._classification_hits = 0

        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                         name=f"FP-{self._fp_id}")
        self._thread.start()
        print(f"[FP{self._fp_id}] Started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        try:
            self.input_queue.put(None, timeout=1)   # shutdown sentinel
        except queue.Full:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print(f"[FP{self._fp_id}] Stopped (processed {self._packets_processed} packets)")

    # ── Worker loop ───────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            try:
                job = self.input_queue.get(timeout=0.1)
            except queue.Empty:
                # Periodic stale-connection cleanup
                self._conn_tracker.cleanup_stale(300)
                continue

            if job is None:   # shutdown sentinel
                break

            self._packets_processed += 1
            action = self._process_packet(job)

            if self._output_callback:
                self._output_callback(job, action)

            if action == PacketAction.DROP:
                self._packets_dropped += 1
            else:
                self._packets_forwarded += 1

    # ── Packet processing ─────────────────────────────────────

    def _process_packet(self, job: PacketJob) -> PacketAction:
        conn = self._conn_tracker.get_or_create_connection(job.tuple)

        # Update stats
        self._conn_tracker.update_connection(conn, len(job.data), is_outbound=True)

        # TCP state machine
        if job.tuple.protocol == 6:
            self._update_tcp_state(conn, job.tcp_flags)

        # Already blocked?
        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP

        # Payload inspection (only if not yet classified)
        if conn.state != ConnectionState.CLASSIFIED and job.payload_length > 0:
            self._inspect_payload(job, conn)

        return self._check_rules(job, conn)

    def _inspect_payload(self, job: PacketJob, conn: Connection) -> None:
        if job.payload_length == 0 or job.payload_offset >= len(job.data):
            return

        if self._try_extract_sni(job, conn):
            return
        if self._try_extract_http_host(job, conn):
            return

        payload = job.data[job.payload_offset:]

        # DNS (port 53)
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            domain = DNSExtractor.extract_query(payload)
            if domain:
                self._conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        # Port-based fallback
        if job.tuple.dst_port == 80:
            self._conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443:
            self._conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def _try_extract_sni(self, job: PacketJob, conn: Connection) -> bool:
        if job.tuple.dst_port != 443 or job.payload_length < 50:
            return False
        if job.payload_offset >= len(job.data) or job.payload_length == 0:
            return False

        payload = job.data[job.payload_offset:]
        sni = SNIExtractor.extract(payload)
        if sni:
            self._sni_extractions += 1
            app = sni_to_app_type(sni)
            self._conn_tracker.classify_connection(conn, app, sni)
            if app not in (AppType.UNKNOWN, AppType.HTTPS):
                self._classification_hits += 1
            return True
        return False

    def _try_extract_http_host(self, job: PacketJob, conn: Connection) -> bool:
        if job.tuple.dst_port != 80:
            return False
        if job.payload_offset >= len(job.data) or job.payload_length == 0:
            return False

        payload = job.data[job.payload_offset:]
        host = HTTPHostExtractor.extract(payload)
        if host:
            app = sni_to_app_type(host)
            self._conn_tracker.classify_connection(conn, app, host)
            if app not in (AppType.UNKNOWN, AppType.HTTP):
                self._classification_hits += 1
            return True
        return False

    def _check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        if not self._rule_manager:
            return PacketAction.FORWARD

        reason = self._rule_manager.should_block(
            job.tuple.src_ip, job.tuple.dst_port,
            conn.app_type, conn.sni,
        )
        if reason:
            type_name = {
                BlockType.IP:     "IP",
                BlockType.APP:    "App",
                BlockType.DOMAIN: "Domain",
                BlockType.PORT:   "Port",
            }.get(reason.type, "?")
            print(f"[FP{self._fp_id}] BLOCKED packet: {type_name} {reason.detail}")
            self._conn_tracker.block_connection(conn)
            return PacketAction.DROP

        return PacketAction.FORWARD

    def _update_tcp_state(self, conn: Connection, flags: int) -> None:
        """Mirrors updateTCPState()."""
        if flags & self._SYN:
            if flags & self._ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (flags & self._ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if flags & self._FIN:
            conn.fin_seen = True

        if flags & self._RST:
            conn.state = ConnectionState.CLOSED

        if conn.fin_seen and (flags & self._ACK):
            conn.state = ConnectionState.CLOSED

    # ── Stats & accessors ─────────────────────────────────────

    def get_stats(self) -> FPStats:
        return FPStats(
            packets_processed   = self._packets_processed,
            packets_forwarded   = self._packets_forwarded,
            packets_dropped     = self._packets_dropped,
            connections_tracked = self._conn_tracker.get_active_count(),
            sni_extractions     = self._sni_extractions,
            classification_hits = self._classification_hits,
        )

    def get_connection_tracker(self) -> ConnectionTracker:
        return self._conn_tracker


# ─────────────────────────────────────────────────────────────
# AggregatedFPStats
# ─────────────────────────────────────────────────────────────

@dataclass
class AggregatedFPStats:
    total_processed:   int = 0
    total_forwarded:   int = 0
    total_dropped:     int = 0
    total_connections: int = 0


# ─────────────────────────────────────────────────────────────
# FPManager
# ─────────────────────────────────────────────────────────────

class FPManager:
    """
    Pool of FastPathProcessor threads.
    Mirrors DPI::FPManager from fast_path.cpp.
    """

    def __init__(self, num_fps: int,
                 rule_manager: Optional[RuleManager],
                 output_callback: Optional[PacketOutputCallback] = None):
        self._fps: List[FastPathProcessor] = [
            FastPathProcessor(i, rule_manager, output_callback)
            for i in range(num_fps)
        ]
        print(f"[FPManager] Created {num_fps} fast path processors")

    def start_all(self) -> None:
        for fp in self._fps:
            fp.start()

    def stop_all(self) -> None:
        for fp in self._fps:
            fp.stop()

    def get_fp(self, index: int) -> FastPathProcessor:
        return self._fps[index]

    def get_queue_ptrs(self) -> "List[queue.Queue]":
        """Return the input queues of all FPs (for LB wiring)."""
        return [fp.input_queue for fp in self._fps]

    def get_aggregated_stats(self) -> AggregatedFPStats:
        stats = AggregatedFPStats()
        for fp in self._fps:
            s = fp.get_stats()
            stats.total_processed   += s.packets_processed
            stats.total_forwarded   += s.packets_forwarded
            stats.total_dropped     += s.packets_dropped
            stats.total_connections += s.connections_tracked
        return stats

    def generate_classification_report(self) -> str:
        app_counts: dict = defaultdict(int)
        domain_counts: dict = defaultdict(int)
        total_classified = 0
        total_unknown    = 0

        for fp in self._fps:
            def _visit(conn: Connection,
                       _ac=app_counts, _dc=domain_counts) -> None:
                nonlocal total_classified, total_unknown
                _ac[conn.app_type] += 1
                if conn.app_type == AppType.UNKNOWN:
                    total_unknown += 1
                else:
                    total_classified += 1
                if conn.sni:
                    _dc[conn.sni] += 1
            fp.get_connection_tracker().for_each(_visit)

        total = total_classified + total_unknown
        classified_pct = (100.0 * total_classified / total) if total else 0
        unknown_pct    = (100.0 * total_unknown    / total) if total else 0

        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║                 APPLICATION CLASSIFICATION REPORT             ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║ Total Connections:    {total:>10}                           ║",
            f"║ Classified:           {total_classified:>10} ({classified_pct:5.1f}%)                  ║",
            f"║ Unidentified:         {total_unknown:>10} ({unknown_pct:5.1f}%)                  ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║                    APPLICATION DISTRIBUTION                   ║",
            "╠══════════════════════════════════════════════════════════════╣",
        ]

        sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
        for app, cnt in sorted_apps:
            pct     = (100.0 * cnt / total) if total else 0
            bar     = "#" * int(pct / 5)
            name    = app_type_to_string(app)
            lines.append(
                f"║ {name:<15}{cnt:>8} {pct:5.1f}% {bar:<20}   ║"
            )

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines) + "\n"
