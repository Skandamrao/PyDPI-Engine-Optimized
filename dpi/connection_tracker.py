"""
dpi/connection_tracker.py
=========================
Python port of src/connection_tracker.cpp + include/connection_tracker.h

ConnectionTracker  — per-FP table of active connections.
GlobalConnectionTable — aggregates stats across all FP trackers.
"""

from __future__ import annotations
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Callable

from .types import (
    FiveTuple, Connection, ConnectionState,
    AppType, PacketAction,
    app_type_to_string,
)


# ─────────────────────────────────────────────────────────────
# TrackerStats
# ─────────────────────────────────────────────────────────────

@dataclass
class TrackerStats:
    active_connections:      int = 0
    total_connections_seen:  int = 0
    classified_connections:  int = 0
    blocked_connections:     int = 0


# ─────────────────────────────────────────────────────────────
# ConnectionTracker
# ─────────────────────────────────────────────────────────────

class ConnectionTracker:
    """
    Per-FP connection table.
    Mirrors DPI::ConnectionTracker from connection_tracker.cpp.
    """

    def __init__(self, fp_id: int, max_connections: int = 100_000):
        self._fp_id           = fp_id
        self._max_connections = max_connections
        self._conns:  Dict[FiveTuple, Connection] = {}
        self._total_seen       = 0
        self._classified_count = 0
        self._blocked_count    = 0

    # ── Lookup / creation ─────────────────────────────────────

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        if tuple_ in self._conns:
            return self._conns[tuple_]

        if len(self._conns) >= self._max_connections:
            self._evict_oldest()

        conn = Connection(tuple=tuple_, state=ConnectionState.NEW,
                          first_seen=time.monotonic(), last_seen=time.monotonic())
        self._conns[tuple_] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        if tuple_ in self._conns:
            return self._conns[tuple_]
        # Try reverse tuple
        rev = tuple_.reverse()
        if rev in self._conns:
            return self._conns[rev]
        return None

    # ── Updates ───────────────────────────────────────────────

    def update_connection(self, conn: Connection, packet_size: int,
                          is_outbound: bool) -> None:
        if conn is None:
            return
        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out   += packet_size
        else:
            conn.packets_in  += 1
            conn.bytes_in    += packet_size

    def classify_connection(self, conn: Connection,
                            app: AppType, sni: str) -> None:
        if conn is None:
            return
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni      = sni
            conn.state    = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        if conn is None:
            return
        conn.state  = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        if tuple_ in self._conns:
            self._conns[tuple_].state = ConnectionState.CLOSED

    # ── Maintenance ───────────────────────────────────────────

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        """
        Remove stale / closed connections.
        Mirrors cleanupStale(std::chrono::seconds).
        """
        now     = time.monotonic()
        to_del  = [
            k for k, v in self._conns.items()
            if (now - v.last_seen) > timeout_seconds
            or v.state == ConnectionState.CLOSED
        ]
        for k in to_del:
            del self._conns[k]
        return len(to_del)

    def clear(self) -> None:
        self._conns.clear()

    # ── Accessors ─────────────────────────────────────────────

    def get_all_connections(self) -> List[Connection]:
        return list(self._conns.values())

    def get_active_count(self) -> int:
        return len(self._conns)

    def get_stats(self) -> TrackerStats:
        return TrackerStats(
            active_connections     = len(self._conns),
            total_connections_seen = self._total_seen,
            classified_connections = self._classified_count,
            blocked_connections    = self._blocked_count,
        )

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in self._conns.values():
            callback(conn)

    # ── Private ───────────────────────────────────────────────

    def _evict_oldest(self) -> None:
        if not self._conns:
            return
        oldest_key = min(self._conns, key=lambda k: self._conns[k].last_seen)
        del self._conns[oldest_key]


# ─────────────────────────────────────────────────────────────
# GlobalConnectionTable
# ─────────────────────────────────────────────────────────────

@dataclass
class GlobalStats:
    total_active_connections: int = 0
    total_connections_seen:   int = 0
    app_distribution:   dict = field(default_factory=dict)
    top_domains: list  = field(default_factory=list)   # [(domain, count), ...]


class GlobalConnectionTable:
    """
    Aggregates stats across all FP ConnectionTrackers.
    Mirrors DPI::GlobalConnectionTable from connection_tracker.cpp.
    """

    def __init__(self, num_fps: int):
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._lock = threading.RLock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        with self._lock:
            if fp_id < len(self._trackers):
                self._trackers[fp_id] = tracker

    def get_global_stats(self) -> GlobalStats:
        with self._lock:
            stats         = GlobalStats()
            domain_counts: dict = {}

            for tracker in self._trackers:
                if tracker is None:
                    continue

                ts = tracker.get_stats()
                stats.total_active_connections += ts.active_connections
                stats.total_connections_seen   += ts.total_connections_seen

                def _collect(conn: Connection,
                             _dc=domain_counts,
                             _ad=stats.app_distribution):
                    _ad[conn.app_type] = _ad.get(conn.app_type, 0) + 1
                    if conn.sni:
                        _dc[conn.sni] = _dc.get(conn.sni, 0) + 1

                tracker.for_each(_collect)

            # Top 20 domains
            sorted_domains = sorted(domain_counts.items(),
                                    key=lambda x: x[1], reverse=True)
            stats.top_domains = sorted_domains[:20]

        return stats

    def generate_report(self) -> str:
        stats = self.get_global_stats()

        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║               CONNECTION STATISTICS REPORT                    ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║ Active Connections:     {stats.total_active_connections:>10}                          ║",
            f"║ Total Connections Seen: {stats.total_connections_seen:>10}                          ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║                    APPLICATION BREAKDOWN                      ║",
            "╠══════════════════════════════════════════════════════════════╣",
        ]

        total = sum(stats.app_distribution.values()) or 1
        sorted_apps = sorted(stats.app_distribution.items(),
                             key=lambda x: x[1], reverse=True)
        for app, cnt in sorted_apps:
            pct = 100.0 * cnt / total
            name = app_type_to_string(app)
            lines.append(f"║ {name:<20}{cnt:>10} ({pct:5.1f}%)           ║")

        if stats.top_domains:
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║                      TOP DOMAINS                             ║",
                "╠══════════════════════════════════════════════════════════════╣",
            ]
            for domain, cnt in stats.top_domains:
                d = domain if len(domain) <= 35 else domain[:32] + "..."
                lines.append(f"║ {d:<40}{cnt:>10}           ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines) + "\n"
