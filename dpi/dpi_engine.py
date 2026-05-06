"""
dpi/dpi_engine.py
=================
Python port of src/dpi_engine.cpp + include/dpi_engine.h

DPIEngine — top-level orchestrator that wires together:
  PcapReader → LBManager → FPManager → output writer
"""

from __future__ import annotations
import queue
import struct
import threading
import time
import sys

# Force UTF-8 output on Windows so box-drawing characters don't crash
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from dataclasses import dataclass, field
from typing import Optional

# Packet-analyzer layer (already converted)
from packet_analyzer import PcapReader, PacketParser, RawPacket

# DPI layer
from .types import (
    FiveTuple, PacketJob, PacketAction,
    AppType, app_type_to_string,
)
from .rule_manager import RuleManager
from .connection_tracker import GlobalConnectionTable
from .load_balancer import LBManager
from .fast_path import FPManager


# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

@dataclass
class DPIConfig:
    num_load_balancers: int  = 2
    fps_per_lb:         int  = 2
    rules_file:         str  = ""
    verbose:            bool = False


# ─────────────────────────────────────────────────────────────
# DPIStats  (mirrors struct DPIStats — atomic counters replaced with ints + lock)
# ─────────────────────────────────────────────────────────────

class DPIStats:
    def __init__(self):
        self._lock             = threading.Lock()
        self.total_packets     = 0
        self.total_bytes       = 0
        self.tcp_packets       = 0
        self.udp_packets       = 0
        self.forwarded_packets = 0
        self.dropped_packets   = 0

    def add_packet(self, size: int, is_tcp: bool, is_udp: bool) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes   += size
            if is_tcp:
                self.tcp_packets += 1
            elif is_udp:
                self.udp_packets += 1

    def add_forwarded(self) -> None:
        with self._lock:
            self.forwarded_packets += 1

    def add_dropped(self) -> None:
        with self._lock:
            self.dropped_packets += 1

    # Snapshot (thread-safe read)
    def snapshot(self) -> dict:
        with self._lock:
            return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


# ─────────────────────────────────────────────────────────────
# DPIEngine
# ─────────────────────────────────────────────────────────────

class DPIEngine:
    """
    Top-level DPI orchestrator.
    Mirrors DPI::DPIEngine from dpi_engine.cpp.
    """

    def __init__(self, config: DPIConfig):
        self._config = config
        self._stats  = DPIStats()

        # Internal state
        self._running             = False
        self._processing_complete = False

        # Output queue (forwarded packets waiting to be written)
        self._output_queue: "queue.Queue[Optional[PacketJob]]" = queue.Queue(maxsize=10_000)
        self._output_thread: Optional[threading.Thread] = None
        self._output_file = None
        self._output_lock = threading.Lock()

        # Sub-components (created in initialize())
        self._rule_manager:    Optional[RuleManager]          = None
        self._fp_manager:      Optional[FPManager]            = None
        self._lb_manager:      Optional[LBManager]            = None
        self._global_conn_tbl: Optional[GlobalConnectionTable] = None

        self._print_banner()

    # ── Banner ────────────────────────────────────────────────

    def _print_banner(self) -> None:
        c = self._config
        total_fps = c.num_load_balancers * c.fps_per_lb
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0                            ║")
        print("║               Deep Packet Inspection System                   ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ Configuration:                                                ║")
        print(f"║   Load Balancers:    {c.num_load_balancers:>3}                                       ║")
        print(f"║   FPs per LB:        {c.fps_per_lb:>3}                                       ║")
        print(f"║   Total FP threads:  {total_fps:>3}                                       ║")
        print("╚══════════════════════════════════════════════════════════════╝")

    # ── Initialization ────────────────────────────────────────

    def initialize(self) -> bool:
        """Wire up RuleManager → FPManager → LBManager (mirrors initialize())."""
        if self._config.num_load_balancers <= 0 or self._config.fps_per_lb <= 0:
            print("[DPIEngine] Error: --lbs and --fps must be greater than zero", file=sys.stderr)
            return False

        self._rule_manager = RuleManager()

        if self._config.rules_file:
            self._rule_manager.load_rules(self._config.rules_file)

        # Output callback: called by each FP when a packet is decided
        def output_cb(job: PacketJob, action: PacketAction) -> None:
            self._handle_output(job, action)

        total_fps = self._config.num_load_balancers * self._config.fps_per_lb

        # FP processors (each owns its own input queue)
        self._fp_manager = FPManager(total_fps, self._rule_manager, output_cb)

        # LB threads (wired to FP queues)
        self._lb_manager = LBManager(
            self._config.num_load_balancers,
            self._config.fps_per_lb,
            self._fp_manager.get_queue_ptrs(),
        )

        # Global connection table
        self._global_conn_tbl = GlobalConnectionTable(total_fps)
        for i in range(total_fps):
            self._global_conn_tbl.register_tracker(
                i, self._fp_manager.get_fp(i).get_connection_tracker()
            )

        print("[DPIEngine] Initialized successfully")
        return True

    # ── Start / Stop ──────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running             = True
        self._processing_complete = False

        # Output writer thread
        self._output_thread = threading.Thread(
            target=self._output_thread_func, daemon=True, name="OutputWriter"
        )
        self._output_thread.start()

        self._fp_manager.start_all()
        self._lb_manager.start_all()

        print("[DPIEngine] All threads started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        self._lb_manager.stop_all()
        self._fp_manager.stop_all()

        # Drain and stop output thread
        try:
            self._output_queue.put(None, timeout=2)
        except queue.Full:
            pass
        if self._output_thread and self._output_thread.is_alive():
            self._output_thread.join(timeout=5)

        print("[DPIEngine] All threads stopped")

    # ── File processing ───────────────────────────────────────

    def process_file(self, input_file: str, output_file: str) -> bool:
        """
        Read input_file, run DPI pipeline, write forwarded packets to output_file.
        Mirrors processFile().
        """
        print(f"\n[DPIEngine] Processing: {input_file}")
        print(f"[DPIEngine] Output to:  {output_file}\n")

        if not self._rule_manager:
            if not self.initialize():
                return False

        # Open output file
        try:
            self._output_file = open(output_file, "wb")
        except OSError as exc:
            print(f"[DPIEngine] Error: Cannot open output file: {exc}", file=sys.stderr)
            return False

        self.start()

        # Reader thread
        reader_thread = threading.Thread(
            target=self._reader_thread_func, args=(input_file,),
            daemon=True, name="PcapReader"
        )
        reader_thread.start()
        reader_thread.join()

        # Let queues drain
        time.sleep(0.5)
        self._processing_complete = True
        time.sleep(0.2)

        self.stop()

        if self._output_file:
            self._output_file.close()
            self._output_file = None

        # Final reports
        print(self.generate_report())
        if self._fp_manager:
            print(self._fp_manager.generate_classification_report())

        return True

    # ── Reader thread ─────────────────────────────────────────

    def _reader_thread_func(self, input_file: str) -> None:
        reader = PcapReader()
        if not reader.open(input_file):
            print("[Reader] Error: Cannot open input file", file=sys.stderr)
            return

        # Write PCAP global header to output
        self._write_output_header(reader._global_header, reader._endian)

        packet_id = 0
        print("[Reader] Starting packet processing...")

        for raw in reader:
            parsed = PacketParser.parse(raw)
            if parsed is None:
                continue

            # Only process IP packets with TCP/UDP
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            job = self._create_packet_job(raw, parsed, packet_id)
            packet_id += 1

            self._stats.add_packet(
                len(raw.data),
                is_tcp=parsed.has_tcp,
                is_udp=parsed.has_udp,
            )

            # Send to appropriate LB
            lb = self._lb_manager.get_lb_for_packet(job.tuple)
            try:
                lb.input_queue.put(job, timeout=1)
            except queue.Full:
                pass

        print(f"[Reader] Finished reading {packet_id} packets")
        reader.close()

    # ── Packet job builder ────────────────────────────────────

    @staticmethod
    def _parse_ip_str(ip_str: str) -> int:
        """Convert dotted-decimal to uint32 (little-endian, matching C++ impl)."""
        parts = ip_str.split(".")
        result = 0
        for i, p in enumerate(parts):
            result |= (int(p) << (i * 8))
        return result

    def _create_packet_job(self, raw: RawPacket, parsed, packet_id: int) -> PacketJob:
        """Mirrors createPacketJob()."""
        job = PacketJob()
        job.packet_id = packet_id
        job.ts_sec    = raw.header.ts_sec
        job.ts_usec   = raw.header.ts_usec
        job.tcp_flags = parsed.tcp_flags
        job.data      = raw.data

        job.tuple = FiveTuple(
            src_ip   = self._parse_ip_str(parsed.src_ip),
            dst_ip   = self._parse_ip_str(parsed.dest_ip),
            src_port = parsed.src_port,
            dst_port = parsed.dest_port,
            protocol = parsed.protocol,
        )

        job.eth_offset = 0
        job.ip_offset  = 14

        if len(raw.data) > 14:
            ip_ihl        = raw.data[14] & 0x0F
            ip_header_len = ip_ihl * 4
            job.transport_offset = 14 + ip_header_len

            if parsed.has_tcp and len(raw.data) > job.transport_offset:
                tcp_data_offset = (raw.data[job.transport_offset + 12] >> 4) & 0x0F
                job.payload_offset = job.transport_offset + tcp_data_offset * 4
            elif parsed.has_udp:
                job.payload_offset = job.transport_offset + 8

            if job.payload_offset < len(raw.data):
                job.payload_length = len(raw.data) - job.payload_offset

        return job

    # ── Output handling ───────────────────────────────────────

    def _handle_output(self, job: PacketJob, action: PacketAction) -> None:
        if action == PacketAction.DROP:
            self._stats.add_dropped()
            return
        self._stats.add_forwarded()
        try:
            self._output_queue.put(job, timeout=1)
        except queue.Full:
            pass

    def _output_thread_func(self) -> None:
        """Drain output_queue and write packets to file."""
        while self._running or not self._output_queue.empty():
            try:
                job = self._output_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if job is None:
                break
            self._write_output_packet(job)

    def _write_output_header(self, global_header, endian: str) -> None:
        """Write PCAP global header to output file (mirrors writeOutputHeader())."""
        with self._output_lock:
            if not self._output_file:
                return
            fmt  = endian + "IHHiIII"
            data = struct.pack(
                fmt,
                global_header.magic_number,
                global_header.version_major,
                global_header.version_minor,
                global_header.thiszone,
                global_header.sigfigs,
                global_header.snaplen,
                global_header.network,
            )
            self._output_file.write(data)

    def _write_output_packet(self, job: PacketJob) -> None:
        """Write one packet record to output file (mirrors writeOutputPacket())."""
        with self._output_lock:
            if not self._output_file:
                return
            hdr = struct.pack(
                "<IIII",
                job.ts_sec,
                job.ts_usec,
                len(job.data),
                len(job.data),
            )
            self._output_file.write(hdr)
            self._output_file.write(job.data)

    # ── Rule management API ───────────────────────────────────

    def block_ip(self, ip: str) -> None:
        if self._rule_manager:
            self._rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        if self._rule_manager:
            self._rule_manager.unblock_ip(ip)

    def block_app(self, app) -> None:
        """Accept AppType enum or string name."""
        if not self._rule_manager:
            return
        if isinstance(app, str):
            for a in AppType:
                if app_type_to_string(a) == app:
                    self._rule_manager.block_app(a)
                    return
            print(f"[DPIEngine] Unknown app: {app}", file=sys.stderr)
        else:
            self._rule_manager.block_app(app)

    def unblock_app(self, app) -> None:
        if not self._rule_manager:
            return
        if isinstance(app, str):
            for a in AppType:
                if app_type_to_string(a) == app:
                    self._rule_manager.unblock_app(a)
                    return
        else:
            self._rule_manager.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        if self._rule_manager:
            self._rule_manager.block_domain(domain)

    def unblock_domain(self, domain: str) -> None:
        if self._rule_manager:
            self._rule_manager.unblock_domain(domain)

    def load_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.load_rules(filename)
        return False

    def save_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.save_rules(filename)
        return False

    # ── Reporting ─────────────────────────────────────────────

    def generate_report(self) -> str:
        snap = self._stats.snapshot()

        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║                    DPI ENGINE STATISTICS                      ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║ PACKET STATISTICS                                             ║",
            f"║   Total Packets:      {snap['total_packets']:>12}                        ║",
            f"║   Total Bytes:        {snap['total_bytes']:>12}                        ║",
            f"║   TCP Packets:        {snap['tcp_packets']:>12}                        ║",
            f"║   UDP Packets:        {snap['udp_packets']:>12}                        ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║ FILTERING STATISTICS                                          ║",
            f"║   Forwarded:          {snap['forwarded_packets']:>12}                        ║",
            f"║   Dropped/Blocked:    {snap['dropped_packets']:>12}                        ║",
        ]

        if snap["total_packets"] > 0:
            drop_rate = 100.0 * snap["dropped_packets"] / snap["total_packets"]
            lines.append(
                f"║   Drop Rate:          {drop_rate:>11.2f}%                        ║"
            )

        if self._lb_manager:
            lb_stats = self._lb_manager.get_aggregated_stats()
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║ LOAD BALANCER STATISTICS                                      ║",
                f"║   LB Received:        {lb_stats.total_received:>12}                        ║",
                f"║   LB Dispatched:      {lb_stats.total_dispatched:>12}                        ║",
            ]

        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║ FAST PATH STATISTICS                                          ║",
                f"║   FP Processed:       {fp_stats.total_processed:>12}                        ║",
                f"║   FP Forwarded:       {fp_stats.total_forwarded:>12}                        ║",
                f"║   FP Dropped:         {fp_stats.total_dropped:>12}                        ║",
                f"║   Active Connections: {fp_stats.total_connections:>12}                        ║",
            ]

        if self._rule_manager:
            rs = self._rule_manager.get_stats()
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║ BLOCKING RULES                                                ║",
                f"║   Blocked IPs:        {rs.blocked_ips:>12}                        ║",
                f"║   Blocked Apps:       {rs.blocked_apps:>12}                        ║",
                f"║   Blocked Domains:    {rs.blocked_domains:>12}                        ║",
                f"║   Blocked Ports:      {rs.blocked_ports:>12}                        ║",
            ]

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines) + "\n"

    def print_status(self) -> None:
        snap = self._stats.snapshot()
        print(
            f"\n--- Live Status ---\n"
            f"Packets: {snap['total_packets']} | "
            f"Forwarded: {snap['forwarded_packets']} | "
            f"Dropped: {snap['dropped_packets']}"
        )
        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            print(f"Connections: {fp_stats.total_connections}")

    def get_stats(self) -> DPIStats:
        return self._stats
