"""
dpi_working.py
==============
Python conversion of src/main_working.cpp.

This is a simple single-threaded DPI pipeline: read PCAP, classify flows, apply
blocking rules, write forwarded packets, and print a compact report. For the
full threaded pipeline, use dpi_main.py or dpi_mt.py.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field

from packet_analyzer import PacketParser, PcapReader, RawPacket
from dpi.sni_extractor import DNSExtractor, HTTPHostExtractor, SNIExtractor
from dpi.types import AppType, FiveTuple, app_type_to_string, sni_to_app_type


@dataclass
class Flow:
    tuple: FiveTuple = field(default_factory=FiveTuple)
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


class BlockingRules:
    def __init__(self):
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains: list[str] = []

    @staticmethod
    def parse_ip(ip: str) -> int:
        result = 0
        for shift, part in enumerate(ip.split(".")):
            result |= int(part) << (shift * 8)
        return result

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(self.parse_ip(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_name: str) -> None:
        for app in AppType:
            if app_type_to_string(app) == app_name:
                self.blocked_apps.add(app)
                print(f"[Rules] Blocked app: {app_name}")
                return
        print(f"[Rules] Unknown app: {app_name}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        sni_lower = sni.lower()
        return (
            src_ip in self.blocked_ips
            or app in self.blocked_apps
            or any(domain in sni_lower for domain in self.blocked_domains)
        )


def _write_pcap_header(out, reader: PcapReader) -> None:
    header = reader._global_header
    out.write(
        struct.pack(
            reader._endian + "IHHiIII",
            header.magic_number,
            header.version_major,
            header.version_minor,
            header.thiszone,
            header.sigfigs,
            header.snaplen,
            header.network,
        )
    )


def _write_packet(out, raw: RawPacket) -> None:
    out.write(struct.pack("<IIII", raw.header.ts_sec, raw.header.ts_usec, len(raw.data), len(raw.data)))
    out.write(raw.data)


def _payload_offset(raw: RawPacket, parsed) -> int:
    offset = 14
    if len(raw.data) <= offset:
        return len(raw.data)
    offset += (raw.data[14] & 0x0F) * 4
    if parsed.has_tcp and offset + 12 < len(raw.data):
        offset += ((raw.data[offset + 12] >> 4) & 0x0F) * 4
    elif parsed.has_udp:
        offset += 8
    return offset


def _parse_ip(ip: str) -> int:
    return BlockingRules.parse_ip(ip)


def _classify(flow: Flow, raw: RawPacket, parsed) -> None:
    offset = _payload_offset(raw, parsed)
    payload = raw.data[offset:] if offset < len(raw.data) else b""

    if parsed.has_tcp and parsed.dest_port == 443 and payload:
        sni = SNIExtractor.extract(payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            return

    if parsed.has_tcp and parsed.dest_port == 80 and payload:
        host = HTTPHostExtractor.extract(payload)
        if host:
            flow.sni = host
            flow.app_type = sni_to_app_type(host)
            return

    if parsed.dest_port == 53 or parsed.src_port == 53:
        query = DNSExtractor.extract_query(payload)
        flow.sni = query or flow.sni
        flow.app_type = AppType.DNS
        return

    if flow.app_type == AppType.UNKNOWN:
        if parsed.dest_port == 443:
            flow.app_type = AppType.HTTPS
        elif parsed.dest_port == 80:
            flow.app_type = AppType.HTTP


def main() -> int:
    parser = argparse.ArgumentParser(description="Single-threaded DPI engine")
    parser.add_argument("input_pcap")
    parser.add_argument("output_pcap")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    args = parser.parse_args()

    rules = BlockingRules()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for domain in args.block_domain:
        rules.block_domain(domain)

    reader = PcapReader()
    if not reader.open(args.input_pcap):
        return 1

    flows: dict[FiveTuple, Flow] = {}
    app_stats: Counter[AppType] = Counter()
    total_packets = forwarded = dropped = 0

    with open(args.output_pcap, "wb") as output:
        _write_pcap_header(output, reader)
        print("[DPI] Processing packets...")

        for raw in reader:
            total_packets += 1
            parsed = PacketParser.parse(raw)
            if parsed is None or not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
                continue

            tuple_ = FiveTuple(
                src_ip=_parse_ip(parsed.src_ip),
                dst_ip=_parse_ip(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )
            flow = flows.setdefault(tuple_, Flow(tuple=tuple_))
            flow.packets += 1
            flow.bytes += len(raw.data)

            if not flow.sni or flow.app_type in (AppType.UNKNOWN, AppType.HTTP, AppType.HTTPS):
                _classify(flow, raw, parsed)

            if not flow.blocked:
                flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
                if flow.blocked:
                    detail = f": {flow.sni}" if flow.sni else ""
                    print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}{detail})")

            app_stats[flow.app_type] += 1
            if flow.blocked:
                dropped += 1
            else:
                forwarded += 1
                _write_packet(output, raw)

    reader.close()

    print("\nProcessing report")
    print(f"  Total packets: {total_packets}")
    print(f"  Forwarded:     {forwarded}")
    print(f"  Dropped:       {dropped}")
    print(f"  Active flows:  {len(flows)}")
    print("\nApplication breakdown")
    for app, count in app_stats.most_common():
        pct = (100.0 * count / total_packets) if total_packets else 0.0
        print(f"  {app_type_to_string(app):<15} {count:>8} {pct:5.1f}%")

    detected = {flow.sni: flow.app_type for flow in flows.values() if flow.sni}
    if detected:
        print("\nDetected applications/domains")
        for sni, app in detected.items():
            print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {args.output_pcap}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
