"""
simple_sni.py
=============
Python conversion of src/main_simple.cpp.

Reads a PCAP file, prints each IP flow, and attempts SNI extraction for HTTPS
packets. This is a small diagnostic script, separate from the full DPI engine.
"""

from __future__ import annotations

import argparse
import sys

from packet_analyzer import PacketParser, PcapReader
from dpi.sni_extractor import SNIExtractor


def _tcp_payload_offset(data: bytes) -> int:
    offset = 14
    if len(data) <= offset:
        return len(data)
    ip_header_len = (data[offset] & 0x0F) * 4
    offset += ip_header_len
    if len(data) <= offset + 12:
        return len(data)
    tcp_header_len = ((data[offset + 12] >> 4) & 0x0F) * 4
    return offset + tcp_header_len


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple SNI extractor demo")
    parser.add_argument("pcap_file", help="Input .pcap file")
    args = parser.parse_args()

    reader = PcapReader()
    if not reader.open(args.pcap_file):
        return 1

    packet_count = 0
    tls_count = 0
    print("Processing packets...")

    for raw in reader:
        packet_count += 1
        parsed = PacketParser.parse(raw)
        if parsed is None or not parsed.has_ip:
            continue

        print(
            f"Packet {packet_count}: "
            f"{parsed.src_ip}:{parsed.src_port} -> "
            f"{parsed.dest_ip}:{parsed.dest_port}",
            end="",
        )

        if parsed.has_tcp and parsed.dest_port == 443 and parsed.payload_length > 0:
            payload_offset = _tcp_payload_offset(raw.data)
            if payload_offset < len(raw.data):
                sni = SNIExtractor.extract(raw.data[payload_offset:])
                if sni:
                    print(f" [SNI: {sni}]", end="")
                    tls_count += 1

        print()

    reader.close()
    print(f"\nTotal packets: {packet_count}")
    print(f"SNI extracted: {tls_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
