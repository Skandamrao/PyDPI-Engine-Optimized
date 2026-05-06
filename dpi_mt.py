"""
dpi_mt.py
=========
Python conversion of src/dpi_mt.cpp.

This entry point uses the package's threaded DPI pipeline. It mirrors the C++
multi-threaded CLI while reusing the Python DPIEngine implementation.
"""

from __future__ import annotations

import argparse
import sys

from dpi.dpi_engine import DPIConfig, DPIEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-threaded Deep Packet Inspection")
    parser.add_argument("input_pcap")
    parser.add_argument("output_pcap")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    args = parser.parse_args()

    engine = DPIEngine(DPIConfig(num_load_balancers=args.lbs, fps_per_lb=args.fps))
    if not engine.initialize():
        return 1

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)

    if not engine.process_file(args.input_pcap, args.output_pcap):
        return 1

    print(f"\nOutput written to: {args.output_pcap}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
