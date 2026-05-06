"""
dpi_main.py
===========
Python port of src/main_dpi.cpp

CLI entry point for the full DPI pipeline.

Usage:
    python dpi_main.py <input.pcap> <output.pcap> [options]

Options:
    --block-ip   <ip>      Block packets from source IP
    --block-app  <app>     Block application (e.g. YouTube, Facebook)
    --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
    --rules <file>         Load blocking rules from file
    --lbs <n>              Number of load-balancer threads (default: 2)
    --fps <n>              FP threads per LB (default: 2)
    --verbose              Enable verbose output

Examples:
    python dpi_main.py capture.pcap filtered.pcap
    python dpi_main.py capture.pcap filtered.pcap --block-app YouTube
    python dpi_main.py capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
    python dpi_main.py capture.pcap filtered.pcap --rules blocking_rules.txt
"""

import sys
import argparse

from dpi.dpi_engine import DPIEngine, DPIConfig
from dpi.types import app_type_to_string, AppType


# ─────────────────────────────────────────────────────────────
# Usage banner  (mirrors printUsage() in main_dpi.cpp)
# ─────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  LB threads distribute to FPs
  │   LB0 │ LB1   │
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub
"""


def print_usage() -> None:
    print(BANNER)


# ─────────────────────────────────────────────────────────────
# main()  (mirrors main() in main_dpi.cpp)
# ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dpi_main.py",
        description="Deep Packet Inspection Engine v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
        add_help=False,
    )

    # Positional
    parser.add_argument("input_pcap",  nargs="?", help="Input .pcap file")
    parser.add_argument("output_pcap", nargs="?", help="Output .pcap file")

    # Optional
    parser.add_argument("--block-ip",     action="append", default=[], metavar="IP",
                        help="Block source IP address")
    parser.add_argument("--block-app",    action="append", default=[], metavar="APP",
                        help="Block application (e.g. YouTube, Facebook)")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN",
                        help="Block domain (supports *.example.com wildcards)")
    parser.add_argument("--rules",        default="", metavar="FILE",
                        help="Load blocking rules from file")
    parser.add_argument("--lbs",          type=int, default=2, metavar="N",
                        help="Number of load-balancer threads (default: 2)")
    parser.add_argument("--fps",          type=int, default=2, metavar="N",
                        help="FP threads per LB (default: 2)")
    parser.add_argument("--verbose",      action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--help", "-h",   action="store_true",
                        help="Show this help message")

    args, _ = parser.parse_known_args()

    if args.help or not args.input_pcap or not args.output_pcap:
        print_usage()
        parser.print_help()
        return 0 if args.help else 1

    # ── Build config ──────────────────────────────────────────
    config = DPIConfig(
        num_load_balancers = args.lbs,
        fps_per_lb         = args.fps,
        rules_file         = args.rules,
        verbose            = args.verbose,
    )

    # ── Create engine ─────────────────────────────────────────
    engine = DPIEngine(config)

    if not engine.initialize():
        print("Failed to initialize DPI engine", file=sys.stderr)
        return 1

    # ── Load file-based rules ─────────────────────────────────
    if args.rules:
        engine.load_rules(args.rules)

    # ── Apply CLI blocking rules ──────────────────────────────
    for ip in args.block_ip:
        engine.block_ip(ip)

    for app in args.block_app:
        engine.block_app(app)

    for domain in args.block_domain:
        engine.block_domain(domain)

    # ── Process ───────────────────────────────────────────────
    if not engine.process_file(args.input_pcap, args.output_pcap):
        print("Failed to process file", file=sys.stderr)
        return 1

    print("\nProcessing complete!")
    print(f"Output written to: {args.output_pcap}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
