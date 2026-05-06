"""
packet_analyzer.py  (Optimized v2.0)
=====================================
Pure-Python PCAP reader and packet parser.

Optimizations applied:
  - Pre-compiled struct.Struct objects (avoid re-parsing format strings per call)
  - __slots__ on all hot dataclasses (lower memory, faster attribute access)
  - Protocol/flag lookups via pre-built dicts (O(1) vs if/elif chains)
  - Payload hex preview uses bytes.hex() (C-speed vs Python loop)
  - MAC formatting uses bytes.hex() with separator (no loop)
  - Single-pass struct unpack for TCP (2H + 2I in one call)
  - context-manager support on PcapReader
"""

from __future__ import annotations

import struct
import sys
import argparse
from datetime import datetime
from typing import Optional

# ── Force UTF-8 output on Windows ────────────────────────────
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP  = 0x0806

class Protocol:
    ICMP = 1
    TCP  = 6
    UDP  = 17

class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

PCAP_MAGIC_NATIVE  = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

# ── Pre-compiled struct objects (avoids format-string parsing on every call) ──
_S_GLOBAL_HDR_LE = struct.Struct("<IHHiIII")   # 24 bytes
_S_GLOBAL_HDR_BE = struct.Struct(">IHHiIII")
_S_PKT_HDR_LE    = struct.Struct("<IIII")       # 16 bytes
_S_PKT_HDR_BE    = struct.Struct(">IIII")
_S_U16_BE        = struct.Struct(">H")
_S_U32_BE        = struct.Struct(">I")
_S_TCP_PORTS     = struct.Struct(">HH")         # src_port + dst_port
_S_TCP_SEQ_ACK   = struct.Struct(">II")         # seq + ack

# ── Pre-built lookup tables ────────────────────────────────────
_ETYPE_NAMES = {EtherType.IPv4: " (IPv4)", EtherType.IPv6: " (IPv6)", EtherType.ARP: " (ARP)"}
_PROTO_NAMES = {Protocol.ICMP: "ICMP", Protocol.TCP: "TCP", Protocol.UDP: "UDP"}
_FLAG_BITS   = [(TCPFlags.SYN,"SYN"),(TCPFlags.ACK,"ACK"),(TCPFlags.FIN,"FIN"),
                (TCPFlags.RST,"RST"),(TCPFlags.PSH,"PSH"),(TCPFlags.URG,"URG")]


# ─────────────────────────────────────────────────────────────
# Lightweight data containers  (__slots__ = less memory + faster access)
# ─────────────────────────────────────────────────────────────

class PcapGlobalHeader:
    __slots__ = ("magic_number","version_major","version_minor",
                 "thiszone","sigfigs","snaplen","network")
    def __init__(self):
        self.magic_number = self.version_major = self.version_minor = 0
        self.thiszone = self.sigfigs = self.snaplen = self.network = 0


class PcapPacketHeader:
    __slots__ = ("ts_sec","ts_usec","incl_len","orig_len")
    def __init__(self, ts_sec=0, ts_usec=0, incl_len=0, orig_len=0):
        self.ts_sec   = ts_sec
        self.ts_usec  = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len


class RawPacket:
    __slots__ = ("header","data")
    def __init__(self, header: PcapPacketHeader, data: bytes):
        self.header = header
        self.data   = data


class ParsedPacket:
    __slots__ = (
        "timestamp_sec","timestamp_usec",
        "src_mac","dest_mac","ether_type",
        "has_ip","ip_version","src_ip","dest_ip","protocol","ttl",
        "has_tcp","src_port","dest_port","seq_number","ack_number","tcp_flags",
        "has_udp",
        "payload_length","payload_data",
    )
    def __init__(self):
        self.timestamp_sec = self.timestamp_usec = 0
        self.src_mac = self.dest_mac = ""
        self.ether_type = 0
        self.has_ip = False
        self.ip_version = 0
        self.src_ip = self.dest_ip = ""
        self.protocol = self.ttl = 0
        self.has_tcp = False
        self.src_port = self.dest_port = 0
        self.seq_number = self.ack_number = self.tcp_flags = 0
        self.has_udp = False
        self.payload_length = 0
        self.payload_data: bytes = b""


# ─────────────────────────────────────────────────────────────
# PcapReader
# ─────────────────────────────────────────────────────────────

class PcapReader:
    """Reads packets from a .pcap file — pure Python, no libpcap needed."""

    __slots__ = ("_file","_needs_swap","_global_header","_endian",
                 "_pkt_hdr_struct")

    def __init__(self):
        self._file          = None
        self._needs_swap    = False
        self._global_header = PcapGlobalHeader()
        self._endian        = "<"
        self._pkt_hdr_struct = _S_PKT_HDR_LE   # updated after open()

    def open(self, filename: str) -> bool:
        self.close()
        try:
            self._file = open(filename, "rb")
        except OSError as exc:
            print(f"Error: Could not open file: {filename} ({exc})", file=sys.stderr)
            return False

        raw = self._file.read(24)
        if len(raw) < 24:
            print("Error: Could not read PCAP global header", file=sys.stderr)
            self.close()
            return False

        # Detect endianness from magic number
        magic = struct.unpack_from("<I", raw, 0)[0]
        if magic == PCAP_MAGIC_NATIVE:
            self._endian, self._pkt_hdr_struct = "<", _S_PKT_HDR_LE
            hdr_struct = _S_GLOBAL_HDR_LE
        elif magic == PCAP_MAGIC_SWAPPED:
            self._endian, self._pkt_hdr_struct = ">", _S_PKT_HDR_BE
            hdr_struct = _S_GLOBAL_HDR_BE
        else:
            magic_be = struct.unpack_from(">I", raw, 0)[0]
            if magic_be == PCAP_MAGIC_NATIVE:
                self._endian, self._pkt_hdr_struct = ">", _S_PKT_HDR_BE
                hdr_struct = _S_GLOBAL_HDR_BE
            else:
                print(f"Error: Invalid PCAP magic number: 0x{magic:08X}", file=sys.stderr)
                self.close()
                return False

        fields = hdr_struct.unpack(raw)
        h = self._global_header
        (h.magic_number, h.version_major, h.version_minor,
         h.thiszone, h.sigfigs, h.snaplen, h.network) = fields

        link = " (Ethernet)" if h.network == 1 else ""
        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {h.version_major}.{h.version_minor}")
        print(f"  Snaplen: {h.snaplen} bytes")
        print(f"  Link type: {h.network}{link}")
        return True

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def read_next_packet(self) -> Optional[RawPacket]:
        if not self._file:
            return None
        raw_hdr = self._file.read(16)
        if len(raw_hdr) < 16:
            return None

        ts_sec, ts_usec, incl_len, orig_len = self._pkt_hdr_struct.unpack(raw_hdr)

        if incl_len > self._global_header.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}", file=sys.stderr)
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data", file=sys.stderr)
            return None

        return RawPacket(PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len), data)

    def __iter__(self):
        pkt = self.read_next_packet()
        while pkt is not None:
            yield pkt
            pkt = self.read_next_packet()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ─────────────────────────────────────────────────────────────
# PacketParser
# ─────────────────────────────────────────────────────────────

class PacketParser:
    """Stateless parser — call PacketParser.parse(raw) → ParsedPacket | None."""

    ETH_HEADER_LEN     = 14
    MIN_IP_HEADER_LEN  = 20
    MIN_TCP_HEADER_LEN = 20
    UDP_HEADER_LEN     = 8

    @classmethod
    def parse(cls, raw: RawPacket) -> Optional[ParsedPacket]:
        parsed = ParsedPacket()
        parsed.timestamp_sec  = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data   = raw.data
        length = len(data)

        # Ethernet
        offset = cls._parse_ethernet(data, length, parsed)
        if offset is None:
            return None

        # IPv4
        if parsed.ether_type == EtherType.IPv4:
            offset = cls._parse_ipv4(data, length, parsed, offset)
            if offset is None:
                return None
            if parsed.protocol == Protocol.TCP:
                offset = cls._parse_tcp(data, length, parsed, offset)
                if offset is None:
                    return None
            elif parsed.protocol == Protocol.UDP:
                offset = cls._parse_udp(data, length, parsed, offset)
                if offset is None:
                    return None

        parsed.payload_length = length - offset if offset < length else 0
        parsed.payload_data   = data[offset:] if offset < length else b""
        return parsed

    # ── Layer parsers ─────────────────────────────────────────

    @staticmethod
    def _parse_ethernet(data: bytes, length: int,
                        parsed: ParsedPacket) -> Optional[int]:
        if length < 14:
            return None
        # MAC formatting via bytes.hex() — pure C-speed, no Python loop
        parsed.dest_mac   = data[0:6].hex(":")
        parsed.src_mac    = data[6:12].hex(":")
        parsed.ether_type = _S_U16_BE.unpack_from(data, 12)[0]
        return 14

    @staticmethod
    def _parse_ipv4(data: bytes, length: int,
                    parsed: ParsedPacket, offset: int) -> Optional[int]:
        if length < offset + 20:
            return None
        b0 = data[offset]
        if (b0 >> 4) != 4:
            return None
        ihl = (b0 & 0x0F) * 4
        if ihl < 20 or length < offset + ihl:
            return None
        parsed.ip_version = 4
        parsed.ttl        = data[offset + 8]
        parsed.protocol   = data[offset + 9]
        # Unpack both IPs in one call
        src_raw, dst_raw  = _S_TCP_SEQ_ACK.unpack_from(data, offset + 12)
        parsed.src_ip     = _ip4(src_raw)
        parsed.dest_ip    = _ip4(dst_raw)
        parsed.has_ip     = True
        return offset + ihl

    @staticmethod
    def _parse_tcp(data: bytes, length: int,
                   parsed: ParsedPacket, offset: int) -> Optional[int]:
        if length < offset + 20:
            return None
        # Unpack ports + seq + ack in two calls (avoids repeated format parsing)
        sp, dp = _S_TCP_PORTS.unpack_from(data, offset)
        sq, ak = _S_TCP_SEQ_ACK.unpack_from(data, offset + 4)
        do     = (data[offset + 12] >> 4) * 4
        if do < 20 or length < offset + do:
            return None
        parsed.src_port   = sp
        parsed.dest_port  = dp
        parsed.seq_number = sq
        parsed.ack_number = ak
        parsed.tcp_flags  = data[offset + 13]
        parsed.has_tcp    = True
        return offset + do

    @staticmethod
    def _parse_udp(data: bytes, length: int,
                   parsed: ParsedPacket, offset: int) -> Optional[int]:
        if length < offset + 8:
            return None
        parsed.src_port, parsed.dest_port = _S_TCP_PORTS.unpack_from(data, offset)
        parsed.has_udp = True
        return offset + 8

    # ── Formatting helpers ────────────────────────────────────

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        return _PROTO_NAMES.get(protocol, f"Unknown({protocol})")

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = [name for bit, name in _FLAG_BITS if flags & bit]
        return " ".join(parts) if parts else "none"


# ── Fast IP formatter (module-level, shared with dpi_engine) ──
def _ip4(ip: int) -> str:
    return f"{(ip>>24)&0xFF}.{(ip>>16)&0xFF}.{(ip>>8)&0xFF}.{ip&0xFF}"


# ─────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────

def print_packet_summary(pkt: ParsedPacket, packet_num: int) -> None:
    ts = datetime.fromtimestamp(pkt.timestamp_sec)
    lines = [
        f"\n========== Packet #{packet_num} ==========",
        f"Time: {ts.strftime('%Y-%m-%d %H:%M:%S')}.{pkt.timestamp_usec:06d}",
        "\n[Ethernet]",
        f"  Source MAC:      {pkt.src_mac}",
        f"  Destination MAC: {pkt.dest_mac}",
        f"  EtherType:       0x{pkt.ether_type:04x}{_ETYPE_NAMES.get(pkt.ether_type,'')}",
    ]

    if pkt.has_ip:
        lines += [
            f"\n[IPv{pkt.ip_version}]",
            f"  Source IP:      {pkt.src_ip}",
            f"  Destination IP: {pkt.dest_ip}",
            f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}",
            f"  TTL:            {pkt.ttl}",
        ]

    if pkt.has_tcp:
        lines += [
            "\n[TCP]",
            f"  Source Port:      {pkt.src_port}",
            f"  Destination Port: {pkt.dest_port}",
            f"  Sequence Number:  {pkt.seq_number}",
            f"  Ack Number:       {pkt.ack_number}",
            f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}",
        ]

    if pkt.has_udp:
        lines += [
            "\n[UDP]",
            f"  Source Port:      {pkt.src_port}",
            f"  Destination Port: {pkt.dest_port}",
        ]

    if pkt.payload_length > 0:
        # bytes.hex() is C-speed; slice to 32, insert spaces
        raw_hex = pkt.payload_data[:32].hex()
        hex_str = " ".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))
        suffix  = " ..." if pkt.payload_length > 32 else ""
        lines += [
            "\n[Payload]",
            f"  Length: {pkt.payload_length} bytes",
            f"  Preview: {hex_str}{suffix}",
        ]

    print("\n".join(lines))


# ─────────────────────────────────────────────────────────────
# main()
# ─────────────────────────────────────────────────────────────

def main() -> int:
    print("====================================")
    print("     Packet Analyzer v2.0")
    print("====================================\n")

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("pcap_file",   nargs="?", default=None)
    parser.add_argument("max_packets", nargs="?", type=int, default=-1)
    args, _ = parser.parse_known_args()

    if args.pcap_file is None:
        print(f"Usage: python {sys.argv[0]} <pcap_file> [max_packets]")
        return 1

    reader = PcapReader()
    if not reader.open(args.pcap_file):
        return 1

    print("\n--- Reading packets ---")
    packet_count = parse_errors = 0

    for raw_packet in reader:
        packet_count += 1
        parsed = PacketParser.parse(raw_packet)
        if parsed is not None:
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1

        if args.max_packets > 0 and packet_count >= args.max_packets:
            print(f"\n(Stopped after {args.max_packets} packets)")
            break

    reader.close()
    print(f"\n====================================\nSummary:\n"
          f"  Total packets read:  {packet_count}\n"
          f"  Parse errors:        {parse_errors}\n"
          f"====================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
