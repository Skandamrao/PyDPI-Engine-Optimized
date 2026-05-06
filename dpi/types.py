"""
dpi/types.py
============
Python port of src/types.cpp + include/types.h

Defines all shared enums, dataclasses, and helper functions used across
the DPI engine (AppType, ConnectionState, FiveTuple, Connection, PacketJob, etc.)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Optional
import time


# ─────────────────────────────────────────────────────────────
# Enumerations  (mirrors types.h enums)
# ─────────────────────────────────────────────────────────────

class AppType(IntEnum):
    UNKNOWN   = 0
    HTTP      = auto()
    HTTPS     = auto()
    DNS       = auto()
    TLS       = auto()
    QUIC      = auto()
    GOOGLE    = auto()
    FACEBOOK  = auto()
    YOUTUBE   = auto()
    TWITTER   = auto()
    INSTAGRAM = auto()
    NETFLIX   = auto()
    AMAZON    = auto()
    MICROSOFT = auto()
    APPLE     = auto()
    WHATSAPP  = auto()
    TELEGRAM  = auto()
    TIKTOK    = auto()
    SPOTIFY   = auto()
    ZOOM      = auto()
    DISCORD   = auto()
    GITHUB    = auto()
    CLOUDFLARE = auto()
    APP_COUNT = auto()   # sentinel — keep last


class ConnectionState(IntEnum):
    NEW         = 0
    ESTABLISHED = auto()
    CLASSIFIED  = auto()
    BLOCKED     = auto()
    CLOSED      = auto()


class PacketAction(IntEnum):
    FORWARD = 0
    DROP    = auto()


# ─────────────────────────────────────────────────────────────
# FiveTuple  (mirrors struct FiveTuple in types.h)
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class FiveTuple:
    src_ip:   int = 0    # uint32 in network byte-order
    dst_ip:   int = 0
    src_port: int = 0    # uint16
    dst_port: int = 0
    protocol: int = 0    # uint8  (6=TCP, 17=UDP)

    def reverse(self) -> "FiveTuple":
        """Return the reverse flow tuple (server → client)."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{_ip_str(self.src_ip)}:{self.src_port} -> "
            f"{_ip_str(self.dst_ip)}:{self.dst_port} ({proto})"
        )

    # Make hashable so it can be used as dict key
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))


def _ip_str(ip: int) -> str:
    """Convert a uint32 IP (little-endian stored) to dotted string."""
    return (
        f"{(ip >> 0) & 0xFF}."
        f"{(ip >> 8) & 0xFF}."
        f"{(ip >> 16) & 0xFF}."
        f"{(ip >> 24) & 0xFF}"
    )


# ─────────────────────────────────────────────────────────────
# Connection  (mirrors struct Connection in types.h)
# ─────────────────────────────────────────────────────────────

@dataclass
class Connection:
    tuple:        FiveTuple       = field(default_factory=FiveTuple)
    state:        ConnectionState = ConnectionState.NEW
    app_type:     AppType         = AppType.UNKNOWN
    sni:          str             = ""
    action:       PacketAction    = PacketAction.FORWARD

    # Timestamps (monotonic, seconds)
    first_seen: float = field(default_factory=time.monotonic)
    last_seen:  float = field(default_factory=time.monotonic)

    # Traffic counters
    packets_in:  int = 0
    packets_out: int = 0
    bytes_in:    int = 0
    bytes_out:   int = 0

    # TCP state flags
    syn_seen:     bool = False
    syn_ack_seen: bool = False
    fin_seen:     bool = False


# ─────────────────────────────────────────────────────────────
# PacketJob  (mirrors struct PacketJob in types.h)
# ─────────────────────────────────────────────────────────────

@dataclass
class PacketJob:
    packet_id: int      = 0
    ts_sec:    int      = 0
    ts_usec:   int      = 0
    tuple:     FiveTuple = field(default_factory=FiveTuple)
    tcp_flags: int      = 0

    # Raw packet data
    data: bytes = b""

    # Byte offsets
    eth_offset:       int = 0
    ip_offset:        int = 14
    transport_offset: int = 0
    payload_offset:   int = 0
    payload_length:   int = 0


# ─────────────────────────────────────────────────────────────
# appTypeToString  (mirrors appTypeToString() in types.cpp)
# ─────────────────────────────────────────────────────────────

_APP_NAMES = {
    AppType.UNKNOWN:    "Unknown",
    AppType.HTTP:       "HTTP",
    AppType.HTTPS:      "HTTPS",
    AppType.DNS:        "DNS",
    AppType.TLS:        "TLS",
    AppType.QUIC:       "QUIC",
    AppType.GOOGLE:     "Google",
    AppType.FACEBOOK:   "Facebook",
    AppType.YOUTUBE:    "YouTube",
    AppType.TWITTER:    "Twitter/X",
    AppType.INSTAGRAM:  "Instagram",
    AppType.NETFLIX:    "Netflix",
    AppType.AMAZON:     "Amazon",
    AppType.MICROSOFT:  "Microsoft",
    AppType.APPLE:      "Apple",
    AppType.WHATSAPP:   "WhatsApp",
    AppType.TELEGRAM:   "Telegram",
    AppType.TIKTOK:     "TikTok",
    AppType.SPOTIFY:    "Spotify",
    AppType.ZOOM:       "Zoom",
    AppType.DISCORD:    "Discord",
    AppType.GITHUB:     "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    return _APP_NAMES.get(app, "Unknown")


def _matches_domain(sni: str, domain: str) -> bool:
    return sni == domain or sni.endswith("." + domain)


# ─────────────────────────────────────────────────────────────
# sniToAppType  (mirrors sniToAppType() in types.cpp)
# ─────────────────────────────────────────────────────────────

def sni_to_app_type(sni: str) -> AppType:
    """Map an SNI / domain string to an AppType."""
    if not sni:
        return AppType.UNKNOWN

    s = sni.lower()

    # YouTube (before Google, since YouTube is owned by Google)
    if any(k in s for k in ("youtube", "ytimg", "yt3.ggpht")) or _matches_domain(s, "youtu.be"):
        return AppType.YOUTUBE

    # Google
    if any(k in s for k in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # Instagram (before Facebook / Meta)
    if any(k in s for k in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp (before Facebook / Meta)
    if "whatsapp" in s or _matches_domain(s, "wa.me"):
        return AppType.WHATSAPP

    # Facebook / Meta
    if (
        any(k in s for k in ("facebook", "fbcdn", "fbsbx"))
        or _matches_domain(s, "fb.com")
        or _matches_domain(s, "meta.com")
    ):
        return AppType.FACEBOOK

    # Twitter / X
    if any(k in s for k in ("twitter", "twimg")) or _matches_domain(s, "x.com") or _matches_domain(s, "t.co"):
        return AppType.TWITTER

    # Netflix
    if any(k in s for k in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Amazon / AWS
    if any(k in s for k in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Microsoft
    if any(k in s for k in ("microsoft", "msn.com", "office", "azure",
                             "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Apple
    if any(k in s for k in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if "telegram" in s or _matches_domain(s, "t.me"):
        return AppType.TELEGRAM

    # TikTok
    if any(k in s for k in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(k in s for k in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in s:
        return AppType.ZOOM

    # Discord
    if any(k in s for k in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(k in s for k in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(k in s for k in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # SNI present but unrecognised → still HTTPS
    return AppType.HTTPS
