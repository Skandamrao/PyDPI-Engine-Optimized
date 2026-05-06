"""
dpi/sni_extractor.py
====================
Python port of src/sni_extractor.cpp + include/sni_extractor.h

Four extractors:
  SNIExtractor       — TLS Client Hello SNI
  HTTPHostExtractor  — HTTP Host header
  DNSExtractor       — DNS query domain
  QUICSNIExtractor   — QUIC Initial packet (simplified)
"""

from __future__ import annotations
import struct
from typing import Optional


# ─────────────────────────────────────────────────────────────
# TLS constants  (mirrors class SNIExtractor static consts)
# ─────────────────────────────────────────────────────────────

CONTENT_TYPE_HANDSHAKE  = 0x16
HANDSHAKE_CLIENT_HELLO  = 0x01
EXTENSION_SNI           = 0x0000
SNI_TYPE_HOSTNAME       = 0x00


# ─────────────────────────────────────────────────────────────
# SNIExtractor  (mirrors class SNIExtractor)
# ─────────────────────────────────────────────────────────────

class SNIExtractor:
    """Extract the Server Name Indication from a TLS Client Hello payload."""

    @staticmethod
    def _u16be(data: bytes, offset: int) -> int:
        return struct.unpack_from(">H", data, offset)[0]

    @staticmethod
    def _u24be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

    @classmethod
    def is_tls_client_hello(cls, payload: bytes) -> bool:
        """Mirrors isTLSClientHello()."""
        if len(payload) < 9:
            return False
        if payload[0] != CONTENT_TYPE_HANDSHAKE:
            return False
        version = cls._u16be(payload, 1)
        if not (0x0300 <= version <= 0x0304):
            return False
        record_length = cls._u16be(payload, 3)
        if record_length > len(payload) - 5:
            return False
        if payload[5] != HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @classmethod
    def extract(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """
        Extract the SNI hostname from a TLS Client Hello.
        Mirrors SNIExtractor::extract().
        Returns hostname string or None.
        """
        if length is not None:
            payload = payload[:length]

        if not cls.is_tls_client_hello(payload):
            return None

        offset = 5  # skip TLS record header

        # Handshake header: type(1) + length(3)
        # handshake_length = cls._u24be(payload, offset + 1)  # not needed
        offset += 4

        # Client version (2 bytes)
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(payload):
            return None
        cipher_suites_len = cls._u16be(payload, offset)
        offset += 2 + cipher_suites_len

        # Compression methods
        if offset >= len(payload):
            return None
        compression_len = payload[offset]
        offset += 1 + compression_len

        # Extensions total length
        if offset + 2 > len(payload):
            return None
        extensions_len = cls._u16be(payload, offset)
        offset += 2

        extensions_end = min(offset + extensions_len, len(payload))

        # Walk extensions
        while offset + 4 <= extensions_end:
            ext_type   = cls._u16be(payload, offset)
            ext_len    = cls._u16be(payload, offset + 2)
            offset    += 4

            if offset + ext_len > extensions_end:
                break

            if ext_type == EXTENSION_SNI:
                if ext_len < 5:
                    break
                # sni_list_length (2) + sni_type (1) + sni_length (2) + value
                sni_type   = payload[offset + 2]
                sni_length = cls._u16be(payload, offset + 3)

                if sni_type != SNI_TYPE_HOSTNAME:
                    break
                if sni_length > ext_len - 5:
                    break

                return payload[offset + 5: offset + 5 + sni_length].decode("ascii", errors="ignore")

            offset += ext_len

        return None


# ─────────────────────────────────────────────────────────────
# HTTPHostExtractor  (mirrors class HTTPHostExtractor)
# ─────────────────────────────────────────────────────────────

_HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


class HTTPHostExtractor:
    """Extract the Host header value from an HTTP/1.x request payload."""

    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        return any(payload[:4] == m for m in _HTTP_METHODS)

    @classmethod
    def extract(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """
        Scan for 'Host:' header and return the hostname.
        Mirrors HTTPHostExtractor::extract().
        """
        if length is not None:
            payload = payload[:length]

        if not cls.is_http_request(payload):
            return None

        # Search case-insensitively for "host:"
        lower = payload.lower()
        pos   = lower.find(b"host:")
        if pos == -1:
            return None

        start = pos + 5
        # Skip whitespace
        while start < len(payload) and payload[start] in (ord(" "), ord("\t")):
            start += 1

        # Find end of line
        end = start
        while end < len(payload) and payload[end] not in (ord("\r"), ord("\n")):
            end += 1

        if end <= start:
            return None

        host = payload[start:end].decode("ascii", errors="ignore").strip()

        # Remove port if present
        if ":" in host:
            host = host.split(":")[0]

        return host if host else None


# ─────────────────────────────────────────────────────────────
# DNSExtractor  (mirrors class DNSExtractor)
# ─────────────────────────────────────────────────────────────

class DNSExtractor:
    """Extract the queried domain name from a DNS query payload."""

    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        """Mirrors isDNSQuery()."""
        if len(payload) < 12:
            return False
        flags = payload[2]
        if flags & 0x80:       # QR bit set → response, not query
            return False
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount > 0

    @classmethod
    def extract_query(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """
        Parse the first QNAME from a DNS query.
        Mirrors DNSExtractor::extractQuery().
        """
        if length is not None:
            payload = payload[:length]

        if not cls.is_dns_query(payload):
            return None

        offset = 12   # DNS header is 12 bytes
        parts: list[str] = []

        while offset < len(payload):
            label_len = payload[offset]
            if label_len == 0:
                break
            if label_len > 63:   # Compression pointer or invalid
                break
            offset += 1
            if offset + label_len > len(payload):
                break
            parts.append(payload[offset: offset + label_len].decode("ascii", errors="ignore"))
            offset += label_len

        return ".".join(parts) if parts else None


# ─────────────────────────────────────────────────────────────
# QUICSNIExtractor  (mirrors class QUICSNIExtractor — simplified)
# ─────────────────────────────────────────────────────────────

class QUICSNIExtractor:
    """Simplified SNI extractor for QUIC Initial packets."""

    @staticmethod
    def is_quic_initial(payload: bytes) -> bool:
        """Mirrors isQUICInitial() — checks long-header form bit."""
        if len(payload) < 5:
            return False
        return bool(payload[0] & 0x80)

    @classmethod
    def extract(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """
        Attempt to find a TLS Client Hello embedded in a QUIC Initial packet.
        Mirrors QUICSNIExtractor::extract() — simplified byte-search approach.
        """
        if length is not None:
            payload = payload[:length]

        if not cls.is_quic_initial(payload):
            return None

        # Search for a Client Hello handshake type byte (0x01) and try SNI from there
        for i in range(len(payload) - 50):
            if payload[i] == HANDSHAKE_CLIENT_HELLO:
                start = max(0, i - 5)
                result = SNIExtractor.extract(payload[start:])
                if result:
                    return result

        return None
