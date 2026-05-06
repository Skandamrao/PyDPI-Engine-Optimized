"""
dpi/rule_manager.py
===================
Python port of src/rule_manager.cpp + include/rule_manager.h

Manages blocking rules for IPs, applications, domains, and ports.
Thread-safe via threading.RLock (replaces C++ shared_mutex).
"""

from __future__ import annotations
import threading
from dataclasses import dataclass
from typing import Optional, List
from enum import IntEnum, auto

from .types import AppType, app_type_to_string


# ─────────────────────────────────────────────────────────────
# BlockReason  (mirrors struct RuleManager::BlockReason)
# ─────────────────────────────────────────────────────────────

class BlockType(IntEnum):
    IP     = 0
    PORT   = auto()
    APP    = auto()
    DOMAIN = auto()


@dataclass
class BlockReason:
    type:   BlockType
    detail: str


# ─────────────────────────────────────────────────────────────
# RuleStats  (mirrors struct RuleManager::RuleStats)
# ─────────────────────────────────────────────────────────────

@dataclass
class RuleStats:
    blocked_ips:     int = 0
    blocked_apps:    int = 0
    blocked_domains: int = 0
    blocked_ports:   int = 0


# ─────────────────────────────────────────────────────────────
# RuleManager  (mirrors class RuleManager)
# ─────────────────────────────────────────────────────────────

class RuleManager:
    """
    Thread-safe store for IP/app/domain/port blocking rules.
    Mirrors DPI::RuleManager from rule_manager.cpp.
    """

    def __init__(self):
        # Each category gets its own lock (mirrors separate shared_mutex per category)
        self._ip_lock     = threading.RLock()
        self._app_lock    = threading.RLock()
        self._domain_lock = threading.RLock()
        self._port_lock   = threading.RLock()

        self._blocked_ips:     set[int]     = set()
        self._blocked_apps:    set[AppType] = set()
        self._blocked_domains: set[str]     = set()
        self._domain_patterns: set[str]     = set()
        self._blocked_ports:   set[int]     = set()

    # ── IP helpers ────────────────────────────────────────────

    @staticmethod
    def _parse_ip(ip_str: str) -> int:
        """Convert dotted-decimal IP to uint32 (little-endian, matching C++ impl)."""
        parts = ip_str.strip().split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address: {ip_str}")
        result = 0
        for i, part in enumerate(parts):
            octet = int(part)
            if not 0 <= octet <= 255:
                raise ValueError(f"Invalid IPv4 address: {ip_str}")
            result |= (octet << (i * 8))
        return result

    @staticmethod
    def _ip_to_string(ip: int) -> str:
        return (
            f"{(ip >> 0) & 0xFF}."
            f"{(ip >> 8) & 0xFF}."
            f"{(ip >> 16) & 0xFF}."
            f"{(ip >> 24) & 0xFF}"
        )

    # ── IP blocking ───────────────────────────────────────────

    def block_ip(self, ip) -> None:
        """Block an IP (accepts dotted string or uint32)."""
        if isinstance(ip, str):
            ip = self._parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.add(ip)
        print(f"[RuleManager] Blocked IP: {self._ip_to_string(ip)}")

    def unblock_ip(self, ip) -> None:
        if isinstance(ip, str):
            ip = self._parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.discard(ip)
        print(f"[RuleManager] Unblocked IP: {self._ip_to_string(ip)}")

    def is_ip_blocked(self, ip: int) -> bool:
        with self._ip_lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        with self._ip_lock:
            return [self._ip_to_string(ip) for ip in self._blocked_ips]

    # ── App blocking ──────────────────────────────────────────

    def block_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._app_lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        with self._app_lock:
            return list(self._blocked_apps)

    # ── Domain blocking ───────────────────────────────────────

    def block_domain(self, domain: str) -> None:
        domain = domain.strip().lower()
        if not domain:
            return
        with self._domain_lock:
            if "*" in domain:
                self._domain_patterns.add(domain)
            else:
                self._blocked_domains.add(domain)
        print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        domain = domain.strip().lower()
        if not domain:
            return
        with self._domain_lock:
            if "*" in domain:
                self._domain_patterns.discard(domain)
            else:
                self._blocked_domains.discard(domain)
        print(f"[RuleManager] Unblocked domain: {domain}")

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """
        Support *.example.com style wildcards.
        Mirrors domainMatchesPattern() in rule_manager.cpp.
        """
        if len(pattern) >= 2 and pattern.startswith("*."):
            suffix = pattern[1:]          # ".example.com"
            return domain.endswith(suffix) or domain == pattern[2:]
        return False

    def is_domain_blocked(self, domain: str) -> bool:
        lower = domain.strip().lower()
        if not lower:
            return False
        with self._domain_lock:
            if lower in self._blocked_domains:
                return True
            for pattern in self._domain_patterns:
                if self._domain_matches_pattern(lower, pattern):
                    return True
        return False

    def get_blocked_domains(self) -> List[str]:
        with self._domain_lock:
            return list(self._blocked_domains) + list(self._domain_patterns)

    # ── Port blocking ─────────────────────────────────────────

    def block_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._port_lock:
            return port in self._blocked_ports

    # ── Combined check ────────────────────────────────────────

    def should_block(self, src_ip: int, dst_port: int,
                     app: AppType, domain: str) -> Optional[BlockReason]:
        """
        Returns a BlockReason if the packet should be dropped, else None.
        Mirrors shouldBlock() in rule_manager.cpp.
        """
        if self.is_ip_blocked(src_ip):
            return BlockReason(BlockType.IP, self._ip_to_string(src_ip))
        if self.is_port_blocked(dst_port):
            return BlockReason(BlockType.PORT, str(dst_port))
        if self.is_app_blocked(app):
            return BlockReason(BlockType.APP, app_type_to_string(app))
        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockType.DOMAIN, domain)
        return None

    # ── Persistence ───────────────────────────────────────────

    def save_rules(self, filename: str) -> bool:
        """Save all rules to a plain-text file (mirrors saveRules())."""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(ip + "\n")

                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(app_type_to_string(app) + "\n")

                f.write("\n[BLOCKED_DOMAINS]\n")
                for domain in self.get_blocked_domains():
                    f.write(domain + "\n")

                f.write("\n[BLOCKED_PORTS]\n")
                with self._port_lock:
                    for port in self._blocked_ports:
                        f.write(str(port) + "\n")

            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError:
            return False

    def load_rules(self, filename: str) -> bool:
        """Load rules from a plain-text file (mirrors loadRules())."""
        try:
            with open(filename, encoding="utf-8") as f:
                section = ""
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("["):
                        section = line
                        continue

                    if section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif section == "[BLOCKED_APPS]":
                        for app in AppType:
                            if app_type_to_string(app) == line:
                                self.block_app(app)
                                break
                    elif section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif section == "[BLOCKED_PORTS]":
                        self.block_port(int(line))

            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except OSError:
            return False

    def clear_all(self) -> None:
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
            self._domain_patterns.clear()
        with self._port_lock:
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    def get_stats(self) -> RuleStats:
        stats = RuleStats()
        with self._ip_lock:
            stats.blocked_ips = len(self._blocked_ips)
        with self._app_lock:
            stats.blocked_apps = len(self._blocked_apps)
        with self._domain_lock:
            stats.blocked_domains = len(self._blocked_domains) + len(self._domain_patterns)
        with self._port_lock:
            stats.blocked_ports = len(self._blocked_ports)
        return stats
