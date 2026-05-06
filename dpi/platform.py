"""
dpi/platform.py
===============
Python equivalent of include/platform.h.

Provides small byte-order helpers used by the packet/DPI code. Python's
integer operations are already portable, so these helpers mainly preserve the
shape and naming of the C++ utility header.
"""

from __future__ import annotations

import sys


def swap_bytes16(value: int) -> int:
    value &= 0xFFFF
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)


def swap_bytes32(value: int) -> int:
    value &= 0xFFFFFFFF
    return (
        ((value & 0xFF000000) >> 24)
        | ((value & 0x00FF0000) >> 8)
        | ((value & 0x0000FF00) << 8)
        | ((value & 0x000000FF) << 24)
    )


def is_little_endian() -> bool:
    return sys.byteorder == "little"


def net_to_host16(value: int) -> int:
    return swap_bytes16(value) if is_little_endian() else value & 0xFFFF


def net_to_host32(value: int) -> int:
    return swap_bytes32(value) if is_little_endian() else value & 0xFFFFFFFF


def host_to_net16(value: int) -> int:
    return net_to_host16(value)


def host_to_net32(value: int) -> int:
    return net_to_host32(value)
