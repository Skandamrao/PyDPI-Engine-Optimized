"""
build.py — Python build script for PacketAnalyzer
Equivalent of CMakeLists.txt (originally CMake 3.16+, C++17)

Usage:
    python build.py            # Build the project
    python build.py --clean    # Remove build artifacts and rebuild
"""

import subprocess
import sys
import os
import shutil
import platform
import argparse

# ─────────────────────────────────────────────────────────────
# Project configuration  (mirrors CMakeLists.txt)
# ─────────────────────────────────────────────────────────────
PROJECT_NAME    = "PacketAnalyzer"
PROJECT_VERSION = "1.0"
CXX_STANDARD    = "17"                # CMAKE_CXX_STANDARD 17

# Source files  (mirrors set(SOURCES ...))
SOURCES = [
    "src/main.cpp",
    "src/pcap_reader.cpp",
    "src/packet_parser.cpp",
]

# Header search path  (mirrors include_directories(${CMAKE_SOURCE_DIR}/include))
INCLUDE_DIRS = [
    "include",
]

# Output executable name  (mirrors add_executable(packet_analyzer ...))
OUTPUT_EXECUTABLE = "packet_analyzer"

# Build output directory
BUILD_DIR = "build"

# ─────────────────────────────────────────────────────────────
# Platform detection  (mirrors if(APPLE) block)
# ─────────────────────────────────────────────────────────────
IS_APPLE   = platform.system() == "Darwin"
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"


def get_compiler() -> str:
    """Return the C++ compiler to use, preferring clang++ then g++."""
    for compiler in ("clang++", "g++"):
        if shutil.which(compiler):
            return compiler
    # On Windows, fall back to MSVC cl.exe
    if IS_WINDOWS and shutil.which("cl"):
        return "cl"
    sys.exit(
        "[ERROR] No C++ compiler found. "
        "Install g++, clang++, or MSVC (cl.exe) and ensure it is on PATH."
    )


def resolve_source_dir() -> str:
    """Return the absolute path of the project root (CMAKE_SOURCE_DIR equivalent)."""
    return os.path.dirname(os.path.abspath(__file__))


def build_compile_command(compiler: str, source_dir: str) -> list:
    """
    Assemble the compiler command that mirrors what CMake would generate:
      - C++17  (CMAKE_CXX_STANDARD 17  +  CMAKE_CXX_STANDARD_REQUIRED ON)
      - include_directories(${CMAKE_SOURCE_DIR}/include)
      - all SOURCES compiled into OUTPUT_EXECUTABLE
    """
    cmd = [compiler]

    # C++ standard flag
    if compiler == "cl":
        cmd += ["/std:c++17", "/EHsc"]
    else:
        cmd += [f"-std=c++{CXX_STANDARD}"]

    # Include directories
    for inc in INCLUDE_DIRS:
        inc_path = os.path.join(source_dir, inc)
        if compiler == "cl":
            cmd += [f"/I{inc_path}"]
        else:
            cmd += [f"-I{inc_path}"]

    # Source files
    for src in SOURCES:
        cmd.append(os.path.join(source_dir, src))

    # Output executable
    exe_path = os.path.join(source_dir, BUILD_DIR, OUTPUT_EXECUTABLE)
    if IS_WINDOWS and compiler != "cl":
        exe_path += ".exe"
    if compiler == "cl":
        cmd += [f"/Fe:{exe_path}"]
    else:
        cmd += ["-o", exe_path]

    # macOS-specific settings  (mirrors if(APPLE) block — currently empty)
    if IS_APPLE:
        pass  # Add any macOS-specific flags here (e.g. -framework CoreFoundation)

    return cmd


def clean(source_dir: str) -> None:
    """Remove the build directory (equivalent to a CMake clean)."""
    build_path = os.path.join(source_dir, BUILD_DIR)
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
        print(f"[INFO] Removed '{build_path}'")
    else:
        print(f"[INFO] Nothing to clean — '{build_path}' does not exist.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Python build script for {PROJECT_NAME} v{PROJECT_VERSION}"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove build directory before building",
    )
    args = parser.parse_args()

    source_dir = resolve_source_dir()
    build_path  = os.path.join(source_dir, BUILD_DIR)

    print(f"[INFO] Project   : {PROJECT_NAME} v{PROJECT_VERSION}")
    print(f"[INFO] Platform  : {platform.system()}")
    print(f"[INFO] Source dir: {source_dir}")

    # ── Clean ──────────────────────────────────
    if args.clean:
        clean(source_dir)

    # ── Prepare build directory ────────────────
    os.makedirs(build_path, exist_ok=True)

    # ── Select compiler ────────────────────────
    compiler = get_compiler()
    print(f"[INFO] Compiler  : {compiler}  (C++{CXX_STANDARD})")

    # ── Validate source files exist ────────────
    for src in SOURCES:
        full = os.path.join(source_dir, src)
        if not os.path.isfile(full):
            sys.exit(f"[ERROR] Source file not found: {full}")

    # ── Build ──────────────────────────────────
    cmd = build_compile_command(compiler, source_dir)
    print("\n[INFO] Compile command:")
    print("  " + " ".join(cmd))
    print()

    result = subprocess.run(cmd)

    if result.returncode != 0:
        sys.exit(f"\n[ERROR] Build FAILED (exit code {result.returncode})")

    exe = os.path.join(build_path, OUTPUT_EXECUTABLE)
    if IS_WINDOWS:
        exe += ".exe"
    print(f"\n[SUCCESS] Built '{PROJECT_NAME}' -> {exe}")


if __name__ == "__main__":
    main()
