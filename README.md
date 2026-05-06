# Optimized Packet Analyzer & DPI Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Code Quality](https://img.shields.io/badge/code%20quality-good-brightgreen.svg)](https://github.com/yourusername/optimized_packet_analyzer)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [Performance Optimizations](#performance-optimizations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

This project provides a **pure-Python implementation** of a network packet analyzer and Deep Packet Inspection (DPI) engine. It enables:

1. **Packet Analysis**: Read and parse PCAP files to extract network protocol information (Ethernet, IPv4, TCP, UDP)
2. **Application Classification**: Identify applications (YouTube, Facebook, Google, etc.) using SNI, HTTP Host headers, and DNS queries
3. **Traffic Filtering**: Block or allow traffic based on IP addresses, applications, domains, and ports
4. **Multi-threaded Processing**: High-performance packet processing using producer-consumer patterns with thread-safe queues
5. **Detailed Reporting**: Generate statistics on traffic volume, application distribution, and filtering effectiveness

The engine is designed for network security monitoring, parental controls, bandwidth management, and enterprise policy enforcement.

## Features

### Core Capabilities
- ✅ **PCAP File Parsing**: Read standard PCAP files (versions 2.4) with proper endianness handling
- ✅ **Protocol Decoding**: Full Ethernet, IPv4, TCP, and UDP header parsing
- ✅ **Application Detection**: 
  - SNI extraction from TLS Client Hello (HTTPS)
  - HTTP Host header extraction
  - DNS query parsing
  - QUIC SNI extraction (experimental)
- ✅ **Flexible Blocking Rules**:
  - Source IP blocking
  - Application-based blocking (YouTube, Facebook, etc.)
  - Domain blocking with wildcard support (*.example.com)
  - Destination port blocking
- ✅ **Multi-threaded Architecture**:
  - Load balancer threads distribute packets by 5-tuple hash
  - Fast path threads perform DPI and classification
  - Thread-safe queues between stages
  - Dedicated output writer thread
- ✅ **Flow-based Processing**: Connection tracking ensures consistent handling of related packets
- ✅ **Comprehensive Reporting**: 
  - Packet and byte statistics
  - Application distribution charts
  - Blocking effectiveness metrics
  - Per-thread performance data

### Performance Optimizations
- Pre-compiled `struct.Struct` objects for zero-format-overhead parsing
- `__slots__` on all hot data classes for reduced memory footprint
- O(1) lookup tables for protocol/flag names instead of if/elif chains
- `bytes.hex()` for fast MAC address and payload hex formatting
- Single-pass struct unpacking where possible
- Minimal memory allocations in hot paths

## Project Structure

```
Optimized_packet_analyzer/
├── dpi/                          # DPI Engine (Python implementation)
│   ├── __init__.py               # Package initializer
│   ├── connection_tracker.py     # Flow state management
│   ├── dpi_engine.py             # Main orchestrator
│   ├── fast_path.py              # Worker threads for DPI processing
│   ├── load_balancer.py          # Load distribution threads
│   ├── rule_manager.py           # Thread-safe rule storage
│   ├── sni_extractor.py          # Application detection (SNI, HTTP, DNS)
│   └── types.py                  # Shared data structures and enums
├── packet_analyzer.py            # Standalone packet analyzer (PCAP reader + parser)
├── dpi_main.py                   # CLI entry point for DPI engine
├── dpi_working.py                # Simplified single-threaded DPI version
├── dpi_mt.py                     # Multi-threaded DPI version
├── build.py                      # Build script for C++ version (reference)
├── CMakeLists.txt                # CMake configuration for C++ version (reference)
├── generate_test_pcap.py         # Test data generation script
├── test_dpi.pcap                 # Sample test capture
├── output*.pcap                  # Example output files
├── PYTHON_CONVERSION_MAP.md      # Mapping between C++ and Python implementations
├── WINDOWS_SETUP.md              # Windows-specific setup instructions
└── README.md                     # This file
```

## Installation

### Prerequisites
- Python 3.8 or higher
- No external dependencies required (uses only standard library)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/optimized_packet_analyzer.git
   cd optimized_packet_analyzer
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. Verify installation:
   ```bash
   python --version
   # Should show Python 3.8+
   ```

## Usage

### Standalone Packet Analyzer
Analyze packets without filtering or classification:
```bash
python packet_analyzer.py <input.pcap> [max_packets]
```

**Example**:
```bash
python packet_analyzer.py test_dpi.pcap 10
```

### DPI Engine (Multi-threaded)
Process packets with application detection and filtering:
```bash
python dpi_main.py <input.pcap> <output.pcap> [options]
```

**Options**:
```
  --block-ip <ip>       Block packets from source IP (can be repeated)
  --block-app <app>     Block application (e.g. YouTube, Facebook) (can be repeated)
  --block-domain <dom>  Block domain (supports wildcards: *.facebook.com) (can be repeated)
  --rules <file>        Load blocking rules from file
  --lbs <n>             Number of load-balancer threads (default: 2)
  --fps <n>             FP threads per LB (default: 2)
  --verbose             Enable verbose output
  -h, --help            Show help message
```

**Examples**:

1. Basic processing (no blocking):
   ```bash
   python dpi_main.py test_dpi.pcap output.pcap
   ```

2. Block specific applications:
   ```bash
   python dpi_main.py test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok
   ```

3. Block by IP and domain:
   ```bash
   python dpi_main.py test_dpi.pcap output.pcap --block-ip 192.168.1.50 --block-domain *.facebook.com
   ```

4. Use custom rules file:
   ```bash
   python dpi_main.py test_dpi.pcap output.pcap --rules my_rules.txt
   ```

5. Configure for high throughput:
   ```bash
   python dpi_main.py test_dpi.pcap output.pcap --lbs 4 --fps 4  # 16 FP threads total
   ```

### DPI Engine (Single-threaded - for debugging/learning)
```bash
python dpi_working.py <input.pcap> <output.pcap> [options]
```
(Same options as multi-threaded version)

## How It Works

### Packet Flow (Multi-threaded Version)
```
┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Reader      │───►│ Load Balancer 0  │───►│ Fast Path 0-1    │───►│                  │
│ (1 thread)  │    │                  │    │                  │    │ Output Queue     │
└─────────────┘    └──────────────────┘    └──────────────────┘    │                  │
           │    ┌──────────────────┐    ┌──────────────────┐    │ (Writer Thread)  │
           └───►│ Load Balancer 1  │───►│ Fast Path 2-3    │───►│                  │
                │                  │    │                  │    └──────────────────┘
                └──────────────────┘    └──────────────────┘
```

1. **Reader Thread**: Reads packets from input PCAP file
2. **Load Balancers**: Distribute packets to FP threads using hash(5-tuple) % num_lbs
3. **Fast Path Threads**: 
   - Extract 5-tuple (srcIP, dstIP, srcPort, dstPort, protocol)
   - Track connection state (TCP handshake, sequence numbers)
   - Perform application classification (SNI/HTTP/DNS extraction)
   - Apply blocking rules
   - Forward or drop packets
4. **Output Writer Thread**: Writes forwarded packets to output PCAP file

### Application Classification
The engine identifies applications in this order:
1. **SNI Extraction** (TLS Client Hello on port 443)
2. **HTTP Host Header** (HTTP requests on port 80)
3. **DNS Query** (DNS packets on port 53)
4. **Port-based Fallback** (well-known ports → HTTP/HTTPS)

### Blocking Mechanism
Blocking is connection-based:
1. When a packet is classified as matching a block rule, the entire connection is marked as blocked
2. All subsequent packets in that connection are dropped
3. This ensures clean termination of blocked connections

## Testing

### Validate Packet Analyzer
```bash
python packet_analyzer.py test_dpi.pcap 5
```
Should display detailed packet information for first 5 packets with 0 parse errors.

### Validate DPI Engine
```bash
python dpi_main.py test_dpi.pcap output.pcap --verbose
```
Check output for:
- Successful initialization
- Packet processing statistics
- Application classification report
- Zero dropped packets (unless blocking rules are applied)

### Test with Blocking Rules
```bash
python dpi_main.py test_dpi.pcap output_blocked.pcap --block-app YouTube
```
Verify in output report:
- Some packets dropped (YouTube traffic)
- Application classification shows YouTube as blocked

## Performance Optimizations

The implementation includes numerous optimizations for high-speed packet processing:

1. **Pre-compiled Struct Objects**
   ```python
   # Instead of: struct.unpack("<IHHiIII", data)
   _S_GLOBAL_HDR_LE = struct.Struct("<IHHiIII")  # Created once
   # Then: _S_GLOBAL_HDR_LE.unpack(data)
   ```

2. **Slotted Classes** for hot data paths:
   ```python
   class PcapGlobalHeader:
       __slots__ = ("magic_number","version_major","version_minor", ...)
   ```

3. **Lookup Tables** replacing conditional chains:
   ```python
   _PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}  # O(1) lookup
   ```

4. **Efficient Hex Formatting**:
   ```python
   # Instead of: ":".join(f"{b:02x}" for b in mac_bytes)
   mac_bytes.hex(":")  # C-speed operation
   ```

5. **Minimal Memory Allocation** in packet processing loop:
   - Reuse packet objects where possible
   - Avoid string creation in hot paths
   - Use bytes slicing instead of copying

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Add type hints for new functions
- Update documentation when changing functionality
- Ensure tests pass before submitting
- Keep commits focused and atomic

### Reporting Issues
Please use the GitHub issue tracker to report bugs or suggest features. Include:
- Python version and OS
- Steps to reproduce
- Sample PCAP if applicable
- Expected vs actual behavior

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

Project Maintainer: [Your Name]  
GitHub: [@yourusername](https://github.com/yourusername)  
Email: [your.email@example.com](mailto:your.email@example.com)

## Acknowledgments

- Inspired by traditional DPI engines and network monitoring tools
- Test PCAP generated using custom Python script
- Special thanks to open-source networking community for RFCs and protocol specifications