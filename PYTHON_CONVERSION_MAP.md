# Python Conversion Map

This project now has Python equivalents for the C++ packet analyzer and DPI
engine files.

## Entry Points

| C++ file | Python equivalent | Purpose |
| --- | --- | --- |
| `src/main.cpp` | `packet_analyzer.py` | PCAP reader/parser CLI |
| `src/main_simple.cpp` | `simple_sni.py` | Simple SNI extraction demo |
| `src/main_working.cpp` | `dpi_working.py` | Single-threaded functional DPI pipeline |
| `src/main_dpi.cpp` | `dpi_main.py` | Full DPI pipeline CLI |
| `src/dpi_mt.cpp` | `dpi_mt.py` | Multi-threaded DPI CLI |

## Core Modules

| C++ source/header | Python equivalent |
| --- | --- |
| `src/pcap_reader.cpp`, `include/pcap_reader.h` | `packet_analyzer.py` |
| `src/packet_parser.cpp`, `include/packet_parser.h` | `packet_analyzer.py` |
| `src/types.cpp`, `include/types.h` | `dpi/types.py` |
| `src/rule_manager.cpp`, `include/rule_manager.h` | `dpi/rule_manager.py` |
| `src/sni_extractor.cpp`, `include/sni_extractor.h` | `dpi/sni_extractor.py` |
| `src/connection_tracker.cpp`, `include/connection_tracker.h` | `dpi/connection_tracker.py` |
| `src/load_balancer.cpp`, `include/load_balancer.h` | `dpi/load_balancer.py` |
| `src/fast_path.cpp`, `include/fast_path.h` | `dpi/fast_path.py` |
| `src/dpi_engine.cpp`, `include/dpi_engine.h` | `dpi/dpi_engine.py` |
| `include/thread_safe_queue.h` | `dpi/thread_safe_queue.py` |
| `include/platform.h` | `dpi/platform.py` |

## Quick Checks

```powershell
py -3 -m compileall -q packet_analyzer.py dpi_main.py dpi_mt.py dpi_working.py simple_sni.py dpi
py -3 simple_sni.py test_dpi.pcap
py -3 dpi_working.py test_dpi.pcap filtered_output_single.pcap --block-app YouTube
py -3 dpi_mt.py test_dpi.pcap filtered_output_mt.pcap --block-app YouTube
```
