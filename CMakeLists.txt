cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)

add_library(packet_analyzer_core STATIC
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

target_include_directories(packet_analyzer_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(packet_analyzer_core PUBLIC cxx_std_17)

if(MSVC)
    target_compile_options(packet_analyzer_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(packet_analyzer_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(packet_analyzer src/main.cpp)
target_link_libraries(packet_analyzer PRIVATE packet_analyzer_core)

add_executable(dpi_engine
    src/main_dpi.cpp
    src/types.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/dpi_engine.cpp
)
target_link_libraries(dpi_engine PRIVATE packet_analyzer_core)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)
