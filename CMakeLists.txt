cmake_minimum_required(VERSION 3.16)
project(Qktgen)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

add_executable(Qktgen
    src/main.c
    src/dpdk.c
    src/pktgen.cpp
    src/Qktgen.h
)
target_include_directories(Qktgen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(Qktgen PRIVATE PkgConfig::DPDK pcap)
target_link_options(Qktgen PRIVATE -Wl,--no-as-needed -L/usr/local/lib64 -lrte_net_ixgbe -lrte_mempool_ring)
