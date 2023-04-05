cmake_minimum_required(VERSION 3.16)
project(pcap)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)
include_directories(packetlib)
include(FindPCAP.cmake)

add_subdirectory(packetlib)
message(STATUS "PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")

add_executable(assignment1
        src/assignment1.cpp utils/pcap_handler.cpp utils/pcap_handler.h utils/logger.cpp utils/logger.h)
target_link_libraries(assignment1 PUBLIC
        packetlib ${PCAP_LIBRARY})
target_include_directories(assignment1 PUBLIC
        "${PROJECT_BINARY_DIR}"
        "${PROJECT_SOURCE_DIR}/build")

add_executable(assignment2
        src/assignment2.cpp utils/pcap_handler.cpp utils/pcap_handler.h utils/logger.cpp utils/logger.h)
target_link_libraries(assignment2 PUBLIC
        packetlib ${PCAP_LIBRARY})
target_include_directories(assignment2 PUBLIC
        "${PROJECT_BINARY_DIR}"
        "${PROJECT_SOURCE_DIR}/build")

