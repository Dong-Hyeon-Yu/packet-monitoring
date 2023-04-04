cmake_minimum_required(VERSION 3.16)
project(pcap)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)
include(FindPCAP.cmake)

add_executable(assignment1
        src/assignment1.cpp utils/pcap_handler.cpp utils/pcap_handler.h utils/logger.cpp utils/logger.h)
target_link_libraries(assignment1
        ${PACKET_LIB} ${PCAP_LIBRARY})

add_executable(assignment2
        src/assignment2.cpp utils/pcap_handler.cpp utils/pcap_handler.h utils/logger.cpp utils/logger.h)
target_link_libraries(assignment2
        ${PACKET_LIB} ${PCAP_LIBRARY})

add_subdirectory(packetlib)
