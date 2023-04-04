cmake_minimum_required(VERSION 3.16)
project(pcap)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)
include(FindPCAP.cmake)

add_executable(assignment1
        assignment1.cpp utils/pcap_handler.cpp utils/pcap_handler.h utils/logger.cpp utils/logger.h)
target_link_libraries(assignment1 ${PCAP_LIBRARY})

