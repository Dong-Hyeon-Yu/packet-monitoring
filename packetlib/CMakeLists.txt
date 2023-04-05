message(STATUS "===  packetlib :: Module ===")

set( PACKET_LIB "packetlib" )

## Gen ./lib directory
#add_custom_target(lib-directory ALL COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_SOURCE_DIR}/libs)
#set( LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/libs )

# Set sources
file( GLOB_RECURSE PACKET_LIB_SOURCES *.cpp )
file( GLOB_RECURSE PACKET_LIB_HEADERS *.h *.hpp)

message(STATUS "PACKET_LIB: ${PACKET_LIB}")
message(STATUS "SOURCES: ${PACKET_LIB_SOURCES}")
message(STATUS "HEADERS: ${PACKET_LIB_HEADERS}")

add_library(${PACKET_LIB}
        ${PACKET_LIB_SOURCES} ${PACKET_LIB_HEADERS})

target_link_libraries(${PACKET_LIB} PUBLIC
        ${PCAP_LIBRARY})

