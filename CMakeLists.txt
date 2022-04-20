cmake_minimum_required(VERSION 3.16.3)
project(Wifibroadcast)

set(CMAKE_CXX_STANDARD 17)

# Build and include wifibroadcast
# ----------------------------------
add_library( radiotap
        SHARED
        src/external/radiotap/radiotap.c
        )

add_library( fec
        SHARED
        src/external/fec/fec.cpp
        )

add_library( wifibroadcast
        SHARED
        src/WBReceiver.cpp
        src/WBTransmitter.cpp
        )

include(cmake/FindPCAP.cmake)
include(cmake/FindSodium.cmake)

include_directories(${sodium_INCLUDE_DIR})
include_directories(${PCAP_INCLUDE_DIR})

SET(USED_LIBS wifibroadcast radiotap fec ${PCAP_LIBRARY} ${sodium_LIBRARY_RELEASE})

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -mavx2 -faligned-new=256")
# ----------------------------------

add_executable(wfb_tx src/tx.cpp)
target_link_libraries(wfb_tx  ${USED_LIBS})

add_executable(wfb_rx src/rx.cpp)
target_link_libraries(wfb_rx  ${USED_LIBS})