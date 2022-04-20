# For including the wifibroadcast code in a cmake project
# NOTE: Does not build the executables

add_library( radiotap
        SHARED
        ${CMAKE_CURRENT_LIST_DIR}/external/radiotap/radiotap.c
        )

add_library( fec
        SHARED
        ${CMAKE_CURRENT_LIST_DIR}/external/fec/fec.cpp
        )

add_library( wifibroadcast
        SHARED
        ${CMAKE_CURRENT_LIST_DIR}/WBReceiver.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WBTransmitter.cpp
        )

target_link_libraries( wifibroadcast radiotap fec)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -mavx2 -faligned-new=256")