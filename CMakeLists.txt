cmake_minimum_required(VERSION 3.16.3)
project(Wifibroadcast)

set(CMAKE_CXX_STANDARD 17)

include(WBLib.cmake)

add_executable(wfb_tx executables/tx.cpp)
target_link_libraries(wfb_tx  ${WB_TARGET_LINK_LIBRARIES})

add_executable(wfb_rx executables/rx.cpp)
target_link_libraries(wfb_rx  ${WB_TARGET_LINK_LIBRARIES})