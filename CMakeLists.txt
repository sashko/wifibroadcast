cmake_minimum_required(VERSION 3.16.3)
project(Wifibroadcast)

set(CMAKE_CXX_STANDARD 17)

# Build and include wifibroadcast
include(src/WBLib.cmake)

add_executable(SerialEndpointTest test_serial_endpoint.cpp
        src/endpoints/SerialEndpoint.cpp)
