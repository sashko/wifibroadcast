#
# Defines WB_TARGET_LINK_LIBRARIES
# which can then be used to integrate wifibroadcast into your project

cmake_minimum_required(VERSION 3.16.3)
set(CMAKE_CXX_STANDARD 17)

option(WB_ENABLE_SIMD_OPTIMIZATIONS "Enable NEON on ARM and AVX2 on X86 if the platform/compiler supports it" OFF)
#if(WIFIBROADCAST_LIBRARIES_ALREADY_BUILD)
#if(get_property(source_list GLOBAL PROPERTY source_list_property))
#    message(STATUS "WIFIBROADCAST_LIBRARIES_ALREADY_BUILD")
#    return()
#endif()
if (TARGET wifibroadcast)
    message(STATUS "WIFIBROADCAST_LIBRARIES_ALREADY_BUILD")
    return()
endif()

#find_library(WIFIBROADCAST_LIB wifibroadcast)
#if(WIFIBROADCAST_LIB)
#    message(STATUS "wifibroadcast already here")
#    return()
#endif()

# Build and include wifibroadcast
# ----------------------------------
#add_library( radiotap
#        SHARED
#        ${CMAKE_CURRENT_LIST_DIR}/src/external/radiotap/radiotap.c
#        )

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
#add_library( fec
#        SHARED
#        ${CMAKE_CURRENT_LIST_DIR}/src/external/fec/fec.cpp
#        )

# Well, let's just build everything together
add_library(wifibroadcast
        STATIC
        # radiotap and fec
        ${CMAKE_CURRENT_LIST_DIR}/src/external/radiotap/radiotap.c
        ${CMAKE_CURRENT_LIST_DIR}/src/external/fec/fec.cpp
        # the couple of non-header-only files for wifibroadcast
        ${CMAKE_CURRENT_LIST_DIR}/src/WBReceiver.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/WBTransmitter.cpp
        )
## FEC Optimizations begin ---------------------------------
set(WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_X86 -mavx2 -faligned-new=256)
set(WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_ARM -mfpu=neon -march=armv7-a -marm)
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-mavx2" COMPILER_SUPPORTS_MAVX2)
check_cxx_compiler_flag("-mfpu=neon" COMPILER_SUPPORTS_NEON)
# AVX2 if supported and option WB_ENABLE_SIMD_OPTIMIZATIONS is true
if(COMPILER_SUPPORTS_MAVX2)
    message(STATUS "Compiler supports AVX2")
    if(WB_ENABLE_SIMD_OPTIMIZATIONS)
        message(STATUS "WB compile with AVX2")
        target_compile_options(wifibroadcast PRIVATE ${WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_X86})
    endif()
endif()
# NEON if supported and option WB_ENABLE_SIMD_OPTIMIZATIONS is true
if(COMPILER_SUPPORTS_NEON)
    message(STATUS "Compiler supports NEON")
    if(WB_ENABLE_SIMD_OPTIMIZATIONS)
        message(STATUS "WB compile with NEON")
        target_compile_options(wifibroadcast PRIVATE ${WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_ARM})
    endif()
endif()
## FEC Optimizations end ---------------------------------

# We need pcap and libsodium to build wifibroadcast
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FindPCAP.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FindSodium.cmake)

target_include_directories(wifibroadcast PUBLIC ${sodium_INCLUDE_DIR})
target_include_directories(wifibroadcast PUBLIC ${PCAP_INCLUDE_DIR})
target_link_libraries(wifibroadcast PUBLIC ${PCAP_LIBRARY})
target_link_libraries(wifibroadcast PUBLIC ${sodium_LIBRARY_RELEASE})

# for some reason, we also need to manually link pthread
find_package(Threads REQUIRED)
target_link_libraries(wifibroadcast PUBLIC Threads::Threads)

SET(WB_TARGET_LINK_LIBRARIES wifibroadcast)
SET(WB_INCLUDE_DIRECTORES ${CMAKE_CURRENT_LIST_DIR}/src)

include_directories(${CMAKE_CURRENT_LIST_DIR}/src/HelperSources)

# ----------------------------------