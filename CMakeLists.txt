include(FetchContent)

cmake_minimum_required(VERSION 3.31)
project(IDA_FastAnalysis)

set(CMAKE_CXX_STANDARD 23)

FetchContent_Declare(
        idasdk
        GIT_REPOSITORY https://github.com/HexRaysSA/ida-sdk.git
        GIT_TAG v9.2
)

FetchContent_Declare(
        libhat
        GIT_REPOSITORY https://github.com/BasedInc/libhat.git
        GIT_TAG v0.9.0
)

FetchContent_Declare(
        safetyhook
        GIT_REPOSITORY https://github.com/cursey/safetyhook
        GIT_TAG v0.6.9
)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

FetchContent_MakeAvailable(idasdk libhat safetyhook)

list(APPEND fastanalysis_sources
        src/main.cpp
        src/ref_scanner_impl/ref_scanner_aarch64.cpp
        src/ref_scanner_impl/ref_scanner_x86_64.cpp
        src/ref_scanner.cpp
        src/hde/hde64.c
        src/hde/hde32.c
)

add_library(fastanalysis SHARED
        ${fastanalysis_sources}
)

target_include_directories(fastanalysis PRIVATE
        ${idasdk_SOURCE_DIR}/src/include/
)

target_compile_definitions(fastanalysis PRIVATE
        __EA64__
        _SILENCE_CXX20_IS_POD_DEPRECATION_WARNING
)

target_link_libraries(fastanalysis PRIVATE
        safetyhook
        libhat
)


set(IDA_8_SDK_PATH "$ENV{IDA_8_SDK}")

if(DEFINED ENV{IDA_8_SDK})
    add_library(ida_8_fastanalysis64 SHARED
            ${fastanalysis_sources}
    )

    target_compile_definitions(ida_8_fastanalysis64 PRIVATE
        IDA_8
    )

    target_include_directories(ida_8_fastanalysis64 PRIVATE
            "${IDA_8_SDK_PATH}/include"
    )

    target_link_libraries(ida_8_fastanalysis64 PRIVATE
            safetyhook
            libhat
    )

    target_compile_definitions(ida_8_fastanalysis64 PRIVATE
            __EA64__
            _SILENCE_CXX20_IS_POD_DEPRECATION_WARNING
    )
else()
    message(WARNING "Will not build for IDA 8.x as no SDK was found! Please define the environment variable IDA_8_SDK as the path to your IDA 8.x SDK.")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fastanalysis PRIVATE "${idasdk_SOURCE_DIR}/src/lib/x64_win_vc_64/ida.lib")
    if(DEFINED ENV{IDA_8_SDK})
        target_link_libraries(ida_8_fastanalysis64 PRIVATE "${IDA_8_SDK_PATH}/lib/x64_win_vc_64_pro/ida.lib")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(fastanalysis PRIVATE "${idasdk_SOURCE_DIR}/src/lib/x64_linux_gcc_64/libida.so")
    if(DEFINED ENV{IDA_8_SDK})
        target_link_libraries(ida_8_fastanalysis64 PRIVATE "${IDA_8_SDK_PATH}/src/lib/x64_linux_gcc_64_pro/libida64.so")
    endif()
else()
    message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} is unsupported")
endif()


