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
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook
        GIT_TAG v1.3.4
)

FetchContent_MakeAvailable(idasdk libhat minhook)

add_library(fastanalysis SHARED
        src/main.cpp
        src/ref_scanner_impl/ref_scanner_x86_64.cpp
        src/ref_scanner.cpp
)

target_include_directories(fastanalysis PRIVATE
        ${idasdk_SOURCE_DIR}/src/include/
        # use hde64 source files from MinHook
        ${minhook_SOURCE_DIR}/src/hde/
)

target_compile_definitions(fastanalysis PRIVATE
        __EA64__
        _SILENCE_CXX20_IS_POD_DEPRECATION_WARNING
)

target_link_libraries(fastanalysis PRIVATE
        minhook
        libhat
)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fastanalysis PRIVATE ${idasdk_SOURCE_DIR}/src/lib/x64_win_vc_64/ida.lib)
else()
    message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} is unsupported")
endif()


