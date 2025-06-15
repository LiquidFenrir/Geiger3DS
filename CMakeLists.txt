cmake_minimum_required(VERSION 3.22)
project(geiger3ds LANGUAGES C CXX)

set(BUILD_TESTING OFF CACHE BOOL "build testing" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "static link" FORCE)

include(FetchContent)
FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG        f2f0a3c351d2e6a1e1eaa5e1e04bf2ec9d65bd23 # branch next as of 2025-05-24T18:05:00Z
)
set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE INTERNAL "")
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE INTERNAL "")
set(CAPSTONE_ARM_SUPPORT ON CACHE INTERNAL "")

FetchContent_Declare(
  magic_enum
  GIT_REPOSITORY https://github.com/Neargye/magic_enum.git
  GIT_TAG        a413fcc9c46a020a746907136a384c227f3cd095 # v0.9.7 + CMake and GCC 15 fixes
)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        11.2.0
)

set(FMT_INSTALL OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(capstone)
FetchContent_MakeAvailable(magic_enum)
FetchContent_MakeAvailable(fmt)

add_library(arm-context INTERFACE)
target_include_directories(arm-context INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_subdirectory(recompiler)
add_subdirectory(runner)
