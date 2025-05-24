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
FetchContent_MakeAvailable(capstone)

add_library(arm-context INTERFACE)
target_include_directories(arm-context INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_subdirectory(recompiler)
add_subdirectory(runner)
