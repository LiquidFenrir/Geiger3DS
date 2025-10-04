cmake_minimum_required(VERSION 3.22)
project(geiger3ds LANGUAGES C CXX)

set(BUILD_TESTING OFF CACHE BOOL "build testing" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "static link" FORCE)

include(FetchContent)
FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG        c66f8774641a3df4f2783b933ca7a50912b56448 # branch next as of 2025-09-27T10:59:00Z
)
set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE INTERNAL "")
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE INTERNAL "")
set(CAPSTONE_ARM_SUPPORT ON CACHE INTERNAL "")

FetchContent_Declare(
  magic_enum
  GIT_REPOSITORY https://github.com/Neargye/magic_enum.git
  GIT_TAG        ec5734e491ab7cb443c6175996d1791854341a55
)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        12.0.0
)

set(FMT_INSTALL OFF CACHE INTERNAL "")

FetchContent_Declare(
  xbyak
  GIT_REPOSITORY https://github.com/herumi/xbyak.git
  GIT_TAG        v7.30
)

FetchContent_MakeAvailable(capstone)
FetchContent_MakeAvailable(magic_enum)
FetchContent_MakeAvailable(fmt)
FetchContent_MakeAvailable(xbyak)

add_library(arm-context INTERFACE)
target_include_directories(arm-context INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(arm-context-embed STATIC)
target_compile_features(arm-context-embed PUBLIC c_std_23)
target_link_libraries(arm-context-embed PUBLIC arm-context)
target_sources(arm-context-embed PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/embed_header.c)

add_subdirectory(recompiler)
add_subdirectory(converter)
add_subdirectory(runner)
