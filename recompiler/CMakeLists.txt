set(PROJECT_NAME recompiler)
add_executable(recompiler)
target_compile_features(recompiler PUBLIC cxx_std_20 c_std_23)
target_compile_options(recompiler PRIVATE
    # Common C/C++ options
    -Wall -Wextra -Wno-psabi
    # -Wno-unused-function
    # -Wno-unused-parameter
    # -Wno-unused-variable
    # -Wno-unused-but-set-variable

    # C++ specific options
    $<$<COMPILE_LANGUAGE:CXX>:-fexceptions -frtti>
)
target_link_libraries(recompiler PRIVATE -static
    arm-context # cpu struct headers
    capstone # disassembler library
    fmt
    magic_enum
)
target_sources(recompiler PRIVATE
    # ${CMAKE_CURRENT_SOURCE_DIR}/recompiler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/recompiler_split.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/recompiler_analysis.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/embed_header.c
)
