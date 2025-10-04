set(PROJECT_NAME converter)
add_executable(converter)
target_compile_features(converter PUBLIC cxx_std_23)
target_compile_options(converter PRIVATE
    # Common C/C++ options
    -Wall -Wextra -Wno-psabi
    # -Wno-unused-function
    -Wno-unused-parameter
    # -Wno-unused-variable
    # -Wno-unused-but-set-variable
    
    $<$<PLATFORM_ID:Windows>:-Wa,-mbig-obj>
    
    # C++ specific options
    $<$<COMPILE_LANGUAGE:CXX>:-fexceptions -frtti>
    $<$<COMPILE_LANGUAGE:CXX>:-ftemplate-depth=1400>
    # $<$<COMPILE_LANGUAGE:CXX>:-fconcepts-diagnostics-depth=2>
)
target_link_libraries(converter PRIVATE -static
    arm-context # cpu struct headers
    capstone # disassembler library
    fmt::fmt-header-only
    magic_enum
    xbyak
)
target_sources(converter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/converter.cpp
)
