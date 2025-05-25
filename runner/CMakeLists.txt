set(PROJECT_NAME runner)
add_executable(runner)
target_compile_features(runner PUBLIC cxx_std_20)
target_compile_options(runner PRIVATE
    # Common C/C++ options
    -Wall -Wextra -Wno-psabi
    -Wno-unused-parameter
    -Wno-unused-variable
    # -Wno-unused-but-set-variable

    # C++ specific options
    $<$<COMPILE_LANGUAGE:CXX>:-fexceptions -frtti>
)
target_link_libraries(runner PRIVATE -static
    arm-context # cpu struct
    WinHvPlatform WinHvEmulation # winapi hypervisor DLLs
)
target_sources(runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/runner.cpp
)
