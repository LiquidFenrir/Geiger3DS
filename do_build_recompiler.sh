#!/bin/bash
capstone_library=$(ls ./capstone-build/*.a  ./capstone-build/*.lib 2> /dev/null)
capstone_library_without_dot=$(echo -n "$capstone_library" | tail -c +3)
g++ -o recompiler recompiler.cpp -Wall -Wextra -g -static -std=c++20 "-Icapstone-build/include" "-L." "-l:$capstone_library_without_dot"
