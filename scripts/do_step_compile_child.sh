#!/bin/bash

my_regular_flags="
-Wno-cpp
-Wl,-eentry
-nostdlib
-mno-red-zone
-mtune=generic
-march=sandybridge
-m64
-mno-mmx
-mfpmath=sse
-mavx
-include ./include/arm_cpu_ctx.h
-ffreestanding
-fno-reorder-functions
-fno-unwind-tables
-ftime-report
-Wstack-usage=0
"

my_regular_flags_clean=$(echo -e "$my_regular_flags" | tr '\n' ' ')

# clang -o "$1.elf" -O2 $my_regular_flags_clean -I. -c "$1.src.c"
gcc -o "$1.elf" -O2 $my_regular_flags_clean -I. -c "$1.src.c"
