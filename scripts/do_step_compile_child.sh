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
-ftime-report
-Wstack-usage=2048
"

my_regular_flags_clean=$(echo -e "$my_regular_flags" | tr '\n' ' ')

gcc -o "$1.elf" -O1 $my_regular_flags_clean -I. -c "$1.src.c"
#  -Wl,--section-start=.text=0x400000000
