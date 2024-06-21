#!/bin/bash
gcc -o "$1.elf" -O2 -Wl,-eentry -nostdlib -mno-red-zone -m64 -ffreestanding -c "$1.src.c" -I$(dirname "$1")
#  -Wl,--section-start=.text=0x400000000
