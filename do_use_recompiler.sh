#!/bin/bash
./recompiler.exe "$1/code.bin"  "$1/rodata.bin"  "$1/data.bin" "$2" > "$2.dump.txt"
