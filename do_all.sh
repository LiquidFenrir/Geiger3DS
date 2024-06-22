#!/bin/bash
echo "bins in folder $1"
echo "output name $2"
set -e -x
./do_compile_capstone.sh
./do_build_recompiler.sh
./recompiler.exe "$1/code.bin"  "$1/rodata.bin"  "$1/data.bin" "$2" > "$2.dump.txt"
./do_step_compile_child.sh outtest
