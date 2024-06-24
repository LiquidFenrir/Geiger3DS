#!/bin/bash
echo "bins in folder $1"
echo "output name $2"
set -e -x
./do_compile_capstone.sh
./do_build_recompiler.sh
./do_use_recompiler "$1" "$2"
./do_step_compile_child.sh "$2"
