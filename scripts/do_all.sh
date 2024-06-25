#!/bin/bash
echo "bins in folder $1"
echo "output name $2"
set -e -x
./scripts/do_compile_capstone.sh
./scripts/do_build_recompiler.sh
./scripts/do_use_recompiler.sh "$1" "$2"
./scripts/do_step_compile_child.sh "$2"
