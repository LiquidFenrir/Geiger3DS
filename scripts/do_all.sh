#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters"
fi

echo "bins in folder $1"
echo "output name $2"
echo "build dir $3"
set -e -x
./scripts/do_build.sh "$3"
./scripts/do_use_recompiler.sh "$1" "$2" "$3"
# ./scripts/do_step_compile_child.sh "$2" "$3"
