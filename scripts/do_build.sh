#!/bin/bash

set -e

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters" && false
fi

build_dir="$1"; shift

cmake -S . -B "$build_dir" -G Ninja
cmake --build "$build_dir"
