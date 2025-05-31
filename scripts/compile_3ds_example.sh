#!/bin/bash

set -e

if [ "$#" -lt 2 ]; then
    echo "Illegal number of parameters" && false
fi

script_name=$0
script_full_path=$(dirname "$0")

examples_bin_dir="$1"; shift
example_name="$1"; shift

echo "Compile $example_name"
"$script_full_path/compile_child.sh" "$examples_bin_dir/$example_name/recompiled" "$@"
