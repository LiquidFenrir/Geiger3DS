#!/bin/bash

set -e

if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters" && false
fi

script_name=$0
script_full_path=$(dirname "$0")

examples_bin_dir="$1"; shift
example_name="$1"; shift
build_dir="$1"; shift

example_self_dir="$examples_bin_dir/$example_name"

echo "Recog $example_name"
"$script_full_path/do_use_recompiler.sh" "$example_self_dir" "$example_self_dir/recompiled" "$build_dir"
