#!/bin/bash

set -e

if [ "$#" -lt 3 ]; then
    echo "Illegal number of parameters" && false
fi

script_name=$0
script_full_path=$(dirname "$0")

examples_bin_dir="$1"; shift
example_name="$1"; shift
build_dir="$1"; shift

echo "3ds examples bin dir $examples_bin_dir"
echo "example name $example_name"
echo "proj build dir $build_dir"

"$script_full_path/recog_3ds_example.sh" "$examples_bin_dir" "$example_name" "$build_dir"
"$script_full_path/check_3ds_example.sh" "$examples_bin_dir" "$example_name"
"$script_full_path/compile_child.sh" "$examples_bin_dir/$example_name/recompiled" "$@"
