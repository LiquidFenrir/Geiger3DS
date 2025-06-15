#!/bin/bash

set -e

# if [ "$#" -ne 3 ]; then
if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters" && false
fi

sections_dir="$1"; shift
# output_path="$1"; shift
build_dir="$1"; shift

# "$build_dir/recompiler/recompiler" "$sections_dir/code.bin"  "$sections_dir/rodata.bin"  "$sections_dir/data.bin" "$output_path" > "$output_path.dump.txt"
"$build_dir/recompiler/recompiler" "$sections_dir"
