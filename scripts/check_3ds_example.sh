#!/bin/bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters" && false
fi

script_name=$0
script_full_path=$(dirname "$0")

examples_bin_dir="$1"; shift
example_name="$1"; shift

example_self_dir="$examples_bin_dir/$example_name"

echo "Check $example_name"
grep -e "^unvisited: " "$example_self_dir/recompiled.dump.txt" > "$example_self_dir/unvisited.txt"
python3 "$script_full_path/recognize_objdump.py" "$example_self_dir/unvisited.txt" "$example_self_dir/$example_name.objdump.txt" > "$example_self_dir/unvisited_checked.txt"
echo -n "Encountered non-matches: "
cat "$example_self_dir/unvisited_checked.txt" | wc -l
