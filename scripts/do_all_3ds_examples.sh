#!/bin/bash

set -e

if [ "$#" -lt 2 ]; then
    echo "Illegal number of parameters" && false
fi

script_name=$0
script_full_path=$(dirname "$0")

# prep_cmd="$1"; shift
# recog_cmd="$1"; shift
# check_cmd="$1"; shift
# compile_cmd="$1"; shift

# only needed once really, so make it fail on next tries
prep_cmd="mkdir $examples_dir/bin"
recog_cmd="true"
# measure the amount of failed recognitions/heuristics, in number of wrongly-matched instructions
check_cmd="true"
# try to compile the C (result of recog) to x64
compile_cmd="true"

examples_dir="$1"; shift
build_dir="$1"; shift

# https://github.com/devkitPro/3ds-examples/
echo "3ds examples dir $examples_dir"
echo "proj build dir $build_dir"

"$prep_cmd" && "$script_full_path/prepare_all_3ds_examples.sh" "$examples_dir"
"$recog_cmd" && "$script_full_path/foreach_example.sh" "$script_full_path/recog_3ds_example.sh" "$examples_dir/bin" "$build_dir"
"$check_cmd" && "$script_full_path/foreach_example.sh" "$script_full_path/check_3ds_example.sh" "$examples_dir/bin"
"$compile_cmd" && "$script_full_path/foreach_example.sh" "$script_full_path/compile_3ds_example.sh" "$examples_dir/bin" "$@"
echo "Done"
