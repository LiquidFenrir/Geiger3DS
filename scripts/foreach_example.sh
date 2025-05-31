#!/bin/bash

set -e

if [ "$#" -lt 2 ]; then
    echo "Illegal number of parameters" && false
fi

script_name=$0
script_full_path=$(dirname "$0")

action_name="$1"; shift
examples_bin_dir="$1"; shift

for appdir in $(ls "$examples_bin_dir");
do
    "$action_name" "$examples_bin_dir" "$appdir" "$@"
done
