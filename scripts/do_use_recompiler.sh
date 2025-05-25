#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters"
fi

$3/recompiler/recompiler "$1/code.bin"  "$1/rodata.bin"  "$1/data.bin" "$2" > "$2.dump.txt"
