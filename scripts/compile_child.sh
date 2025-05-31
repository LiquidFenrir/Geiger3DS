#!/bin/bash

# WIP
# optimal flags have not been found yet
# compile times are awful, even for the examples

set -e

if [ "$#" -lt 1 ]; then
    echo "Illegal number of parameters" && false
fi

working_on="$1"; shift
extra_flags="$@"

my_regular_flags="
    -Wno-cpp
    -Wl,-eentry
    -nostdlib
    -mno-red-zone
    -mtune=generic
    -march=sandybridge
    -m64
    -mno-mmx
    -mfpmath=sse
    -std=c23
    -mavx
    -ffreestanding
    -masm=intel
    -Wstack-usage=8
    -fno-reorder-functions
    -fno-reorder-blocks
    -fno-unwind-tables
    -fno-gcse
    -fno-dce
    -fno-dse
    -fno-tree-reassoc
    -fno-tree-dce
    -fno-code-hoisting
    -fno-tree-pre
    -fno-tree-fre
    -fno-tree-partial-pre
    -fno-guess-branch-probability
    -fno-tree-tail-merge
    -fno-crossjumping
    -fno-branch-count-reg
    -fno-delayed-branch
    -fno-if-conversion
    -fno-if-conversion2
    -fno-inline-functions-called-once
    -fno-move-loop-invariants
    -fno-move-loop-stores
    -fno-ssa-phiopt
    -fno-tree-bit-ccp
    -fno-tree-ccp
    -fno-tree-dse
    -fno-tree-pta
    -fno-thread-jumps
    -fno-cprop-registers
    -fno-compare-elim
    -fno-toplevel-reorder
    -fno-ipa-pure-const
    -fno-ipa-reference
    -fno-ipa-reference-addressable
    -fno-ipa-profile
    -fno-ipa-modref
    -fno-tree-dominator-opts
"
# -fno-tree-loop-optimize ?
# -fverbose-asm
# -fno-reorder-functions
# -fno-reorder-blocks
# -fno-reorder-blocks-and-partition
# -fno-unwind-tables
# -fno-ssa-backprop ?
# -fno-tree-ter
# -fno-tree-coalesce-vars ?

# example:
# ./scripts/compile_child.sh <path> '-ftime-report'
my_full_flags="$my_regular_flags $extra_flags"

my_flags_clean=$(echo -e "$my_full_flags" | tr '\n' ' ')

output_path="${working_on}.s"
gcc -o "$output_path" -O1 -S $my_flags_clean -c "${working_on}.src.c"
gcc -o "${working_on}.elf" $my_flags_clean -c "$output_path"

# both produce the same result, dont need to actually compile source twice or have different elf names
# gcc -o "${working_on}.s.elf" -O1 $my_flags_clean -c "${working_on}.s"
# gcc -o "${working_on}.c.elf" -O1 $my_flags_clean -c "${working_on}.src.c"
