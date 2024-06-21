#!/bin/bash
set -e -x
./do_compile_capstone.sh
./do_build_recompiler.sh
./recompiler.exe ./code.bin ./rodata.bin ./data.bin outtest > outtest.dump.txt
./do_step_compile_child.sh outtest
