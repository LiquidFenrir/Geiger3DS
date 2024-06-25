#!/bin/bash

for appdir in $(ls ./3ds-examples/bin);
do
    ./scripts/do_use_recompiler.sh "./3ds-examples/bin/$appdir" "./3ds-examples/bin/$appdir/recompiled"
    grep -e "^unvisited: " "./3ds-examples/bin/$appdir/recompiled.dump.txt" > "./3ds-examples/bin/$appdir/unvisited.txt"
    python3 ./scripts/recognize_objump.py "./3ds-examples/bin/$appdir/unvisited.txt" "./3ds-examples/bin/$appdir/$appdir.objdump.txt" > "./3ds-examples/bin/$appdir/unvisited_checked.txt"
done
