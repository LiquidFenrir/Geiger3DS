#!/bin/bash

cd ./3ds-examples
make -j4

# copy every elf to the bin folder next to its related 3dsx
find . -name \*.elf -exec cp {} ./bin/ ';'

cd ./bin

# move every 3dsx and elf to a folder with the same name
find . -maxdepth 1 -name \*.3dsx -exec bash -c 'echo $1 | tail -c +3 | head -c -6' namesfrom3dsx {} ';' | xargs -i bash -c 'mkdir "./{}" && mv "./{}.*" "./{}/"'

# dump the 3dsx and the bin's page count per section
find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c '3dsxdump "./{}/{}.3dsx" "./{}/{}.bin" > "./{}/{}.pages.txt"'

# disassemble the elf
find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c '$DEVKITARM/bin/arm-none-eabi-objdump -j .text -z -d "./{}/{}.elf" > "./{}/{}.objdump.txt"'

# code size
# find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'echo $((4*$(cat "./{}/{}.pages.txt" | tail -n +1 | head -n 1 | tail -c +9 | head -c -8)))KiB'
# rodata size
# find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'echo $((4*$(cat "./{}/{}.pages.txt" | tail -n +2 | head -n 1 | tail -c +9 | head -c -8)))KiB'
# data size
# find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'echo $((4*$(cat "./{}/{}.pages.txt" | tail -n +3 | head -n 1 | tail -c +9 | head -c -8)))KiB'

# code
find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'head -c $((4*$(cat "./{}/{}.pages.txt" | tail -n +1 | head -n 1 | tail -c +9 | head -c -8)))KiB ./{}/{}.bin > ./{}/code.bin'

# rodata
find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'tail -c +$((4096*$(cat "./{}/{}.pages.txt" | tail -n +1 | head -n 1 | tail -c +9 | head -c -8)+1)) ./{}/{}.bin > ./{}/remcode.bin'
find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'head -c $((4*$(cat "./{}/{}.pages.txt" | tail -n +2 | head -n 1 | tail -c +9 | head -c -8)))KiB ./{}/remcode.bin > ./{}/rodata.bin'

# data (aka remainder after rodata)
find . -maxdepth 1 -exec bash -c 'echo $1 | tail -c +3' names {} ';' | xargs -i bash -c 'tail -c +$((4096*$(cat "./{}/{}.pages.txt" | tail -n +2 | head -n 1 | tail -c +9 | head -c -8)+1)) ./{}/remcode.bin > ./{}/data.bin'
