# some sort of ARM binary to C static recompiler

Beginning of a Windows-only 3ds emulator, for fun.  

## License

BDS 3-clause like Capstone, I guess ? a few bits of its headers for arm ended up in the arm_cpu_ctx.h  
Also adapted some parts of dynarmic (BSD-0) for ldrex/strex/clrex.

## Usage

Clone https://github.com/capstone-engine/capstone (branch next as of 2024-06-21) inside this repo's folder, then run `./scripts/do_all.sh <path to the folder with the bins> <output name/path, without extension>` in this repo's folder.  
Make sure to have cut up a 3ds exefs codebin (or 3dsxdump a homebrew) into .text (code.bin), .rodata (rodata.bin) and .data (data.bin) and put the files (names in parens) somewhere. Don't need to remove zero padding to page align, if it exists.  

Needs MINGW64 environment of MSYS2 on Windows  
Maybe don't use this ? Or read `/scripts/do_all.sh` and `recompiler.cpp` for examples.  
Not a great tool, not great code, only barely works, written in a week's worth of late nights. No warranty or liability.  
Has a couple heuristics (switch detection from cmp->ldr(ls|lo) pc, treats all pointers to the code area from rodata/data as function pointers, etc) to detect more actual code and hopefully miss none (also avoid false positives)  
Constant pools make this surprisingly hard.

## TODO

- linker script to put the generated .o/.elf at the right spot for the Windows Hypervisor Platform VM (in `runner.cpp`) to work.  
- finish the VM/kernel
- add decoding files to extract codebins
- run some actual sysmodules to not HLE everything
- don't get burned out
