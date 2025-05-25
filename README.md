# some sort of ARM binary to C static recompiler

Beginning of a Windows-only 3ds emulator, for fun.  

## License

BDS 3-clause like Capstone, I guess ? a few bits of its headers for arm ended up in the arm_cpu_ctx.h file  
Also adapted some parts of dynarmic (BSD-0) for ldrex/strex/clrex.

## Usage

Build with CMake. There are 2 resulting subfolders with .exe in them, one for recompiler and one for runner.
Make sure to have cut up a 3ds exefs codebin (or 3dsxdump a homebrew) into .text (code.bin), .rodata (rodata.bin) and .data (data.bin) and put the files (names in parens) somewhere. Don't need to remove zero padding to page align, if it exists.  

Needs MINGW64 environment of MSYS2 on Windows, this will not compile under MSVC  
Maybe don't use this ? Or read `/scripts/do_all.sh` and `recompiler.cpp` for examples.  
Not a great tool, not great code, only barely works, written in a week's worth of late nights. No warranty or liability.  
Has a couple heuristics (switch detection from cmp->ldr(ls|lo) pc, treats all pointers to the code area from rodata/data as function pointers, etc) to detect more actual code and hopefully miss none (also avoid false positives)  
Constant pools make this surprisingly hard.  
I learned since then and the PC register value used in some decompiled instructions is incorrect (pipeline stuff), figuring it out.

## TODO

- linker script to put the generated .o/.elf at the right spot for the Windows Hypervisor Platform VM (in `runner.cpp`) to work.  
- finish the VM/kernel
- add decoding files to extract codebins
- run some actual sysmodules to not HLE everything
- don't get burned out <- that went well.
