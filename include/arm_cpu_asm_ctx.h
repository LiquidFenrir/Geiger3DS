#pragma once

#include "typedefs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYNC_INVALID_EXCLUSIVE_ADDRESS (0xffffffff)

typedef struct arm_cpu_asm_ctx {
    union {
        struct {
            u32_t r6;
            u32_t r7;
            u32_t r8;
            u32_t r9;
            u32_t r10;
            u32_t r11;
            u32_t r12;
        };
        u32_t regs[7];
    };
    union {
        union {
            float f32_banks[4][8];
            struct {
                float s0;
                float s1;
                float s2;
                float s3;
                float s4;
                float s5;
                float s6;
                float s7;
                float s8;
                float s9;
                float s10;
                float s11;
                float s12;
                float s13;
                float s14;
                float s15;
                float s16;
                float s17;
                float s18;
                float s19;
                float s20;
                float s21;
                float s22;
                float s23;
                float s24;
                float s25;
                float s26;
                float s27;
                float s28;
                float s29;
                float s30;
                float s31;
            };
        };
        union {
            double f64_banks[4][4];
            struct {
                double d0;
                double d1;
                double d2;
                double d3;
                double d4;
                double d5;
                double d6;
                double d7;
                double d8;
                double d9;
                double d10;
                double d11;
                double d12;
                double d13;
                double d14;
                double d15;
            };
        };
    };
    struct {
        u32_t thread_upro;
        u32_t thread_uprw;
    } cp15;
    u32_t cpsr; // start as 0x00000010
    u32_t fpscr;
    u32_t fpexc;
    u32_t fpsid; // 0x410120b4
    const void* indirect_brancher; // noreturn void indirect_brancher(arm_cpu_ctx*, u32_t);
    u32_t thread_id;
    u32_t mxcsr_value;
    // [0, ..., N)
    u32_t cpu_id;
    u32_t num_cpus;
    // lock value for cmpxchg: cpu_id + 1 when set, 0 when unset.
    u32_t* sync_data_lock;
    // offset: cpu_id
    volatile u32_t* sync_addresses;
    volatile u64_t* sync_data;
} arm_cpu_asm_ctx;

#ifdef __cplusplus
}
#endif
