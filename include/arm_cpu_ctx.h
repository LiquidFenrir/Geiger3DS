#include <stdint.h>
#include <stddef.h>

#define ATTR_FORCE_INLINE __attribute__((__always_inline__))
#define ATTR_NORETURN __attribute__((__noreturn__))
#define ATTR_FASTCALL __attribute__((__fastcall__))
#define ATTR_NO_SAVE_REGS __attribute__((__no_callee_saved_registers__))
#define ARM_CPU_PC_AHEAD_THUMB (2 * 2)
#define ARM_CPU_PC_AHEAD_ARM (4 * 2)

#define ARM_SYNC_EXCLUSIVE_MASK (0xfffffff8)
#define ARM_SYNC_INVALID_EXCLUSIVE_ADDRESS (0xffffffff)

typedef enum arm_cpu_cc {
  arm_cpu_cc_eq = 0, // Equal
  arm_cpu_cc_ne, // Not equal
  arm_cpu_cc_hs, // Carry set
  arm_cpu_cc_lo, // Carry clear
  arm_cpu_cc_mi, // Minus, negative
  arm_cpu_cc_pl, // Plus, positive or zero
  arm_cpu_cc_vs, // Overflow
  arm_cpu_cc_vc, // No overflow
  arm_cpu_cc_hi, // Unsigned higher
  arm_cpu_cc_ls, // Unsigned lower or same
  arm_cpu_cc_ge, // Greater than or equal
  arm_cpu_cc_lt, // Less than
  arm_cpu_cc_gt, // Greater than
  arm_cpu_cc_le, // Less than or equal
  arm_cpu_cc_al, // Always (unconditional)
  arm_cpu_cc_undef = 15, // Undefined
} arm_cpu_cc;

#define ARM_CPU_STATUS_get(cpsr, bitindex) ((cpsr) & (1u << (bitindex)))

#define ARM_CPU_STATUS_N_GET(ctx) ARM_CPU_STATUS_get((ctx)->cpsr, 31)
#define ARM_CPU_STATUS_Z_GET(ctx) ARM_CPU_STATUS_get((ctx)->cpsr, 30)
#define ARM_CPU_STATUS_C_GET(ctx) ARM_CPU_STATUS_get((ctx)->cpsr, 29)
#define ARM_CPU_STATUS_V_GET(ctx) ARM_CPU_STATUS_get((ctx)->cpsr, 28)
#define ARM_CPU_STATUS_Q_GET(ctx) ARM_CPU_STATUS_get((ctx)->cpsr, 27)
#define ARM_CPU_STATUS_T_GET(ctx) ARM_CPU_STATUS_get((ctx)->cpsr, 5)
#define ARM_CPU_STATUS_GE_GET(ctx) (((ctx)->cpsr) & 0x000f0000)

#define ARM_CPU_STATUS_bitindex(cpsr, bitindex) (int)(ARM_CPU_STATUS_get(cpsr, bitindex) != 0)

#define ARM_CPU_STATUS_N(ctx) ARM_CPU_STATUS_bitindex((ctx)->cpsr, 31)
#define ARM_CPU_STATUS_Z(ctx) ARM_CPU_STATUS_bitindex((ctx)->cpsr, 30)
#define ARM_CPU_STATUS_C(ctx) ARM_CPU_STATUS_bitindex((ctx)->cpsr, 29)
#define ARM_CPU_STATUS_V(ctx) ARM_CPU_STATUS_bitindex((ctx)->cpsr, 28)
#define ARM_CPU_STATUS_Q(ctx) ARM_CPU_STATUS_bitindex((ctx)->cpsr, 27)
#define ARM_CPU_STATUS_T(ctx) ARM_CPU_STATUS_bitindex((ctx)->cpsr, 5)
#define ARM_CPU_STATUS_GE(ctx) (((ctx)->cpsr >> 16) & 0xf)

#define ARM_CPU_STATUS_set(ctx, new_flag, bitindex) (((ctx)->cpsr & ~(1u << (bitindex))) | (new_flag << (bitindex)))

#define ARM_CPU_STATUS_N_SET(ctx, new_flag) ARM_CPU_STATUS_set(ctx, new_flag, 31)
#define ARM_CPU_STATUS_Z_SET(ctx, new_flag) ARM_CPU_STATUS_set(ctx, new_flag, 30)
#define ARM_CPU_STATUS_C_SET(ctx, new_flag) ARM_CPU_STATUS_set(ctx, new_flag, 29)
#define ARM_CPU_STATUS_V_SET(ctx, new_flag) ARM_CPU_STATUS_set(ctx, new_flag, 28)
#define ARM_CPU_STATUS_Q_SET(ctx, new_flag) ARM_CPU_STATUS_set(ctx, new_flag, 27)
#define ARM_CPU_STATUS_GE_SET(ctx, new_value) (((ctx)->cpsr & ~0x000f0000) | (((new_value) & 0xf) << 16))
// #define ARM_CPU_STATUS_T_SET(ctx, value) ((ctx)->cpsr = ((((ctx)->cpsr) & ~(1u << 5)) | ((uint32_t)(value != 0) << 5)))

typedef struct arm_cpu_ctx {
    union {
        struct {
            uint32_t r0;
            uint32_t r1;
            uint32_t r2;
            uint32_t r3;
            uint32_t r4;
            uint32_t r5;
            uint32_t r6;
            uint32_t r7;
            union {
                uint32_t r8;
                uint32_t r8_usr;
            };
            union {
                uint32_t r9;
                uint32_t r9_usr;
            };
            union {
                uint32_t r10;
                uint32_t r10_usr;
            };
            union {
                uint32_t r11;
                uint32_t r11_usr;
            };
            union {
                uint32_t r12;
                uint32_t r12_usr;
            };
            union {
                uint32_t sp;
                uint32_t sp_usr;
                uint32_t r13;
            };
            union {
                uint32_t lr;
                uint32_t lr_usr;
                uint32_t r14;
            };
            union {
                uint32_t pc;
                uint32_t r15;
            };
        };
        uint32_t regs[16];
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
        uint32_t thread_upro;
        uint32_t thread_uprw;
    } cp15;
    uint32_t cpsr; // start as 0x00000010
    uint32_t fpscr;
    uint32_t fpexc;
    uint32_t fpsid; // 0x410120b4
    uint32_t base_addr;
#if ARM_RUNTIME_PC_OFFSET
    uint32_t pc_offset;
#endif
    uint32_t thread_id;
    // [0, ..., N)
    uint32_t cpu_id;
    uint32_t num_cpus;
    // lock value for cmpxchg: cpu_id + 1 when set, 0 when unset.
    uint32_t* sync_data_lock;
    // offset: cpu_id
    volatile uint32_t* sync_addresses;
    volatile uint64_t* sync_data;
} arm_cpu_ctx;

// begins the extraction:
// expands ARGEXTRACT_X arguments [aka ARGEXTRACT_X (abc, def)(ijk, lmn)] to
// ARGEXTRACT_X_LOOP_BODY(abc, def,) ARGEXTRACT_X_LOOP_B(ijk, lmn)_END
// aka ARGEXTRACT_X_LOOP_BODY(abc, def,) ARGEXTRACT_X_LOOP_BODY(ijk, lmn, 0) ARGEXTRACT_X_LOOP_C_END
// and so on for different lengths of 'arguments' tuple
#define ARGEXTRACT_DO(...) ARGEXTRACT_DO_(__VA_ARGS__)
#define ARGEXTRACT_DO_(...) __VA_ARGS__##_END

static inline int ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_check_cc(const arm_cpu_ctx* const ctx, const arm_cpu_cc cc)
{
    // disable the "negative" ones which are always the opposite of the one before
    // thus need to invert the check when the "negative" one is the actual value
#define ARM_CPU_PERFORM_cc(check) (((int)(cc) & 1) != (check))
    switch((int)cc & ~1)
    {
    case arm_cpu_cc_eq: // Equal
        return ARM_CPU_PERFORM_cc(ARM_CPU_STATUS_Z(ctx) == 1);
    case arm_cpu_cc_hs: // Carry set
        return ARM_CPU_PERFORM_cc(ARM_CPU_STATUS_C(ctx) == 1);
    case arm_cpu_cc_mi: // Minus, negative
        return ARM_CPU_PERFORM_cc(ARM_CPU_STATUS_N(ctx) == 1);
    case arm_cpu_cc_vs: // Overflow
        return ARM_CPU_PERFORM_cc(ARM_CPU_STATUS_V(ctx) == 1);
    case arm_cpu_cc_hi: // Unsigned higher
        return ARM_CPU_PERFORM_cc((ARM_CPU_STATUS_C(ctx) == 1) && (ARM_CPU_STATUS_Z(ctx) == 0));
    case arm_cpu_cc_ge: // Greater than or equal
        return ARM_CPU_PERFORM_cc(ARM_CPU_STATUS_N(ctx) == ARM_CPU_STATUS_V(ctx));
    case arm_cpu_cc_gt: // Greater than
        return ARM_CPU_PERFORM_cc((ARM_CPU_STATUS_Z(ctx) == 0) && (ARM_CPU_STATUS_N(ctx) == ARM_CPU_STATUS_V(ctx)));
    case arm_cpu_cc_al: // Always (unconditional)
        return ARM_CPU_PERFORM_cc(1);
    default: // Undefined or invalid value
        return 0;
    }
#undef ARM_CPU_PERFORM_cc
}

static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_set_cpsr(arm_cpu_ctx* const ctx, const uint32_t value)
{
    // clear the bits that are "read-as-X" and then set the ones that need to be "read-as-1"
    ctx->cpsr = (value & 0xf90f03ff) | 0x00000000;
}
static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_set_apsr(arm_cpu_ctx* const ctx, const char* flags_to_write, const uint32_t value)
{
    while(flags_to_write && *flags_to_write) switch(*flags_to_write++)
    {
    case 'N':
        ARM_CPU_STATUS_N_SET(ctx, ARM_CPU_STATUS_bitindex(value, 31));
        break;
    case 'Z':
        ARM_CPU_STATUS_Z_SET(ctx, ARM_CPU_STATUS_bitindex(value, 30));
        break;
    case 'C':
        ARM_CPU_STATUS_C_SET(ctx, ARM_CPU_STATUS_bitindex(value, 29));
        break;
    case 'V':
        ARM_CPU_STATUS_V_SET(ctx, ARM_CPU_STATUS_bitindex(value, 28));
        break;
    case 'Q':
        ARM_CPU_STATUS_Q_SET(ctx, ARM_CPU_STATUS_bitindex(value, 27));
        break;
    case 'G':
        ARM_CPU_STATUS_GE_SET(ctx, ((value >> 16) & 0xf));
        break;
    default:
        break;
    }
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_get_apsr(const arm_cpu_ctx* const ctx, const char* flags_to_write)
{
    uint32_t out = 0;
    while(flags_to_write && *flags_to_write) switch(*flags_to_write++)
    {
    case 'N':
        out |= ARM_CPU_STATUS_N_GET(ctx);
        break;
    case 'Z':
        out |= ARM_CPU_STATUS_Z_GET(ctx);
        break;
    case 'C':
        out |= ARM_CPU_STATUS_C_GET(ctx);
        break;
    case 'V':
        out |= ARM_CPU_STATUS_V_GET(ctx);
        break;
    case 'Q':
        out |= ARM_CPU_STATUS_Q_GET(ctx);
        break;
    case 'G':
        out |= ARM_CPU_STATUS_GE_GET(ctx);
        break;
    default:
        break;
    }
    return out;
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_compute_arm_offset(arm_cpu_ctx* const ctx, const uint32_t addr)
{
    return (addr - ctx->base_addr) >> 2;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_compute_thumb_offset(arm_cpu_ctx* const ctx, const uint32_t addr)
{
    return (addr - ctx->base_addr) >> 1;
}

// ONLY PASS 0 OR 1 IN NEW_FLAG
static inline void ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_STATUS_T_SET(arm_cpu_ctx* const ctx, const uint32_t new_flag)
{
    ctx->cpsr = ((ctx->cpsr) & ~(1u << 5)) | (new_flag << 5);
#if ARM_RUNTIME_PC_OFFSET
    if(new_flag) // thumb
        ctx->pc_offset = 4;
    else // arm
        ctx->pc_offset = 8;
#endif
}

static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_update_pc(volatile arm_cpu_ctx* const ctx, const uint32_t new_pc
#if !ARM_RUNTIME_PC_OFFSET
, const uint32_t pc_offset
#endif
)
{
    // slow but works
    // ctx->pc = new_pc + (ARM_CPU_STATUS_T(ctx) ? 4 : 8);
    // faster ?
    // ctx->pc = new_pc + (((ARM_CPU_STATUS_T_GET(ctx) ^ (1u << 5)) + (1u << 5)) >> 3);
    // even better ? at least way less instructions than either
    ctx->pc = new_pc +
#if ARM_RUNTIME_PC_OFFSET
    ctx->
#endif
    pc_offset;
}

static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_instr_svc(arm_cpu_ctx* const ctx, const int64_t svc_id)
{
    __asm__ __volatile__ ("int3"
        : /* No outputs */
        : "d"(svc_id)
        : "memory");
}
static inline void ATTR_FASTCALL ATTR_NORETURN ATTR_FORCE_INLINE arm_cpu_instr_runtime_error(arm_cpu_ctx* const ctx)
{
    arm_cpu_instr_svc(ctx, -1);
    __builtin_unreachable();
}
static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_instr_udf(arm_cpu_ctx* const ctx, const int64_t udf_id)
{
    arm_cpu_instr_svc(ctx, -(16 + udf_id));
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE util_rotl32(const uint32_t n, uint32_t c)
{
    const uint32_t mask = 31;
    c &= mask;
    return (n << c) | (n >> ((-c) & mask));
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE util_rotr32(const uint32_t n, uint32_t c)
{
    const uint32_t mask = 31;
    c &= mask;
    return (n >> c) | (n << ((-c) & mask));
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_update_carry_flag_constant_operand2(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t imm)
{
    if(!set_flags) return imm;
    if(imm <= 255) return imm;
    for(unsigned i = 1; i < 32; ++i)
    {
        const uint32_t rotted = util_rotl32(imm, i);
        if(util_rotr32(rotted & 0xff, i) == imm)
        {
            ARM_CPU_STATUS_C_SET(ctx, ((imm & (1u << 31)) != 0));
            break;
        }
    }
    return imm;
}
static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_update_flags_NZ_32(arm_cpu_ctx* const ctx, const uint32_t value)
{
    ARM_CPU_STATUS_N_SET(ctx, ((value & (1u << 31)) != 0));
    ARM_CPU_STATUS_Z_SET(ctx, (value == 0));
}
static inline void ATTR_FASTCALL ATTR_FORCE_INLINE arm_cpu_update_flags_NZ_64(arm_cpu_ctx* const ctx, const uint64_t value)
{
    ARM_CPU_STATUS_N_SET(ctx, ((value & (1ull << 63)) != 0));
    ARM_CPU_STATUS_Z_SET(ctx, (value == 0));
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_ASR(arm_cpu_ctx* const ctx, const uint32_t value, const uint32_t shift)
{
    return (uint32_t)((int32_t)value >> shift);
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_LSL(arm_cpu_ctx* const ctx, const uint32_t value, const uint32_t shift)
{
    return value << shift;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_LSR(arm_cpu_ctx* const ctx, const uint32_t value, const uint32_t shift)
{
    return value >> shift;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_ROR(arm_cpu_ctx* const ctx, const uint32_t value, const uint32_t shift)
{
    return util_rotr32(value, shift);
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_RRX(arm_cpu_ctx* const ctx, const uint32_t value, const int update_flags)
{
    const uint32_t current_carry = ARM_CPU_STATUS_C(ctx);
    if(update_flags) ARM_CPU_STATUS_C_SET(ctx, (value & 1));
    return (value >> 1) | (current_carry << 31);
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_ASR_REG(arm_cpu_ctx* const ctx, const uint32_t value, const int update_flags, uint8_t shift)
{
    if(shift == 0) return value;
    if(shift >= 32)
    {
        const uint32_t output = (int32_t)value >> 31;
        if(update_flags)
        {
            ARM_CPU_STATUS_C_SET(ctx, (output & 1));
        }
        return output;
    }
    else
    {
        const uint32_t output = (int32_t)value >> shift;
        if(update_flags)
        {
            ARM_CPU_STATUS_C_SET(ctx, ((value >> (shift - 1)) & 1));
        }
        return output;
    }
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_LSL_REG(arm_cpu_ctx* const ctx, const uint32_t value, const int update_flags, const uint8_t shift)
{
    if(shift == 0) return value;
    if(shift >= 32)
    {
        if(update_flags)
        {
            if(shift >= 33)
            {
                ARM_CPU_STATUS_C_SET(ctx, 0);
            }
            else
            {
                ARM_CPU_STATUS_C_SET(ctx, (value & 1));
            }
        }
        return 0;
    }
    else
    {
        const uint32_t output = value << shift;
        if(update_flags)
        {
            ARM_CPU_STATUS_C_SET(ctx, ((value & (1u << (32 - shift))) != 0));
        }
        return output;
    }
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_LSR_REG(arm_cpu_ctx* const ctx, const uint32_t value, const int update_flags, const uint8_t shift)
{
    if(shift == 0) return value;
    if(shift >= 32)
    {
        if(update_flags)
        {
            if(shift >= 33)
            {
                ARM_CPU_STATUS_C_SET(ctx, 0);
            }
            else
            {
                ARM_CPU_STATUS_C_SET(ctx, ((value >> 31) & 1));
            }
        }
        return 0;
    }
    else
    {
        const uint32_t output = value >> shift;
        if(update_flags)
        {
            ARM_CPU_STATUS_C_SET(ctx, ((value >> (shift - 1)) & 1));
        }
        return output;
    }
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_ROR_REG(arm_cpu_ctx* const ctx, const uint32_t value, const int update_flags, const uint8_t shift)
{
    if(shift == 0) return value;
    if(shift % 32 == 0)
    {
        if(update_flags)
        {
            ARM_CPU_STATUS_C_SET(ctx, ((value >> 31) & 1));
        }
        return value;
    }
    else
    {
        const uint32_t output = util_rotr32(value, shift % 32);
        if(update_flags)
        {
            ARM_CPU_STATUS_C_SET(ctx, ((value >> (shift - 1)) & 1));
        }
        return output;
    }
}

#define ARM_CPU_PERFORM_ARM_B(ctx, target) do { \
    goto LABEL_ARM_##target; \
} while(0)

#define ARM_CPU_PERFORM_THUMB_B(ctx, target) do { \
    goto LABEL_THUMB_##target; \
} while(0)

#define ARM_CPU_PERFORM_BRANCH_REG(ctx, reg) do { \
    if(ARM_CPU_STATUS_T(ctx)) goto* (&&LABEL_THUMB_start + LABELS_THUMB_TABLE[arm_cpu_compute_thumb_offset(ctx, reg)]); \
    else goto* (&&LABEL_ARM_start + LABELS_ARM_TABLE[arm_cpu_compute_arm_offset(ctx, reg)]); \
} while(0)

#define ARM_CPU_PERFORM_BX(ctx, reg) do { \
    if((reg) & 1) { \
        ARM_CPU_STATUS_T_SET(ctx, 1); \
        goto* (&&LABEL_THUMB_start + LABELS_THUMB_TABLE[arm_cpu_compute_thumb_offset(ctx, reg)]); \
    } else { \
        ARM_CPU_STATUS_T_SET(ctx, 0); \
        goto* (&&LABEL_ARM_start + LABELS_ARM_TABLE[arm_cpu_compute_arm_offset(ctx, reg)]); \
    } \
} while(0)

#define ARM_CPU_PERFORM_ARM_BL(ctx, target) do { \
    ctx->lr = ctx->pc - 4; \
    goto LABEL_ARM_##target; \
} while(0)
#define ARM_CPU_PERFORM_ARM_BLX_IMM(ctx, target) do { \
    ctx->lr = ctx->pc - 4; \
    ARM_CPU_STATUS_T_SET(ctx, 1); \
    goto LABEL_THUMB_##target; \
} while(0)
#define ARM_CPU_PERFORM_THUMB_BL(ctx, target) do { \
    ctx->lr = (ctx->pc - 2) | 1; \
    goto LABEL_THUMB_##target; \
} while(0)
#define ARM_CPU_PERFORM_THUMB_BLX_IMM(ctx, target) do { \
    ctx->lr = (ctx->pc - 2) | 1; \
    ARM_CPU_STATUS_T_SET(ctx, 0); \
    goto LABEL_ARM_##target; \
} while(0)

#define ARM_CPU_PERFORM_BLX_REG(ctx, reg) do { \
    if(ARM_CPU_STATUS_T(ctx)) ctx->lr = (ctx->pc - 2) | 1; \
    else ctx->lr = ctx->pc - 4; \
    ARM_CPU_PERFORM_BX(ctx, reg); \
} while(0)

#define ARM_CPU_PERFORM_LDR_ALL(ctx, destination, type_access, type_cast, base, operator, index, writeback, post_index) do { \
    uint32_t addr = base; \
    const uint32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    destination = type_cast *(type_access*)(uintptr_t)(addr); \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
    if((const unsigned char*)&(destination) == (const unsigned char*)&(ctx->pc)) ARM_CPU_PERFORM_BX(ctx, ctx->pc); \
} while(0)

#define ARM_CPU_PERFORM_LDRD(ctx, destinationA, destinationB, base, operator, index, writeback, post_index) do { \
    uint32_t addr = base; \
    const uint32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    destinationA = *(uint32_t*)(uintptr_t)(addr); \
    destinationB = *(uint32_t*)(uintptr_t)(addr + 4); \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
} while(0)

#define ARM_CPU_PERFORM_STR_ALL(ctx, source, type_access, bitmask_and, base, operator, index, writeback, post_index) do { \
    uint32_t addr = base; \
    const uint32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    *(type_access*)(uintptr_t)(addr) = source bitmask_and; \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
} while(0)

#define ARM_CPU_PERFORM_STRD(ctx, sourceA, sourceB, base, operator, index, writeback, post_index) do { \
    uint32_t addr = base; \
    const uint32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    *(uint32_t*)(uintptr_t)(addr) = sourceA; \
    *(uint32_t*)(uintptr_t)(addr + 4) = sourceB; \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
} while(0)

#define ARGEXTRACT_MULTIPLE_LDM(...) ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(__VA_ARGS__,) ARGEXTRACT_MULTIPLE_LDM_LOOP_B
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_B(...) ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_LDM_LOOP_C
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_C(...) ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_LDM_LOOP_B
#define ARGEXTRACT_MULTIPLE_LDM_END
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_B_END
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_C_END

#define ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(c_ldm_type, c_reg_index, c_reg_name, ...) ctx->c_reg_name = *(c_ldm_type*)(uintptr_t)(addr_start + c_reg_index * step_off);

#define ARM_CPU_PERFORM_LDM_ALL(ctx, base, writeback, init_off, step, final_off, arguments, write_pc) do { \
    const uint32_t addr_start = base + (init_off); \
    const uint32_t step_off = (step); \
    ARGEXTRACT_DO(ARGEXTRACT_MULTIPLE_LDM arguments); \
    if(writeback) base = base + (final_off); /* not allowed to have base in the reglist, but not checked */ \
    if(write_pc) ARM_CPU_PERFORM_BX(ctx, ctx->pc); \
} while(0)

#define ARGEXTRACT_MULTIPLE_STM(...) ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(__VA_ARGS__,) ARGEXTRACT_MULTIPLE_STM_LOOP_B
#define ARGEXTRACT_MULTIPLE_STM_LOOP_B(...) ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_STM_LOOP_C
#define ARGEXTRACT_MULTIPLE_STM_LOOP_C(...) ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_STM_LOOP_B
#define ARGEXTRACT_MULTIPLE_STM_END
#define ARGEXTRACT_MULTIPLE_STM_LOOP_B_END
#define ARGEXTRACT_MULTIPLE_STM_LOOP_C_END

#define ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(c_stm_type, c_reg_index, c_reg_name, ...) *(c_stm_type*)(uintptr_t)(addr_start + c_reg_index * step_off) = ctx->c_reg_name;

#define ARM_CPU_PERFORM_STM_ALL(ctx, base, writeback, init_off, step, final_off, arguments) do { \
    const uint32_t addr_start = base + (init_off); \
    const uint32_t step_off = (step); \
    ARGEXTRACT_DO(ARGEXTRACT_MULTIPLE_STM arguments); \
    if(writeback) base = base + (final_off); /* not allowed to have base in the reglist, but not checked */ \
} while(0)

#define ARM_CPU_PERFORM_FLAGS_cmp(ctx, argA, argB) do { \
    const uint32_t result = (argA) - (argB); \
    const int64_t result_big = (int64_t)(argA) - (int64_t)(argB); \
    ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    ARM_CPU_STATUS_Z_SET(ctx, (result == 0)); \
    ARM_CPU_STATUS_C_SET(ctx, (result_big >= 0)); \
    ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big)); \
} while(0)

#define ARM_CPU_PERFORM_FLAGS_cmn(ctx, argA, argB) do { \
    const uint32_t result = (argA) + (argB); \
    const int64_t result_big = (int64_t)(argA) + (int64_t)(argB); \
    ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    ARM_CPU_STATUS_Z_SET(ctx, (result == 0)); \
    ARM_CPU_STATUS_C_SET(ctx, (result_big >= (1ll << 32))); \
    ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big)); \
} while(0)

#define ARM_CPU_PERFORM_FLAGS_tst(ctx, argA, argB) do {  \
    const uint32_t result = (argA) & (argB); \
    ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    ARM_CPU_STATUS_Z_SET(ctx, (result == 0)); \
} while(0)

#define ARM_CPU_PERFORM_FLAGS_teq(ctx, argA, argB) do {  \
    const uint32_t result = (argA) ^ (argB); \
    ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    ARM_CPU_STATUS_Z_SET(ctx, (result == 0)); \
} while(0)

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_add(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t argA, const uint32_t argB)
{
    const uint32_t result = (argA) + (argB);
    if(set_flags)
    {
        const int64_t result_big = (int64_t)(argA) + (int64_t)(argB);
        ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        ARM_CPU_STATUS_Z_SET(ctx, (result == 0));
        ARM_CPU_STATUS_C_SET(ctx, (result_big >= (1ll << 32)));
        ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_sub(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t argA, const uint32_t argB)
{
    const uint32_t result = (argA) - (argB);
    if(set_flags)
    {
        const int64_t result_big = (int64_t)(argA) - (int64_t)(argB);
        ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        ARM_CPU_STATUS_Z_SET(ctx, (result == 0));
        ARM_CPU_STATUS_C_SET(ctx, (result_big >= 0));
        ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_rsb(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t argA, const uint32_t argB)
{
    const uint32_t result = (argB) - (argA);
    if(set_flags)
    {
        const int64_t result_big = (int64_t)(argB) - (int64_t)(argA);
        ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        ARM_CPU_STATUS_Z_SET(ctx, (result == 0));
        ARM_CPU_STATUS_C_SET(ctx, (result_big >= 0));
        ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_adc(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t argA, const uint32_t argB)
{
    const uint32_t result = (argA) + (argB) + (ARM_CPU_STATUS_C(ctx) ? 1 : 0);
    if(set_flags)
    {
        const int64_t result_big = (int64_t)(argA) + (int64_t)(argB) + (ARM_CPU_STATUS_C(ctx) ? 1 : 0);
        ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        ARM_CPU_STATUS_Z_SET(ctx, (result == 0));
        ARM_CPU_STATUS_C_SET(ctx, (result_big >= (1ll << 32)));
        ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_sbc(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t argA, const uint32_t argB)
{
    const uint32_t result = (argA) - (argB) + (ARM_CPU_STATUS_C(ctx) ? 0 : -1);
    if(set_flags)
    {
        const int64_t result_big = (int64_t)(argA) - (int64_t)(argB) + (ARM_CPU_STATUS_C(ctx) ? 0 : -1);
        ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        ARM_CPU_STATUS_Z_SET(ctx, (result == 0));
        ARM_CPU_STATUS_C_SET(ctx, (result_big >= 0));
        ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_rsc(arm_cpu_ctx* const ctx, const int set_flags, const uint32_t argA, const uint32_t argB)
{
    const uint32_t result = (argB) - (argA) + (ARM_CPU_STATUS_C(ctx) ? 0 : -1);
    if(set_flags)
    {
        const int64_t result_big = (int64_t)(argB) - (int64_t)(argA) + (ARM_CPU_STATUS_C(ctx) ? 0 : -1);
        ARM_CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        ARM_CPU_STATUS_Z_SET(ctx, (result == 0));
        ARM_CPU_STATUS_C_SET(ctx, (result_big >= 0));
        ARM_CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}

static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_rev(arm_cpu_ctx* const ctx, const uint32_t value)
{
    uint32_t output = 0;
    output |= ((value >> 0) & 0xff) << 24;
    output |= ((value >> 8) & 0xff) << 16;
    output |= ((value >> 16) & 0xff) << 8;
    output |= ((value >> 24) & 0xff) << 0;
    return output;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_rev16(arm_cpu_ctx* const ctx, const uint32_t value)
{
    uint32_t output = 0;
    output |= ((value >> 0) & 0xff) << 8;
    output |= ((value >> 8) & 0xff) << 0;
    output |= ((value >> 16) & 0xff) << 24;
    output |= ((value >> 24) & 0xff) << 16;
    return output;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_revsh(arm_cpu_ctx* const ctx, const uint32_t value)
{
    int16_t output = 0;
    output |= ((value >> 0) & 0xff) << 8;
    output |= ((value >> 8) & 0xff) << 0;
    return (int32_t)output;
}
static inline uint32_t ATTR_FASTCALL ATTR_FORCE_INLINE ARM_CPU_PERFORM_clz(arm_cpu_ctx* const ctx, const uint32_t value)
{
    uint32_t output = 0;
    for(int i = 31; i >= 0; --i, ++output)
    {
        if(value & (1u << i))
            break;
    }
    return output;
}

#define ARM_CPU_PERFORM_LDREX_ALL(ctx, destination, type_access, base) do { \
    const uint32_t addr = base; \
    const uint32_t cpu_id = ctx->cpu_id; \
    const uint32_t masked_addr = addr & ARM_SYNC_EXCLUSIVE_MASK; \
    const uint32_t value = *(type_access*)(uintptr_t)(addr); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); ctx->sync_addresses[cpu_id] = masked_addr; \
    ctx->sync_data[cpu_id * 2 + 1] = value; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    destination = value; \
} while(0)

#define ARM_CPU_PERFORM_LDREXD(ctx, destinationA, destinationB, base) do { \
    const uint32_t addr = base; \
    const uint32_t cpu_id = ctx->cpu_id; \
    const uint32_t masked_addr = addr & ARM_SYNC_EXCLUSIVE_MASK; \
    const uint32_t valueA = *(uint32_t*)(uintptr_t)(addr); \
    const uint32_t valueB = *(uint32_t*)(uintptr_t)(addr + 4); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); \
    ctx->sync_addresses[cpu_id] = masked_addr; \
    ctx->sync_data[cpu_id] = (((uint64_t)valueB) << 32) | ((uint64_t)valueA); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    destinationA = valueA; \
    destinationB = valueB; \
} while(0)

#define ARM_CPU_PERFORM_STREX_ALL(ctx, destination, source, type_access, bitmask_and, base) do { \
    const uint32_t addr = base; \
    const uint32_t cpu_id = ctx->cpu_id; \
    const uint32_t num_cpus = ctx->num_cpus; \
    const uint32_t masked_addr = addr & ARM_SYNC_EXCLUSIVE_MASK; \
    const type_access value = source & bitmask_and; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); ctx->sync_addresses[cpu_id] = masked_addr; \
    if(ctx->sync_addresses[cpu_id] != masked_addr) { \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
        destination = 1; /* 1 indicates failure */ \
    } else { \
        for(int other_addr_idx = 0; other_addr_idx < num_cpus; ++other_addr_idx) \
            if(ctx->sync_addresses[other_addr_idx] == masked_addr) ctx->sync_addresses[other_addr_idx] = ARM_SYNC_INVALID_EXCLUSIVE_ADDRESS; \
        const type_access old_value = ctx->sync_data[cpu_id] & bitmask_and; \
        const type_access actual = __sync_val_compare_and_swap((type_access*)(uintptr_t)(addr), old_value, value); \
        destination = old_value != actual; /* 1 indicates failure, 0 success */ \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    } \
} while(0)

#define ARM_CPU_PERFORM_STREXD(ctx, destination, sourceA, sourceB, base) do { \
    const uint32_t addr = base; \
    const uint32_t cpu_id = ctx->cpu_id; \
    const uint32_t num_cpus = ctx->num_cpus; \
    const uint32_t masked_addr = addr & ARM_SYNC_EXCLUSIVE_MASK; \
    const uint64_t value = (((uint64_t)sourceB) << 32) | ((uint64_t)sourceA); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); ctx->sync_addresses[cpu_id] = masked_addr; \
    if(ctx->sync_addresses[cpu_id] != masked_addr) { \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
        destination = 1; /* 1 indicates failure */ \
    } else { \
        for(int other_addr_idx = 0; other_addr_idx < num_cpus; ++other_addr_idx) \
            if(ctx->sync_addresses[other_addr_idx] == masked_addr) ctx->sync_addresses[other_addr_idx] = ARM_SYNC_INVALID_EXCLUSIVE_ADDRESS; \
        const uint64_t old_value = ctx->sync_data[cpu_id]; \
        const uint64_t actual = __sync_val_compare_and_swap((uint64_t*)(uintptr_t)(addr), old_value, value); \
        destination = old_value != actual; /* 1 indicates failure, 0 success */ \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    } \
} while(0)

#define ARM_CPU_PERFORM_CLREX(ctx) do { \
    const uint32_t cpu_id = ctx->cpu_id; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); \
    ctx->sync_addresses[cpu_id] = ARM_SYNC_INVALID_EXCLUSIVE_ADDRESS; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
} while(0)

#define ARM_CPU_PERFORM_XT(ctx, destination, source, rot, mask_and, basic_type, extend_type) do { \
    destination = (uint32_t)(extend_type)(basic_type)(util_rotr32(source, rot) & mask_and); \
} while(0)

#define ARM_CPU_PERFORM_XTB16(ctx, destination, source, ROTFLAGS_REGISTRATIONKEEPSALIVE, basic_type, extend_type) do { \
    const uint32_t rotated = util_rotr32(source, rot); \
    const uint16_t valueA = (uint16_t)(extend_type)(basic_type)(rotated & 0xff); \
    const uint16_t valueB = (uint16_t)(extend_type)(basic_type)((rotated >> 24) & 0xff); \
    destination = ((uint32_t)valueB << 16) | (uint32_t)valueA; \
} while(0)

#define ARM_CPU_PERFORM_XTA(ctx, destination, source, rot, mask_and, basic_type, extend_type, addend) do { \
    destination = addend + (uint32_t)(extend_type)(basic_type)(util_rotr32(source, rot) & mask_and); \
} while(0)

#define ARM_CPU_PERFORM_XTAB16(ctx, destination, source, rot, basic_type, extend_type, addend) do { \
    const uint32_t rotated = util_rotr32(source, rot); \
    const uint32_t addend_value = util_rotr32(source, rot); \
    const uint16_t valueA = ((uint16_t)(addend_value & 0xffff) + (uint16_t)(extend_type)(basic_type)(rotated & 0xff)) & 0xffff; \
    const uint16_t valueB = ((uint16_t)((addend_value >> 16) & 0xffff) + (uint16_t)(extend_type)(basic_type)((rotated >> 24) & 0xff)) & 0xffff; \
    destination = ((uint32_t)valueB << 16) | (uint32_t)valueA; \
} while(0)

#define ARM_CPU_PERFORM_MLA(ctx, set_flags, destination, argA, argB, addend) do { \
    const uint32_t result = argA * argB + addend; \
    if(set_flags) arm_cpu_update_flags_NZ_32(ctx, result); \
    destination = result; \
} while(0)

#define ARM_CPU_PERFORM_MUL(ctx, set_flags, destination, argA, argB) ARM_CPU_PERFORM_MLA(ctx, set_flags, destination, argA, argB, 0)

#define ARM_CPU_PERFORM_xMULL(ctx, base_type, set_flags, destLo, destHi, argA, argB) do { \
    const uint64_t result = (uint64_t)((base_type)argA * (base_type)argB); \
    if(set_flags) arm_cpu_update_flags_NZ_64(ctx, result); \
    destLo = (uint32_t)(result & 0xffffffff); \
    destHi = (uint32_t)((result >> 32) & 0xffffffff); \
} while(0)

#define ARM_CPU_PERFORM_xMLAL(ctx, base_type, set_flags, destLo, destHi, argA, argB) do { \
    const uint64_t result = (uint64_t)((base_type)argA * (base_type)argB); \
    const uint64_t existing = ((uint64_t)destHi << 32) | (uint64_t)destLo; \
    const uint64_t result = existing + result_mul; \
    if(set_flags) arm_cpu_update_flags_NZ_64(ctx, result); \
    destLo = (uint32_t)(result & 0xffffffff); \
    destHi = (uint32_t)((result >> 32) & 0xffffffff); \
} while(0)

#define ARM_CPU_PERFORM_SEL(ctx, destination, argA, argB) do { \
    uint32_t mask = 0; \
    const uint32_t ge_flag = ARM_CPU_STATUS_GE(ctx); \
    const uint32_t argA_value = argA; \
    const uint32_t argB_value = argB; \
    mask |= (ge_flag & 1) ? 0x000000ff : 0; \
    mask |= (ge_flag & 2) ? 0x0000ff00 : 0; \
    mask |= (ge_flag & 4) ? 0x00ff0000 : 0; \
    mask |= (ge_flag & 8) ? 0xff000000 : 0; \
    const uint32_t result = (argA_value & mask) | (argB_value & ~mask); \
    destination = result; \
} while(0)

#define ARM_CPU_PERFORM_SIMD_8_TYPE(ctx, base_type, operation, destination, argA, argB) do { \
    const uint32_t argA_value = argA; \
    const uint32_t argB_value = argB; \
    const uint32_t argA_parts[4] = { \
        ((argA_value >> 0) & 0xff), \
        ((argA_value >> 8) & 0xff), \
        ((argA_value >> 16) & 0xff), \
        ((argA_value >> 24) & 0xff), \
    }; \
    const uint32_t argB_parts[4] = { \
        ((argB_value >> 0) & 0xff), \
        ((argB_value >> 8) & 0xff), \
        ((argB_value >> 16) & 0xff), \
        ((argB_value >> 24) & 0xff), \
    }; \
    const base_type operated_base[4] = { \
        (base_type)(((base_type)(argA_parts[0]) operation (base_type)(argB_parts[0])) & 0xff), \
        (base_type)(((base_type)(argA_parts[1]) operation (base_type)(argB_parts[1])) & 0xff), \
        (base_type)(((base_type)(argA_parts[2]) operation (base_type)(argB_parts[2])) & 0xff), \
        (base_type)(((base_type)(argA_parts[3]) operation (base_type)(argB_parts[3])) & 0xff), \
    }; \
    const int32_t operated_big[4] = { \
        (int32_t)(argA_parts[0]) operation (int32_t)(argB_parts[0]), \
        (int32_t)(argA_parts[1]) operation (int32_t)(argB_parts[1]), \
        (int32_t)(argA_parts[2]) operation (int32_t)(argB_parts[2]), \
        (int32_t)(argA_parts[3]) operation (int32_t)(argB_parts[3]), \
    }; \
    if((#operation)[0] == '-') { /* subtraction operation */ \
        const uint32_t new_ge_flag = 0 \
            | ((operated_big[0] >= 0) ? (1u << 0) : 0u) \
            | ((operated_big[1] >= 0) ? (1u << 1) : 0u) \
            | ((operated_big[2] >= 0) ? (1u << 2) : 0u) \
            | ((operated_big[3] >= 0) ? (1u << 3) : 0u); \
        ARM_CPU_STATUS_GE_SET(ctx, new_ge_flag); \
    } else { /* addition operation */ \
        const uint32_t new_ge_flag = 0 \
            | ((operated_big[0] >= (1u << 8)) ? (1u << 0) : 0u) \
            | ((operated_big[1] >= (1u << 8)) ? (1u << 1) : 0u) \
            | ((operated_big[2] >= (1u << 8)) ? (1u << 2) : 0u) \
            | ((operated_big[3] >= (1u << 8)) ? (1u << 3) : 0u); \
        ARM_CPU_STATUS_GE_SET(ctx, new_ge_flag); \
    } \
    const uint32_t result = 0 \
        | ((uint32_t)(operated_base[0]) << 0) \
        | ((uint32_t)(operated_base[1]) << 8) \
        | ((uint32_t)(operated_base[2]) << 16) \
        | ((uint32_t)(operated_base[3]) << 24); \
    destination = result; \
} while(0)

#define ARM_CPU_PERFORM_SIMD_16_TYPE_ALL(ctx, base_type, shiftLo, shiftHi, opLo, opHi, destination, argA, argB) do { \
    const uint32_t argA_value = argA; \
    const uint32_t argB_value = argB; \
    const uint32_t argA_parts[2] = { \
        ((argA_value >> 0) & 0xffff), \
        ((argA_value >> 16) & 0xffff), \
    }; \
    const uint32_t argB_parts[2] = { \
        ((argB_value >> shiftLo) & 0xffff), \
        ((argB_value >> shiftHi) & 0xffff), \
    }; \
    const base_type operated_base[2] = { \
        (base_type)(((base_type)(argA_parts[0]) opLo (base_type)(argB_parts[0])) & 0xffff), \
        (base_type)(((base_type)(argA_parts[1]) opHi (base_type)(argB_parts[1])) & 0xffff), \
    }; \
    const int32_t operated_big[2] = { \
        (int32_t)(argA_parts[0]) opLo (int32_t)(argB_parts[0]), \
        (int32_t)(argA_parts[1]) opHi (int32_t)(argB_parts[1]), \
    }; \
    uint32_t new_ge_flag = 0; \
    if((#opLo)[0] == '-') new_ge_flag |= (operated_big[0] >= 0) ? (3u << 0) : 0u; \
    else new_ge_flag |= (operated_big[0] >= (1u << 16)) ? (3u << 0) : 0u; \
    if((#opHi)[0] == '-') new_ge_flag |= (operated_big[1] >= 0) ? (3u << 2) : 0u; \
    else new_ge_flag |= (operated_big[1] >= (1u << 16)) ? (3u << 2) : 0u; \
    ARM_CPU_STATUS_GE_SET(ctx, new_ge_flag); \
    const uint32_t result = 0 \
        | ((uint32_t)(operated_base[0]) << 0) \
        | ((uint32_t)(operated_base[1]) << 16); \
    destination = result; \
} while(0)

#define ARM_CPU_PERFORM_SIMD_16_TYPE(ctx, base_type, operation, destination, argA, argB) \
    ARM_CPU_PERFORM_SIMD_16_TYPE_ALL(ctx, base_type, 0, 16, operation, operation, destination, argA, argB)

#define ARM_CPU_PERFORM_SIMD_16_DUAL_TYPE(ctx, base_type, opHi, opLo, destination, argA, argB) \
    ARM_CPU_PERFORM_SIMD_16_TYPE_ALL(ctx, base_type, 16, 0, opLo, opHi, destination, argA, argB)

#define ARM_CPU_PERFORM_MCR(ctx, source, coproc_id, opcodeA, opcodeB, coproc_regA, coproc_regB) do { \
    if(coproc_id != 15) goto LABEL_ARM_error; \
    if(opcodeA == 0 && opcodeB == 2 && coproc_regA == 13 && coproc_regB == 0) \
        ctx->cp15.thread_uprw = source; \
    else if(opcodeA == 0 && opcodeB == 4 && coproc_regA == 7 && coproc_regB == 5) \
        /* flush prefetch buffer */; \
    else if(opcodeA == 0 && opcodeB == 4 && coproc_regA == 7 && coproc_regB == 10) \
        /* data sync barrier */; \
    else if(opcodeA == 0 && opcodeB == 5 && coproc_regA == 7 && coproc_regB == 10) \
        /* data memory barrier */; \
    else goto LABEL_ARM_error; \
} while(0)

#define ARM_CPU_PERFORM_MRC(ctx, source, coproc_id, opcodeA, opcodeB, coproc_regA, coproc_regB) do { \
    if(coproc_id != 15) goto LABEL_ARM_error; \
    if(opcodeA == 0 && opcodeB == 2 && coproc_regA == 13 && coproc_regB == 0) \
        source = ctx->cp15.thread_uprw; \
    if(opcodeA == 0 && opcodeB == 3 && coproc_regA == 13 && coproc_regB == 0) \
        source = ctx->cp15.thread_upro; \
    else goto LABEL_ARM_error; \
} while(0)
