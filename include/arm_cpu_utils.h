#include "arm_cpu_ctx.h"
#include <immintrin.h>

#define ATTR_FORCE_INLINE __attribute__((__always_inline__))
#define ATTR_NORETURN __attribute__((__noreturn__))
#define ATTR_CALLCONV __attribute__((__sysv_abi__))
#define ATTR_ENTRY_CALLCONV __attribute__((__ms_abi__))
#define ATTR_NO_SAVE_REGS __attribute__((__no_callee_saved_registers__))

#define ATTR_FUNC_BASE ATTR_FORCE_INLINE ATTR_CALLCONV

#define SYNC_EXCLUSIVE_MASK (0xfffffff8)
#define CPU_PC_ADVANCE_THUMB (2)
#define CPU_PC_AHEAD_THUMB ((CPU_PC_ADVANCE_THUMB) * 2)
#define CPU_PC_ADVANCE_ARM (4)
#define CPU_PC_AHEAD_ARM ((CPU_PC_ADVANCE_ARM) * 2)

#define IND(X) X
#define STR(X) #X
#define STRM(X) STR(X)

#define LABN(kind,addr) L_##kind##_##addr
#define LABNI(kind,addr) LABN(kind,addr)

#define LABDP(name,prev) \
name: \
do { \
    __asm__ goto ("" \
    ".globl " STR(name) \
    "\n" STR(name) ":" \
    : : : "memory" : name, prev); \
} while(0);

#define LABP(kind,addr,prev) LABDP(LABN(kind,addr),LABN(kind,prev))

#define LABD(name) \
    name: \
    __asm__ goto ("" \
        ".globl " STR(name) \
        "\n" STR(name) ":" \
    : : : "memory" : name);

#define LAB(kind,addr) LABD(LABN(kind,addr))

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

#define BITS_value_shift_in(value, bitindex) ((value) << (bitindex))

#define BITS_mask_width(width) (BITS_value_shift_in(1u, (width)) - 1)
#define BITS_mask_shift_in(width, bitindex) BITS_value_shift_in(BITS_mask_width(width), (bitindex))

#define BITS_value_mask_shift_out(value, mask, bitindex) (((value) >> (bitindex)) & (mask))
#define BITS_value_width_shift_out(value, width, bitindex) BITS_value_mask_shift_out((value), BITS_mask_width(width), (bitindex))

#define BITS_get_mask(cpsr, bitindex, mask) ((cpsr) & BITS_value_shift_in(mask, bitindex))
#define BITS_get_width(cpsr, bitindex, width) ((cpsr) & BITS_mask_shift_in(width, bitindex))
#define BITS_get(cpsr, bitindex) BITS_get_width(cpsr, bitindex, 1u)

#define CPU_STATUS_N_GET(ctx) BITS_get((ctx)->cpsr, 31)
#define CPU_STATUS_Z_GET(ctx) BITS_get((ctx)->cpsr, 30)
#define CPU_STATUS_C_GET(ctx) BITS_get((ctx)->cpsr, 29)
#define CPU_STATUS_V_GET(ctx) BITS_get((ctx)->cpsr, 28)
#define CPU_STATUS_Q_GET(ctx) BITS_get((ctx)->cpsr, 27)
#define CPU_STATUS_T_GET(ctx) BITS_get((ctx)->cpsr, 5)
#define CPU_STATUS_GE_GET(ctx) BITS_get_width((ctx)->cpsr, 16, 4u)

#define BITS_bitindex_mask(cpsr, bitindex, mask) (int)(BITS_get_mask(cpsr, bitindex, mask) != 0)
#define BITS_bitindex_width(cpsr, bitindex, width) (int)(BITS_get_width(cpsr, bitindex, width) != 0)
#define BITS_bitindex(cpsr, bitindex) BITS_bitindex_width(cpsr, bitindex, 1u)

#define BITS_named(ctx, name) (int)(CPU_STATUS_##name##_GET(ctx) != 0)
#define CPU_STATUS_N(ctx) BITS_named(ctx, N)
#define CPU_STATUS_Z(ctx) BITS_named(ctx, Z)
#define CPU_STATUS_C(ctx) BITS_named(ctx, C)
#define CPU_STATUS_V(ctx) BITS_named(ctx, V)
#define CPU_STATUS_Q(ctx) BITS_named(ctx, Q)
#define CPU_STATUS_T(ctx) BITS_named(ctx, T)
#define CPU_STATUS_GE(ctx) BITS_named(ctx, GE)

#define FPU_BITS_LEN(ctx) (BITS_value_width_shift_out((ctx)->fpscr, 3u, 16) + 1)
#define FPU_BITS_STRIDE(ctx) ((BITS_value_mask_shift_out((ctx)->fpscr, 0x3u, 20) == 0x3u) ? 2 : 1)
#define FPU_BITS_ROUNDING_MODE(ctx) BITS_value_width_shift_out((ctx)->fpscr, 2u, 22)
// return default NaN if any instruction takes/generates any NaN
// f32: 0x7fc00000
// f64: 0x7fc0000000000000
#define FPU_BITS_DEFAULT_NAN(ctx) BITS_bitindex((ctx)->fpscr, 25)
#define FPU_BITS_FLUSH_DENORM_ZERO(ctx) BITS_bitindex((ctx)->fpscr, 24)

#define BITS_set_width(cpsr, new_flag, bitindex, width) \
    ((cpsr) = (((cpsr) & ~BITS_value_shift_in(width, bitindex)) | BITS_value_shift_in(new_flag, bitindex)))
#define BITS_set(cpsr, new_flag, bitindex) \
    BITS_set_width(cpsr, new_flag, bitindex, 1u)

#define CPU_STATUS_N_SET(ctx, new_flag) BITS_set((ctx)->cpsr, new_flag, 31)
#define CPU_STATUS_Z_SET(ctx, new_flag) BITS_set((ctx)->cpsr, new_flag, 30)
#define CPU_STATUS_C_SET(ctx, new_flag) BITS_set((ctx)->cpsr, new_flag, 29)
#define CPU_STATUS_V_SET(ctx, new_flag) BITS_set((ctx)->cpsr, new_flag, 28)
#define CPU_STATUS_Q_SET(ctx, new_flag) BITS_set((ctx)->cpsr, new_flag, 27)
#define CPU_STATUS_GE_SET(ctx, new_value) (((ctx)->cpsr & ~BITS_value_shift_in(0xfu, 16)) | BITS_value_shift_in(new_value, 16))
// #define CPU_STATUS_T_SET(ctx, value) ((ctx)->cpsr = ((((ctx)->cpsr) & ~(1u << 5)) | ((u32_t)(value != 0) << 5)))

#define CPU_CTX_DEFINE(name, ...) __VA_ARGS__ arm_cpu_ctx* const name __attribute__((unused))

typedef struct arm_fpu_bank {
    u8_t index;
    u8_t offset;
} arm_fpu_bank;

// begins the extraction:
// expands ARGEXTRACT_X arguments [aka ARGEXTRACT_X (abc, def)(ijk, lmn)] to
// ARGEXTRACT_X_LOOP_BODY(abc, def,) ARGEXTRACT_X_LOOP_B(ijk, lmn)_END
// aka ARGEXTRACT_X_LOOP_BODY(abc, def,) ARGEXTRACT_X_LOOP_BODY(ijk, lmn, 0) ARGEXTRACT_X_LOOP_C_END
// and so on for different lengths of 'arguments' tuple
#define ARGEXTRACT_DO(...) ARGEXTRACT_DO_(__VA_ARGS__)
#define ARGEXTRACT_DO_(...) __VA_ARGS__##_END

#define ARGEXTRACT_GOTO_ALL_A(...) ARGEXTRACT_GOTO_ALL_A_LOOP_BODY(__VA_ARGS__,) ARGEXTRACT_GOTO_ALL_A_LOOP_B
#define ARGEXTRACT_GOTO_ALL_A_LOOP_B(...) ARGEXTRACT_GOTO_ALL_A_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_GOTO_ALL_A_LOOP_C
#define ARGEXTRACT_GOTO_ALL_A_LOOP_C(...) ARGEXTRACT_GOTO_ALL_A_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_GOTO_ALL_A_LOOP_B
#define ARGEXTRACT_GOTO_ALL_A_END
#define ARGEXTRACT_GOTO_ALL_A_LOOP_B_END
#define ARGEXTRACT_GOTO_ALL_A_LOOP_C_END

#define ARGEXTRACT_GOTO_ALL_T(...) ARGEXTRACT_GOTO_ALL_T_LOOP_BODY(__VA_ARGS__,) ARGEXTRACT_GOTO_ALL_T_LOOP_B
#define ARGEXTRACT_GOTO_ALL_T_LOOP_B(...) ARGEXTRACT_GOTO_ALL_T_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_GOTO_ALL_T_LOOP_C
#define ARGEXTRACT_GOTO_ALL_T_LOOP_C(...) ARGEXTRACT_GOTO_ALL_T_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_GOTO_ALL_T_LOOP_B
#define ARGEXTRACT_GOTO_ALL_T_END
#define ARGEXTRACT_GOTO_ALL_T_LOOP_B_END
#define ARGEXTRACT_GOTO_ALL_T_LOOP_C_END

#define ARGEXTRACT_GOTO_ALL_A_LOOP_BODY(lab_name, ...) __asm__ goto ("" : : : : LABNI(A,lab_name) );
#define ARGEXTRACT_GOTO_ALL_T_LOOP_BODY(lab_name, ...) __asm__ goto ("" : : : : LABNI(T,lab_name) );

#define INIT_GOTO_ALL(kind,labs) ARGEXTRACT_DO(ARGEXTRACT_GOTO_ALL_##kind (error)(start)labs)
#define INIT_GOTO_START(lab) __asm__ goto ("" : : : : IND(lab));

#if 0
static inline void ATTR_FUNC_BASE util_get_mxcsr(u32_t* const into)
{
    *into = _mm_getcsr();
}
static inline void ATTR_FUNC_BASE util_set_mxcsr(const u32_t* const from)
{
    _mm_setcsr(*from);
}
#else
static inline void ATTR_FUNC_BASE util_get_mxcsr(u32_t* const into)
{
    __asm__ __volatile__ ("stmxcsr %0"
        : "=m"(*into)
        : /* No inputs, "r"(into) is 'register' and not '[register]' needed for memory */
        : /* No clobbers */
    );
}
static inline void ATTR_FUNC_BASE util_set_mxcsr(const u32_t* const from)
{
    __asm__ __volatile__ ("ldmxcsr %0"
        : /* No outputs */
        : "m"(*from)
        : "cc"
    );
}
#endif

static inline int ATTR_FUNC_BASE arm_cpu_check_cc(CPU_CTX_DEFINE(ctx, const), const arm_cpu_cc cc)
{
    // disable the "negative" ones which are always the opposite of the one before
    // thus need to invert the check when the "negative" one is the actual value
#define CPU_PERFORM_cc(check) (((int)(cc) & 1) != (check))
    switch((unsigned)cc & ~1u)
    {
    case arm_cpu_cc_eq: // Equal
        return CPU_PERFORM_cc(CPU_STATUS_Z(ctx) == 1);
    case arm_cpu_cc_hs: // Carry set
        return CPU_PERFORM_cc(CPU_STATUS_C(ctx) == 1);
    case arm_cpu_cc_mi: // Minus, negative
        return CPU_PERFORM_cc(CPU_STATUS_N(ctx) == 1);
    case arm_cpu_cc_vs: // Overflow
        return CPU_PERFORM_cc(CPU_STATUS_V(ctx) == 1);
    case arm_cpu_cc_hi: // Unsigned higher
        return CPU_PERFORM_cc((CPU_STATUS_C(ctx) == 1) && (CPU_STATUS_Z(ctx) == 0));
    case arm_cpu_cc_ge: // Greater than or equal
        return CPU_PERFORM_cc(CPU_STATUS_N(ctx) == CPU_STATUS_V(ctx));
    case arm_cpu_cc_gt: // Greater than
        return CPU_PERFORM_cc((CPU_STATUS_Z(ctx) == 0) && (CPU_STATUS_N(ctx) == CPU_STATUS_V(ctx)));
    case arm_cpu_cc_al: // Always (unconditional)
        return CPU_PERFORM_cc(1);
    default: // Undefined or invalid value
        return 0;
    }
#undef CPU_PERFORM_cc
}

static inline void ATTR_FUNC_BASE arm_cpu_set_cpsr(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    // clear the bits that are "read-as-X" and then set the ones that need to be "read-as-1"
    ctx->cpsr = (value & 0xf90f03ff) | 0x00000000;
}
static inline void ATTR_FUNC_BASE arm_cpu_set_fpscr(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    ctx->fpscr = value;
    util_get_mxcsr(&ctx->mxcsr_value);
    ctx->mxcsr_value &= ~0xe000u;
    switch(FPU_BITS_ROUNDING_MODE(ctx))
    {
    case 0: // to nearest
        ctx->mxcsr_value |= 0x0000;
        break;
    case 1: // to +inf
        ctx->mxcsr_value |= 0x4000;
        break;
    case 2: // to -inf
        ctx->mxcsr_value |= 0x2000;
        break;
    case 3: // to 0
        ctx->mxcsr_value |= 0x6000;
        break;
    default:
        break;
    }
    if(FPU_BITS_FLUSH_DENORM_ZERO(ctx))
        ctx->mxcsr_value |= 0x8000;
    util_set_mxcsr(&ctx->mxcsr_value);
}
static inline void ATTR_FUNC_BASE arm_cpu_set_apsr(CPU_CTX_DEFINE(ctx), const char* flags_to_write, const u32_t value)
{
    while(flags_to_write && *flags_to_write) switch(*flags_to_write++)
    {
    case 'N':
        ctx->cpsr = CPU_STATUS_N_SET(ctx, BITS_bitindex(value, 31));
        break;
    case 'Z':
        ctx->cpsr = CPU_STATUS_Z_SET(ctx, BITS_bitindex(value, 30));
        break;
    case 'C':
        ctx->cpsr = CPU_STATUS_C_SET(ctx, BITS_bitindex(value, 29));
        break;
    case 'V':
        ctx->cpsr = CPU_STATUS_V_SET(ctx, BITS_bitindex(value, 28));
        break;
    case 'Q':
        ctx->cpsr = CPU_STATUS_Q_SET(ctx, BITS_bitindex(value, 27));
        break;
    case 'G':
        ctx->cpsr = CPU_STATUS_GE_SET(ctx, ((value >> 16) & 0xf));
        break;
    default:
        break;
    }
}
static inline u32_t ATTR_FUNC_BASE arm_cpu_get_apsr(CPU_CTX_DEFINE(ctx, const), const char* flags_to_write)
{
    u32_t out = 0;
    while(flags_to_write && *flags_to_write) switch(*flags_to_write++)
    {
    case 'N':
        out |= CPU_STATUS_N_GET(ctx);
        break;
    case 'Z':
        out |= CPU_STATUS_Z_GET(ctx);
        break;
    case 'C':
        out |= CPU_STATUS_C_GET(ctx);
        break;
    case 'V':
        out |= CPU_STATUS_V_GET(ctx);
        break;
    case 'Q':
        out |= CPU_STATUS_Q_GET(ctx);
        break;
    case 'G':
        out |= CPU_STATUS_GE_GET(ctx);
        break;
    default:
        break;
    }
    return out;
}

// ONLY PASS 0 OR 1 IN NEW_FLAG
static inline void ATTR_FUNC_BASE CPU_STATUS_T_SET(CPU_CTX_DEFINE(ctx), const u32_t new_flag)
{
    ctx->cpsr = ((ctx->cpsr) & ~(1u << 5)) | (new_flag << 5);
#if RUNTIME_PC_OFFSET
    if(new_flag) // thumb
        ctx->pc_offset = 4;
    else // arm
        ctx->pc_offset = 8;
#endif
}

static inline void ATTR_FUNC_BASE arm_cpu_update_pc(CPU_CTX_DEFINE(ctx, volatile), const u32_t new_pc
#if !RUNTIME_PC_OFFSET
, const u32_t pc_offset
#endif
)
{
    // slow but works
    // ctx->pc = new_pc + (CPU_STATUS_T(ctx) ? 4 : 8);
    // faster ?
    // ctx->pc = new_pc + (((CPU_STATUS_T_GET(ctx) ^ (1u << 5)) + (1u << 5)) >> 3);
    // even better ? at least way less instructions than either
    ctx->pc = new_pc +
#if RUNTIME_PC_OFFSET
    ctx->
#endif
    pc_offset;
}

static inline void ATTR_FUNC_BASE util_get_f32_defaultNaN(float* const into)
{
    *(u32_t*)into = 0x7fc00000u;
}
static inline void ATTR_FUNC_BASE util_get_f64_defaultNaN(double* const into)
{
    *(u64_t*)into = 0x7fc0000000000000ull;
}
static inline int ATTR_FUNC_BASE util_f32_isNaN(const float* const value)
{
    // const u32_t value_cmp = (0x7fffffffu & *(const u32_t*)value);
    // return value_cmp > 0x7f800000u;
    return *value != *value;
}
static inline int ATTR_FUNC_BASE util_f64_isNaN(const double* const value)
{
    // const u64_t value_cmp = (0x7fffffffffffffffull & *(const u64_t*)value);
    // return value_cmp > 0x7ff0000000000000ull;
    return *value != *value;
}
static inline int ATTR_FUNC_BASE util_f32_isDenormal(const float* const value)
{
    const u32_t value_cmp = (0x7fffffffu & *(const u32_t*)value);
    return value_cmp != 0 /* not zero */ && (value_cmp & 0x7f800000u) == 0 /* not normal/NaN/inf */;
}
static inline int ATTR_FUNC_BASE util_f64_isDenormal(const double* const value)
{
    const u64_t value_cmp = (0x7fffffffffffffffull & *(const u64_t*)value);
    return value_cmp != 0 /* not zero */ && (value_cmp & 0x7ff0000000000000ull) == 0 /* not normal/NaN/inf */;
}

#define _mm_sqrt_sd(v) _mm_sqrt_sd(_mm_undefined_pd(), (v))
#define MAKE_UTILS_FOR_FLOAT_TYPE(float_type, float_suffix_std,  float_vector_type, float_suffix_intr) \
static inline void ATTR_FUNC_BASE util_##float_type##_vcmp(CPU_CTX_DEFINE(ctx), const float_type##_t lhs, const float_type##_t rhs) \
{ \
    const float_vector_type lhs_vec = _mm_load_s##float_suffix_intr(&lhs); \
    const float_vector_type rhs_vec = _mm_load_s##float_suffix_intr(&rhs); \
    const unsigned res_lt = _mm_cvts##float_suffix_intr##_##float_type(_mm_cmp_s##float_suffix_intr(lhs_vec, rhs_vec, _CMP_LT_OQ)) != 0; \
    const unsigned res_eq = _mm_cvts##float_suffix_intr##_##float_type(_mm_cmp_s##float_suffix_intr(lhs_vec, rhs_vec, _CMP_EQ_OQ)) != 0; \
    const unsigned res_geu = _mm_cvts##float_suffix_intr##_##float_type(_mm_cmp_s##float_suffix_intr(lhs_vec, rhs_vec, _CMP_NLT_UQ)) != 0; \
    const unsigned res_u = _mm_cvts##float_suffix_intr##_##float_type(_mm_cmp_s##float_suffix_intr(lhs_vec, rhs_vec, _CMP_UNORD_Q)) != 0; \
    BITS_set((ctx)->fpscr, res_lt, 31); \
    BITS_set((ctx)->fpscr, res_eq, 30); \
    BITS_set((ctx)->fpscr, res_geu, 29); \
    BITS_set((ctx)->fpscr, res_u, 28); \
} \
static inline void ATTR_FUNC_BASE util_##float_type##_vcmpe(CPU_CTX_DEFINE(ctx), const float_type##_t lhs, const float_type##_t rhs) \
{ \
    /* should raise exception (invalid operation) on NaN, don't care so just stub as a normal vcmp */ \
    util_##float_type##_vcmp(ctx, lhs, rhs); \
} \
static inline float_type##_t ATTR_FUNC_BASE util_##float_type##_vsqrt(const float_type##_t value) \
{ \
    return _mm_cvts##float_suffix_intr##_##float_type(_mm_sqrt_s##float_suffix_intr(_mm_load_s##float_suffix_intr(&value))); \
} \
static inline float_type##_t ATTR_FUNC_BASE util_##float_type##_vabs(const float_type##_t value) \
{ \
    return __builtin_fabs##float_suffix_std(value); \
} \
static inline float_type##_t ATTR_FUNC_BASE util_##float_type##_vneg(const float_type##_t value) \
{ \
    return -(value); \
} \
static inline float_type##_t ATTR_FUNC_BASE util_##float_type##_vadd(const float_type##_t lhs, const float_type##_t rhs) \
{ \
    return lhs + rhs; \
} \
static inline float_type##_t ATTR_FUNC_BASE util_##float_type##_vsub(const float_type##_t lhs, const float_type##_t rhs) \
{ \
    return lhs - rhs; \
} \
static inline float_type##_t ATTR_FUNC_BASE util_##float_type##_vdiv(const float_type##_t lhs, const float_type##_t rhs) \
{ \
    return lhs / rhs; \
} \
static inline float_type##_t ATTR_FUNC_BASE util_get_##float_type##_in_bank(CPU_CTX_DEFINE(ctx, const), const arm_fpu_bank bank, int* const cumulative_nan) \
{ \
    float_type##_t out = ctx->float_type##_banks[bank.index][bank.offset]; \
    if(FPU_BITS_DEFAULT_NAN(ctx) && util_##float_type##_isNaN(&out)) \
    { \
        *cumulative_nan = 1; \
    } \
    else if(FPU_BITS_FLUSH_DENORM_ZERO(ctx) && util_##float_type##_isDenormal(&out)) \
    { \
        out = 0; \
    } \
    return out; \
} \
static inline void ATTR_FUNC_BASE util_set_##float_type##_in_bank(CPU_CTX_DEFINE(ctx), const arm_fpu_bank bank, const float_type##_t value, const int* const cumulative_nan) \
{ \
    if(FPU_BITS_DEFAULT_NAN(ctx) && ((cumulative_nan != NULL && *cumulative_nan == 1) || util_##float_type##_isNaN(&value)) && cumulative_nan != NULL) \
    { \
        util_get_##float_type##_defaultNaN(&ctx->float_type##_banks[bank.index][bank.offset]); \
    } \
    else \
    { \
        ctx->float_type##_banks[bank.index][bank.offset] = value; \
    } \
}

MAKE_UTILS_FOR_FLOAT_TYPE(f32, f, __m128, s)
MAKE_UTILS_FOR_FLOAT_TYPE(f64, , __m128d, d)

static inline void ATTR_FUNC_BASE arm_cpu_instr_svc_raw(CPU_CTX_DEFINE(ctx), const u64_t signal_id)
{
    __asm__ __volatile__ (
        "int3"
        : "+m"(*ctx)
        : "D"(signal_id)
        : "memory");
}
static inline void ATTR_FUNC_BASE arm_cpu_instr_svc(CPU_CTX_DEFINE(ctx), const u32_t svc_id)
{
    return arm_cpu_instr_svc_raw(ctx, svc_id);
}
static inline void ATTR_NORETURN ATTR_FUNC_BASE arm_cpu_instr_branch_to_addr(CPU_CTX_DEFINE(ctx), const u32_t addr)
{
    __asm__ goto (
        "jmp %0"
        : /* No outputs. */
        : "r" (ctx->indirect_brancher), "S"(addr)
        : /* No clobbers. */
        : /* No (local) labels */ after_jump
    );
after_jump:
    __builtin_unreachable();
}
static inline void ATTR_NORETURN ATTR_FUNC_BASE arm_cpu_instr_runtime_error(CPU_CTX_DEFINE(ctx))
{
    arm_cpu_instr_svc_raw(ctx, -1);
    __builtin_unreachable();
}
static inline void ATTR_FUNC_BASE arm_cpu_instr_entry_setup_done(CPU_CTX_DEFINE(ctx))
{
    arm_cpu_instr_svc_raw(ctx, -2);
}
static inline void ATTR_FUNC_BASE arm_cpu_instr_udf(CPU_CTX_DEFINE(ctx), const s32_t udf_id)
{
    arm_cpu_instr_svc_raw(ctx, (u64_t)udf_id + (1ull << 32));
}

static inline u32_t ATTR_FUNC_BASE util_rotl32(const u32_t n, u32_t c)
{
    const u32_t mask = 31;
    c &= mask;
    return (n << c) | (n >> ((-c) & mask));
}
static inline u32_t ATTR_FUNC_BASE util_rotr32(const u32_t n, u32_t c)
{
    const u32_t mask = 31;
    c &= mask;
    return (n >> c) | (n << ((-c) & mask));
}

static inline u32_t ATTR_FUNC_BASE arm_cpu_update_carry_flag_constant_operand2(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t imm)
{
    if(!set_flags) return imm;
    if(imm <= 255) return imm;
    for(unsigned i = 1; i < 32; ++i)
    {
        const u32_t rotted = util_rotl32(imm, i);
        if(util_rotr32(rotted & 0xff, i) == imm)
        {
            CPU_STATUS_C_SET(ctx, ((imm & (1u << 31)) != 0));
            break;
        }
    }
    return imm;
}
static inline void ATTR_FUNC_BASE arm_cpu_update_flags_NZ_32(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    CPU_STATUS_N_SET(ctx, ((value & (1u << 31)) != 0));
    CPU_STATUS_Z_SET(ctx, (value == 0));
}
static inline void ATTR_FUNC_BASE arm_cpu_update_flags_NZ_64(CPU_CTX_DEFINE(ctx), const u64_t value)
{
    CPU_STATUS_N_SET(ctx, ((value & (1ull << 63)) != 0));
    CPU_STATUS_Z_SET(ctx, (value == 0));
}

static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_ASR(CPU_CTX_DEFINE(ctx), const u32_t value, const u32_t shift)
{
    return (u32_t)((s32_t)value >> shift);
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_LSL(CPU_CTX_DEFINE(ctx), const u32_t value, const u32_t shift)
{
    return value << shift;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_LSR(CPU_CTX_DEFINE(ctx), const u32_t value, const u32_t shift)
{
    return value >> shift;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_ROR(CPU_CTX_DEFINE(ctx), const u32_t value, const u32_t shift)
{
    return util_rotr32(value, shift);
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_RRX(CPU_CTX_DEFINE(ctx), const u32_t value, const int update_flags)
{
    const u32_t current_carry = CPU_STATUS_C_GET(ctx);
    if(update_flags) CPU_STATUS_C_SET(ctx, (value & 1));
    return (value >> 1) | (current_carry << 31);
}

static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_asr_REG(CPU_CTX_DEFINE(ctx), const u32_t value, const int update_flags, u8_t shift)
{
    if(shift == 0) return value;
    if(shift >= 32)
    {
        const u32_t output = (s32_t)value >> 31;
        if(update_flags)
        {
            CPU_STATUS_C_SET(ctx, (output & 1));
        }
        return output;
    }
    else
    {
        const u32_t output = (s32_t)value >> shift;
        if(update_flags)
        {
            CPU_STATUS_C_SET(ctx, ((value >> (shift - 1)) & 1));
        }
        return output;
    }
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_lsl_REG(CPU_CTX_DEFINE(ctx), const u32_t value, const int update_flags, const u8_t shift)
{
    if(shift == 0) return value;
    if(shift >= 32)
    {
        if(update_flags)
        {
            if(shift >= 33)
            {
                CPU_STATUS_C_SET(ctx, 0);
            }
            else
            {
                CPU_STATUS_C_SET(ctx, (value & 1));
            }
        }
        return 0;
    }
    else
    {
        const u32_t output = value << shift;
        if(update_flags)
        {
            CPU_STATUS_C_SET(ctx, ((value & (1u << (32 - shift))) != 0));
        }
        return output;
    }
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_lsr_REG(CPU_CTX_DEFINE(ctx), const u32_t value, const int update_flags, const u8_t shift)
{
    if(shift == 0) return value;
    if(shift >= 32)
    {
        if(update_flags)
        {
            if(shift >= 33)
            {
                CPU_STATUS_C_SET(ctx, 0);
            }
            else
            {
                CPU_STATUS_C_SET(ctx, ((value >> 31) & 1));
            }
        }
        return 0;
    }
    else
    {
        const u32_t output = value >> shift;
        if(update_flags)
        {
            CPU_STATUS_C_SET(ctx, ((value >> (shift - 1)) & 1));
        }
        return output;
    }
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_ror_REG(CPU_CTX_DEFINE(ctx), const u32_t value, const int update_flags, const u8_t shift)
{
    if(shift == 0) return value;
    if(shift % 32 == 0)
    {
        if(update_flags)
        {
            CPU_STATUS_C_SET(ctx, ((value >> 31) & 1));
        }
        return value;
    }
    else
    {
        const u32_t output = util_rotr32(value, shift % 32);
        if(update_flags)
        {
            CPU_STATUS_C_SET(ctx, ((value >> (shift - 1)) & 1));
        }
        return output;
    }
}

#define CPU_PERFORM_ARM_B(ctx, target) do { \
    goto LABN(A,target); \
} while(0)

#define CPU_PERFORM_THUMB_B(ctx, target) do { \
    goto LABN(T,target); \
} while(0)

#define CPU_PERFORM_BRANCH_REG(ctx, value_in) do { \
    const u32_t value = (value_in); \
    arm_cpu_instr_branch_to_addr(ctx, value); \
} while(0)

#define CPU_PERFORM_BX(ctx, reg) do { \
    if((reg) & 1) CPU_STATUS_T_SET(ctx, 1); \
    else CPU_STATUS_T_SET(ctx, 0); \
    CPU_PERFORM_BRANCH_REG(ctx, reg); \
} while(0)

#define CPU_PERFORM_ARM_BL(ctx, target) do { \
    ctx->lr = ctx->pc - (CPU_PC_ADVANCE_ARM); \
    goto LABN(A,target); \
} while(0)
#define CPU_PERFORM_ARM_BLX_IMM(ctx, target) do { \
    ctx->lr = ctx->pc - (CPU_PC_ADVANCE_ARM); \
    CPU_STATUS_T_SET(ctx, 1); \
    goto LABN(T,target); \
} while(0)
#define CPU_PERFORM_THUMB_BL(ctx, target) do { \
    ctx->lr = (ctx->pc - (CPU_PC_ADVANCE_THUMB)) | 1; \
    goto LABN(T,target); \
} while(0)
#define CPU_PERFORM_THUMB_BLX_IMM(ctx, target) do { \
    ctx->lr = (ctx->pc - (CPU_PC_ADVANCE_THUMB)) | 1; \
    CPU_STATUS_T_SET(ctx, 0); \
    goto LABN(A,target); \
} while(0)

#define CPU_PERFORM_BLX_REG(ctx, reg) do { \
    if(CPU_STATUS_T(ctx)) ctx->lr = (ctx->pc - (CPU_PC_ADVANCE_THUMB)) | 1; \
    else ctx->lr = ctx->pc - (CPU_PC_ADVANCE_ARM); \
    CPU_PERFORM_BX(ctx, reg); \
} while(0)

#define CPU_PERFORM_LDR_ALL(ctx, destination, type_access, type_cast, base, operator, index, writeback, post_index) do { \
    u32_t addr = base; \
    const u32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    destination = type_cast *(type_access*)(void*)(uintptr_t)(addr); \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
    if((const unsigned char*)&(destination) == (const unsigned char*)&(ctx->pc)) CPU_PERFORM_BX(ctx, ctx->pc); \
} while(0)

#define CPU_PERFORM_LDRD(ctx, destinationA, destinationB, base, operator, index, writeback, post_index) do { \
    u32_t addr = base; \
    const u32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    destinationA = *(u32_t*)(void*)(uintptr_t)(addr); \
    destinationB = *(u32_t*)(void*)(uintptr_t)(addr + 4); \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
} while(0)

#define CPU_PERFORM_STR_ALL(ctx, source, type_access, bitmask_and, base, operator, index, writeback, post_index) do { \
    u32_t addr = base; \
    const u32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    *(type_access*)(void*)(uintptr_t)(addr) = source bitmask_and; \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
} while(0)

#define CPU_PERFORM_STRD(ctx, sourceA, sourceB, base, operator, index, writeback, post_index) do { \
    u32_t addr = base; \
    const u32_t addr_off = index; \
    if(!post_index) addr += addr_off; \
    *(u32_t*)(void*)(uintptr_t)(addr) = sourceA; \
    *(u32_t*)(void*)(uintptr_t)(addr + 4) = sourceB; \
    if(post_index) addr += addr_off; \
    if(writeback) base = addr; \
} while(0)

#define ARGEXTRACT_MULTIPLE_LDM(...) ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(__VA_ARGS__,) ARGEXTRACT_MULTIPLE_LDM_LOOP_B
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_B(...) ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_LDM_LOOP_C
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_C(...) ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_LDM_LOOP_B
#define ARGEXTRACT_MULTIPLE_LDM_END
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_B_END
#define ARGEXTRACT_MULTIPLE_LDM_LOOP_C_END

#define ARGEXTRACT_MULTIPLE_LDM_LOOP_BODY(c_ldm_type, c_reg_index, c_reg_name, ...) ctx->c_reg_name = *(c_ldm_type*)(void*)(uintptr_t)(addr_start + c_reg_index * step_off);

#define CPU_PERFORM_LDM_ALL(ctx, base, writeback, init_off, step, final_off, arguments, write_pc) do { \
    const u32_t addr_start = base + (init_off); \
    const u32_t step_off = (step); \
    ARGEXTRACT_DO(ARGEXTRACT_MULTIPLE_LDM arguments); \
    if(writeback) base = base + (final_off); /* not allowed to have base in the reglist, but not checked */ \
    if(write_pc) CPU_PERFORM_BX(ctx, ctx->pc); \
} while(0)

#define ARGEXTRACT_MULTIPLE_STM(...) ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(__VA_ARGS__,) ARGEXTRACT_MULTIPLE_STM_LOOP_B
#define ARGEXTRACT_MULTIPLE_STM_LOOP_B(...) ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_STM_LOOP_C
#define ARGEXTRACT_MULTIPLE_STM_LOOP_C(...) ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(__VA_ARGS__,0) ARGEXTRACT_MULTIPLE_STM_LOOP_B
#define ARGEXTRACT_MULTIPLE_STM_END
#define ARGEXTRACT_MULTIPLE_STM_LOOP_B_END
#define ARGEXTRACT_MULTIPLE_STM_LOOP_C_END

#define ARGEXTRACT_MULTIPLE_STM_LOOP_BODY(c_stm_type, c_reg_index, c_reg_name, ...) *(c_stm_type*)(void*)(uintptr_t)(addr_start + c_reg_index * step_off) = ctx->c_reg_name;

#define CPU_PERFORM_STM_ALL(ctx, base, writeback, init_off, step, final_off, arguments) do { \
    const u32_t addr_start = base + (init_off); \
    const u32_t step_off = (step); \
    ARGEXTRACT_DO(ARGEXTRACT_MULTIPLE_STM arguments); \
    if(writeback) base = base + (final_off); /* not allowed to have base in the reglist, but not checked */ \
} while(0)

#define CPU_PERFORM_FLAGS_cmp(ctx, argA, argB) do { \
    const u32_t result = (argA) - (argB); \
    const s64_t result_big = (s64_t)(argA) - (s64_t)(argB); \
    CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    CPU_STATUS_Z_SET(ctx, (result == 0)); \
    CPU_STATUS_C_SET(ctx, (result_big >= 0)); \
    CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big)); \
} while(0)

#define CPU_PERFORM_FLAGS_cmn(ctx, argA, argB) do { \
    const u32_t result = (argA) + (argB); \
    const s64_t result_big = (s64_t)(argA) + (s64_t)(argB); \
    CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    CPU_STATUS_Z_SET(ctx, (result == 0)); \
    CPU_STATUS_C_SET(ctx, (result_big >= (1ll << 32))); \
    CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big)); \
} while(0)

#define CPU_PERFORM_FLAGS_tst(ctx, argA, argB) do {  \
    const u32_t result = (argA) & (argB); \
    CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    CPU_STATUS_Z_SET(ctx, (result == 0)); \
} while(0)

#define CPU_PERFORM_FLAGS_teq(ctx, argA, argB) do {  \
    const u32_t result = (argA) ^ (argB); \
    CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0)); \
    CPU_STATUS_Z_SET(ctx, (result == 0)); \
} while(0)

static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_add(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t argA, const u32_t argB)
{
    const u32_t result = (argA) + (argB);
    if(set_flags)
    {
        const s64_t result_big = (s64_t)(argA) + (s64_t)(argB);
        CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        CPU_STATUS_Z_SET(ctx, (result == 0));
        CPU_STATUS_C_SET(ctx, (result_big >= (1ll << 32)));
        CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_sub(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t argA, const u32_t argB)
{
    const u32_t result = (argA) - (argB);
    if(set_flags)
    {
        const s64_t result_big = (s64_t)(argA) - (s64_t)(argB);
        CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        CPU_STATUS_Z_SET(ctx, (result == 0));
        CPU_STATUS_C_SET(ctx, (result_big >= 0));
        CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_rsb(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t argA, const u32_t argB)
{
    const u32_t result = (argB) - (argA);
    if(set_flags)
    {
        const s64_t result_big = (s64_t)(argB) - (s64_t)(argA);
        CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        CPU_STATUS_Z_SET(ctx, (result == 0));
        CPU_STATUS_C_SET(ctx, (result_big >= 0));
        CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}

static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_adc(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t argA, const u32_t argB)
{
    const u32_t result = (argA) + (argB) + (CPU_STATUS_C(ctx) ? 1 : 0);
    if(set_flags)
    {
        const s64_t result_big = (s64_t)(argA) + (s64_t)(argB) + (CPU_STATUS_C(ctx) ? 1 : 0);
        CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        CPU_STATUS_Z_SET(ctx, (result == 0));
        CPU_STATUS_C_SET(ctx, (result_big >= (1ll << 32)));
        CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_sbc(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t argA, const u32_t argB)
{
    const u32_t result = (argA) - (argB) + (CPU_STATUS_C(ctx) ? 0 : -1);
    if(set_flags)
    {
        const s64_t result_big = (s64_t)(argA) - (s64_t)(argB) + (CPU_STATUS_C(ctx) ? 0 : -1);
        CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        CPU_STATUS_Z_SET(ctx, (result == 0));
        CPU_STATUS_C_SET(ctx, (result_big >= 0));
        CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_rsc(CPU_CTX_DEFINE(ctx), const int set_flags, const u32_t argA, const u32_t argB)
{
    const u32_t result = (argB) - (argA) + (CPU_STATUS_C(ctx) ? 0 : -1);
    if(set_flags)
    {
        const s64_t result_big = (s64_t)(argB) - (s64_t)(argA) + (CPU_STATUS_C(ctx) ? 0 : -1);
        CPU_STATUS_N_SET(ctx, ((result & (1u << 31)) != 0));
        CPU_STATUS_Z_SET(ctx, (result == 0));
        CPU_STATUS_C_SET(ctx, (result_big >= 0));
        CPU_STATUS_V_SET(ctx, ((result_big < -(1ll << 31)) || (1ll << 31) >= result_big));
    }
    return result;
}

static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_rev(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    u32_t output = 0;
    output |= ((value >> 0) & 0xff) << 24;
    output |= ((value >> 8) & 0xff) << 16;
    output |= ((value >> 16) & 0xff) << 8;
    output |= ((value >> 24) & 0xff) << 0;
    return output;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_rev16(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    u32_t output = 0;
    output |= ((value >> 0) & 0xff) << 8;
    output |= ((value >> 8) & 0xff) << 0;
    output |= ((value >> 16) & 0xff) << 24;
    output |= ((value >> 24) & 0xff) << 16;
    return output;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_revsh(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    u16_t output = 0;
    output |= ((value >> 0) & 0xff) << 8;
    output |= ((value >> 8) & 0xff) << 0;
    return (s32_t)(s16_t)output;
}
static inline u32_t ATTR_FUNC_BASE CPU_PERFORM_clz(CPU_CTX_DEFINE(ctx), const u32_t value)
{
    u32_t output = 0;
    for(int i = 31; i >= 0; --i, ++output)
    {
        if(value & (1u << i))
            break;
    }
    return output;
}

#define CPU_PERFORM_LDREX_ALL(ctx, destination, type_access, base) do { \
    const u32_t addr = base; \
    const u32_t cpu_id = ctx->cpu_id; \
    const u32_t masked_addr = addr & SYNC_EXCLUSIVE_MASK; \
    const u32_t value = *(type_access*)(void*)(uintptr_t)(addr); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); ctx->sync_addresses[cpu_id] = masked_addr; \
    ctx->sync_data[cpu_id] = value; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    destination = value; \
} while(0)

#define CPU_PERFORM_LDREXD(ctx, destinationA, destinationB, base) do { \
    const u32_t addr = base; \
    const u32_t cpu_id = ctx->cpu_id; \
    const u32_t masked_addr = addr & SYNC_EXCLUSIVE_MASK; \
    const u32_t valueA = *(u32_t*)(void*)(uintptr_t)(addr); \
    const u32_t valueB = *(u32_t*)(void*)(uintptr_t)(addr + 4); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); \
    ctx->sync_addresses[cpu_id] = masked_addr; \
    ctx->sync_data[cpu_id] = (((u64_t)valueB) << 32) | ((u64_t)valueA); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    destinationA = valueA; \
    destinationB = valueB; \
} while(0)

#define CPU_PERFORM_STREX_ALL(ctx, destination, source, type_access, bitmask_and, base) do { \
    const u32_t addr = base; \
    const u32_t cpu_id = ctx->cpu_id; \
    const u32_t num_cpus = ctx->num_cpus; \
    const u32_t masked_addr = addr & SYNC_EXCLUSIVE_MASK; \
    const type_access value = source & bitmask_and; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); ctx->sync_addresses[cpu_id] = masked_addr; \
    if(ctx->sync_addresses[cpu_id] != masked_addr) { \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
        destination = 1; /* 1 indicates failure */ \
    } else { \
        for(int other_addr_idx = 0; other_addr_idx < num_cpus; ++other_addr_idx) \
            if(ctx->sync_addresses[other_addr_idx] == masked_addr) ctx->sync_addresses[other_addr_idx] = SYNC_INVALID_EXCLUSIVE_ADDRESS; \
        const type_access old_value = ctx->sync_data[cpu_id] & bitmask_and; \
        const type_access actual = __sync_val_compare_and_swap((type_access*)(void*)(uintptr_t)(addr), old_value, value); \
        destination = old_value != actual; /* 1 indicates failure, 0 success */ \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    } \
} while(0)

#define CPU_PERFORM_STREXD(ctx, destination, sourceA, sourceB, base) do { \
    const u32_t addr = base; \
    const u32_t cpu_id = ctx->cpu_id; \
    const u32_t num_cpus = ctx->num_cpus; \
    const u32_t masked_addr = addr & SYNC_EXCLUSIVE_MASK; \
    const u64_t value = (((u64_t)sourceB) << 32) | ((u64_t)sourceA); \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); ctx->sync_addresses[cpu_id] = masked_addr; \
    if(ctx->sync_addresses[cpu_id] != masked_addr) { \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
        destination = 1; /* 1 indicates failure */ \
    } else { \
        for(int other_addr_idx = 0; other_addr_idx < num_cpus; ++other_addr_idx) \
            if(ctx->sync_addresses[other_addr_idx] == masked_addr) ctx->sync_addresses[other_addr_idx] = SYNC_INVALID_EXCLUSIVE_ADDRESS; \
        const u64_t old_value = ctx->sync_data[cpu_id]; \
        const u64_t actual = __sync_val_compare_and_swap((u64_t*)(void*)(uintptr_t)(addr), old_value, value); \
        destination = old_value != actual; /* 1 indicates failure, 0 success */ \
        while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
    } \
} while(0)

#define CPU_PERFORM_CLREX(ctx) do { \
    const u32_t cpu_id = ctx->cpu_id; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, 0, cpu_id + 1)); \
    ctx->sync_addresses[cpu_id] = SYNC_INVALID_EXCLUSIVE_ADDRESS; \
    while(!__sync_bool_compare_and_swap(ctx->sync_data_lock, cpu_id + 1, 0)); \
} while(0)

#define CPU_PERFORM_XT(ctx, destination, source, rot, mask_and, basic_type, extend_type) do { \
    destination = (u32_t)(extend_type)(basic_type)(util_rotr32(source, rot) & mask_and); \
} while(0)

#define CPU_PERFORM_XTB16(ctx, destination, source, ROTFLAGS_REGISTRATIONKEEPSALIVE, basic_type, extend_type) do { \
    const u32_t rotated = util_rotr32(source, rot); \
    const u16_t valueA = (u16_t)(extend_type)(basic_type)(rotated & 0xff); \
    const u16_t valueB = (u16_t)(extend_type)(basic_type)((rotated >> 24) & 0xff); \
    destination = ((u32_t)valueB << 16) | (u32_t)valueA; \
} while(0)

#define CPU_PERFORM_XTA(ctx, destination, source, rot, mask_and, basic_type, extend_type, addend) do { \
    destination = addend + (u32_t)(extend_type)(basic_type)(util_rotr32(source, rot) & mask_and); \
} while(0)

#define CPU_PERFORM_XTAB16(ctx, destination, source, rot, basic_type, extend_type, addend) do { \
    const u32_t rotated = util_rotr32(source, rot); \
    const u32_t addend_value = util_rotr32(source, rot); \
    const u16_t valueA = ((u16_t)(addend_value & 0xffff) + (u16_t)(extend_type)(basic_type)(rotated & 0xff)) & 0xffff; \
    const u16_t valueB = ((u16_t)((addend_value >> 16) & 0xffff) + (u16_t)(extend_type)(basic_type)((rotated >> 24) & 0xff)) & 0xffff; \
    destination = ((u32_t)valueB << 16) | (u32_t)valueA; \
} while(0)

#define CPU_PERFORM_MLA(ctx, set_flags, destination, argA, argB, addend) do { \
    const u32_t result = ((argA) * (argB)) + addend; \
    if(set_flags) arm_cpu_update_flags_NZ_32(ctx, result); \
    destination = result; \
} while(0)

#define CPU_PERFORM_MUL(ctx, set_flags, destination, argA, argB) CPU_PERFORM_MLA(ctx, set_flags, destination, argA, argB, 0)

#define CPU_PERFORM_xMULL(ctx, base_type, set_flags, destLo, destHi, argA, argB) do { \
    const u64_t result = (u64_t)((base_type)argA * (base_type)argB); \
    if(set_flags) arm_cpu_update_flags_NZ_64(ctx, result); \
    destLo = (u32_t)(result & 0xffffffff); \
    destHi = (u32_t)((result >> 32) & 0xffffffff); \
} while(0)

#define CPU_PERFORM_xMLAL(ctx, base_type, set_flags, destLo, destHi, argA, argB) do { \
    const u64_t mul_result = (u64_t)((base_type)argA * (base_type)argB); \
    const u64_t existing = ((u64_t)destHi << 32) | (u64_t)destLo; \
    const u64_t result = existing + mul_result; \
    if(set_flags) arm_cpu_update_flags_NZ_64(ctx, result); \
    destLo = (u32_t)(result & 0xffffffff); \
    destHi = (u32_t)((result >> 32) & 0xffffffff); \
} while(0)

#define CPU_PERFORM_SEL(ctx, destination, argA, argB) do { \
    u32_t mask = 0; \
    const u32_t ge_flag = CPU_STATUS_GE_GET(ctx); \
    const u32_t argA_value = argA; \
    const u32_t argB_value = argB; \
    mask |= (ge_flag & 1) ? 0x000000ff : 0; \
    mask |= (ge_flag & 2) ? 0x0000ff00 : 0; \
    mask |= (ge_flag & 4) ? 0x00ff0000 : 0; \
    mask |= (ge_flag & 8) ? 0xff000000 : 0; \
    const u32_t result = (argA_value & mask) | (argB_value & ~mask); \
    destination = result; \
} while(0)

#define CPU_PERFORM_SIMD_8_TYPE(ctx, base_type, operation, destination, argA, argB) do { \
    const u32_t argA_value = argA; \
    const u32_t argB_value = argB; \
    const u32_t argA_parts[4] = { \
        ((argA_value >> 0) & 0xff), \
        ((argA_value >> 8) & 0xff), \
        ((argA_value >> 16) & 0xff), \
        ((argA_value >> 24) & 0xff), \
    }; \
    const u32_t argB_parts[4] = { \
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
    const s32_t operated_big[4] = { \
        (s32_t)(argA_parts[0]) operation (s32_t)(argB_parts[0]), \
        (s32_t)(argA_parts[1]) operation (s32_t)(argB_parts[1]), \
        (s32_t)(argA_parts[2]) operation (s32_t)(argB_parts[2]), \
        (s32_t)(argA_parts[3]) operation (s32_t)(argB_parts[3]), \
    }; \
    if((#operation)[0] == '-') { /* subtraction operation */ \
        const u32_t new_ge_flag = 0 \
            | ((operated_big[0] >= 0) ? (1u << 0) : 0u) \
            | ((operated_big[1] >= 0) ? (1u << 1) : 0u) \
            | ((operated_big[2] >= 0) ? (1u << 2) : 0u) \
            | ((operated_big[3] >= 0) ? (1u << 3) : 0u); \
        CPU_STATUS_GE_SET(ctx, new_ge_flag); \
    } else { /* addition operation */ \
        const u32_t new_ge_flag = 0 \
            | ((operated_big[0] >= (1u << 8)) ? (1u << 0) : 0u) \
            | ((operated_big[1] >= (1u << 8)) ? (1u << 1) : 0u) \
            | ((operated_big[2] >= (1u << 8)) ? (1u << 2) : 0u) \
            | ((operated_big[3] >= (1u << 8)) ? (1u << 3) : 0u); \
        CPU_STATUS_GE_SET(ctx, new_ge_flag); \
    } \
    const u32_t result = 0 \
        | ((u32_t)(operated_base[0]) << 0) \
        | ((u32_t)(operated_base[1]) << 8) \
        | ((u32_t)(operated_base[2]) << 16) \
        | ((u32_t)(operated_base[3]) << 24); \
    destination = result; \
} while(0)

#define CPU_PERFORM_SIMD_16_TYPE_ALL(ctx, base_type, shiftLo, shiftHi, opLo, opHi, destination, argA, argB) do { \
    const u32_t argA_value = argA; \
    const u32_t argB_value = argB; \
    const u32_t argA_parts[2] = { \
        ((argA_value >> 0) & 0xffff), \
        ((argA_value >> 16) & 0xffff), \
    }; \
    const u32_t argB_parts[2] = { \
        ((argB_value >> shiftLo) & 0xffff), \
        ((argB_value >> shiftHi) & 0xffff), \
    }; \
    const base_type operated_base[2] = { \
        (base_type)(((base_type)(argA_parts[0]) opLo (base_type)(argB_parts[0])) & 0xffff), \
        (base_type)(((base_type)(argA_parts[1]) opHi (base_type)(argB_parts[1])) & 0xffff), \
    }; \
    const s32_t operated_big[2] = { \
        (s32_t)(argA_parts[0]) opLo (s32_t)(argB_parts[0]), \
        (s32_t)(argA_parts[1]) opHi (s32_t)(argB_parts[1]), \
    }; \
    u32_t new_ge_flag = 0; \
    if((#opLo)[0] == '-') new_ge_flag |= (operated_big[0] >= 0) ? (3u << 0) : 0u; \
    else new_ge_flag |= (operated_big[0] >= (1u << 16)) ? (3u << 0) : 0u; \
    if((#opHi)[0] == '-') new_ge_flag |= (operated_big[1] >= 0) ? (3u << 2) : 0u; \
    else new_ge_flag |= (operated_big[1] >= (1u << 16)) ? (3u << 2) : 0u; \
    CPU_STATUS_GE_SET(ctx, new_ge_flag); \
    const u32_t result = 0 \
        | ((u32_t)(operated_base[0]) << 0) \
        | ((u32_t)(operated_base[1]) << 16); \
    destination = result; \
} while(0)

#define CPU_PERFORM_SIMD_16_TYPE(ctx, base_type, operation, destination, argA, argB) \
    CPU_PERFORM_SIMD_16_TYPE_ALL(ctx, base_type, 0, 16, operation, operation, destination, argA, argB)

#define CPU_PERFORM_SIMD_16_DUAL_TYPE(ctx, base_type, opHi, opLo, destination, argA, argB) \
    CPU_PERFORM_SIMD_16_TYPE_ALL(ctx, base_type, 16, 0, opLo, opHi, destination, argA, argB)

#define CPU_PERFORM_MCR(ctx, source, coproc_id, opcodeA, opcodeB, coproc_regA, coproc_regB) do { \
    if(coproc_id != 15) goto LABN(A,error); \
    if(opcodeA == 0 && opcodeB == 2 && coproc_regA == 13 && coproc_regB == 0) \
        ctx->cp15.thread_uprw = source; \
    else if(opcodeA == 0 && opcodeB == 4 && coproc_regA == 7 && coproc_regB == 5) \
        /* flush prefetch buffer */; \
    else if(opcodeA == 0 && opcodeB == 4 && coproc_regA == 7 && coproc_regB == 10) \
        /* data sync barrier */; \
    else if(opcodeA == 0 && opcodeB == 5 && coproc_regA == 7 && coproc_regB == 10) \
        /* data memory barrier */; \
    else goto LABN(A,error); \
} while(0)

#define CPU_PERFORM_MRC(ctx, source, coproc_id, opcodeA, opcodeB, coproc_regA, coproc_regB) do { \
    if(coproc_id != 15) goto LABN(A,error); \
    if(opcodeA == 0 && opcodeB == 2 && coproc_regA == 13 && coproc_regB == 0) \
        source = ctx->cp15.thread_uprw; \
    if(opcodeA == 0 && opcodeB == 3 && coproc_regA == 13 && coproc_regB == 0) \
        source = ctx->cp15.thread_upro; \
    else goto LABN(A,error); \
} while(0)

#define FPU_PERFORM_VMUL_ALL(ctx, float_type, bank_size, sum_preop, mul_postop, dest_bank_index, dest_bank_offset, lhs_bank_index, lhs_bank_offset, rhs_bank_index, rhs_bank_offset) do { \
    const u8_t len = (dest_bank_index == 0) ? 1 : FPU_BITS_LEN(ctx); \
    const u8_t stride = FPU_BITS_STRIDE(ctx); \
    const u8_t rhs_stride = rhs_bank_index == 0 ? 0 : stride; \
    arm_fpu_bank dst = {.index = dest_bank_index, .offset = dest_bank_offset}; \
    arm_fpu_bank lhs = {.index = lhs_bank_index, .offset = lhs_bank_offset}; \
    arm_fpu_bank rhs = {.index = rhs_bank_index, .offset = rhs_bank_offset}; \
    for(u8_t ctr = 0; ctr < len; \
        dst.offset = (dst.offset + stride) % bank_size, lhs.offset = (lhs.offset + stride) % bank_size, rhs.offset = (rhs.offset + rhs_stride) % bank_size, ++ctr \
    ) \
    { \
        int cumulative_nan = 0; \
        if(*#sum_preop == '\0') \
            util_set_##float_type##_in_bank(ctx, dst, mul_postop \
                (util_get_##float_type##_in_bank(ctx, lhs, &cumulative_nan) * util_get_##float_type##_in_bank(ctx, rhs, &cumulative_nan)), \
            &cumulative_nan);\
        else \
            util_set_##float_type##_in_bank(ctx, dst, sum_preop (util_get_##float_type##_in_bank(ctx, dst, &cumulative_nan)) mul_postop \
                (util_get_##float_type##_in_bank(ctx, lhs, &cumulative_nan) * util_get_##float_type##_in_bank(ctx, rhs, &cumulative_nan)), \
            &cumulative_nan); \
    } \
} while(0)

#define FPU_PERFORM_OP1_ALL(ctx, action, float_type, bank_size, dest_bank_index, dest_bank_offset, op_bank_index, op_bank_offset) do { \
    const u8_t len = (dest_bank_index == 0) ? 1 : FPU_BITS_LEN(ctx); \
    const u8_t stride = FPU_BITS_STRIDE(ctx); \
    const u8_t op_stride = op_bank_index == 0 ? 0 : stride; \
    arm_fpu_bank dst = {.index = dest_bank_index, .offset = dest_bank_offset}; \
    arm_fpu_bank op = {.index = op_bank_index, .offset = op_bank_offset}; \
    for(u8_t ctr = 0; ctr < len; \
        dst.offset = (dst.offset + stride) % bank_size, op.offset = (op.offset + op_stride) % bank_size, ++ctr \
    ) \
    { \
        int cumulative_nan = 0; \
        if((#action)[4] == '\0') \
        { /* vneg or vabs, keeps NaN values */ \
            util_set_##float_type##_in_bank(ctx, dst, \
                util_##float_type##_##action( \
                    util_get_##float_type##_in_bank(ctx, op, &cumulative_nan) \
                ), NULL); \
        } \
        else \
        { \
            util_set_##float_type##_in_bank(ctx, dst, \
                util_##float_type##_##action( \
                    util_get_##float_type##_in_bank(ctx, op, &cumulative_nan) \
                ), &cumulative_nan); \
        } \
    } \
} while(0)

#define FPU_PERFORM_ARITH_ALL(ctx, action, float_type, bank_size, dest_bank_index, dest_bank_offset, lhs_bank_index, lhs_bank_offset, rhs_bank_index, rhs_bank_offset) do { \
    const u8_t len = (dest_bank_index == 0) ? 1 : FPU_BITS_LEN(ctx); \
    const u8_t stride = FPU_BITS_STRIDE(ctx); \
    const u8_t rhs_stride = rhs_bank_index == 0 ? 0 : stride; \
    arm_fpu_bank dst = {.index = dest_bank_index, .offset = dest_bank_offset}; \
    arm_fpu_bank lhs = {.index = lhs_bank_index, .offset = lhs_bank_offset}; \
    arm_fpu_bank rhs = {.index = rhs_bank_index, .offset = rhs_bank_offset}; \
    for(u8_t ctr = 0; ctr < len; \
        dst.offset = (dst.offset + stride) % bank_size, lhs.offset = (lhs.offset + stride) % bank_size, rhs.offset = (rhs.offset + rhs_stride) % bank_size, ++ctr \
    ) \
    { \
        int cumulative_nan = 0; \
        util_set_##float_type##_in_bank(ctx, dst, \
            util_##float_type##_##action( \
                util_get_##float_type##_in_bank(ctx, lhs, &cumulative_nan), \
                util_get_##float_type##_in_bank(ctx, rhs, &cumulative_nan) \
            ), &cumulative_nan); \
    } \
} while(0)
