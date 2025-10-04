#include "utils/program.h"
#include "utils/arm_info.h"
#include "utils/section.h"
#include "utils/files.h"
#include "utils/formatters.h"
#include "utils/offsets.h"
#include "utils/signature_info.h"
#include "utils/overload.h"
#include "arm_cpu_asm_ctx.h"
#include <concepts>
#include <type_traits>
#include <chrono>
#include <utility>
#include <functional>
#include <algorithm>
#include <fmt/format.h>
#include <fmt/chrono.h>
#include <xbyak/xbyak.h>
#include <magic_enum/magic_enum_switch.hpp>

namespace ranges = std::ranges;

#define PRINT_NULLIFY 1

namespace recompiler {

namespace fmt_root = ::fmt;

namespace fmt_base {

using fmt_root::println;
using fmt_root::print;
using fmt_root::format;
using fmt_root::format_to;

}

namespace fmt_null {

[[maybe_unused]] void println([[maybe_unused]] auto&&... args) noexcept { }
[[maybe_unused]] void print([[maybe_unused]] auto&&... args) noexcept { }
using fmt_root::format;
using fmt_root::format_to;

}

#ifdef PRINT_NULLIFY
namespace fmt = fmt_null;
#else
namespace fmt = fmt_base;
#endif

template<auto I>
using enum_constant = magic_enum::enum_constant<I>;

template<typename EV, typename... EVs>
concept one_of_raw = false || (std::is_same_v<EV, EVs> || ...);

template<typename EV, auto... EVs>
concept one_of = one_of_raw<EV, enum_constant<EVs>...>;

template<typename I, arm_insn IC>
concept is_insn = std::is_same_v<I, enum_constant<IC>>;

#define INSN_xy_ABLE(insn) insn ## TT, insn ## TB, insn ## BT, insn ## BB

#define INSN_Wy_ABLE(insn) insn ## T, insn ## B

#define INSN_X_ABLE(insn) insn, insn ## X

template<typename I>
concept is_branch_and_exchange = one_of<I, ARM_INS_BX, ARM_INS_BLX>;
template<typename I>
concept is_branch = one_of<I, ARM_INS_B, ARM_INS_BX>;
template<typename I>
concept is_branch_with_link = one_of<I, ARM_INS_BL, ARM_INS_BLX>;

template<typename I>
concept is_store_to_mem_multiple = one_of<I, ARM_INS_STM, ARM_INS_STMIB, ARM_INS_STMDA, ARM_INS_STMDB>;
template<typename I>
concept is_load_from_mem_multiple = one_of<I, ARM_INS_LDM, ARM_INS_LDMIB, ARM_INS_LDMDA, ARM_INS_LDMDB>;

template<typename I>
concept is_store_to_mem = one_of<I, ARM_INS_STRB, ARM_INS_STRH, ARM_INS_STR, ARM_INS_STRD>;
template<typename I>
concept is_load_from_mem = one_of<I, ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDR, ARM_INS_LDRD>;

template<typename I>
concept is_store_to_mem_any = is_store_to_mem<I> || is_store_to_mem_multiple<I>;
template<typename I>
concept is_load_from_mem_any = is_load_from_mem<I> || is_load_from_mem_multiple<I>;

template<typename I>
concept is_unsigned_mul = one_of<I, ARM_INS_UMAAL, ARM_INS_UMLAL, ARM_INS_UMULL>;

template<typename I>
concept is_signed_mul = one_of<I,
    ARM_INS_SMMLA,
    ARM_INS_SMMLS,
    ARM_INS_SMMUL,
    ARM_INS_SMULL,
    ARM_INS_SMLAL,
    ARM_INS_SMLSLD,

    INSN_xy_ABLE(ARM_INS_SMLA),
    INSN_xy_ABLE(ARM_INS_SMLAL),
    INSN_xy_ABLE(ARM_INS_SMUL),

    INSN_Wy_ABLE(ARM_INS_SMLAW),
    INSN_Wy_ABLE(ARM_INS_SMULW),

    INSN_X_ABLE(ARM_INS_SMLAD),
    INSN_X_ABLE(ARM_INS_SMLALD),
    INSN_X_ABLE(ARM_INS_SMLSD),
    INSN_X_ABLE(ARM_INS_SMUAD),
    INSN_X_ABLE(ARM_INS_SMUSD)>;

template<typename I>
concept is_special_mul = is_unsigned_mul<I> || is_signed_mul<I>;

/*
eax <- r0
ebx
ecx
edx <- r3

esi <- r4
edi <- r5

esp <- x86 sp, sp
ebp <- lr
eip <- x86 pc, cant use

r8d <- pc
r9 <- context ptr (64bit)
*/
struct Converter : Xbyak::CodeGenerator {
    OffsetTranslator builder;

    static constexpr std::size_t INSN_RESERVED_SIZE = 120;
    csh handle;
    bool in_arm_mode;
    cs_mode get_cpu_mode() const
    {
        return in_arm_mode ? CS_MODE_ARM : CS_MODE_THUMB;
    }
    cs_mode get_inv_cpu_mode() const
    {
        return in_arm_mode ? CS_MODE_THUMB : CS_MODE_ARM;
    }

    const Xbyak::Reg64 CTX = rdi;

    struct InsnAddr {
        std::size_t byte_offset;
        std::size_t insn_addr;
    };
    std::vector<InsnAddr> converted_addresses;

    Converter(const Program& program_in, std::span<u8_t> into)
        : Xbyak::CodeGenerator(into.size(), into.data())
        , builder{program_in}
    {
        converted_addresses.reserve(program_in.code_sec.length() / 4);
    }

    void set_cpu_mode(csh handle_in, cs_mode cpu_mode_in)
    {
        handle = handle_in;
        in_arm_mode = cpu_mode_in == CS_MODE_ARM;
    }

    void append_instruction(const cs_insn& insn)
    {
#ifdef NDEBUG
#define REPORT_ERROR(...) throw std::runtime_error(fmt::format(__VA_ARGS__));
#else
#define REPORT_ERROR(...) fmt::println(__VA_ARGS__);
#endif

        if(insn.id == ARM_INS_INVALID)
            return;

        if(insn.detail == nullptr)
            return;

        const std::span<const u8_t> grps = std::span(insn.detail->groups, insn.detail->groups_count);

        // removes about 70% of the possible instructions
        // all of those we have no access at all on the v6k mpcore
        static constexpr u8_t not_allowed_groups[] = {
            ARM_FEATURE_HASNEON,
            ARM_FEATURE_HASMVEINT,
            ARM_FEATURE_ISTHUMB2,
            ARM_FEATURE_HASMVEFLOAT,
            ARM_FEATURE_HASV8_1MMAINLINE,
            ARM_FEATURE_HASV8,
            ARM_FEATURE_HASFPARMV8,
            ARM_FEATURE_PREV8,
            ARM_FEATURE_HASCDE,
            ARM_FEATURE_HASACQUIRERELEASE,
            ARM_FEATURE_HASV7,
            ARM_FEATURE_HASV8MBASELINE,
            ARM_FEATURE_HASVFP4,
            ARM_FEATURE_HASV6T2,
            ARM_FEATURE_HASFPREGS16,
            ARM_FEATURE_HASV8MMAINLINE,
            ARM_FEATURE_HASFPREGSV8_1M,
            ARM_FEATURE_HASVFP3,
            ARM_FEATURE_HASV6M,
            ARM_FEATURE_HASV8_4A,
            ARM_FEATURE_HASDOTPROD,
            ARM_FEATURE_HASFULLFP16,
            ARM_FEATURE_HASFP16,
            ARM_FEATURE_HASBF16,
            ARM_FEATURE_HASMATMULINT8,
            ARM_FEATURE_HASDIVIDEINARM,
            ARM_FEATURE_HASVIRTUALIZATION,
            ARM_FEATURE_HASTRUSTZONE,
            ARM_FEATURE_HAS8MSECEXT,

            // subsumed by other flags
            // ARM_FEATURE_HASV8_1A, // hasneon, hasV8
            // ARM_FEATURE_HASV8_2A, // empty
            // ARM_FEATURE_HASV8_3A, // hasneon, fparmV8
            // ARM_FEATURE_HASV8_5A, // empty
            // ARM_FEATURE_HASV8_6A, // empty
            // ARM_FEATURE_HASV8_7A, // empty
            // ARM_FEATURE_HASSHA2, // hasV8
            // ARM_FEATURE_HASDSP, // isTHUMB2
            // ARM_FEATURE_HASMP, // hasV7
            // ARM_FEATURE_HASV7CLREX, // hasacquirerelease
            // ARM_FEATURE_HASAES, // hasV8
            // ARM_FEATURE_HASCRYPTO, // empty
            // ARM_FEATURE_HASCRC, // hasV8
            // ARM_FEATURE_HASRAS, // empty
            // ARM_FEATURE_HASLOB, // hasV8_1Mmainline
            // ARM_FEATURE_HASPACBTI, // hasV8_1Mmainline
            // ARM_FEATURE_HASFP16FML, // hasneon
            // ARM_FEATURE_HASDIVIDEINTHUMB, // hasV8Mbaseline
        };
        for(const u8_t not_allowed : not_allowed_groups)
        {
            if(ranges::contains(grps, not_allowed))
            {
                return;
            }
        }

        const arm_insn raw_insn_id = insn.id == ARM_INS_HINT && insn.is_alias ? arm_insn(insn.alias_id) : arm_insn(insn.id);

        // disallowed instructions not covered by the group/revision check
        switch(raw_insn_id)
        {
        case ARM_INS_SRSIA:
        case ARM_INS_SRSIB:
        case ARM_INS_SRSDA:
        case ARM_INS_SRSDB:

        case ARM_INS_STRBT:
        case ARM_INS_STRHT:
        case ARM_INS_STRT:

        case ARM_INS_LDRBT:
        case ARM_INS_LDRSBT:
        case ARM_INS_LDRHT:
        case ARM_INS_LDRSHT:
        case ARM_INS_LDRT:
            // invalid instructions for user-mode
            return;

        case ARM_INS_LDM:
        case ARM_INS_LDMIB:
        case ARM_INS_LDMDA:
        case ARM_INS_LDMDB:
        case ARM_INS_STM:
        case ARM_INS_STMIB:
        case ARM_INS_STMDA:
        case ARM_INS_STMDB:
            // invalid instructions for user-mode (ldm/stm reg, {...}^)
            if(insn.detail->arm.usermode)
                return;

        case ARM_INS_LDC:
        case ARM_INS_LDCL:
        case ARM_INS_STC:
        case ARM_INS_STCL:
        case ARM_INS_MRRC:
        case ARM_INS_MCRR:
        case ARM_INS_FLDMDBX:
        case ARM_INS_FLDMIAX:
        case ARM_INS_FSTMDBX:
        case ARM_INS_FSTMIAX:
            return;

        default:
            break;
        }

        // nonsense instruction condition
        if(insn.detail->arm.cc == ARMCC_UNDEF)
        {
            // just some special instructions have this, ensure it's in the list otherwise discard
            switch(insn.id)
            {
            case ARM_INS_BX:
            case ARM_INS_BL:
            case ARM_INS_BLX:
            case ARM_INS_UDF:
            case ARM_INS_CLREX:
            case ARM_INS_PLD:
                break;
            default:
                // probably should be silent? maybe still helps to know when something is unimplemented
                REPORT_ERROR("WEIRD UNDEF @ 0x{:08x}: {}", insn.address, insn);
                return;
            }
        }

        // using handler_t = void (*)(Converter*, const InstructionState&);
        // const handler_t handler = magic_enum::enum_switch<handler_t, arm_insn>([this](auto id) -> handler_t {
        //     using insn_t = decltype(id);
        //     using mfunc_t = void (Converter::*)(const InstructionState&, insn_t);
        //     if constexpr (requires (Converter* self, const InstructionState& state) {
        //         self->instruction(state, insn_t{});
        //     })
        //     {
        //         static constexpr mfunc_t overload = static_cast<mfunc_t>(&this->instruction);
        //         return [](Converter* self, const InstructionState& state) {
        //             return (self->*overload)(state, insn_t{});
        //         };
        //     }
        //     else return nullptr;
        // }, raw_insn_id);
        
        // using validator_t = bool (*)(Converter*, const InstructionState&);
        // const validator_t validator = magic_enum::enum_switch<validator_t, arm_insn>([this](auto id) -> validator_t {
        //     using insn_t = decltype(id);
        //     using mfunc_t = bool (Converter::*)(const InstructionState&, insn_t);
        //     if constexpr (requires (Converter* self, const InstructionState& state) {
        //         { self->validate(state, insn_t{}) } -> std::same_as<bool>;
        //     })
        //     {
        //         static constexpr mfunc_t overload = static_cast<mfunc_t>(&this->validate);
        //         return [](Converter* self, const InstructionState& state) {
        //             return (self->*overload)(state, insn_t{});
        //         };
        //     }
        //     else return nullptr;
        // }, raw_insn_id);

        const auto handler = OVERLOAD_ENUM_RESOLVER(instruction, raw_insn_id, void (Converter::*)(const InstructionState&));
        const auto validator = OVERLOAD_ENUM_RESOLVER(validate, raw_insn_id, bool (Converter::*)(const InstructionState&));

        if(handler == nullptr)
        {
            // lets me know to maybe implement something
            // maybe ignore later when it becomes a false positive generator
            REPORT_ERROR("UNIMPL @ 0x{:08x}: {}", insn.address, insn);
            return;
        }

        cs_regs regs_read_val, regs_write_val;
        u8_t read_count = 0, write_count = 0;
        cs_regs_access(handle, &insn, regs_read_val, &read_count, regs_write_val, &write_count);
        const std::string addr_string = make_label(insn.address);

        InstructionState state{
            .insn = insn,
            .addr_string = addr_string,
            .regs_read = std::span(regs_read_val, read_count),
            .regs_write = std::span(regs_write_val, write_count),
        };

        if(validator != nullptr && not validator(this, state))
        {
            // not an error, but discard: failed the check
            return;
        }

        L(addr_string);
        const auto start_point = getSize();
        converted_addresses.emplace_back(getSize(), std::size_t(insn.address));

        inLocalLabel();
        append_instruction_header(state);

        // magic_enum::enum_switch([this, &state](auto id) {
        //     this->instruction(state, id);
        // }, arm_insn(insn.id == ARM_INS_HINT && insn.is_alias ? insn.alias_id : insn.id));
        handler(this, state);

        L(".fin");
        outLocalLabel();

        const auto end_point = getSize();
        const auto interp_size = end_point - start_point;
        if( interp_size >= Converter::INSN_RESERVED_SIZE )
        {
            REPORT_ERROR("EXCESS {} @ 0x{:08x}: {}", interp_size, insn.address, insn);
            return;
        }
    }

private:
    struct InstructionState {
        const cs_insn& insn;
        std::string_view addr_string;
        const std::span<const u16_t> regs_read, regs_write;
        const u32_t arm_addr = u32_t(insn.address);
        const cs_detail* const detail{insn.detail};
        const cs_arm& arm{detail ? detail->arm : cs_arm{}};
        const std::span<const cs_arm_op> ops = detail ? std::span(arm.operands, arm.op_count) : std::span<const cs_arm_op>{};
    };

    const char* get_cpu_mode_str(cs_mode cpu_mode) const
    {
        switch(cpu_mode)
        {
        case CS_MODE_ARM:
            return "ARM";
        case CS_MODE_THUMB:
            return "Thumb";
        default:
            std::unreachable();
        }
    }
    const char* get_cpu_mode_str() const
    {
        return get_cpu_mode_str(get_cpu_mode());
    }

    std::string make_label(const u64_t to_addr, cs_mode cpu_mode) const
    {
        const std::string_view cpu_mode_str = get_cpu_mode_str();
        return fmt::format("L{}_x{:08x}", cpu_mode_str[0], to_addr);
    }
    std::string make_label(const u64_t to_addr) const
    {
        return make_label(to_addr, get_cpu_mode());
    }

    static constexpr inline auto direct_register_map = OverloadList<arm_reg, const Xbyak::Reg32 (Xbyak::CodeGenerator::*)>
        ::with<ARM_REG_R0, &Xbyak::CodeGenerator::eax>
        ::with<ARM_REG_R1, &Xbyak::CodeGenerator::ebx>
        ::with<ARM_REG_R2, &Xbyak::CodeGenerator::ecx>
        ::with<ARM_REG_R3, &Xbyak::CodeGenerator::edx>
        ::with<ARM_REG_R4, &Xbyak::CodeGenerator::esi>
        ::with<ARM_REG_SP, &Xbyak::CodeGenerator::esp>
        ::with<ARM_REG_LR, &Xbyak::CodeGenerator::ebp>
        ::with<ARM_REG_PC, &Xbyak::CodeGenerator::r10d>
        ::make();
    
    static constexpr inline auto indirect_register_map = OverloadList<arm_reg, std::size_t>
        ::with<ARM_REG_R6, offsetof(arm_cpu_asm_ctx, r6)>
        ::with<ARM_REG_R7, offsetof(arm_cpu_asm_ctx, r7)>
        ::with<ARM_REG_R8, offsetof(arm_cpu_asm_ctx, r8)>
        ::with<ARM_REG_R9, offsetof(arm_cpu_asm_ctx, r9)>
        ::with<ARM_REG_R10, offsetof(arm_cpu_asm_ctx, r10)>
        ::with<ARM_REG_R11, offsetof(arm_cpu_asm_ctx, r11)>
        ::with<ARM_REG_R12, offsetof(arm_cpu_asm_ctx, r12)>
        ::make();

    template<arm_reg REG>
    requires requires { direct_register_map.get(enum_constant<REG>{}); }
    Xbyak::Reg32 get_arm_reg(enum_constant<REG> reg)
    {
        const auto member_offset = direct_register_map.get(reg);
        return this->*member_offset;
    }

    template<arm_reg REG>
    requires requires { indirect_register_map.get(enum_constant<REG>{}); }
    Xbyak::Address get_arm_reg(enum_constant<REG> reg)
    {
        const auto offset_in_ctx = indirect_register_map.get(reg);
        return dword[CTX + offset_in_ctx];
    }

    void get_arm_reg(arm_reg reg, auto&& f)
    {
        const auto handler_direct = OVERLOAD_ENUM_RESOLVER(get_arm_reg, reg, Xbyak::Reg32 (Converter::*)());
        if(handler_direct)
            f(handler_direct(this));
        
        const auto handler_indirect = OVERLOAD_ENUM_RESOLVER(get_arm_reg, reg, Xbyak::Address (Converter::*)());
        if(handler_indirect)
            f(handler_indirect(this));

        std::unreachable();
    }

    static constexpr inline auto condcode_jmp_map = OverloadList<ARMCC_CondCodes, void (Xbyak::CodeGenerator::*)(std::string, Xbyak::CodeGenerator::LabelType)>
        ::with<ARMCC_EQ, &je>
        ::with<ARMCC_NE, &jne>
        ::with<ARMCC_MI, &js>
        ::with<ARMCC_PL, &jns>
        ::with<ARMCC_VS, &jo>
        ::with<ARMCC_VC, &jno>
        ::with<ARMCC_GE, &jge>
        ::with<ARMCC_LT, &jl>
        ::with<ARMCC_GT, &jg>
        ::with<ARMCC_LE, &jle>
        // WARNING: ARM carry flag is inverted compared to x86
        // HS := C, LO := !C, HI := C && !Z, LS := !C || Z
        // -> can't just "translate" the C usage into jc/jnc
        // runtime has to set/get ARM flags register with C inverse of x86 flags
        ::with<ARMCC_HS, &jae> // jae == jnc
        ::with<ARMCC_LO, &jb> // jb == jc
        ::with<ARMCC_HI, &ja>
        ::with<ARMCC_LS, &jbe>
        ::make();

    template<ARMCC_CondCodes CC> requires (not one_of<enum_constant<CC>, ARMCC_AL, ARMCC_UNDEF, ARMCC_Invalid>)
    void conditional_jump(std::string&& to_label, enum_constant<CC> cc)
    {
        (this->*(condcode_jmp_map.get(cc)))(std::forward<std::string>(to_label), T_NEAR);
    }

    void append_instruction_header(const InstructionState& state)
    {
        // single byte NOP, runtime can replace with 0xCC for breakpoints/debugging
        nop(1, false);
        write_arm_reg(ARM_REG_PC, state.arm_addr);
        if(state.arm.cc != ARMCC_UNDEF && state.arm.cc != ARMCC_AL)
        {
            // fmt::println("header: conditional {}", state.arm.cc);
            const auto handler = OVERLOAD_ENUM_RESOLVER(conditional_jump, state.arm.cc, void (Converter::*)(std::string&&));
            [[assume(handler != nullptr)]];
            handler(this, ".fin");
        }
    }

    void write_arm_reg(const arm_reg dst_reg, const u32_t value)
    {
        assert(dst_reg != ARM_REG_PC);
        get_arm_reg(dst_reg, [&](auto dst) {
            mov(dst, value);
        });
    }
    void write_arm_reg(const arm_reg dst_reg, const Xbyak::Operand& src)
    {
        assert(dst_reg != ARM_REG_PC);
        get_arm_reg(dst_reg, [&](auto dst) {
            if(dst.isMEM() && src.isMEM())
            {
                mov(r15d, src);
                mov(dst, r15d);
            }
            else
            {
                mov(dst, src);
            }
        });
    }
    void write_arm_reg(const arm_reg dst_reg, const arm_reg src_reg)
    {
        assert(dst_reg != ARM_REG_PC);
        get_arm_reg(src_reg, [&](auto src) {
            write_arm_reg(dst_reg, src);
        });
    }

    void perform_indirect_branch_exchange(const Xbyak::Operand& src)
    {
        fmt::println("TODO: {}", __func__);
    }
    void perform_indirect_branch_exchange(const arm_reg src_reg)
    {
        get_arm_reg(src_reg, [&](auto src) {
            perform_indirect_branch_exchange(src);
        });
    }

    void perform_indirect_branch(const Xbyak::Operand& src)
    {
        fmt::println("TODO: {}", __func__);
    }
    void perform_indirect_branch(const arm_reg src_reg)
    {
        get_arm_reg(src_reg, [&](auto src) {
            perform_indirect_branch(src);
        });
    }

    void instruction([[maybe_unused]] const InstructionState& state, enum_constant<ARM_INS_ALIAS_NOP>)
    {
        // nop: do nothing
    }

    bool validate(const InstructionState& state, enum_constant<ARM_INS_B>)
    {
        const auto branch_target_abs = builder.make<Kind::Absolute>(state.ops[0].imm);
        if(not branch_target_abs.in_code(4))
            return false;

        return true;
    }

    void instruction(const InstructionState& state, enum_constant<ARM_INS_B>)
    {
        const auto branch_target_abs = builder.make<Kind::Absolute>(state.ops[0].imm);
        fmt::println("branch to 0x{:08x}", *branch_target_abs);
        const auto branch_target_label = make_label(*branch_target_abs);
        jmp(branch_target_label);
    }

    template<typename INSN> requires is_branch<INSN>
    void instruction(const InstructionState& state, INSN)
    {
        if constexpr (is_insn<INSN, ARM_INS_B>)
        {
            const auto branch_target_abs = builder.make<Kind::Absolute>(state.ops[0].imm);
            fmt::println("branch to 0x{:08x}", *branch_target_abs);
            const auto branch_target_label = fmt::format("LA_x{:08x}", *branch_target_abs);
            jmp(branch_target_label);
        }
        else
        {
            const auto branch_target_reg = arm_reg(state.ops[0].reg);
            fmt::println("branch-exchange on {}", branch_target_reg);
            perform_indirect_branch(branch_target_reg);
        }
    }

    template<typename INSN> requires is_branch_with_link<INSN>
    bool validate(const InstructionState& state, INSN)
    {
        if(not op_is_a(state.ops[0], arm_op_type::ARM_OP_IMM))
        {
            // blx lr is nonsense
            return not op_is(state.ops[0], arm_reg::ARM_REG_LR);
        }

        const auto branch_target_abs = builder.make<Kind::Absolute>(state.ops[0].imm);
        if(not branch_target_abs.in_code(4))
            return false;

        return true;
    }

    template<typename INSN> requires one_of<INSN, ARM_INS_BL, ARM_INS_BLX>
    void instruction(const InstructionState& state, INSN)
    {
        write_arm_reg(ARM_REG_LR, ARM_REG_PC);

        if(op_is_a(state.ops[0], arm_op_type::ARM_OP_IMM))
        {
            const auto branch_target_abs = builder.make<Kind::Absolute>(state.ops[0].imm);
            if constexpr (is_insn<INSN, ARM_INS_BL>)
            {
                fmt::println("call to 0x{:08x}", *branch_target_abs);
                const auto branch_target_label = make_label(*branch_target_abs);
                jmp(branch_target_label);
            }
            else 
            {
                const auto branch_target_label = make_label(*branch_target_abs, get_inv_cpu_mode());
                fmt::println("call-exchange to 0x{:08x} ({} -> {})",
                    *branch_target_abs,
                    get_cpu_mode_str(get_cpu_mode()), get_cpu_mode_str(get_inv_cpu_mode()));
                jmp(branch_target_label);
            }
        }
        else
        {
            const auto branch_target_reg = arm_reg(state.ops[0].reg);
            fmt::println("call-exchange on {}", branch_target_reg);
            perform_indirect_branch_exchange(branch_target_reg);
        }
    }
    
    template<typename INSN> requires is_load_from_mem<INSN>
    void instruction(const InstructionState& state, INSN)
    {

    }

#define DUMMIFY_INSN(insn_type) \
    void instruction(const InstructionState& state, enum_constant<ARM_INS_ ## insn_type>) { \
        /* fmt::println("TODO @ 0x{:08x}: {}", state.arm_addr, state.insn); */ \
        fmt::println("TODO {}", state.addr_string); \
    }

#define DUMMIFY_INSN_CONCEPT(concept_name) \
    template<typename INSN> requires (concept_name<INSN>) \
    void instruction(const InstructionState& state, INSN) { \
        /* fmt::println("TODO @ 0x{:08x}: {}", state.arm_addr, state.insn); */ \
        fmt::println("TODO {}", state.addr_string); \
    }

#pragma region "Syscall"
    DUMMIFY_INSN(SVC)
    DUMMIFY_INSN(UDF)
#pragma endregion

#pragma region "Coprocessor"
    DUMMIFY_INSN(MCR)
    DUMMIFY_INSN(MRC)
    DUMMIFY_INSN(MRS)
    DUMMIFY_INSN(MSR)
    DUMMIFY_INSN(PLD)
#pragma endregion

#pragma region "Bitwise"
    DUMMIFY_INSN(BIC)
    DUMMIFY_INSN(AND)
    DUMMIFY_INSN(ORR)
    DUMMIFY_INSN(EOR)
    DUMMIFY_INSN(CLZ)
#pragma endregion

#pragma region "Logic"
    DUMMIFY_INSN(CMP)
    DUMMIFY_INSN(CMN)
    DUMMIFY_INSN(TST)
    DUMMIFY_INSN(TEQ)
#pragma endregion

#pragma region "Arithmetic"
    DUMMIFY_INSN(ADD)
    DUMMIFY_INSN(ADC)

    DUMMIFY_INSN(SUB)
    DUMMIFY_INSN(SBC)

    DUMMIFY_INSN(RSB)
    DUMMIFY_INSN(RSC)
#pragma endregion

#pragma region "Saturate"
    DUMMIFY_INSN(SSAT)
    DUMMIFY_INSN(SSAT16)
    DUMMIFY_INSN(USAT)
    DUMMIFY_INSN(USAT16)
#pragma endregion

#pragma region "Sum of Absolute Differences"
    DUMMIFY_INSN(USAD8)
    DUMMIFY_INSN(USADA8)
#pragma endregion

#define DUMMIFY_PARALLEL_PREFIX(prefix) \
    DUMMIFY_INSN(prefix ## ADD8) \
    DUMMIFY_INSN(prefix ## ADD16) \
    DUMMIFY_INSN(prefix ## SUB8) \
    DUMMIFY_INSN(prefix ## SUB16) \
    DUMMIFY_INSN(prefix ## ASX) \
    DUMMIFY_INSN(prefix ## SAX)

#pragma region "Parallel signed"
    DUMMIFY_PARALLEL_PREFIX(S)
#pragma endregion
#pragma region "Parallel signed saturating"
    DUMMIFY_INSN(QADD)
    DUMMIFY_INSN(QDADD)
    DUMMIFY_INSN(QSUB)
    DUMMIFY_INSN(QDSUB)
    DUMMIFY_PARALLEL_PREFIX(Q)
#pragma endregion
#pragma region "Parallel signed halving"
    DUMMIFY_PARALLEL_PREFIX(SH)
#pragma endregion

#pragma region "Parallel unsigned"
    DUMMIFY_PARALLEL_PREFIX(U)
#pragma endregion
#pragma region "Parallel unsigned saturating"
    DUMMIFY_PARALLEL_PREFIX(UQ)
#pragma endregion
#pragma region "Parallel unsigned halving"
    DUMMIFY_PARALLEL_PREFIX(UH)
#pragma endregion

#pragma region "Move"
    DUMMIFY_INSN(MOV)
    DUMMIFY_INSN(MVN)
#pragma endregion

#pragma region "Sign extend"
    DUMMIFY_INSN(SXTB)
    DUMMIFY_INSN(SXTB16)
    DUMMIFY_INSN(SXTH)
#pragma endregion

#pragma region "Sign extend with add"
    DUMMIFY_INSN(SXTAB)
    DUMMIFY_INSN(SXTAB16)
    DUMMIFY_INSN(SXTAH)
#pragma endregion

#pragma region "Zero extend"
    DUMMIFY_INSN(UXTB)
    DUMMIFY_INSN(UXTB16)
    DUMMIFY_INSN(UXTH)
#pragma endregion

#pragma region "Zero extend with add"
    DUMMIFY_INSN(UXTAB)
    DUMMIFY_INSN(UXTAB16)
    DUMMIFY_INSN(UXTAH)
#pragma endregion

#pragma region "Packing"
    DUMMIFY_INSN(SEL)
    DUMMIFY_INSN(PKHBT)
    DUMMIFY_INSN(PKHTB)
#pragma endregion

#pragma region "Reverse"
    DUMMIFY_INSN(REV)
    DUMMIFY_INSN(REV16)
    DUMMIFY_INSN(REVSH)
#pragma endregion

#pragma region "Exclusive"
    DUMMIFY_INSN(CLREX)

    DUMMIFY_INSN(LDREXB)
    DUMMIFY_INSN(LDREXH)
    DUMMIFY_INSN(LDREX)
    DUMMIFY_INSN(LDREXD)

    DUMMIFY_INSN(STREXB)
    DUMMIFY_INSN(STREXH)
    DUMMIFY_INSN(STREX)
    DUMMIFY_INSN(STREXD)
#pragma endregion

#pragma region "Multiply"
    DUMMIFY_INSN(MUL)
    DUMMIFY_INSN(MLA)

    DUMMIFY_INSN_CONCEPT(is_special_mul)
#pragma endregion

#pragma region "Vector"
    DUMMIFY_INSN(VADD)
    DUMMIFY_INSN(VSUB)
    DUMMIFY_INSN(VDIV)
    
    DUMMIFY_INSN(VMUL)
    DUMMIFY_INSN(VNMUL)
    DUMMIFY_INSN(VMLA)
    DUMMIFY_INSN(VMLS)
    DUMMIFY_INSN(VNMLA)
    DUMMIFY_INSN(VNMLS)

    DUMMIFY_INSN(VNEG)
    DUMMIFY_INSN(VABS)
    DUMMIFY_INSN(VSQRT)

    DUMMIFY_INSN(VMOV)
    DUMMIFY_INSN(VCVT)

    DUMMIFY_INSN(VCMP)
    DUMMIFY_INSN(VCMPE)
    DUMMIFY_INSN(VMSR)
    DUMMIFY_INSN(VMRS)
    
    DUMMIFY_INSN(VLDR)
    DUMMIFY_INSN(VLDMIA)
    DUMMIFY_INSN(VLDMDB)
    
    DUMMIFY_INSN(VSTR)
    DUMMIFY_INSN(VSTMIA)
    DUMMIFY_INSN(VSTMDB)
#pragma endregion

};

static void convert_arm(Converter& conv, const Program& program, cs_mode cpu_mode)
{
    Handle_csh handle_ptr{CS_ARCH_ARM, cpu_mode};
    csh handle = handle_ptr.handle;
    cs_insn_ptr insn_ptr = handle_ptr.alloc_insn();
    cs_insn& insn = *insn_ptr;
    const auto code = program.code_sec.bytes;
    const u8_t* const code_ptr_init = code.data();
    const size_t code_size_init = code.size();
    // actual section address
    const u64_t address_init = program.code_sec.start_addr;
    // dummy 0 address for simpler math
    // u64_t const address_init = 0;

    const u8_t* code_ptr = code_ptr_init;
    size_t code_size = code_size_init;
    u64_t address = address_init;

    conv.set_cpu_mode(handle, cpu_mode);

    while(code_size > 0)
    {
        cs_disasm_iter(handle, &code_ptr, &code_size, &address, &insn);

        conv.append_instruction(insn);

        const s64_t next_address = [&] {
            /*
            if(insn.address == address_init && insn.id == ARM_INS_B && insn.detail && insn.detail->arm.cc == ARMCC_CondCodes::ARMCC_AL)
            {
                // homebrew. skip metadata.
                fmt::println("homebrew init, skip to branch dest");
                return insn.detail->arm.operands[0].imm;
            }
            else
            */
                return insn.address + insn.size;
        }();
        const u64_t address_offset = next_address - address_init;
        code_ptr = code_ptr_init + address_offset;
        code_size = code_size_init - address_offset;
        address = next_address;
    }
}

static void convert(const Program& program, [[maybe_unused]] const std::string& out_file)
{
    // estimate number of x64 bytes per 1 ARM instruction (4 bytes)
    std::vector<u8_t> out_bytes(std::size_t(program.code_sec.length() * Converter::INSN_RESERVED_SIZE / 4), u8_t());
    Converter conv(program, out_bytes);
    convert_arm(conv, program, CS_MODE_ARM);
    convert_arm(conv, program, CS_MODE_THUMB);
    out_bytes.resize(conv.getSize());
}

}

static std::vector<u8_t> load_data(const std::string& path, const size_t align_to_n=0x1000u)
{
    recompiler::FILE_ptr fh_ptr{std::fopen(path.c_str(), "rb")};
    if(!fh_ptr) return {};

    auto fh = fh_ptr.get();
    std::fseek(fh, 0, SEEK_END);
    const long fhsz = std::ftell(fh);
    if(fhsz <= 0L) return {};

    std::fseek(fh, 0, SEEK_SET);
    std::vector<u8_t> data(fhsz);
    if(std::fread(data.data(), 1, data.size(), fh) != (size_t)fhsz) return {};

    // ensure consistent behaviour whether or not the file was zero-padded to be page-aligned
    data.resize(ALIGN_TO_NUM(data.size(), align_to_n), 0);

    return data;
}

int main(int argc, char** argv)
{
    std::string path_code, path_rodata, path_data;
    std::string path_out;

    if(argc == 3)
    {
        std::string_view folder = argv[1];
        while(!folder.empty() && folder.back() == '/')
            folder.remove_suffix(1);

        path_code = fmt::format("{}/code.bin", folder);
        path_rodata = fmt::format("{}/rodata.bin", folder);
        path_data = fmt::format("{}/data.bin", folder);

        path_out = argv[2];
    }
    else if(argc == 5)
    {
        path_code = argv[1];
        path_rodata = argv[2];
        path_data = argv[3];
        path_out = argv[4];
    }
    else
    {
        fmt::println(stderr, "Usage: {} [<section binaries folder> <output file> | <code binary> <rodata binary> <data binary> <output file>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    auto sec_code = load_data(path_code);
    auto sec_rodata = load_data(path_rodata);
    auto sec_data = load_data(path_data);
    u32_t code_addr = 0x0010'0000u;
    u32_t bss_size = 0;

    const auto before_time = std::chrono::steady_clock::now();
    recompiler::Program prog(sec_code, sec_rodata, sec_data, code_addr, bss_size);
    recompiler::convert(prog, path_out);
    const auto after_time = std::chrono::steady_clock::now();
    const auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(after_time - before_time);
    fmt::println(stderr, "Time taken: (Conversion) {}", dur);
}
