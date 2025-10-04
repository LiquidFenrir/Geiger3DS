#include <bitset>
#include <compare>
#include <utility>
#include <algorithm>
#include <tuple>
#include <span>

#include "recompiler.h"
#include <utils/arm_info.h>
#include <utils/formatters.h>
#include <utils/bounds.h>
#include <utils/offsets.h>
#include <utils/fuzzy.h>
#include <utils/scope.h>

namespace p {

namespace base {

using fmt::println;
using fmt::print;

}

namespace null {

[[maybe_unused]] void println([[maybe_unused]] auto&&... args) noexcept { }
[[maybe_unused]] void print([[maybe_unused]] auto&&... args) noexcept { }

}

}

#define print_to(file_ptr, ...) (print)(file_ptr, __VA_ARGS__)
#define print(...) print_to(stderr, __VA_ARGS__)

#define println_to(file_ptr, ...) (println)(file_ptr, __VA_ARGS__)
#define println(...) println_to(stderr, __VA_ARGS__)

using namespace recompiler;
namespace ranges = std::ranges;

// find_if
// constexpr bool ranges::contains(const auto& r, auto&& v)
// {
//     return std::find(std::begin(r), std::end(r), v) != std::end(r);
// }
// constexpr bool ranges::contains(const auto& r, auto&& v, auto&& accessor)
// {
//     return std::find_if(std::begin(r), std::end(r), [&](const auto& cv) {
//         return accessor(cv) == v;
//     }) != std::end(r);
// }

enum class BranchSource : u8_t {
    None,
    Static,
    DynamicRegister,
    DynamicMemory,
    DynamicSwitch,
};
enum class NoreturnCase : u8_t {
    Unknown,

    // same condition state before conditional noreturn -> can propagate with the same flag

    OnPass, // conditional execution
    OnFail, // conditional execution

    Never,
    Always,
};

ENUM_FORMATTER_BASE(BranchSource)
ENUM_FORMATTER_BASE(NoreturnCase)

struct InsnMetadata {
    // absolute address
    u32_t addr{};
    // can take an absolute address, or an arm_reg value. type is determined by the BranchSource below
    u32_t branch_destination{};
    // arm_insn
    u16_t insn{ARM_INS_INVALID};
    // ARMCC_CondCodes
    u8_t cc{ARMCC_Invalid};
    // ARMCC_CondCodes, set after analysis of flags clobbering
    u8_t previous_branch_cc{ARMCC_Invalid};
    bool sets_flags{};

    // nothing for BranchSource::Static
    // otherwise, extra data about the register/load
    // example, other operand for the operation taking the arm_reg in branch_destination (also an )
    // union {
    //     arm_reg reg;
    //     int64_t imm;
    //     arm_op_mem mem;
    // } second_part;
    // arm_op_type
    // u8_t second_part_type;

    // can be conditional, but always something that modifies pc
    BranchSource branch{BranchSource::None};
    Fuzzy branch_with_link{Fuzzy::Unknown}; // is a call: sets LR, can be returned to. Sometimes soft: set LR somehow, then set PC somehow
    
    Fuzzy function_start{Fuzzy::Unknown};
    Fuzzy is_exit{Fuzzy::Unknown}; // -> noreturn (propagates up)
    NoreturnCase noreturn_path{NoreturnCase::Unknown};
    // branch static destination, or detected dynamic/computed destination
    Fuzzy is_destination{Fuzzy::Unknown};
    // follows a branch with link and can in fact be returned to (link was not a noreturn)
    Fuzzy is_return_destination{Fuzzy::Unknown};

    Fuzzy is_code{Fuzzy::Unknown};
    // bool jumptable_entry{}; // not is_code, and certainly part of a jumptable: not necessarily a dead end for the code path
    
    Fuzzy reachable{Fuzzy::Unknown};

    // no more modifications to be done on this
    bool fully_handled() const noexcept
    {
        return is_sure(is_code);
    }

    bool is_condition(ARMCC_CondCodes check_for) const noexcept
    {
        return cc == check_for;
    }
    ARMCC_CondCodes get_opposite_condition() const noexcept
    {
        return ARMCC_getOppositeCondition((ARMCC_CondCodes)cc);
    }
    bool is_opposite_condition(ARMCC_CondCodes opposite) const noexcept
    {
        return is_condition(ARMCC_getOppositeCondition(opposite));
    }
    bool unconditional_raw() const noexcept
    {
        return is_condition(ARMCC_AL) || undef();
    }
    bool conditional() const noexcept
    {
        if(unconditional_raw())
            return false;

        // is branch, last branch was conditional with opposite condition
        // -> this is fuctionally unconditional
        if((ARMCC_CondCodes)previous_branch_cc != ARMCC_Invalid && is_branch())
            return !is_opposite_condition((ARMCC_CondCodes)previous_branch_cc);

        return true;
    }
    bool undef() const noexcept
    {
        return is_condition(ARMCC_UNDEF);
    }
    bool is_branch() const noexcept
    {
        return branch != BranchSource::None;
    }

    // any non-linear access visible
    bool is_jumped_to() const noexcept
    {
        return is_destination == Fuzzy::Yes || is_return_destination == Fuzzy::Yes;
    }
    bool is_not_jumped_to() const noexcept
    {
        return is_destination == Fuzzy::No && is_return_destination == Fuzzy::No;
    }
};
struct PassInfo {
    const char* name{nullptr};
    unsigned extra_times{0};
};
struct Coverage {
    OffsetTranslator& builder;
    std::vector<InsnMetadata> metadatas;
    std::vector<PassInfo> passes_applied;

    explicit Coverage(OffsetTranslator& builder_in)
        : builder(builder_in)
        , metadatas(builder.make<Kind::RelativeByte>(builder.program.code_sec.length()).get<Kind::RelativeArm>())
    { }

    InsnMetadata& get_metadata(const Offset<Kind::RelativeArm> offset)
    {
        return metadatas[*offset];
    }
    InsnMetadata* get_metadata_safe(const Offset<Kind::RelativeArm> offset)
    {
        const auto raw_offset = *offset;
        if(raw_offset >= metadatas.size()) return nullptr;
        return &metadatas[raw_offset];
    }

    struct FuzzyStats {
        size_t total[5] = {};

        size_t& total_for(Fuzzy f)
        {
            return total[static_cast<s8_t>(f)+2];
        }
        size_t total_for(Fuzzy f) const
        {
            return total[static_cast<s8_t>(f)+2];
        }

        size_t total_below(Fuzzy f) const
        {
            size_t out = 0;
            switch(f)
            {
            case Fuzzy::Yes:
                out += total_for(Fuzzy::MaybeYes);
            case Fuzzy::MaybeYes:
                out += total_for(Fuzzy::Unknown);
            case Fuzzy::Unknown:
                out += total_for(Fuzzy::MaybeNo);
            case Fuzzy::MaybeNo:
                out += total_for(Fuzzy::No);
            case Fuzzy::No:
                break;
            }
            return out;
        }
        size_t total_below_including(Fuzzy f) const
        {
            size_t out = 0;
            switch(f)
            {
            case Fuzzy::Yes:
                out += total_for(Fuzzy::Yes);
            case Fuzzy::MaybeYes:
                out += total_for(Fuzzy::MaybeYes);
            case Fuzzy::Unknown:
                out += total_for(Fuzzy::Unknown);
            case Fuzzy::MaybeNo:
                out += total_for(Fuzzy::MaybeNo);
            case Fuzzy::No:
                out += total_for(Fuzzy::No);
                break;
            }
            return out;
        }
        size_t total_above(Fuzzy f) const
        {
            size_t out = 0;
            switch(f)
            {
            case Fuzzy::No:
                out += total_for(Fuzzy::MaybeNo);
            case Fuzzy::MaybeNo:
                out += total_for(Fuzzy::Unknown);
            case Fuzzy::Unknown:
                out += total_for(Fuzzy::MaybeYes);
            case Fuzzy::MaybeYes:
                out += total_for(Fuzzy::Yes);
            case Fuzzy::Yes:
                break;
            }
            return out;
        }
        size_t total_above_including(Fuzzy f) const
        {
            size_t out = 0;
            switch(f)
            {
            case Fuzzy::No:
                out += total_for(Fuzzy::No);
            case Fuzzy::MaybeNo:
                out += total_for(Fuzzy::MaybeNo);
            case Fuzzy::Unknown:
                out += total_for(Fuzzy::Unknown);
            case Fuzzy::MaybeYes:
                out += total_for(Fuzzy::MaybeYes);
            case Fuzzy::Yes:
                out += total_for(Fuzzy::Yes);
                break;
            }
            return out;
        }
    };
    struct Stats {
        FuzzyStats code{}, reach{};
        size_t code_reachable{};
        size_t code_maybe_reachable{};
        size_t maybe_code_reachable{};
        size_t is_exit{};
        size_t is_noreturn{};
        size_t noreturn_stop_point{};
        size_t count{};
    };
    Stats measure_coverage() const
    {
        Stats out;
        out.count = metadatas.size();
        for(const auto& meta : metadatas)
        {
            out.code.total_for(meta.is_code) += 1;
            out.reach.total_for(meta.reachable) += 1;

            if(meta.is_exit == Fuzzy::Yes)
                out.is_exit += 1;
            // if(meta.is_noreturn())
            //     out.is_noreturn += 1;

            // noreturn_stop_point will be > is_noreturn because noreturn blocks end on a conditional branch
            // if(meta.noreturn_path == Fuzzy::Yes)
            //     out.noreturn_stop_point += 1;

            if(meta.is_code == Fuzzy::Yes)
            {
                if(meta.reachable == Fuzzy::Yes)
                    out.code_reachable += 1;
                else if(meta.reachable == Fuzzy::MaybeYes)
                    out.code_maybe_reachable += 1;
            }
            else if(meta.is_code == Fuzzy::MaybeYes && meta.reachable == Fuzzy::Yes)
            {
                out.maybe_code_reachable += 1;
            }
        }

        // fix the count (dont want to include non-stop points)
        out.noreturn_stop_point -= out.is_noreturn;
        return out;
    }
};
template <> struct fmt::formatter<Coverage::FuzzyStats> : skip_flags_parse {
    format_context::iterator format(const Coverage::FuzzyStats& value, format_context& ctx) const
    {
#define format_sep "={}, "
#define format_finish "={})"
        return fmt::format_to(ctx.out(), "FuzzyStats("
                "Yes" format_sep
                "MaybeYes" format_sep
                "Unknown" format_sep
                "MaybeNo" format_sep
                "No" format_finish,
            value.total_for(Fuzzy::Yes),
            value.total_for(Fuzzy::MaybeYes),
            value.total_for(Fuzzy::Unknown),
            value.total_for(Fuzzy::MaybeNo),
            value.total_for(Fuzzy::No)
        );
#undef format_sep
#undef format_finish
    }
};
template <> struct fmt::formatter<Coverage::Stats> : skip_flags_parse {
    format_context::iterator format(const Coverage::Stats& value, format_context& ctx) const
    {
#define format_sep "={}, "
#define format_finish "={})"
        return fmt::format_to(ctx.out(), "Stats("
            "code" format_sep
            "reach" format_sep
            "code_reachable" format_sep
            "code_maybe_reachable" format_sep
            "maybe_code_reachable" format_sep
            "is_exit" format_sep
            "is_noreturn" format_sep
            "noreturn_stop_point" format_sep
            "count" format_finish,
            value.code,
            value.reach,
            value.code_reachable,
            value.code_maybe_reachable,
            value.maybe_code_reachable,
            value.is_exit,
            value.is_noreturn,
            value.noreturn_stop_point,
            value.count
        );
#undef format_sep
#undef format_finish
    }
};
template <> struct fmt::formatter<InsnMetadata> : skip_flags_parse {
    format_context::iterator format(const InsnMetadata& value, format_context& ctx) const
    {
        std::string extra_end;
        if(value.is_exit == Fuzzy::Yes)
            fmt::format_to(std::back_inserter(extra_end), "{}is_exit", extra_end.empty()?"":"+");
        
        if(value.branch_with_link == Fuzzy::Yes)
            fmt::format_to(std::back_inserter(extra_end), "{}branch_link", extra_end.empty()?"":"+");

#define format_sep "={}, "
#define format_finish "={})"
        return fmt::format_to(ctx.out(), "Metadata("
            "function_start" format_sep
            "noreturn_path" format_sep
            "branch_dest" format_sep
            "return_dest" format_sep
            "code={}, reachable={}"
            "{}{})",
            value.function_start,
            value.noreturn_path,
            value.is_destination,
            value.is_return_destination,
            value.is_code,
            value.reachable,
            extra_end.empty() ? "" : ", extra=", extra_end
        );
#undef format_sep
#undef format_finish
    }
};

struct PassDataBase {
    const cs_insn& insn;
    std::span<u16_t> regs_read, regs_write;
};
struct PassData : PassDataBase {
    OffsetTranslator& builder;
    Coverage& cover;

    const cs_detail* const detail{insn.detail};
    const cs_arm& arm{detail ? detail->arm : cs_arm{}};

    Offset<Kind::Absolute> next_address = builder.make<Kind::Absolute>(insn.address + insn.size);
    const Offset<Kind::RelativeArm> insn_offset_next = next_address;
    const Offset<Kind::RelativeArm> insn_offset_prev = builder.make<Kind::Absolute>(insn.address - insn.size);
    const Offset<Kind::RelativeArm> insn_offset = builder.make<Kind::Absolute>(insn.address);

    const Offset<Kind::RelativeByte> insn_byte_offset = insn_offset;
    const Offset<Kind::Absolute> insn_addr = insn_offset;

    const InsnMetadata* const metadata_prev = cover.get_metadata_safe(insn_offset_prev);
    InsnMetadata& metadata = cover.get_metadata(insn_offset);
    InsnMetadata* const metadata_next = cover.get_metadata_safe(insn_offset_next);

    const std::span<const u8_t> grps = detail ? std::span(detail->groups, detail->groups_count) : std::span<const u8_t>{};
    const std::span<const cs_arm_op> ops = detail ? std::span(arm.operands, arm.op_count) : std::span<const cs_arm_op>{};
};
template<class T>
struct PassDataGen : PassData, protected T {
    using Data_t = T;
    using Self_t = PassDataGen<T>;
    PassDataGen(const PassData& pd, const T& t)
        : PassData(pd), T(t)
    {

    }
};
template<class P, class T>
struct Pass {
    OffsetTranslator& builder;
    Coverage& cover;
    const char* pass_name;
    T data;

    void start()
    {
        if(cover.passes_applied.empty() or cover.passes_applied.back().name != pass_name)
        {
            cover.passes_applied.emplace_back().name = pass_name;
        }
        else
        {
            cover.passes_applied.back().extra_times++;
        }
    }

    void finish()
    {

    }

    u64_t operator()(const PassDataBase& base, auto&&... args)
    {
        P p_inst{PassData{base, builder, cover}, data};
        p_inst(std::forward<decltype(args)>(args)...);
        return *p_inst.next_address;
    }
};

#define MAKE_PASS_ARGS(...) (__VA_ARGS__)

#define PASS_CREATE_START(name, args, ...) \
    const auto name##_t_get_members = [&]() { return std::forward_as_tuple(__VA_ARGS__); }; \
    struct name##_t : PassDataGen<decltype(name##_t_get_members())> { \
        using Self_t::Self_t; \
        void operator()args { [[maybe_unused]] auto& [ __VA_ARGS__ ] = *(Data_t*)(this);

#define PASS_CREATE_FINISH(name) } }; \
    Pass<name##_t, name##_t::Data_t> name(builder, cover, #name, name##_t_get_members());

template<class P>
static void iterate_all_insn(const Handle_csh& handle_ptr, const Section& code_sec, P& pass, auto&&... args)
{
    csh handle = handle_ptr.handle;
    cs_insn_ptr insn_ptr = handle_ptr.alloc_insn();
    cs_insn& insn = *insn_ptr;
    const auto code = code_sec.bytes;
    const u8_t* const code_ptr_init = code.data();
    size_t const code_size_init = code.size();
    // actual section address
    u64_t const address_init = code_sec.start_addr;
    // dummy 0 address for simpler math
    // u64_t const address_init = 0;

    const u8_t* code_ptr = code_ptr_init;
    size_t code_size = code_size_init;
    u64_t address = address_init;

    cs_regs regs_read_val, regs_write_val;
    std::span regs_read(regs_read_val);
    std::span regs_write(regs_write_val);

    pass.start();
    while(code_size > 0)
    {
        const bool iter_success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, &insn);
        u8_t read_count = 0, write_count = 0;
        if(iter_success)
        {
            cs_regs_access(handle, &insn, regs_read_val, &read_count, regs_write_val, &write_count);
        }
        address = pass(PassDataBase{insn, regs_read.first(read_count), regs_write.first(write_count)}, std::forward<decltype(args)>(args)...);

        const u64_t address_offset = address - address_init;
        code_ptr = code_ptr_init + address_offset;
        code_size = code_size_init - address_offset;
    }
    pass.finish();
}

namespace passes {

#define PASS_META_PRINT 1
#define PASS_REACH_PRINT 1
// #define PASS_A_PRINT 1
// #define PASS_B_PRINT 1

#ifndef PASS_META_PRINT
#define PASS_META_PRINT 0
#endif
#ifndef PASS_REACH_PRINT
#define PASS_REACH_PRINT 0
#endif
#ifndef PASS_A_PRINT
#define PASS_A_PRINT 0
#endif
#ifndef PASS_B_PRINT
#define PASS_B_PRINT 0
#endif

namespace Meta {
#if PASS_META_PRINT
    using namespace p::base;
#else
    using namespace p::null;
#endif
}
namespace A {
#if PASS_A_PRINT
    using namespace p::base;
#else
    using namespace p::null;
#endif
}
namespace B {
#if PASS_B_PRINT
    using namespace p::base;
#else
    using namespace p::null;
#endif
}
namespace Reach {
#if PASS_REACH_PRINT
    using namespace p::base;
#else
    using namespace p::null;
#endif
}

}

namespace recompiler {

VisitTagged analysis(const Program& program)
{
    VisitTagged visits(VisitList(program.code_sec.start_addr, program.code_sec.end_addr));

    if(true)
    {
        using namespace passes::Meta;
        
        println("Analysis: {}", program);
        OffsetTranslator builder(program);
        Coverage cover(builder);

        u64_t initial_skip_offset = 0;
        size_t visited_len_pass_1 = 0;

#pragma region "Pass 0: init"
        PASS_CREATE_START(Pass0,
            MAKE_PASS_ARGS(),
            visited_len_pass_1
        )
        {
            using namespace passes::Meta;

            visited_len_pass_1 += insn.size;
            metadata.addr = insn.address;

            // invalid decode
            // comment is not exactly equivalent, because detail might not be null when decode failed!
            if(insn.id == ARM_INS_INVALID /* || insn.detail == nullptr */)
            {
                metadata.reachable = Fuzzy::No;
                metadata.is_code = Fuzzy::No;
            }

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
                    metadata.reachable = Fuzzy::No;
                    metadata.is_code = Fuzzy::No;
                    break;
                }
            }

            // conditional AND sets flags = high likelihood of garbage?
            // countercase; cmp/tst/cmn
            /*
            if(arm.cc != ARMCC_AL && arm.cc != ARMCC_UNDEF && arm.update_flags)
            {
                if(insn.id != ARM_INS_CMP && insn.id != ARM_INS_CMN && insn.id != ARM_INS_TST)
                {
                    metadata.reachable = Fuzzy::No;
                    metadata.is_code = Fuzzy::No;
                }
            }
            */

            if(metadata.is_code == Fuzzy::No)
                return;

            metadata.insn = insn.id;
            metadata.cc = arm.cc;
            metadata.sets_flags = arm.update_flags;
            // metadata.is_code = Fuzzy::MaybeYes;

            // start symbol is special
            if(*insn_byte_offset == 0)
            {
                metadata.is_code = Fuzzy::Yes;
                metadata.function_start = Fuzzy::Yes;
                metadata.reachable = Fuzzy::Yes;
            }
        }
        PASS_CREATE_FINISH(Pass0)
#pragma endregion

#pragma region "Pass 1: detect all obvious branches"
        PASS_CREATE_START(PassA,
            MAKE_PASS_ARGS(),
            initial_skip_offset
        )
        {
            using namespace passes::A;

            if(metadata.is_code == Fuzzy::No)
                return;

            const bool current_is_branch_reg = ranges::contains(regs_write, (u16_t)ARM_REG_PC);
            const bool current_is_branch_grp = ranges::contains(grps, (u8_t)ARM_GRP_JUMP);
            const bool current_is_call_grp = ranges::contains(grps, (u8_t)ARM_GRP_CALL);

            bool current_is_branch = current_is_branch_reg | current_is_branch_grp | current_is_call_grp;
            if(!current_is_branch)
                return;
            
            // but it might be a false positive
            auto failed_detection = [&]() {
                metadata.branch = BranchSource::None;
                metadata.is_code = Fuzzy::No;
                metadata.reachable = Fuzzy::No;
                current_is_branch = false;
                
                println("Invalid @ 0x{:08x}: {}", *insn_addr, insn);
            };

            if(insn.is_alias && insn.alias_id != (u64_t)-1)
            {
                if(insn.alias_id == ARM_INS_ALIAS_POP)
                {
                    metadata.branch = BranchSource::DynamicMemory;
                }
            }
            else switch(insn.id)
            {
            case ARM_INS_STR:
            case ARM_INS_STRT:
            case ARM_INS_STRB:
            case ARM_INS_STRBT:
            case ARM_INS_STRH:
            case ARM_INS_STRHT:
            case ARM_INS_STRD:
            case ARM_INS_STREX:
            case ARM_INS_STREXB:
            case ARM_INS_STREXH:
            case ARM_INS_STREXD:
                // STR using [PC] with writeback is nonsense
                failed_detection();
                break;

            case ARM_INS_LDRB:
            case ARM_INS_LDRBT:
            case ARM_INS_LDRSB:
            case ARM_INS_LDRSBT:
            case ARM_INS_LDRH:
            case ARM_INS_LDRHT:
            case ARM_INS_LDRSH:
            case ARM_INS_LDRSHT:
            case ARM_INS_LDRD:
            case ARM_INS_LDREXB:
            case ARM_INS_LDREXH:
            case ARM_INS_LDREXD:
                // non-exactly 32bit LDR to PC is nonsense
                // (or using PC as index with writeback)
                failed_detection();
                break;
            
            case ARM_INS_MUL:
                // mul with result to pc is supremely unlikely to be correct
                failed_detection();
                break;
            
            // not a branch for our purposes, but still a valid instruction
            case ARM_INS_SVC:
                metadata.branch = BranchSource::None;
                current_is_branch = false;
                break;

            case ARM_INS_B: {
                const auto branch_target_abs = builder.make<Kind::Absolute>(ops[0].imm);

                if(not branch_target_abs.in_code(4))
                {
                    // cannot branch to outside executable section
                    failed_detection();
                    break;
                }

                metadata.branch = BranchSource::Static;
                metadata.branch_destination = *branch_target_abs;

                // Let the reach propagation do it
                // InsnMetadata& target_metadata = cover.get_metadata(branch_target_abs);
                // target_metadata.is_destination = Fuzzy::MaybeYes;

                // for homebrew, search needs to skip the loader junk after the first instruction (an unconditional branch)
                if(arm.cc == ARMCC_AL && *insn_offset == 0)
                {
                    initial_skip_offset = branch_target_abs.get<Kind::RelativeByte>();
                    for(Offset<Kind::RelativeArm> a = insn_offset_next; a < branch_target_abs; ++a)
                    {
                        auto& inbetween_meta = cover.get_metadata(a);
                        inbetween_meta.is_code = Fuzzy::No;
                        inbetween_meta.reachable = Fuzzy::No;
                    }
                    // Let the reach propagation do it
                    // target_metadata.is_destination = Fuzzy::Yes;
                    // target_metadata.reachable = Fuzzy::Yes;
                    // target_metadata.is_code = Fuzzy::Yes;
                    next_address = branch_target_abs;
                }
                break;
            }
            case ARM_INS_BX: {
                const arm_reg branch_target_reg = (arm_reg)ops[0].reg;
                metadata.branch = BranchSource::DynamicRegister;
                metadata.branch_destination = (u32_t)branch_target_reg;
                break;
            }
            case ARM_INS_BL:
            case ARM_INS_BLX: {
                if(op_is_a(ops[0], ARM_OP_IMM))
                {
                    const auto branch_target_abs = builder.make<Kind::Absolute>(ops[0].imm);

                    if(not branch_target_abs.in_code(4))
                    {
                        // cannot branch to outside executable section
                        failed_detection();
                        break;
                    }

                    metadata.branch = BranchSource::Static;
                    metadata.branch_destination = *branch_target_abs;

                    // Let the reach propagation do it
                    // InsnMetadata& target_metadata = cover.get_metadata(branch_target_abs);
                    // target_metadata.is_destination = Fuzzy::MaybeYes;
                    // target_metadata.function_start = Fuzzy::MaybeYes;
                }
                else if(op_is_a(ops[0], ARM_OP_REG))
                {
                    const arm_reg branch_target_reg = (arm_reg)ops[0].reg;
                    metadata.branch = BranchSource::DynamicRegister;
                    metadata.branch_destination = (u32_t)branch_target_reg;
                }

                metadata.branch_with_link = Fuzzy::Yes;
                // Let the reach propagation do it
                /*
                if(metadata_next)
                {
                    // probably a destination (on the return)
                    // but maybe call is to a noreturn (abort/panic/svcexitprocess)
                    metadata_next->is_destination = Fuzzy::MaybeYes;
                }
                */
                break;
            }

            // probably switch after a series of calculations/checks
            case ARM_INS_LDR:
            case ARM_INS_LDRT:
            case ARM_INS_ADC:
            case ARM_INS_ADD:
            case ARM_INS_ADR:
            case ARM_INS_SUB:
            case ARM_INS_RSC:
                // println("Fine but unhandled @ 0x{:08x}: {}", *insn_addr, insn);
                break;

            // less likely to be used for that
            // case ARM_INS_EOR:
            // case ARM_INS_AND:
            // case ARM_INS_ORR:
            // case ARM_INS_LSL:
            // case ARM_INS_ASR:
            // case ARM_INS_LSR:
            // case ARM_INS_ROR:
                // break;

            // return/pop
            case ARM_INS_LDM:
            case ARM_INS_LDMDA:
            case ARM_INS_LDMDB:
            case ARM_INS_LDMIB:
                // println("Fine but unhandled @ 0x{:08x}: {}", *insn_addr, insn);
                break;

            default:
                println("Unexpected @ 0x{:08x}: {}", *insn_addr, insn);
                break;
            }
        }
        PASS_CREATE_FINISH(PassA)
#pragma endregion

#pragma region "Pass 2: detect obvious invalid uses of instructions"
        PASS_CREATE_START(PassB,
            MAKE_PASS_ARGS(),
            program
        )
        {
            using namespace passes::B;

            if(metadata.is_code == Fuzzy::No)
                return;

            auto failed_detection = [&]() {
                metadata.reachable = Fuzzy::No;
                if(metadata.is_code == Fuzzy::No) return;
                metadata.is_code = Fuzzy::No;
                
                println("Invalid @ 0x{:08x}: {}", *insn_addr, insn);
            };

            bool already_handled = false;
            if(insn.is_alias && insn.alias_id != (u64_t)-1)
            {
                if(insn.alias_id == ARM_INS_ALIAS_POP)
                {
                    // println("Pop alias @ 0x{:08x}: {}", *insn_addr, insn);
                    // println("ops: {}", ops);
                    // pop with sp in list is nonsense
                    // if(ranges::contains(ops.subspan(1), (u16_t)ARM_REG_SP))
                    //     failed_detection();
                }
                else
                {
                    println("Non-pop alias @ 0x{:08x}: {}", *insn_addr, insn);
                    already_handled = true;
                }
            }

            for(const auto& op : ops)
            {
                // shifting pc or sp as flexible operands or using as shifter values is invalid
                if(op.type != ARM_OP_REG)
                    continue;

                if(op.shift.type != ARM_SFT_INVALID && (op.reg == ARM_REG_PC || op.reg == ARM_REG_SP))
                {
                    failed_detection();
                    already_handled = true;
                    break;
                }

                if(op.shift.type > ARM_SFT_REG && (op.shift.value == ARM_REG_PC || op.shift.value == ARM_REG_SP))
                {
                    failed_detection();
                    already_handled = true;
                    break;
                }
            }
            
            if(!already_handled) switch(insn.id)
            {
#pragma region "store to memory"
            case ARM_INS_STR:
            case ARM_INS_STRT:
            case ARM_INS_STRB:
            case ARM_INS_STRBT:
            case ARM_INS_STRH:
            case ARM_INS_STRHT:
            case ARM_INS_STRD: {
                const arm_op_mem& mem = (insn.id == ARM_INS_STRD) ? ops[2].mem : ops[1].mem;
                // in writeback (pre-index/post-index), src must not be base
                if(detail->writeback && ops[0].reg == mem.base)
                    failed_detection();
                // pc may not be base with writeback
                else if(detail->writeback && mem.base == ARM_REG_PC)
                    failed_detection();
                // pc may not be index
                else if(mem.index == ARM_REG_PC)
                    failed_detection();
                // (custom because memory protection)
                // pc may not be base with immediate offset if range is inside code/rodata (right at end is ok)
                else if(mem.base == ARM_REG_PC && mem.index == ARM_REG_INVALID \
                    && is_between<Bound::Closed, Bound::Open>(*insn_addr + mem.disp, program.code_sec.start_addr, program.data_sec.start_addr))
                    failed_detection();
                else if(insn.id == ARM_INS_STRD)
                {
                    // src1 must be even
                    if((ops[0].reg & 1) == 0)
                        failed_detection();
                    // src1 must not be LR
                    else if(ops[0].reg == ARM_REG_LR)
                        failed_detection();
                    // src2 must not be right after src1
                    else if(ops[1].reg != (ops[0].reg + 1))
                        failed_detection();
                    // in writeback (pre-index/post-index), src2 must not be base
                    else if(detail->writeback && ops[1].reg == mem.base)
                        failed_detection();
                }
                break;
            }

            case ARM_INS_STREXD:
                // pc is not allowed at all (extra reg because doubleword)
                if(ops[3].reg == ARM_REG_PC)
                    failed_detection();
                // status dest must not be the others (extra reg because doubleword)
                else if(ops[0].reg == ops[3].reg)
                    failed_detection();
                // src1 must be even
                else if((ops[1].reg & 1) == 0)
                    failed_detection();
                // src1 must not be LR
                else if(ops[1].reg == ARM_REG_LR)
                    failed_detection();
                // src2 must be right after src1
                else if(ops[2].reg != (ops[1].reg + 1))
                    failed_detection();
                [[fallthrough]];
            case ARM_INS_STREX:
            case ARM_INS_STREXB:
            case ARM_INS_STREXH:
                // pc is not allowed at all
                if(ops[0].reg == ARM_REG_PC)
                    failed_detection();
                else if(ops[1].reg == ARM_REG_PC)
                    failed_detection();
                else if(ops[2].reg == ARM_REG_PC)
                    failed_detection();
                // status dest must not be the others
                else if(ops[0].reg == ops[1].reg)
                    failed_detection();
                else if(ops[0].reg == ops[2].reg)
                    failed_detection();
                break;

            case ARM_INS_STM:
            case ARM_INS_STMDA:
            case ARM_INS_STMDB:
            case ARM_INS_STMIB: {
                // pc may not be base
                if(ops[0].reg == ARM_REG_PC)
                    failed_detection();
                // with writeback, base may only appear in the reglist if it is the lowest-numbered register
                // reglist decoded is ordered, so base being the lowest means it's at position 1 as well as 0
                else if(detail->writeback && ranges::contains(ops.subspan(1), ops[0].reg, [](const cs_arm_op& op) {
                    return op.reg;
                }) && ops[0].reg > ops[1].reg)
                    failed_detection();
                break;
            }
#pragma endregion

#pragma region "load from memory"
            case ARM_INS_LDR:
            case ARM_INS_LDRT:
            case ARM_INS_LDRB:
            case ARM_INS_LDRBT:
            case ARM_INS_LDRSB:
            case ARM_INS_LDRSBT:
            case ARM_INS_LDRH:
            case ARM_INS_LDRHT:
            case ARM_INS_LDRSH:
            case ARM_INS_LDRSHT:
            case ARM_INS_LDRD: {
                const arm_op_mem& mem = (insn.id == ARM_INS_LDRD) ? ops[2].mem : ops[1].mem;
                // in writeback (pre-index/post-index), dest must not be base
                if(detail->writeback && ops[0].reg == mem.base)
                    failed_detection();
                // pc may not be dest outside word LDR
                else if(ops[0].reg == ARM_REG_PC && not (insn.id == ARM_INS_LDR || insn.id == ARM_INS_LDRT))
                    failed_detection();
                // pc may not be base with writeback
                else if(detail->writeback && mem.base == ARM_REG_PC)
                    failed_detection();
                // pc may not be index
                else if(mem.index == ARM_REG_PC)
                    failed_detection();
                // doubleword form
                else if(insn.id == ARM_INS_LDRD)
                {
                    // dest1 must be even
                    if((ops[0].reg & 1) == 0)
                        failed_detection();
                    // dest1 must not be LR
                    else if(ops[0].reg == ARM_REG_LR)
                        failed_detection();
                    // dest2 must be right after dest1
                    else if(ops[1].reg != (ops[0].reg + 1))
                        failed_detection();
                    // dest1 must not be index
                    else if(ops[0].reg == mem.index)
                        failed_detection();
                    // dest2 must not be index
                    else if(ops[1].reg == mem.index)
                        failed_detection();
                    // in writeback (pre-index/post-index), dest2 must not be base
                    else if(detail->writeback && ops[1].reg == mem.base)
                        failed_detection();
                }
                break;
            }

            case ARM_INS_LDREXD:
                // pc is not allowed at all (extra reg because doubleword)
                if(ops[2].reg == ARM_REG_PC)
                    failed_detection();
                // dest1 must be even
                else if((ops[0].reg & 1) == 0)
                    failed_detection();
                // dest1 must not be LR
                else if(ops[0].reg == ARM_REG_LR)
                    failed_detection();
                // dest2 must be right after dest1
                else if(ops[1].reg != (ops[0].reg + 1))
                    failed_detection();
                [[fallthrough]];
            case ARM_INS_LDREX:
            case ARM_INS_LDREXB:
            case ARM_INS_LDREXH:
                // pc is not allowed at all
                if(ops[0].reg == ARM_REG_PC)
                    failed_detection();
                else if(ops[1].reg == ARM_REG_PC)
                    failed_detection();
                break;

            case ARM_INS_LDM:
            case ARM_INS_LDMDA:
            case ARM_INS_LDMDB:
            case ARM_INS_LDMIB: {
                // pc may not be base
                if(ops[0].reg == ARM_REG_PC)
                    failed_detection();
                // with writeback, base may not appear in the reglist
                else if(detail->writeback && ranges::contains(ops.subspan(1), ops[0].reg, [](const cs_arm_op& op) {
                    return op.reg;
                }))
                    failed_detection();
                break;
            }
#pragma endregion

            case ARM_INS_SVC: {
                const s64_t svc_id = ops[0].imm;
                if(arm.cc != ARMCC_AL)
                {
                    // no conditional svc allowed (or at least seen outside of detection errors)
                    failed_detection();
                }
                if(svc_id >= 0x80 && svc_id != 0xff)
                {
                    // invalid svc range (only 0 <= 0x7f, and 0xff for debug breakpoint)
                    failed_detection();
                }
                else switch(svc_id)
                {
                case 0x03: // exitprocess
                case 0x09: // exitthread
                case 0x3c: // break
                    metadata.is_exit = Fuzzy::Yes;
                    metadata.noreturn_path = NoreturnCase::Always;
                    break;
                }
                break;
            }

            default:
                // println("Unexpected @ 0x{:08x}: {}", *insn_addr, insn);
                break;
            }
        }
        PASS_CREATE_FINISH(PassB)
#pragma endregion

#pragma region "Intermediate (repeatable) pass handler: propagate reachability"
        PASS_CREATE_START(PropagateReach,
            MAKE_PASS_ARGS(bool& propagate_reach_pass_did_any, ARMCC_CondCodes& prev_branch_condcode),
            initial_skip_offset
        )
        {
            using namespace passes::Reach;

            // updates the "did any" flag if this causes a change in values
            auto do_replace_raw = [&propagate_reach_pass_did_any](auto& into, const auto& with) -> decltype(into)
            {
                if(std::exchange(into, with) != with)
                    propagate_reach_pass_did_any = true;
                return into;
            };

            auto do_replace = [&do_replace_raw, insn_addr=insn.address](Fuzzy& into, const Fuzzy& with) -> Fuzzy&
            {
                // may not change sure values
                if(is_sure(into))
                    return into;
                return do_replace_raw(into, with);
            };
            [[maybe_unused]] auto do_upgrade = [&do_replace, insn_addr=insn.address](Fuzzy& into, const Fuzzy with) -> Fuzzy&
            {
                // may not upgrade sure values
                if(is_sure(into))
                    return into;
                return do_replace(into, std::max(into, with));
            };
            [[maybe_unused]] auto do_downgrade = [&do_replace, insn_addr=insn.address](Fuzzy& into, const Fuzzy with) -> Fuzzy&
            {
                // may not downgrade sure values
                if(is_sure(into))
                    return into;
                return do_replace(into, std::min(into, with));
            };

            if(metadata.is_code == Fuzzy::No)
                return;

            if(metadata.reachable == Fuzzy::No)
                return;
            
            if(metadata.sets_flags || metadata.is_destination == Fuzzy::Yes)
            {
                // flags from last branch cannot be expected
                prev_branch_condcode = ARMCC_Invalid;
            }

            if(metadata.is_branch())
            {
                do_replace_raw(metadata.previous_branch_cc, prev_branch_condcode);
                // unconditional branch -> trashes the flags
                // having a condition code, but marked as following another branch means it's unconditional
                if(not metadata.conditional())
                    // end the conditional branches block
                    prev_branch_condcode = ARMCC_Invalid;
                else
                    // set a new conditional branches block flag
                    prev_branch_condcode = (ARMCC_CondCodes)metadata.cc;
            }
            
            if(metadata_prev == nullptr)
            {
                if(initial_skip_offset)
                    next_address = builder.make<Kind::RelativeByte>(initial_skip_offset);
            }
            else if(metadata_prev->is_code == Fuzzy::Yes && metadata_prev->reachable == Fuzzy::Yes)
            {
                // follows exit, and is not jumped to by something else
                if(metadata_prev->is_exit == Fuzzy::Yes && metadata.is_destination == Fuzzy::No)
                {
                    do_downgrade(metadata.reachable, Fuzzy::No);
                }
                // linear flow
                else if(metadata_prev->branch == BranchSource::None)
                {
                    do_upgrade(metadata.reachable, Fuzzy::Yes);
                    do_upgrade(metadata.is_code, metadata_prev->is_code);
                }
                // branch flow
                else if(metadata_prev->branch_with_link == Fuzzy::Yes)
                {
                    // follows a call. still might be a tail call/to a noreturn (panic, etc)
                    if(metadata_prev->noreturn_path == NoreturnCase::Always)
                    {
                        do_downgrade(metadata.is_return_destination, Fuzzy::No);
                    }
                    else
                    {
                        do_upgrade(metadata.is_return_destination, Fuzzy::Yes);
                    }
                    do_upgrade(metadata.reachable, Fuzzy::Yes);
                    do_upgrade(metadata.is_code, Fuzzy::Yes);
                }
                else if(metadata_prev->conditional())
                {
                    // follows conditional branch -> expect branch may not run
                    do_upgrade(metadata.reachable, Fuzzy::Yes);
                    do_upgrade(metadata.is_code, metadata_prev->is_code);
                }
                else
                {
                    // follows unconditional branch
                    if(metadata.is_not_jumped_to())
                    {
                        // is not jumped to by something else -> can never be accessed
                        do_downgrade(metadata.reachable, Fuzzy::No);
                    }
                    else
                    {
                        // do_upgrade(metadata.is_code, metadata_prev->is_code);
                    }
                }
            }
            else if((metadata_prev->is_code == Fuzzy::No || metadata_prev->reachable == Fuzzy::No) && metadata.is_not_jumped_to())
            {
                // follows non-executed thing, and is not jumped to by something else
                do_downgrade(metadata.reachable, Fuzzy::No);
            }

            if(metadata.reachable == Fuzzy::Yes)
            {
                /*
                if(metadata.branch_with_link != Fuzzy::Yes)
                {
                    if(metadata.cc == prev_branch_opp_condcode)
                    {
                        prev_branch_opp_condcode = metadata.get_opposite_condition();
                    }
                }
                */
                if(metadata.branch == BranchSource::Static)
                {
                    auto& dest_metadata = cover.get_metadata(builder.make<Kind::Absolute>(metadata.branch_destination));
                    do_upgrade(dest_metadata.reachable, metadata.reachable);
                    do_upgrade(dest_metadata.is_destination, metadata.reachable);
                    do_upgrade(dest_metadata.is_code, metadata.is_code);

                    // extremely unlikely for a branch with link to be used elsewhere than to a function
                    // except maybe when skipping the start of a function as some optimisation?
                    // but then it's still a function start, just has another function "branching" to it directly above
                    if(metadata.branch_with_link == Fuzzy::Yes)
                        do_upgrade(dest_metadata.function_start, metadata.reachable);

                    if(dest_metadata.noreturn_path == NoreturnCase::Always)
                    {
                        metadata.noreturn_path = metadata.conditional() ? NoreturnCase::OnPass : NoreturnCase::Always;
                    }

                    
                    if(metadata_next != nullptr && metadata_next->reachable == Fuzzy::Yes && metadata_next->is_code == Fuzzy::Yes)
                    {
                        
                    }
                }
                else if(metadata.branch == BranchSource::None)
                {
                    // not a branch
                }
            }

            if(metadata.is_return_destination == Fuzzy::Yes && not metadata.unconditional_raw())
            {
                // is returned to, but is conditional: flags are trashed. always bad.
                do_downgrade(metadata.reachable, Fuzzy::No);
                do_downgrade(metadata.is_code, Fuzzy::No);
            }

            if(metadata_next != nullptr && metadata_next->reachable == Fuzzy::Yes && metadata_next->is_code == Fuzzy::Yes)
            {
                if(metadata_next->noreturn_path == NoreturnCase::Always)
                {
                    if(metadata.branch == BranchSource::None)
                    {
                        // not a branch
                        if(metadata_next->is_branch() && metadata_next->conditional())
                        {

                        }
                        else
                        {
                            metadata.noreturn_path = NoreturnCase::Always;
                        }
                    }
                    else if(metadata.conditional())
                    {

                    }
                    else
                    {
                        // uncond branch
                    }
                }
            }
        }
        PASS_CREATE_FINISH(PropagateReach)
        auto perform_propagate_pass_single = [&]() -> bool
        {
            using namespace passes::Reach;

            // passes::Reach::println("Propagation pass");
            bool pass_did_any = false;
            ARMCC_CondCodes prev_branch_condcode = ARMCC_Invalid;
            iterate_all_insn({CS_ARCH_ARM, CS_MODE_ARM}, program.code_sec, PropagateReach, std::ref(pass_did_any), std::ref(prev_branch_condcode));
            // passes::Reach::println("Did anything: {}", propagate_reach_pass_did_any);
            return pass_did_any;
        };
        auto perform_propagate_pass_full = [&]() -> void
        {
            using namespace passes::Reach;
            println("Propagation pass");
            println("Coverage before: {}", cover.measure_coverage());

            unsigned iterations = 0;
            while(perform_propagate_pass_single())
            {
                // passes::Reach::println("Coverage @ {}: {}", iterations, cover.measure_coverage());
                ++iterations;
            }
            println("Coverage after {} iterations: {}", iterations, cover.measure_coverage());
        };
#pragma endregion

#pragma region "Pass F: dump results"
        PASS_CREATE_START(PassF,
            MAKE_PASS_ARGS(FILE* into),
            program
        )
        {
            using p::base::println;
            using p::base::print;

            if(metadata.is_code != Fuzzy::No)
            {
                println_to(into, "# {}", metadata);
            }

            const u32_t insn_value = (u32_t(insn.bytes[3]) << 24) | (u32_t(insn.bytes[2]) << 16) | (u32_t(insn.bytes[1]) << 8) | u32_t(insn.bytes[0]);
            print_to(into, "{:08x}: {:08x} ", insn.address, insn_value);
            if(metadata.is_code == Fuzzy::No)
            {
                println_to(into, ".word 0x{:08x}", insn_value);
            }
            else
            {
                println_to(into, "{}{}{}", insn.mnemonic, insn.op_str[0] == '\0' ? "" : " ", insn.op_str);
            }
        }
        PASS_CREATE_FINISH(PassF)
#pragma endregion

        println("Pass 0");
        iterate_all_insn({CS_ARCH_ARM, CS_MODE_ARM}, program.code_sec, Pass0);
        println("Visited: {}/{} bytes", visited_len_pass_1, program.code_sec.length());

        println("Pass 2");
        iterate_all_insn({CS_ARCH_ARM, CS_MODE_ARM}, program.code_sec, PassB);
        println("Pass 1");
        iterate_all_insn({CS_ARCH_ARM, CS_MODE_ARM}, program.code_sec, PassA);

        perform_propagate_pass_full();

        [&] {
            using p::base::println;
            using p::base::print;

            for(const auto pass_info : cover.passes_applied)
            {
                print_to(stdout, "{}", pass_info.name);
                if(pass_info.extra_times)
                {
                    print_to(stdout, " (x{})", pass_info.extra_times + 1);
                }
                println_to(stdout, "");
            }
            iterate_all_insn({CS_ARCH_ARM, CS_MODE_ARM}, program.code_sec, PassF, stdout);
        }();
    }

    if(false)
    {
        Handle_csh handle_thumb{CS_ARCH_ARM, CS_MODE_THUMB};
        cs_insn_ptr insn_thumb = handle_thumb.alloc_insn();
        std::vector<InsnMetadata> metadata_thumb(visits.unknown.root.length() / 2);
    }

    return visits;
}

}
