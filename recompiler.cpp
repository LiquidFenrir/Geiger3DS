extern "C" {
#include "capstone/platform.h"
#include "capstone/capstone.h"
}
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <memory>
#include <string>
#include <span>
#include <set>
#include <map>
#include <utility>
#include <tuple>
#include <format>
#include <algorithm>

#define safe_fprintf(ptr, ...) do { if(ptr) fprintf(ptr, __VA_ARGS__); } while(0)
#define safe_fwrite(a, b, c, ptr) do { if(ptr) fwrite(a, b, c, ptr); } while(0)
#define cond_printf(...) do { if(!ctx.suppress_print) printf(__VA_ARGS__); } while(0)
using u32 = std::uint32_t;
using u8 = std::uint8_t;

struct cs_insn_deleter {
    void operator()(cs_insn* ptr)
    {
        cs_free(ptr, 1);
    }
};
using cs_insn_ptr = std::unique_ptr<cs_insn, cs_insn_deleter>;

struct FILE_deleter {
    void operator()(FILE* ptr)
    {
        fclose(ptr);
    }
};
using FILE_ptr = std::unique_ptr<FILE, FILE_deleter>;

#define DISASM_LIST_UNIMPL 1
struct ProcessDisasmContext {
    const u32 start_addr;
    const u32 start_code_addr;
    const std::span<const u8> start_code;
    const u32 end_code_addr;
    const u32 start_rodata_addr;
    const std::span<const u8> start_rodata;
    const u32 end_rodata_addr;
    const u32 start_data_addr;
    const std::span<const u8> start_data;
    const u32 end_data_addr;
    const bool allow_thumb;
    bool suppress_print{false};

    // mapping goes
    // ((4x) / 4) * 3 -> ARM mapping
    // ((4x + 1) / 4) * 3 + 1 -> THUMB mapping (first)
    // ((4x + 3) / 4) * 3 + 2 -> THUMB mapping (second)
    struct MappingValue {
        bool visited{false};
        bool tried{false};
        bool jumptable_entry{false};
        bool is_unrecover_branch{false};
        bool is_function_start{false};
        bool failed_guess{false};
        u32 has_adr_start{0};

        void reset()
        {
            visited = false;
            is_unrecover_branch = false;
            is_function_start = false;
        }
    };
    std::vector<MappingValue> analyzed{(start_code.size() / 4) * 3};
    std::span<const u8> get_from_pointer(const u32 addr, const u32 size)
    {
        if(start_code_addr <= addr && addr + size <= end_code_addr)
        {
            const auto offset = get_offset_text(addr);
            return start_code.subspan(offset, size);
        }
        else if(start_rodata_addr <= addr && addr + size <= end_rodata_addr)
        {
            const auto offset = get_offset_rodata(addr);
            return start_rodata.subspan(offset, size);
        }
        else if(start_data_addr <= addr && addr + size <= end_data_addr)
        {
            const auto offset = get_offset_data(addr);
            return start_data.subspan(offset, size);
        }
        return {};
    }

    std::size_t get_offset(const u32 addr)
    {
        return addr - start_addr;
    }
    std::size_t get_offset_text(const u32 addr)
    {
        return addr - start_code_addr;
    }
    std::size_t get_offset_rodata(const u32 addr)
    {
        return addr - start_rodata_addr;
    }
    std::size_t get_offset_data(const u32 addr)
    {
        return addr - start_data_addr;
    }

    u32 get_mapping_index(const u32 addr)
    {
        const u32 offset = get_offset(addr);
        const u32 instr_offset = offset / 4;
        const bool instr_is_thumb = (offset & 1) == 1;
        if(instr_is_thumb)
        {
            const bool instr_is_second_half_thumb = (offset & 2) == 2;
            const u32 instr_thumb_offset = (instr_is_second_half_thumb ? 2 : 1);
            return instr_offset * 3 + instr_thumb_offset;
        }
        else
            return instr_offset * 3;
    }
    MappingValue& get_mapping(const u32 addr)
    {
        const auto mapping_index = get_mapping_index(addr);
        if(mapping_index >= analyzed.size())
        {
            fprintf(stderr, "mapping index for addr 0x%08x %d\n", addr, mapping_index);
        }
        return analyzed[mapping_index];
    }
    struct BranchDestination {
        u32 addr;
        bool is_function_start;
        bool is_thumb;
        bool ignore_previous;
        ARMCC_CondCodes with_condcode{ARMCC_CondCodes::ARMCC_AL};
        bool is_guess{false};

        bool operator<(const BranchDestination& other) const
        {
            return (!is_guess && other.is_guess) || (!is_thumb && other.is_thumb) || (
                (!is_guess && addr < other.addr)
                || 
                (is_guess && !(addr < other.addr)) // guesses are stored in reverse order
            );
        }
    };
    // always sorted like <arm sure> <thumb sure> <arm guess> <thumb guess>
    std::set<BranchDestination> branches{};
    std::vector<BranchDestination> branches_temp_list{};
    u32 initial_skip_offset{0};
    void add_branch(BranchDestination dest)
    {
        branches_temp_list.push_back(dest);
    }
    void add_guess_branch(BranchDestination dest)
    {
        dest.is_guess = true;
        add_branch(dest);
    }
    void commit_branches()
    {
        for(auto dest : branches_temp_list)
        {
            if(dest.is_thumb || (dest.addr & 1))
            {
                dest.addr |= 1;
                dest.is_thumb = true;
            }

            // printf("Adding %s branch to 0x%08x as func? %d as thumb? %d\n", dest.is_guess ? "guess" : "", dest.addr, (int)dest.is_function_start, (int)dest.is_thumb);

            if(dest.is_thumb && !allow_thumb)
            {
                // printf("DISABLED\n");
                continue;
            }

            if(const auto& mapping = get_mapping(dest.addr); mapping.visited || mapping.tried)
            {
                // printf("ALREADYVISITED\n");
                continue;
            }

            auto [it, inserted] = branches.insert(dest);
            // printf("INSERT: %d\n", (int)inserted);
        }
        branches_temp_list.clear();
    }
    void discard_branches()
    {
        branches_temp_list.clear();
    }

    bool find_temp_branch(const auto& pred)
    {
        return std::find_if(branches_temp_list.cbegin(), branches_temp_list.cend(), pred) != branches_temp_list.cend();
    }

    // returns the next branch, if it matches de predicate
    // if it does not, it is left in the structure
    std::optional<BranchDestination> get_next_branch_if(const auto& pred)
    {
        if(branches.empty())
            return std::nullopt;
        const auto it = branches.begin();
        if(!pred(*it))
            return std::nullopt;

        const auto dest = *it;
        branches.erase(it);
        return dest;
    }
    std::optional<BranchDestination> get_next_branch()
    {
        return get_next_branch_if([]([[maybe_unused]] const auto&  x) { return true; });
    }

    struct Handle_csh {
        csh handle;
        Handle_csh(auto&&... args)
        {
            cs_open(args..., &handle);
            cs_option(handle, CS_OPT_NO_BRANCH_OFFSET, CS_OPT_ON);
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        }
        ~Handle_csh()
        {
            cs_close(&handle);
        }
    };
    Handle_csh handle_arm{CS_ARCH_ARM, CS_MODE_ARM}, handle_thumb{CS_ARCH_ARM, CS_MODE_THUMB};
    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    cs_insn_ptr insn_arm{cs_malloc(handle_arm.handle)};
    cs_insn_ptr insn_thumb{cs_malloc(handle_thumb.handle)};
    std::map<uint64_t, std::string> insn_list{};
    using insn_temp_t = std::tuple<std::pair<uint64_t, std::string>
#if DISASM_LIST_UNIMPL
        , arm_insn
#endif
    >;
    std::vector<insn_temp_t> insn_temp_list{};
#if DISASM_LIST_UNIMPL
    std::set<std::string> insn_unimplemented_list{};
#endif

    struct State {
        csh* handle;
        const uint8_t* code;
        size_t code_size;
        uint64_t address;
        cs_insn* insn;
    };

    void add_insn(auto&&... parts)
    {
        insn_temp_list.emplace_back(std::forward<decltype(parts)>(parts)...);
    }
    void commit_insns(const State& state)
    {
        for(auto& temp_insn : insn_temp_list)
        {
            insn_list.insert(std::move(std::get<0>(temp_insn)));
#if DISASM_LIST_UNIMPL
            if(const auto insn_id = std::get<1>(temp_insn); insn_id != arm_insn::ARM_INS_INVALID)
                insn_unimplemented_list.insert(cs_insn_name(*state.handle, insn_id));
#endif
        }
        insn_temp_list.clear();
    }
    void discard_insns(const BranchDestination& entry)
    {
        for(auto& temp_insn : insn_temp_list)
        {
            auto& mapping = get_mapping(std::get<0>(temp_insn).first);
            mapping.reset();
            mapping.failed_guess = true;
        }
        auto& mapping = get_mapping(entry.addr);
        mapping.failed_guess = true;
        insn_temp_list.clear();
    }
};

#define INSN_APPEND_LDREX_TYPE(c_ldr_type) \
    result += std::format("ARM_CPU_PERFORM_LDREX_ALL(ctx, ctx->{}, " #c_ldr_type ", ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.base));

#define INSN_APPEND_LDREXD() \
    result += std::format("ARM_CPU_PERFORM_LDREXD(ctx, ctx->{}, ctx->{}, ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.base));

#define INSN_APPEND_STREX_TYPE(c_str_type, c_str_and) \
    result += std::format("ARM_CPU_PERFORM_STREX_ALL(ctx, ctx->{}, ctx->{}, " #c_str_type ", " #c_str_and ", ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.base));

#define INSN_APPEND_STREXD() \
    result += std::format("ARM_CPU_PERFORM_STREXD(ctx, ctx->{}, ctx->{}, ctx->{}, ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[3].mem.base));

#define INSN_APPEND_LDR_TYPE(c_ldr_type, c_ldr_cast) \
    result += std::format("ARM_CPU_PERFORM_LDR_ALL(ctx, ctx->{}, " #c_ldr_type ", " #c_ldr_cast ", ctx->{}, ", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.base)); \
    if(insn.detail->arm.operands[1].subtracted) \
        result += "-"; \
    else \
        result += "+"; \
    result += ", (uint32_t)("; \
    if(insn.detail->arm.operands[1].mem.index == arm_reg::ARM_REG_INVALID) \
        result += std::format("{}", insn.detail->arm.operands[1].mem.disp); \
    else { \
        if(insn.detail->arm.operands[1].shift.type != ARM_SFT_INVALID) { \
            if(insn.detail->arm.operands[1].shift.type == ARM_SFT_LSL) \
                result += std::format("ctx->{} << ", cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.index)); \
            else if(insn.detail->arm.operands[1].shift.type == ARM_SFT_LSR) \
                result += std::format("ctx->{} >> ", cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.index)); \
            else if(insn.detail->arm.operands[1].shift.type == ARM_SFT_ASR) \
                result += std::format("(int32_t)(ctx->{}) >> ", cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.index)); \
            result += std::format("{}", insn.detail->arm.operands[1].shift.value); \
        } else \
                result += std::format("ctx->{}", cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.index)); \
    } \
    result += std::format("), {}, {});", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);

#define INSN_APPEND_STR_TYPE(c_str_type, c_str_and) \
    result += std::format("ARM_CPU_PERFORM_STR_ALL(ctx, ctx->{}, " #c_str_type ", " #c_str_and ", ctx->{}, ", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.base)); \
    if(insn.detail->arm.operands[1].subtracted) \
        result += "-"; \
    else \
        result += "+"; \
    result += ", ("; \
    if(insn.detail->arm.operands[1].mem.index == arm_reg::ARM_REG_INVALID) \
        result += std::format("{}", insn.detail->arm.operands[1].mem.disp); \
    else { \
        result += std::format("ctx->{}", cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.index)); \
        if(insn.detail->arm.operands[1].shift.type != ARM_SFT_INVALID) { \
            if(insn.detail->arm.operands[1].shift.type == ARM_SFT_LSL) \
                result += " << "; \
            else if(insn.detail->arm.operands[1].shift.type == ARM_SFT_LSR) \
                result += " >> "; \
            result += std::format("{}", insn.detail->arm.operands[1].shift.value); \
        } \
    } \
    result += std::format("), {}, {});", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);

#define INSN_APPEND_POP(c_ldm_type, c_ldm_init, c_ldm_step, c_ldm_final) \
    result += std::format("ARM_CPU_PERFORM_LDM_ALL(ctx, ctx->sp, 1, {}, {}, {}, ", c_ldm_init, c_ldm_step, c_ldm_final); \
    { \
    bool have_pc_in_list = false; \
    for(int reg_idx = 0; reg_idx < insn.detail->arm.op_count; ++reg_idx) { \
        result += std::format("(" #c_ldm_type ", {}, {})", reg_idx, cs_reg_name(*state.handle, insn.detail->arm.operands[reg_idx].reg)); \
        if(insn.detail->arm.operands[reg_idx].reg == arm_reg::ARM_REG_PC) have_pc_in_list = true; \
    } \
    result += std::format(", {});", (int)have_pc_in_list); \
    }

#define INSN_APPEND_LDM(c_ldm_type, c_ldm_init, c_ldm_step, c_ldm_final) \
    result += std::format("ARM_CPU_PERFORM_LDM_ALL(ctx, ctx->{}, {}, {}, {}, {}, ", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), (int)insn.detail->writeback, c_ldm_init, c_ldm_step, c_ldm_final); \
    { \
    bool have_pc_in_list = false; \
    for(int reg_idx = 1; reg_idx < insn.detail->arm.op_count; ++reg_idx) { \
        result += std::format("(" #c_ldm_type ", {}, {})", reg_idx - 1, cs_reg_name(*state.handle, insn.detail->arm.operands[reg_idx].reg)); \
        if(insn.detail->arm.operands[reg_idx].reg == arm_reg::ARM_REG_PC) have_pc_in_list = true; \
    } \
    result += std::format(", {});", (int)have_pc_in_list); \
    }

#define INSN_APPEND_PUSH(c_stm_type, c_stm_init, c_stm_step, c_stm_final) \
    result += std::format("ARM_CPU_PERFORM_STM_ALL(ctx, ctx->sp, 1, {}, {}, {}, ", c_stm_init, c_stm_step, c_stm_final); \
    for(int reg_idx = 0; reg_idx < insn.detail->arm.op_count; ++reg_idx) \
        result += std::format("(" #c_stm_type ", {}, {})", reg_idx, cs_reg_name(*state.handle, insn.detail->arm.operands[reg_idx].reg)); \
    result += ");";

#define INSN_APPEND_STM(c_stm_type, c_stm_init, c_stm_step, c_stm_final) \
    result += std::format("ARM_CPU_PERFORM_STM_ALL(ctx, ctx->{}, {}, {}, {}, {}, ", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), (int)insn.detail->writeback, c_stm_init, c_stm_step, c_stm_final); \
    for(int reg_idx = 1; reg_idx < insn.detail->arm.op_count; ++reg_idx) \
        result += std::format("(" #c_stm_type ", {}, {})", reg_idx - 1, cs_reg_name(*state.handle, insn.detail->arm.operands[reg_idx].reg)); \
    result += ");";

#define INSN_APPEND_operand2(c_op_updates_flags, c_op_idx) \
    if(insn.detail->arm.operands[c_op_idx].type == arm_op_type::ARM_OP_REG) switch(insn.detail->arm.operands[c_op_idx].shift.type) { \
    case arm_shifter::ARM_SFT_INVALID: \
        result += std::format("ctx->{}", cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg)); \
        break; \
    case arm_shifter::ARM_SFT_ASR: \
        result += std::format("ARM_CPU_PERFORM_ASR(ctx, ctx->{}, arm_cpu_update_carry_flag_constant_operand2(ctx, {}, {}))", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, insn.detail->arm.operands[c_op_idx].shift.value); \
        break; \
    case arm_shifter::ARM_SFT_LSL: \
        result += std::format("ARM_CPU_PERFORM_LSL(ctx, ctx->{}, arm_cpu_update_carry_flag_constant_operand2(ctx, {}, {}))", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, insn.detail->arm.operands[c_op_idx].shift.value); \
        break; \
    case arm_shifter::ARM_SFT_LSR: \
        result += std::format("ARM_CPU_PERFORM_LSR(ctx, ctx->{}, arm_cpu_update_carry_flag_constant_operand2(ctx, {}, {}))", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, insn.detail->arm.operands[c_op_idx].shift.value); \
        break; \
    case arm_shifter::ARM_SFT_ROR: \
        result += std::format("ARM_CPU_PERFORM_ROR(ctx, ctx->{}, arm_cpu_update_carry_flag_constant_operand2(ctx, {}, {}))", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, insn.detail->arm.operands[c_op_idx].shift.value); \
        break; \
    case arm_shifter::ARM_SFT_RRX: \
        result += std::format("ARM_CPU_PERFORM_RRX(ctx, ctx->{}, {})", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags); \
        break; \
    case arm_shifter::ARM_SFT_ASR_REG: \
        result += std::format("ARM_CPU_PERFORM_asr_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    case arm_shifter::ARM_SFT_LSL_REG: \
        result += std::format("ARM_CPU_PERFORM_lsl_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    case arm_shifter::ARM_SFT_LSR_REG: \
        result += std::format("ARM_CPU_PERFORM_lsr_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    case arm_shifter::ARM_SFT_ROR_REG: \
        result += std::format("ARM_CPU_PERFORM_ror_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    default: \
        assert(false && "Invalid shift operand2"); \
        break; \
    } else if(insn.detail->arm.operands[c_op_idx].type == arm_op_type::ARM_OP_IMM) result += std::format("{}", insn.detail->arm.operands[c_op_idx].imm);

#define INSN_APPEND_XT_TYPE(c_basic_type, c_extend_type, c_and_mask) \
    result += std::format("ARM_CPU_PERFORM_XT(ctx, ctx->{}, ctx->{}, {}, " #c_and_mask ", " #c_basic_type ", " #c_extend_type ");", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    (insn.detail->arm.operands[1].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0));

#define INSN_APPEND_XTA_TYPE(c_basic_type, c_extend_type, c_and_mask) \
    result += std::format("ARM_CPU_PERFORM_XTA(ctx, ctx->{}, ctx->{}, {}, " #c_and_mask ", " #c_basic_type ", " #c_extend_type ", ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    (insn.detail->arm.operands[2].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));

#define INSN_APPEND_XTB16_TYPE(c_basic_type, c_extend_type) \
    result += std::format("ARM_CPU_PERFORM_XTB16(ctx, ctx->{}, ctx->{}, {}, " #c_basic_type ", " #c_extend_type ");", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    (insn.detail->arm.operands[1].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0));

#define INSN_APPEND_XTAB16_TYPE(c_basic_type, c_extend_type) \
    result += std::format("ARM_CPU_PERFORM_XTAB16(ctx, ctx->{}, ctx->{}, {}, " #c_basic_type ", " #c_extend_type ", ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    (insn.detail->arm.operands[2].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));

#define INSN_APPEND_MUL() \
    result += std::format("ARM_CPU_PERFORM_MUL(ctx, {}, ctx->{}, ctx->{}, ctx->{});", \
    (int)insn.detail->arm.update_flags, \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));

#define INSN_APPEND_MLA() \
    result += std::format("ARM_CPU_PERFORM_MLA(ctx, {}, ctx->{}, ctx->{}, ctx->{}, ctx->{});", \
    (int)insn.detail->arm.update_flags, \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[3].reg));

#define INSN_APPEND_MUL_MLA_LONG_TYPE(c_mul_mla_kind, c_base_type) \
    result += std::format("ARM_CPU_PERFORM_x" #c_mul_mla_kind "L(ctx, " #c_base_type ", {}, ctx->{}, ctx->{}, ctx->{}, ctx->{});", \
    (int)insn.detail->arm.update_flags, \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[3].reg));

#define INSN_APPEND_SIMD_N_TYPE(c_base_type, c_bitness, c_operation) \
    result += std::format("ARM_CPU_PERFORM_SIMD_" #c_bitness "_TYPE(ctx, " #c_base_type ", " #c_operation ", ctx->{}, ctx->{}, ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));
    
#define INSN_APPEND_SIMD_16_DUAL_TYPE(c_base_type, c_operation_top, c_operation_bottom) \
    result += std::format("ARM_CPU_PERFORM_SIMD_16_DUAL_TYPE(ctx, " #c_base_type ", " #c_operation_top ", " #c_operation_bottom ", ctx->{}, ctx->{}, ctx->{});", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));


struct FPUBankOperand {
    arm_reg reg;
    int bank_index; // 0: scalar ; 1, 2, 3: vector ; 4: zero
    int bank_offset; // [0,4) for doubles, [0,8) for floats

    FPUBankOperand(const arm_reg reg_in = arm_reg::ARM_REG_INVALID, int bank_index_in = 4, int bank_offset_in = 0)
        : reg{reg_in}
        , bank_index{bank_index_in}
        , bank_offset{bank_offset_in}
    {

    }

private:
    FPUBankOperand(const arm_reg reg_in, const std::div_t div_res)
        : FPUBankOperand(reg_in, div_res.quot, div_res.rem)
    {
        
    }

public:
    FPUBankOperand(const arm_reg reg_in, const bool real_type_is_f64)
        : FPUBankOperand(reg_in, std::div(
            real_type_is_f64 ? (reg_in - arm_reg::ARM_REG_D0) : (reg_in - arm_reg::ARM_REG_S0),
            real_type_is_f64 ? 4 : 8
        ))
    {
        
    }
    FPUBankOperand(const arm_reg reg_in)
        : FPUBankOperand(reg_in, arm_reg::ARM_REG_D0 <= reg_in && reg_in <= arm_reg::ARM_REG_D15)
    {

    }
};

static void disasm_chunk(ProcessDisasmContext& ctx, const ProcessDisasmContext::BranchDestination& entry)
{
    bool iter_success = false;
    const bool in_thumb_mode = entry.is_thumb;
    ProcessDisasmContext::State state{
        .handle = in_thumb_mode ? &ctx.handle_thumb.handle : &ctx.handle_arm.handle,
        .code = ctx.start_code.data() + ctx.get_offset(entry.addr & ~1),
        .code_size = ctx.start_code.size() - ctx.get_offset(entry.addr & ~1),
        .address = entry.addr & ~1,
        .insn = in_thumb_mode ? ctx.insn_thumb.get() : ctx.insn_arm.get(),
    };

    const char* label_kind = in_thumb_mode ? "THUMB" : "ARM";
    cond_printf("Entering chunk %08x in %s mode \n", entry.addr & ~1, label_kind);

    int last_cmp = 0;
    int last_cmp_reg = arm_reg::ARM_REG_INVALID;
    int64_t last_cmp_imm = 0;
    int last_adr_reg = arm_reg::ARM_REG_INVALID;
    int64_t last_adr_value = 0;
    u32 last_branch_addr = -1;
    ARMCC_CondCodes last_branch_condcode = ARMCC_AL;
    int last_ldr_offset_for_switch_reg = arm_reg::ARM_REG_INVALID;
    u32 last_ldr_offset_for_switch_addr = -1;
    int64_t last_ldr_offset_for_switch_max_offset = 0;
    std::string_view last_ldr_offset_for_switch_type;
    bool last_is_uncond_bl = false;

    // pair: value, known unchanged
    std::map<arm_reg, uint32_t> last_known_reg_from_pc_value;

    while((iter_success = cs_disasm_iter(*state.handle, &state.code, &state.code_size, &state.address, state.insn)))
    {
        const auto& insn = *state.insn;
        bool uncond_branch = false;
        const u32 active_address = insn.address + (in_thumb_mode ? 1 : 0);
        auto& mapping = ctx.get_mapping(active_address);
        const auto arm_mapping = ctx.get_mapping(active_address & ~3u);

        u32 prev_addr_arm = 0;
        u32 self_value_arm = 0;
        std::optional<ProcessDisasmContext::MappingValue> previous_mapping;
        if(!entry.ignore_previous && active_address == entry.addr)
        {
            if((active_address & 3) == 3)
            {
                prev_addr_arm = active_address - 7;
            }
            else if((active_address & 1) == 1)
            {
                prev_addr_arm = active_address - 5;
            }
            else
            {
                prev_addr_arm = active_address - 4;
            }
            std::memcpy(&self_value_arm, ctx.start_code.data() + ctx.get_offset(prev_addr_arm + 4), sizeof(u32));
        }

        if(prev_addr_arm && prev_addr_arm >= ctx.start_addr && prev_addr_arm < ctx.start_addr + ctx.start_code.size())
        {
            // cond_printf("Checking previous instruction at 0x%08x\n", prev_addr_arm);
            previous_mapping = ctx.get_mapping(prev_addr_arm);
            // cond_printf("previous: %d %d %d\n", previous_mapping->visited, previous_mapping->tried, previous_mapping->is_unrecover_branch);
        }

        // already passed the instruction, thus the chunk
        // also check if this thumb was visited as arm, at worst a double check of the same value
        // aka don't support polyglot code
        /* if(active_address != entry.addr && entry.is_guess && (mapping.is_function_start || arm_mapping.is_function_start))
        {
            cond_printf("reached a function start from a guess: %08x\n", (u32)insn.address);
            cond_printf("we were in a constant pool. discard.\n");
            iter_success = false;
            mapping.failed_guess = true;
            break;
        }
        else */ if(active_address == entry.addr && entry.is_guess && !entry.is_function_start && previous_mapping && previous_mapping->failed_guess)
        {
            cond_printf("non-function guess follows a failed guess: %08x\n", (u32)insn.address);
            cond_printf("assume we were in a constant pool. discard.\n");
            iter_success = false;
            mapping.failed_guess = true;
            break;
        }
        else if(active_address == entry.addr && (mapping.visited || arm_mapping.visited))
        {
            cond_printf("already visited: %08x\n", (u32)(insn.address & ~3u));
            break;
        }
        
        if(cs_insn_group(*state.handle, &insn, arm_insn_group::ARM_FEATURE_IsThumb2))
        {
            // we don't have thumb2 in v6k
            cond_printf("thumb2 -> invalid\n");
            iter_success = false;
            mapping.failed_guess = true;
            break;
        }
        else if(last_is_uncond_bl && !(insn.detail->arm.cc == ARMCC_AL || insn.detail->arm.cc == ARMCC_UNDEF))
        {
            cond_printf("condition after bl -> invalid\n");
            mapping.failed_guess = true;
            break;
        }
        else if(active_address == entry.addr && (entry.is_function_start || entry.is_guess || (previous_mapping && previous_mapping->visited && previous_mapping->is_unrecover_branch)))
        {
            bool invalid_function_start = false;
            if(self_value_arm == 0xe320f000 && in_thumb_mode)
            {
                // part of a nop, f000 isn't a valid thumb instruction
                invalid_function_start = true;
            }
            else if(insn.detail->arm.cc == ARMCC_AL || insn.detail->arm.cc == ARMCC_UNDEF)
            {
                /*
                if(insn.is_alias) switch(insn.alias_id)
                {
                case arm_insn::ARM_INS_ALIAS_PUSH:
                case arm_insn::ARM_INS_ALIAS_VPUSH:
                case arm_insn::ARM_INS_ALIAS_POP:
                case arm_insn::ARM_INS_ALIAS_VPOP:
                    break;
                default:
                    // any other = bad
                    invalid_function_start = true;
                    break;
                }
                else switch(insn.id)
                {
                case arm_insn::ARM_INS_LDM: // push
                case arm_insn::ARM_INS_LDMIB:
                case arm_insn::ARM_INS_LDMDA:
                case arm_insn::ARM_INS_LDMDB:
                case arm_insn::ARM_INS_VLDMIA:
                case arm_insn::ARM_INS_VLDMDB:
                case arm_insn::ARM_INS_LDR:
                case arm_insn::ARM_INS_LDRH:
                case arm_insn::ARM_INS_LDRB:
                case arm_insn::ARM_INS_LDRSH:
                case arm_insn::ARM_INS_LDRSB:
                case arm_insn::ARM_INS_LDRD:
                case arm_insn::ARM_INS_VLDR:
                case arm_insn::ARM_INS_STM:
                case arm_insn::ARM_INS_STMIB:
                case arm_insn::ARM_INS_STMDA:
                case arm_insn::ARM_INS_STMDB:
                case arm_insn::ARM_INS_VSTMIA:
                case arm_insn::ARM_INS_VSTMDB:
                case arm_insn::ARM_INS_STR:
                case arm_insn::ARM_INS_STRH:
                case arm_insn::ARM_INS_STRB:
                case arm_insn::ARM_INS_STRD:
                case arm_insn::ARM_INS_MOV:
                case arm_insn::ARM_INS_VMOV:
                case arm_insn::ARM_INS_BX: // return directly
                case arm_insn::ARM_INS_B: // go elsewhere directly
                    break;
                default:
                    // any other = bad
                    invalid_function_start = true;
                    break;
                }
                */
            }
            else
            {
                cond_printf("First instruction condition is nonsense\n");
                invalid_function_start = true;
            }

            if(invalid_function_start)
            {
                cond_printf("function start detection failed, skip chunk\n");
                cond_printf("FAIL REASON: 0x%08llx (%u/%llu): %s %s\n", insn.address, insn.id, insn.alias_id, insn.mnemonic, insn.op_str);
                mapping.failed_guess = true;
                break;
            }
        }
        mapping.visited = true;
        if(active_address == entry.addr && entry.is_function_start)
        {
            mapping.is_function_start = true;
        }

        if(insn.address == ctx.start_addr && insn.id == arm_insn::ARM_INS_B)
        {
            ctx.initial_skip_offset = insn.address - ctx.start_addr;
        }

        cond_printf("0x%08llx (%u/%llu): %s %s\n", insn.address, insn.id, insn.alias_id, insn.mnemonic, insn.op_str);
        // for(int i = 0; i < insn.detail->arm.op_count; ++i)
        // {
        //     cond_printf("op %d: type %d\n", i, insn.detail->arm.operands[i].type);
        //     if(insn.detail->arm.operands[i].type == arm_op_type::ARM_OP_SYSREG)
        //     {
        //         cond_printf("ARM_OP_SYSREG: mclasssysreg: %04x\n", (int)insn.detail->arm.operands[i].sysop.reg.mclasssysreg);
        //     }
        // }
        if(insn.detail->arm.cc == ARMCC_UNDEF)
        {
            cond_printf("condcode: undefined\n");
        }

        std::string result;
        result += std::format("arm_cpu_update_pc(ctx, 0x{:08x}, {});\n", insn.address, in_thumb_mode ? 4 : 8);
        if(insn.detail->arm.cc != ARMCC_AL && insn.detail->arm.cc != ARMCC_UNDEF)
        {
            result += std::format("if(arm_cpu_check_cc(ctx, arm_cpu_cc_{}))", ARMCondCodeToString(insn.detail->arm.cc));
            result += " {\n";
        }

        if(insn.detail->arm.update_flags)
        {
            last_branch_condcode = ARMCC_AL;
        }

        arm_insn arm_insn_used = arm_insn::ARM_INS_INVALID;
        bool got_okay_can_skip = false;
        if(insn.is_alias) switch(insn.alias_id)
        {
        case ARM_INS_ALIAS_POP: {
            // beyond this is code recognition
            for(int i = 0; i < insn.detail->arm.op_count; ++i)
            {
                if(insn.detail->arm.operands[i].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[i].reg == arm_reg::ARM_REG_PC)
                {
                    if(insn.detail->arm.cc == ARMCC_AL)
                    {
                        uncond_branch = true;
                        mapping.is_unrecover_branch = true;
                    }
                    else
                    {
                        cond_printf("load to PC but not unconditional?\n");
                    }
                    break;
                }
            }
            INSN_APPEND_POP(uint32_t, 0, 4, 4 * (insn.detail->arm.op_count));
            got_okay_can_skip = true;
            break;
        }
        case ARM_INS_ALIAS_VPOP: {
            if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_POP(double, 0, 8, 8 * (insn.detail->arm.op_count));
            }
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_POP(float, 0, 4, 4 * (insn.detail->arm.op_count));
            }
            got_okay_can_skip = true;
            break;
        }
        case ARM_INS_ALIAS_PUSH: {
            INSN_APPEND_PUSH(uint32_t, 0, 4, 4 * (insn.detail->arm.op_count));
            got_okay_can_skip = true;
            break;
        }
        case ARM_INS_ALIAS_VPUSH: {
            if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_PUSH(double, 0, 8, 8 * (insn.detail->arm.op_count));
            }
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_PUSH(float, 0, 4, 4 * (insn.detail->arm.op_count));
            }
            got_okay_can_skip = true;
            break;
        }
        case ARM_INS_ALIAS_NOP: {
            got_okay_can_skip = true;
            uncond_branch = true;
            cond_printf("got NOP, assume alignment/before a constant pool\n");
            break;
        }
        default: {
            break;
        }
        }

        const int last_cmp_used = last_cmp;
        if(last_cmp > 0)
            --last_cmp;

        const int last_adr_reg_used = last_adr_reg;
        const int last_ldr_offset_for_switch_reg_used = last_ldr_offset_for_switch_reg;
        last_adr_reg = arm_reg::ARM_REG_INVALID;
        last_ldr_offset_for_switch_reg = arm_reg::ARM_REG_INVALID;
        last_is_uncond_bl = false;
        if(!got_okay_can_skip) switch(insn.id)
        {
        case ARM_INS_B: {
            const uint64_t branch_target = insn.detail->arm.operands[0].imm;
            if (ctx.start_addr + ctx.initial_skip_offset <= branch_target && branch_target < ctx.start_addr + ctx.start_code.size())
            {
                result += std::format("ARM_CPU_PERFORM_{}_B(ctx, 0x{:08x});", label_kind, branch_target);
                ctx.add_branch({(u32)branch_target, false, in_thumb_mode, true, insn.detail->arm.cc});
            }
            // if unconditional, or the opposite of the last conditional branch without a flag setting inbetween, assume return
            if(insn.detail->arm.cc == ARMCC_AL)
            {
                uncond_branch = true;
                mapping.is_unrecover_branch = true;
            }
            else if((insn.detail->arm.cc ^ 1) == last_branch_condcode)
            {
                // if there is a jump to this with a condcode opposite and no flag change, it cannot be "unconditional"
                if(!ctx.find_temp_branch([&](const ProcessDisasmContext::BranchDestination& dest) {
                    return last_branch_addr <= dest.addr && dest.addr <= active_address && (insn.detail->arm.cc ^ 1) == last_branch_condcode;
                }))
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            last_branch_condcode = insn.detail->arm.cc;
            last_branch_addr = active_address;
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_BX: {
            const auto branch_target_reg = insn.detail->arm.operands[0].reg;
            result += std::format("ARM_CPU_PERFORM_BX(ctx, ctx->{});", cs_reg_name(*state.handle, branch_target_reg));
            // if(auto it = last_known_reg_value.find((arm_reg)branch_target_reg); it != last_known_reg_value.end() && it->second.second)
            // {
            //     const auto value = it->second.first;
            //     if (ctx.start_addr <= value && value < ctx.start_addr + ctx.start_code.size())
            //     {
            //         cond_printf("Identified indirect jump to %08x\n", value);
            //         ctx.add_branch(value);
            //     }
            // }
            if(insn.detail->arm.cc == ARMCC_AL || insn.detail->arm.cc == ARMCC_UNDEF)
            {
                uncond_branch = true;
                mapping.is_unrecover_branch = true;
            }
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_BL: {
            const uint64_t branch_target = insn.detail->arm.operands[0].imm;
            if (ctx.start_addr + ctx.initial_skip_offset <= branch_target && branch_target < ctx.start_addr + ctx.start_code.size())
            {
                result += std::format("ARM_CPU_PERFORM_{}_BL(ctx, 0x{:08x});", label_kind, branch_target);
                ctx.add_branch({(u32)branch_target, true, in_thumb_mode, true});
            }
            last_is_uncond_bl = true;
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_BLX: {
            if(insn.detail->arm.operands[0].type == ARM_OP_REG)
            {
                const auto branch_target_reg = insn.detail->arm.operands[0].reg;
                result += std::format("ARM_CPU_PERFORM_BLX_REG(ctx, ctx->{});", cs_reg_name(*state.handle, branch_target_reg));
                // if(auto it = last_known_reg_value.find((arm_reg)branch_target_reg); it != last_known_reg_value.end() && it->second.second)
                // {
                //     const auto value = it->second.first;
                //     if (ctx.start_addr <= value && value < ctx.start_addr + ctx.start_code.size())
                //     {
                //         cond_printf("Identified indirect jump to %08x\n", value);
                //         ctx.add_branch(value);
                //     }
                // }
            }
            else
            {
                const uint64_t branch_target = insn.detail->arm.operands[0].imm;
                if (ctx.start_addr + ctx.initial_skip_offset <= branch_target && branch_target < ctx.start_addr + ctx.start_code.size())
                {
                    result += std::format("ARM_CPU_PERFORM_{}_BLX_IMM(ctx, 0x{:08x});", label_kind, branch_target);
                    ctx.add_branch({(u32)(branch_target), true, !in_thumb_mode, true});
                }
            }
            if(insn.detail->arm.cc == ARMCC_AL)
            {
                last_is_uncond_bl = true;
            }
            // last_known_reg_value.clear();
            break;
        }
        
        case ARM_INS_SVC: {
            const auto svc_id = insn.detail->arm.operands[0].imm;
            result += std::format("arm_cpu_instr_svc(ctx, {});", svc_id);
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_UDF: {
            const auto udf_id = insn.detail->arm.operands[0].imm;
            result += std::format("arm_cpu_instr_udf(ctx, {});", udf_id);
            break;
        }
        
        case ARM_INS_MCR: {
            result += std::format("ARM_CPU_PERFORM_MCR(ctx, ctx->{}, {}, {}, {}, {}, {});",
                cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg),
                insn.detail->arm.operands[0].imm, /* ARM_OP_PIMM */
                insn.detail->arm.operands[1].imm,
                insn.detail->arm.operands[5].imm,
                insn.detail->arm.operands[3].imm, /* ARM_OP_CIMM */
                insn.detail->arm.operands[4].imm /* ARM_OP_CIMM */
            );
            break;
        }
        case ARM_INS_MRC: {
            result += std::format("ARM_CPU_PERFORM_MRC(ctx, ctx->{}, {}, {}, {}, {}, {});",
                cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg),
                insn.detail->arm.operands[0].imm, /* ARM_OP_PIMM */
                insn.detail->arm.operands[1].imm,
                insn.detail->arm.operands[5].imm,
                insn.detail->arm.operands[3].imm, /* ARM_OP_CIMM */
                insn.detail->arm.operands[4].imm /* ARM_OP_CIMM */
            );
            break;
        }

        case ARM_INS_MSR:
        case ARM_INS_MRS:
        case ARM_INS_VMSR:
        case ARM_INS_VMRS: {
            if(insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_SYSREG)
            {
                std::string flags_str;
                switch(insn.detail->arm.operands[0].sysop.reg.mclasssysreg)
                {
                case arm_sysreg::ARM_MCLASSSYSREG_APSR_G:
                    flags_str = "G";
                    break;
                case arm_sysreg::ARM_MCLASSSYSREG_APSR_NZCVQ:
                    flags_str = "NZCVQ";
                    break;
                case arm_sysreg::ARM_MCLASSSYSREG_APSR_NZCVQG:
                    flags_str = "NZCVQG";
                    break;
                default:
                    break;
                }
                result += std::format("arm_cpu_set_apsr(ctx, \"{}\", ctx->{});",
                    flags_str.c_str(),
                    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            }
            else if(insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_APSR)
            {
                result += std::format("arm_cpu_set_apsr(ctx, \"NZCVQG\", ctx->{});",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            }
            else if(insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_APSR_NZCV)
            {
                result += std::format("arm_cpu_set_apsr(ctx, \"NZCV\", ctx->{});",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            }
            else if(insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_SYSREG)
            {
                std::string flags_str;
                switch(insn.detail->arm.operands[1].sysop.reg.mclasssysreg)
                {
                case arm_sysreg::ARM_MCLASSSYSREG_APSR_G:
                    flags_str = "G";
                    break;
                case arm_sysreg::ARM_MCLASSSYSREG_APSR_NZCVQ:
                    flags_str = "NZCVQ";
                    break;
                case arm_sysreg::ARM_MCLASSSYSREG_APSR_NZCVQG:
                    flags_str = "NZCVQG";
                    break;
                default:
                    break;
                }
                result += std::format("ctx->{} = arm_cpu_get_apsr(ctx, \"{}\");",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                    flags_str.c_str());
            }
            else if(insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[1].reg == arm_reg::ARM_REG_APSR_NZCV)
            {
                result += std::format("ctx->{} = arm_cpu_get_apsr(ctx, \"NZCV\");",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            }
            else if(insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[1].reg == arm_reg::ARM_REG_APSR)
            {
                result += std::format("ctx->{} = arm_cpu_get_apsr(ctx, \"NZCVQG\");",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            }
            else if(insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_CPSR)
            {
                // writes to cpsr need to keep some reserved bits, so reads can be simplified
                result += std::format("arm_cpu_set_cpsr(ctx, ctx->{});",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            }
            else if(insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_FPSCR)
            {
                // writes to cpsr need to keep some reserved bits, so reads can be simplified
                result += std::format("arm_cpu_set_fpscr(ctx, ctx->{});",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            }
            else
            {
                result += std::format("ctx->{} = ctx->{};",
                    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            }
            break;
        }

        case ARM_INS_CMP:
            // beyond this is code recognition
            if(insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_IMM)
            {
                last_cmp = -1; // leave some wiggle room for register setting before the ldr
                last_cmp_reg = insn.detail->arm.operands[0].reg;
                last_cmp_imm = insn.detail->arm.operands[1].imm;
            }
            [[fallthrough]];
        case ARM_INS_CMN: {
            result += std::format("ARM_CPU_PERFORM_FLAGS_{}(ctx, ctx->{}, ", cs_insn_name(*state.handle, insn.id), cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(0, 1);
            result += ");";
            break;
        }
        case ARM_INS_TST:
        case ARM_INS_TEQ: {
            result += std::format("ARM_CPU_PERFORM_FLAGS_{}(ctx, ctx->{}, ", cs_insn_name(*state.handle, insn.id), cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(1, 1);
            result += ");";
            break;
        }

        case ARM_INS_REV:
        case ARM_INS_REV16:
        case ARM_INS_REVSH:
        case ARM_INS_CLZ: {
            result += std::format("ctx->{} = ARM_CPU_PERFORM_{}(ctx, ctx->{});",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_insn_name(*state.handle, insn.id),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            break;
        }

        case ARM_INS_VCMP:
        case ARM_INS_VCMPE: {
            const bool real_type_f64 = arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15;
            const FPUBankOperand lhs_bank((arm_reg)insn.detail->arm.operands[0].reg, real_type_f64);

            result += std::format("util_{}_{}(ctx, ctx->{}_banks[{}][{}], "
                    , real_type_f64 ? "f64" : "f32"
                    , cs_insn_name(*state.handle, insn.id)
                    , real_type_f64 ? "f64" : "f32"
                    , lhs_bank.bank_index, lhs_bank.bank_offset
            );

            if(insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_REG)
            {
                const FPUBankOperand rhs_bank((arm_reg)insn.detail->arm.operands[1].reg, real_type_f64);
                result += std::format("ctx->{}_banks[{}][{}]"
                    , real_type_f64 ? "f64" : "f32"
                    , rhs_bank.bank_index, rhs_bank.bank_offset
                );
            }
            else /* if(insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_IMM && insn.detail->arm.operands[1].imm == 0) */
            {
                result += "0";
            }

            result += ");\n";
            break;
        }

        case ARM_INS_VMOV: {
            /*
            64 bits:
            d <- d
            or 32 bits:
            s <- s
            r <- s
            s <- r
            **/
            if(insn.detail->arm.op_count == 2)
            {
                if(arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15
                && arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[1].reg && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_D15)
                {
                    result += std::format("*(uint64_t*)&(ctx->{}) = *(uint64_t*)&(ctx->{});\n"
                        , cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg)
                        , cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg)
                    );
                }
                else
                {
                    result += std::format("*(uint32_t*)&(ctx->{}) = *(uint32_t*)&(ctx->{});\n"
                        , cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg)
                        , cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg)
                    );
                }
            }
            /*
            s, s (consecutive) <- r, r
            r, r <- s, s (consecutive)
            aka
            d <- r, r == d[31:0], d[63:32] <- r, r
            r, r <- d == r, r <- d[31:0], d[63:32]
            */
            else if(insn.detail->arm.op_count == 3)
            {
                const arm_reg lhs_a =  (arm_reg)(arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15 \
                    ? (insn.detail->arm.operands[0].reg - arm_reg::ARM_REG_D0) * 2 + arm_reg::ARM_REG_S0
                    : insn.detail->arm.operands[0].reg
                );
                const arm_reg lhs_b =  (arm_reg)(arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15 \
                    ? (insn.detail->arm.operands[0].reg - arm_reg::ARM_REG_D0) * 2 + arm_reg::ARM_REG_S0 + 1
                    : insn.detail->arm.operands[1].reg
                );
                const arm_reg rhs_a =  (arm_reg)(arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[2].reg && insn.detail->arm.operands[2].reg <= arm_reg::ARM_REG_D15 \
                    ? (insn.detail->arm.operands[2].reg - arm_reg::ARM_REG_D0) * 2 + arm_reg::ARM_REG_S0
                    : insn.detail->arm.operands[1].reg
                );
                const arm_reg rhs_b =  (arm_reg)(arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[2].reg && insn.detail->arm.operands[2].reg <= arm_reg::ARM_REG_D15 \
                    ? (insn.detail->arm.operands[2].reg - arm_reg::ARM_REG_D0) * 2 + arm_reg::ARM_REG_S0 + 1
                    : insn.detail->arm.operands[2].reg
                );

                result += std::format("*(uint32_t*)&(ctx->{}) = *(uint32_t*)&(ctx->{});\n"
                    , cs_reg_name(*state.handle, lhs_a)
                    , cs_reg_name(*state.handle, rhs_a)
                );
                result += std::format("*(uint32_t*)&(ctx->{}) = *(uint32_t*)&(ctx->{});\n"
                    , cs_reg_name(*state.handle, lhs_b)
                    , cs_reg_name(*state.handle, rhs_b)
                );
            }
            break;
        }
        case ARM_INS_VADD:
        case ARM_INS_VSUB:
        case ARM_INS_VDIV: {
            const bool real_type_f64 = arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15;
            const FPUBankOperand dest_bank((arm_reg)insn.detail->arm.operands[0].reg, real_type_f64);
            const FPUBankOperand op_a_bank = FPUBankOperand((arm_reg)insn.detail->arm.operands[1].reg, real_type_f64);
            const FPUBankOperand op_b_bank = FPUBankOperand((arm_reg)insn.detail->arm.operands[2].reg, real_type_f64);
            // ct, type, banksize, dest bank, lhs bank, rhs bank
            result += std::format("ARM_FPU_PERFORM_ARITH_ALL(ctx, {}, {}, {}, {}, {}, {}, {}, {}, {});\n"
                , cs_insn_name(*state.handle, insn.id)
                , real_type_f64 ? "f64" : "f32"
                , real_type_f64 ? 4 : 8
                , dest_bank.bank_index, dest_bank.bank_offset
                , op_a_bank.bank_index, op_a_bank.bank_offset
                , op_b_bank.bank_index, op_b_bank.bank_offset
            );
            break;
        }
        case ARM_INS_VMUL:
        case ARM_INS_VNMUL:
        case ARM_INS_VMLA:
        case ARM_INS_VMLS:
        case ARM_INS_VNMLA:
        case ARM_INS_VNMLS: {
            const bool real_type_f64 = arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15;
            const FPUBankOperand dest_bank((arm_reg)insn.detail->arm.operands[0].reg, real_type_f64);
            const FPUBankOperand op_a_bank((arm_reg)insn.detail->arm.operands[1].reg, real_type_f64);
            const FPUBankOperand op_b_bank((arm_reg)insn.detail->arm.operands[2].reg, real_type_f64);

            result += std::format("ARM_FPU_PERFORM_VMUL_ALL(ctx, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});\n"
                , real_type_f64 ? "f64" : "f32"
                , real_type_f64 ? 4 : 8
                // operation on the summand value
                , (insn.id == ARM_INS_VMUL || insn.id == ARM_INS_VNMUL) ? "" : ((insn.id == ARM_INS_VNMLA || insn.id == ARM_INS_VNMLS) ? "-" : "+")
                // operation on the mult result
                , (insn.id == ARM_INS_VNMUL || insn.id == ARM_INS_VMLS || insn.id == ARM_INS_VNMLA) ? "-" : "+"
                , dest_bank.bank_index, dest_bank.bank_offset
                , op_a_bank.bank_index, op_a_bank.bank_offset
                , op_b_bank.bank_index, op_b_bank.bank_offset
            );
            break;
        }
        
        case ARM_INS_VNEG:
        case ARM_INS_VABS:
        case ARM_INS_VSQRT: {
            const bool real_type_f64 = arm_reg::ARM_REG_D0 <= insn.detail->arm.operands[0].reg && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15;
            const FPUBankOperand dest_bank((arm_reg)insn.detail->arm.operands[0].reg, real_type_f64);
            const FPUBankOperand src_bank((arm_reg)insn.detail->arm.operands[1].reg, real_type_f64);

            result += std::format("ARM_FPU_PERFORM_OP1_ALL(ctx, {}, {}, {}, {}, {}, {}, {});\n"
                , cs_insn_name(*state.handle, insn.id)
                , real_type_f64 ? "f64" : "f32"
                , real_type_f64 ? 4 : 8
                , dest_bank.bank_index, dest_bank.bank_offset
                , src_bank.bank_index, src_bank.bank_offset
            );
            break;
        }

        case ARM_INS_ADD:
        case ARM_INS_ADC:
        case ARM_INS_SUB:
        case ARM_INS_SBC:
        case ARM_INS_RSB:
        case ARM_INS_RSC: {
            result += std::format("ctx->{} = ARM_CPU_PERFORM_{}(ctx, {}, ctx->{}, ",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_insn_name(*state.handle, insn.id), (int)insn.detail->arm.update_flags,
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(0, 2);
            result += ");";
            if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                if(insn.detail->arm.update_flags)
                    assert(false && "Attempt to use a flag setting arithmetic insn with PC as Rd");
                else
                {
                    result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                    if(insn.detail->arm.cc == ARMCC_AL)
                    {
                        uncond_branch = true;
                        mapping.is_unrecover_branch = true;
                    }
                }

                if(insn.detail->arm.cc == ARMCC_AL && insn.id == ARM_INS_ADD
                    && insn.detail->arm.operands[1].reg == arm_reg::ARM_REG_PC
                    && insn.detail->arm.operands[2].type == arm_op_type::ARM_OP_REG
                    && insn.detail->arm.operands[2].reg == last_ldr_offset_for_switch_reg_used
                    && insn.detail->arm.operands[2].shift.type == arm_shifter::ARM_SFT_LSL && insn.detail->arm.operands[2].shift.value == 2)
                {
                    cond_printf("offset switch statement detected: %lld entries\n", last_ldr_offset_for_switch_max_offset);
                    std::vector<int64_t> switch_offsets;
                    using append_offset_f_t = void(*)(ProcessDisasmContext&, std::vector<int64_t>&, const u32, const int64_t);
                    append_offset_f_t append_offset = [](ProcessDisasmContext&, std::vector<int64_t>&, const u32, const int64_t) { };
#define MAKE_APPEND_OFFSET(T) [](ProcessDisasmContext& ctx, std::vector<int64_t>& switch_offsets, const u32 pointer_base, const int64_t index) { \
        const u32 pointer = pointer_base + index * sizeof(T); \
        T value = 0; \
        { \
            auto sp = ctx.get_from_pointer(pointer, sizeof(T)); \
            /* cond_printf("offset switch statement entry %lld: vptr %08x ptr %p sz %zd\n", index, pointer, sp.data(), sp.size()); */ \
            std::memcpy(&value, sp.data(), sizeof(T)); \
            if(pointer < ctx.start_code_addr) \
            { \
                auto& entry_mapping = ctx.get_mapping(pointer); \
                entry_mapping.tried = true; \
                entry_mapping.jumptable_entry = true; \
            } \
        } \
        switch_offsets.push_back(value); \
    }

                    if(last_ldr_offset_for_switch_type == "b")
                    {
                        append_offset = MAKE_APPEND_OFFSET(uint8_t);
                    }
                    else if(last_ldr_offset_for_switch_type == "sb")
                    {
                        append_offset = MAKE_APPEND_OFFSET(int8_t);
                    }
                    else if(last_ldr_offset_for_switch_type == "h")
                    {
                        append_offset = MAKE_APPEND_OFFSET(uint16_t);
                    }
                    else if(last_ldr_offset_for_switch_type == "sh")
                    {
                        append_offset = MAKE_APPEND_OFFSET(int16_t);
                    }

                    last_ldr_offset_for_switch_type = "";

                    for(int64_t index = 0; index < last_ldr_offset_for_switch_max_offset; ++index)
                    {
                        append_offset(ctx, switch_offsets, last_ldr_offset_for_switch_addr, index);
                    }

                    for(int64_t index = 0; index < last_ldr_offset_for_switch_max_offset; ++index)
                    {
                        const int64_t offset = switch_offsets[index];
                        const u32 value = active_address + (in_thumb_mode ? 4 : 8) + offset * 4;
                        cond_printf("Entry %lld (pc off %08llx): 0x%08x\n", index, offset, value);
                        ctx.add_branch({(u32)(value), false, false, false});
                    }
                }
            }
            else if(insn.detail->arm.operands[1].reg == arm_reg::ARM_REG_PC && insn.detail->arm.operands[2].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == insn.detail->arm.operands[2].reg)
            {
                if(auto it = last_known_reg_from_pc_value.find((arm_reg)(insn.detail->arm.operands[0].reg)); it != last_known_reg_from_pc_value.end())
                {
                    const u32 pointer = active_address + (in_thumb_mode ? 4 : 8) + it->second;
                    if (ctx.start_addr + ctx.initial_skip_offset <= pointer && pointer < ctx.start_addr + ctx.start_code.size())
                    {
                        cond_printf("found 2-step function pointer: 0x%08x (from offset at 0x%08x)\n", pointer, it->second);
                        ctx.add_guess_branch({(u32)(pointer), false, in_thumb_mode, false});
                    }
                    last_known_reg_from_pc_value.erase(it);
                }
            }
            // if we are an ADR
            else if(insn.detail->arm.operands[1].reg == arm_reg::ARM_REG_PC && insn.detail->arm.operands[2].type == arm_op_type::ARM_OP_IMM)
            {
                if(insn.id == ARM_INS_ADD)
                {
                    const u32 pointer = active_address + (in_thumb_mode ? 4 : 8) + insn.detail->arm.operands[2].imm;
                    if (ctx.start_addr + ctx.initial_skip_offset <= pointer && pointer < ctx.start_addr + ctx.start_code.size())
                    {
                        cond_printf("found ADR (add)! 0x%08x\n", pointer);
                        if(last_adr_reg_used != arm_reg::ARM_REG_INVALID) // if there was an ADR before this one
                        {
                            cond_printf("ADR complete! 0x%08llx\n", last_adr_value);
                            ctx.get_mapping(last_adr_value).has_adr_start = last_adr_value;
                            ctx.add_guess_branch({(u32)(last_adr_value), false, in_thumb_mode, false});
                        }
                    }
                    last_adr_reg = insn.detail->arm.operands[0].reg;
                    last_adr_value = pointer;
                }
                else if(insn.id == ARM_INS_SUB)
                {
                    const u32 pointer = active_address + (in_thumb_mode ? 4 : 8) - insn.detail->arm.operands[2].imm;
                    if (ctx.start_addr + ctx.initial_skip_offset <= pointer && pointer < ctx.start_addr + ctx.start_code.size())
                    {
                        cond_printf("found ADR (sub)! 0x%08x\n", pointer);
                        if(last_adr_reg_used != arm_reg::ARM_REG_INVALID) // if there was an ADR before this one
                        {
                            cond_printf("ADR complete! 0x%08llx\n", last_adr_value);
                            ctx.get_mapping(last_adr_value).has_adr_start = last_adr_value;
                            ctx.add_guess_branch({(u32)(last_adr_value), false, in_thumb_mode, false});
                        }
                    }
                    last_adr_reg = insn.detail->arm.operands[0].reg;
                    last_adr_value = pointer;
                }
                else
                {
                    cond_printf("looks like ADR? not quite\n");
                }
            }
            // if we are in a continued ADR (ADRL)
            else if(last_adr_reg_used == insn.detail->arm.operands[1].reg && insn.detail->arm.operands[0].reg == insn.detail->arm.operands[1].reg)
            {
                if(insn.id == ARM_INS_ADD)
                {
                    last_adr_value += insn.detail->arm.operands[2].imm;
                    cond_printf("found ADRL (add)! 0x%08llx\n", last_adr_value);
                }
                else if(insn.id == ARM_INS_SUB)
                {
                    last_adr_value -= insn.detail->arm.operands[2].imm;
                    cond_printf("found ADRL (sub)! 0x%08llx\n", last_adr_value);
                }
            }
            break;
        }

        case ARM_INS_ASR:
        case ARM_INS_LSL:
        case ARM_INS_LSR:
        case ARM_INS_ROR: {
            result += std::format("ctx->{} = ARM_CPU_PERFORM_{}_REG(ctx, ctx->{}, {}, ",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_insn_name(*state.handle, insn.id),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg),
                (int)insn.detail->arm.update_flags);
            if(insn.detail->arm.operands[2].type == arm_op_type::ARM_OP_REG)
                result += std::format("ctx->{}", cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));
            else
                result += std::format("{}", insn.detail->arm.operands[2].imm);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }
        case ARM_INS_RRX: {
            result += std::format("ctx->{} = ARM_CPU_PERFORM_RRX(ctx, ctx->{}, {});\n",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg),
                (int)insn.detail->arm.update_flags);
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }

        case ARM_INS_MOVS:
        case ARM_INS_MOV: {
            result += std::format("ctx->{} = ", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 1);
            result += ";\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            
            if(insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[1].reg == arm_reg::ARM_REG_PC)
            {
                const u32 pointer = active_address + (in_thumb_mode ? 4 : 8) + insn.detail->arm.operands[2].imm;
                cond_printf("found emulated bl! 0x%08x\n", pointer);
                ctx.add_guess_branch({(u32)(pointer), false, in_thumb_mode, false});
                last_is_uncond_bl = true;
            }
            break;
        }
        case ARM_INS_MVN: {
            result += std::format("ctx->{} = ~(", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 1);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }
        case ARM_INS_AND: {
            result += std::format("ctx->{} = ctx->{} & (",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }
        case ARM_INS_ORR: {
            result += std::format("ctx->{} = ctx->{} | (",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }
        case ARM_INS_EOR: {
            result += std::format("ctx->{} = ctx->{} ^ (",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }
        case ARM_INS_BIC: {
            result += std::format("ctx->{} = ctx->{} & ~(",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);");
                if(insn.detail->arm.cc == ARMCC_AL)
                {
                    uncond_branch = true;
                    mapping.is_unrecover_branch = true;
                }
            }
            break;
        }
        
        case ARM_INS_MUL: {
            INSN_APPEND_MUL();
            break;
        }
        case ARM_INS_MLA: {
            INSN_APPEND_MLA();
            break;
        }
        case ARM_INS_UMULL: {
            INSN_APPEND_MUL_MLA_LONG_TYPE(MUL, uint64_t);
            break;
        }
        case ARM_INS_UMLAL: {
            INSN_APPEND_MUL_MLA_LONG_TYPE(MLA, uint64_t);
            break;
        }
        case ARM_INS_SMULL: {
            INSN_APPEND_MUL_MLA_LONG_TYPE(MUL, int64_t);
            break;
        }
        case ARM_INS_SMLAL: {
            INSN_APPEND_MUL_MLA_LONG_TYPE(MLA, int64_t);
            break;
        }

        case ARM_INS_UADD8: {
            INSN_APPEND_SIMD_N_TYPE(uint8_t, 8, +);
            break;
        }
        case ARM_INS_USUB8: {
            INSN_APPEND_SIMD_N_TYPE(uint8_t, 8, -);
            break;
        }
        case ARM_INS_UADD16: {
            INSN_APPEND_SIMD_N_TYPE(uint16_t, 16, +);
            break;
        }
        case ARM_INS_USUB16: {
            INSN_APPEND_SIMD_N_TYPE(uint16_t, 16, -);
            break;
        }
        case ARM_INS_UASX: {
            INSN_APPEND_SIMD_16_DUAL_TYPE(uint16_t, +, -);
            break;
        }
        case ARM_INS_USAX: {
            INSN_APPEND_SIMD_16_DUAL_TYPE(uint16_t, -, +);
            break;
        }

        case ARM_INS_SADD8: {
            INSN_APPEND_SIMD_N_TYPE(int8_t, 8, +);
            break;
        }
        case ARM_INS_SSUB8: {
            INSN_APPEND_SIMD_N_TYPE(int8_t, 8, -);
            break;
        }
        case ARM_INS_SADD16: {
            INSN_APPEND_SIMD_N_TYPE(int16_t, 16, +);
            break;
        }
        case ARM_INS_SSUB16: {
            INSN_APPEND_SIMD_N_TYPE(int16_t, 16, -);
            break;
        }
        case ARM_INS_SASX: {
            INSN_APPEND_SIMD_16_DUAL_TYPE(int16_t, +, -);
            break;
        }
        case ARM_INS_SSAX: {
            INSN_APPEND_SIMD_16_DUAL_TYPE(int16_t, -, +);
            break;
        }

        case ARM_INS_SEL: {
            result += std::format("ARM_CPU_PERFORM_SEL(ctx, ctx->{}, ctx->{}, ctx->{});",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg)
            );
            break;
        }

        case ARM_INS_UXTH: {
            INSN_APPEND_XT_TYPE(uint16_t, uint32_t, 0xffff);
            break;
        }
        case ARM_INS_UXTB: {
            INSN_APPEND_XT_TYPE(uint8_t, uint32_t, 0xff);
            break;
        }
        case ARM_INS_UXTB16: {
            INSN_APPEND_XTB16_TYPE(uint8_t, uint16_t);
            break;
        }

        case ARM_INS_SXTH: {
            INSN_APPEND_XT_TYPE(int16_t, int32_t, 0xffff);
            break;
        }
        case ARM_INS_SXTB: {
            INSN_APPEND_XT_TYPE(int8_t, int32_t, 0xff);
            break;
        }
        case ARM_INS_SXTB16: {
            INSN_APPEND_XTB16_TYPE(int8_t, int16_t);
            break;
        }
        
        case ARM_INS_UXTAH: {
            INSN_APPEND_XTA_TYPE(uint16_t, uint32_t, 0xffff);
            break;
        }
        case ARM_INS_UXTAB: {
            INSN_APPEND_XTA_TYPE(uint8_t, uint32_t, 0xff);
            break;
        }
        case ARM_INS_UXTAB16: {
            INSN_APPEND_XTAB16_TYPE(uint8_t, uint16_t);
            break;
        }

        case ARM_INS_SXTAH: {
            INSN_APPEND_XTA_TYPE(int16_t, int32_t, 0xffff);
            break;
        }
        case ARM_INS_SXTAB: {
            INSN_APPEND_XTA_TYPE(int8_t, int32_t, 0xff);
            break;
        }
        case ARM_INS_SXTAB16: {
            INSN_APPEND_XTAB16_TYPE(int8_t, int16_t);
            break;
        }

        case ARM_INS_LDREXB: {
            INSN_APPEND_LDREX_TYPE(uint8_t);
            break;
        }
        case ARM_INS_LDREXH: {
            INSN_APPEND_LDREX_TYPE(uint16_t);
            break;
        }
        case ARM_INS_LDREX: {
            INSN_APPEND_LDREX_TYPE(uint32_t);
            break;
        }
        case ARM_INS_LDREXD: {
            INSN_APPEND_LDREXD();
            break;
        }
        
        case ARM_INS_STREXB: {
            INSN_APPEND_STREX_TYPE(uint8_t, 0xff);
            break;
        }
        case ARM_INS_STREXH: {
            INSN_APPEND_STREX_TYPE(uint16_t, 0xffff);
            break;
        }
        case ARM_INS_STREX: {
            INSN_APPEND_STREX_TYPE(uint32_t, 0xffffffff);
            break;
        }
        case ARM_INS_STREXD: {
            INSN_APPEND_STREXD();
            break;
        }

        case ARM_INS_CLREX: {
            result += "ARM_CPU_PERFORM_CLREX(ctx);";
            break;
        }
        
        case ARM_INS_LDRB: {
            INSN_APPEND_LDR_TYPE(uint8_t, (uint32_t));
            
            // beyond this is code recognition
            // switch-case detection for uint8 offset table
            if(auto it = last_known_reg_from_pc_value.end(); last_cmp_used != 0 && (insn.detail->arm.cc == ARMCC_AL) && insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && (it = last_known_reg_from_pc_value.find(insn.detail->arm.operands[1].mem.base)) != last_known_reg_from_pc_value.end()
                && insn.detail->arm.operands[1].mem.index == last_cmp_reg
            )
            {
                last_ldr_offset_for_switch_reg = insn.detail->arm.operands[0].reg;
                last_ldr_offset_for_switch_addr = it->second;
                last_ldr_offset_for_switch_max_offset = last_branch_condcode == ARMCC_CondCodes::ARMCC_HI ? /* branched on > */ (last_cmp_imm + 1) : /* branched on >= */ last_cmp_imm;
                last_ldr_offset_for_switch_type = "b";
                cond_printf("possible offset switch: offtab base %08x, max indexd %lld, type 'b'\n", last_ldr_offset_for_switch_addr, last_ldr_offset_for_switch_max_offset);
                last_cmp = 0; // found a switch
            }
            break;
        }
        case ARM_INS_LDRSB: {
            INSN_APPEND_LDR_TYPE(int8_t, (int32_t));

            // beyond this is code recognition
            // switch-case detection for int8 offset table
            if(auto it = last_known_reg_from_pc_value.end(); last_cmp_used != 0 && (insn.detail->arm.cc == ARMCC_AL) && insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && (it = last_known_reg_from_pc_value.find(insn.detail->arm.operands[1].mem.base)) != last_known_reg_from_pc_value.end()
                && insn.detail->arm.operands[1].mem.index == last_cmp_reg
            )
            {
                last_ldr_offset_for_switch_reg = insn.detail->arm.operands[0].reg;
                last_ldr_offset_for_switch_addr = it->second;
                last_ldr_offset_for_switch_max_offset = last_branch_condcode == ARMCC_CondCodes::ARMCC_HI ? /* branched on > */ (last_cmp_imm + 1) : /* branched on >= */ last_cmp_imm;
                last_ldr_offset_for_switch_type = "sb";
                cond_printf("possible offset switch: offtab base %08x, max indexd %lld, type 'sb'\n", last_ldr_offset_for_switch_addr, last_ldr_offset_for_switch_max_offset);
                last_cmp = 0; // found a switch
            }
            break;
        }
        case ARM_INS_LDRH: {
            INSN_APPEND_LDR_TYPE(uint16_t, (uint32_t));

            // beyond this is code recognition
            // switch-case detection for uint16 offset table
            if(auto it = last_known_reg_from_pc_value.end(); last_cmp_used != 0 && (insn.detail->arm.cc == ARMCC_AL) && insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && (it = last_known_reg_from_pc_value.find(insn.detail->arm.operands[1].mem.base)) != last_known_reg_from_pc_value.end()
                && insn.detail->arm.operands[1].mem.index == last_cmp_reg
            )
            {
                last_ldr_offset_for_switch_reg = insn.detail->arm.operands[0].reg;
                last_ldr_offset_for_switch_addr = it->second;
                last_ldr_offset_for_switch_max_offset = last_branch_condcode == ARMCC_CondCodes::ARMCC_HI ? /* branched on > */ (last_cmp_imm + 1) : /* branched on >= */ last_cmp_imm;
                last_ldr_offset_for_switch_type = "h";
                cond_printf("possible offset switch: offtab base %08x, max indexd %lld, type 'h'\n", last_ldr_offset_for_switch_addr, last_ldr_offset_for_switch_max_offset);
                last_cmp = 0; // found a switch
            }
            break;
        }
        case ARM_INS_LDRSH: {
            INSN_APPEND_LDR_TYPE(int16_t, (int32_t));
            
            // beyond this is code recognition
            // switch-case detection for int16 offset table
            if(auto it = last_known_reg_from_pc_value.end(); last_cmp_used != 0 && (insn.detail->arm.cc == ARMCC_AL) && insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && (it = last_known_reg_from_pc_value.find(insn.detail->arm.operands[1].mem.base)) != last_known_reg_from_pc_value.end()
                && insn.detail->arm.operands[1].mem.index == last_cmp_reg
            )
            {
                last_ldr_offset_for_switch_reg = insn.detail->arm.operands[0].reg;
                last_ldr_offset_for_switch_addr = it->second;
                last_ldr_offset_for_switch_max_offset = last_branch_condcode == ARMCC_CondCodes::ARMCC_HI ? /* branched on > */ (last_cmp_imm + 1) : /* branched on >= */ last_cmp_imm;
                last_ldr_offset_for_switch_type = "sh";
                cond_printf("possible offset switch: offtab base %08x, max indexd %lld, type 'sh'\n", last_ldr_offset_for_switch_addr, last_ldr_offset_for_switch_max_offset);
                last_cmp = 0; // found a switch
            }
            break;
        }
        case ARM_INS_LDR: {
            INSN_APPEND_LDR_TYPE(uint32_t,);

            // beyond this is code recognition

            // switch-case detection for jump table
            if(last_cmp_used != 0 && (insn.detail->arm.cc == ARMCC_LS || insn.detail->arm.cc == ARMCC_LO) && insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && insn.detail->arm.operands[1].mem.base == arm_reg::ARM_REG_PC
                && insn.detail->arm.operands[1].mem.index == last_cmp_reg
                && insn.detail->arm.operands[1].shift.type == ARM_SFT_LSL
                && insn.detail->arm.operands[1].shift.value == 2
            )
            {
                const int last_cmp_imm_offset = (insn.detail->arm.cc == ARMCC_LS) ? 1 : 0;
                cond_printf("jump table switch statement detected: %lld entries\n", (last_cmp_imm + last_cmp_imm_offset));
                for(int64_t index = 0; index < (last_cmp_imm + last_cmp_imm_offset); ++index)
                {
                    u32 value = 0;
                    const u32 pointer = (active_address & ~1) + (in_thumb_mode ? 4 : 8) + index * 4;
                    
                    std::memcpy(&value, ctx.get_from_pointer(pointer, 4).data(), 4);
                    cond_printf("Entry %lld (0x%08x): 0x%08x\n", index, pointer, value);
                    auto& entry_mapping = ctx.get_mapping(pointer);
                    entry_mapping.tried = true;
                    entry_mapping.jumptable_entry = true;
                    ctx.add_branch({(u32)(value), false, false, false});
                }
                last_cmp = 0; // found a switch
            }
            // function pointer write to register for further bx/blx (assumed) detection
            else if(insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && insn.detail->arm.operands[1].mem.base == arm_reg::ARM_REG_PC
                && insn.detail->arm.operands[1].mem.index == arm_reg::ARM_REG_INVALID
            )
            {
                u32 value = 0;
                const int64_t disp = insn.detail->arm.operands[1].subtracted
                    ? -insn.detail->arm.operands[1].mem.disp
                    : insn.detail->arm.operands[1].mem.disp;
                const u32 pointer = (active_address & ~1) + (in_thumb_mode ? 4 : 8) + disp;
                std::memcpy(&value, ctx.get_from_pointer(pointer, 4).data(), 4);
                cond_printf("register set detected: from pc[%lld:+4] == %08x @ %08x\n", disp, value, pointer);
                last_known_reg_from_pc_value[(arm_reg)insn.detail->arm.operands[0].reg] = value;
                // HACK: if the set value looks like a pointer to code, add it to the queue
                if (ctx.start_addr + ctx.initial_skip_offset <= value && value < ctx.start_addr + ctx.start_code.size())
                {
                    ctx.get_mapping(value).has_adr_start = value;
                    if(!((value & 2) == 2 && (value & 1) == 0)) // not misaligned arm
                    {
                        cond_printf("Maybe identified function pointer to %08x\n", value);
                        // would need to check LR being set before to be suire about is_function_start
                        ctx.add_guess_branch({(u32)(value), false, false, false});
                    }
                }
            }
            // direct load to PC
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC && insn.detail->arm.cc == ARMCC_AL)
            {
                cond_printf("ldr as return detected\n");
                uncond_branch = true;
                mapping.is_unrecover_branch = true;
            }
            break;
        }
        case ARM_INS_LDRD: {
            result += std::format("ARM_CPU_PERFORM_LDRD(ctx, ctx->{}, ctx->{}, ctx->{}, ",
            cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg),
            cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.base));
            if(insn.detail->arm.operands[1].subtracted)
                result += "-";
            else
                result += "+";
            result += ", (";
            if(insn.detail->arm.operands[2].mem.index == arm_reg::ARM_REG_INVALID)
                result += std::format("{}", insn.detail->arm.operands[2].mem.disp);
            else
                result += std::format("ctx->{}", cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.index));
            result += std::format("), {}, {});", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);
            break;
        }
        
        case ARM_INS_VLDR: {
            if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_LDR_TYPE(double,);
            }
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_LDR_TYPE(float,);
            }
            break;
        }
        case ARM_INS_VLDMIA: {
            if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_LDM(double, 0, 8, 8 * (insn.detail->arm.op_count - 1));
            }
            else if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_LDM(float, 0, 4, 4 * (insn.detail->arm.op_count - 1));
            }
            break;
        }
        case ARM_INS_VLDMDB: {
            if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_LDM(double, -8 * (insn.detail->arm.op_count - 1), +8, -8 * (insn.detail->arm.op_count - 1));
            }
            else if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_LDM(float, -4 * (insn.detail->arm.op_count - 1), +4, -4 * (insn.detail->arm.op_count - 1));
            }
            break;
        }
        
        case ARM_INS_LDM: { // LDMIA
            INSN_APPEND_LDM(uint32_t, 0, 4, 4 * (insn.detail->arm.op_count - 1));
            break;
        }
        case ARM_INS_LDMIB: {
            INSN_APPEND_LDM(uint32_t, 4, 4, 4 * (insn.detail->arm.op_count - 1));
            break;
        }
        case ARM_INS_LDMDA: {
            INSN_APPEND_LDM(uint32_t, -4 * (insn.detail->arm.op_count - 1) + 4, +4, -4 * (insn.detail->arm.op_count - 1));
            break;
        }
        case ARM_INS_LDMDB: {
            INSN_APPEND_LDM(uint32_t, -4 * (insn.detail->arm.op_count - 1), +4, -4 * (insn.detail->arm.op_count - 1));
            break;
        }
        
        case ARM_INS_STRB: {
            INSN_APPEND_STR_TYPE(uint8_t, & 0xff);
            break;
        }
        case ARM_INS_STRH: {
            INSN_APPEND_STR_TYPE(uint16_t, & 0xffff);
            break;
        }
        case ARM_INS_STR: {
            INSN_APPEND_STR_TYPE(uint32_t, & 0xffffffff);
            break;
        }
        case ARM_INS_STRD: {
            result += std::format("ARM_CPU_PERFORM_STRD(ctx, ctx->{}, ctx->{}, ctx->{}, ",
            cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg),
            cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.base));
            if(insn.detail->arm.operands[1].subtracted)
                result += "-";
            else
                result += "+";
            result += ", (";
            if(insn.detail->arm.operands[2].mem.index == arm_reg::ARM_REG_INVALID)
                result += std::format("{}", insn.detail->arm.operands[2].mem.disp);
            else
                result += std::format("ctx->{}", cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.index));
            result += std::format("), {}, {});", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);
            break;
        }
        
        case ARM_INS_VSTR: {
            if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_STR_TYPE(double,);
            }
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_STR_TYPE(float,);
            }
            break;
        }
        case ARM_INS_VSTMIA: {
            if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_STM(double, 0, 8, 8 * (insn.detail->arm.op_count - 1));
            }
            else if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_STM(float, 0, 4, 4 * (insn.detail->arm.op_count - 1));
            }
            break;
        }
        case ARM_INS_VSTMDB: {
            if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_D0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_D15)
            {
                INSN_APPEND_STM(double, -8 * (insn.detail->arm.op_count - 1), +8, -8 * (insn.detail->arm.op_count - 1));
            }
            else if(insn.detail->arm.operands[1].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[1].reg <= arm_reg::ARM_REG_S31)
            {
                INSN_APPEND_STM(float, -4 * (insn.detail->arm.op_count - 1), +4, -4 * (insn.detail->arm.op_count - 1));
            }
            break;
        }
        
        case ARM_INS_STM: { // STMIA
            INSN_APPEND_STM(uint32_t, 0, 4, 4 * (insn.detail->arm.op_count - 1));
            break;
        }
        case ARM_INS_STMIB: {
            INSN_APPEND_STM(uint32_t, 4, 4, 4 * (insn.detail->arm.op_count - 1));
            break;
        }
        case ARM_INS_STMDA: {
            INSN_APPEND_STM(uint32_t, -4 * (insn.detail->arm.op_count - 1) + 4, +4, -4 * (insn.detail->arm.op_count - 1));
            break;
        }
        case ARM_INS_STMDB: {
            INSN_APPEND_STM(uint32_t, -4 * (insn.detail->arm.op_count - 1), +4, -4 * (insn.detail->arm.op_count - 1));
            break;
        }
        
        default:
            result += std::format("#warning \"unimplemented: {} {}\"", insn.mnemonic, insn.op_str);
            arm_insn_used = (arm_insn)insn.id;
            break;
        }

        if(insn.detail->arm.cc != ARMCC_AL && insn.detail->arm.cc != ARMCC_UNDEF)
        {
            result += "\n}";
        }

        if(last_adr_reg_used != arm_reg::ARM_REG_INVALID && last_adr_reg == arm_reg::ARM_REG_INVALID)
        {
            if (ctx.start_addr + ctx.initial_skip_offset <= (u32)last_adr_value && (u32)last_adr_value < ctx.start_addr + ctx.start_code.size())
            {
                cond_printf("ADR complete: 0x%08llx\n", last_adr_value);
                ctx.get_mapping(last_adr_value).has_adr_start = last_adr_value;
                ctx.add_guess_branch({(u32)(last_adr_value), false, in_thumb_mode, false});
            }
            last_adr_reg = arm_reg::ARM_REG_INVALID;
        }

        if(insn.id != arm_insn::ARM_INS_LDR && insn.detail->arm.op_count >= 2 && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG)
        {
            last_known_reg_from_pc_value.erase((arm_reg)(insn.detail->arm.operands[0].reg));
        }

        ctx.add_insn(std::make_pair<int64_t, std::string>(active_address, std::move(result))
#if DISASM_LIST_UNIMPL
            , arm_insn_used
#endif
        );
        if(uncond_branch)
        {
            cond_printf("Unconditional branch detected, stop.\n");
            break;
        }
    }

    if(!iter_success)
    {
        // discards chunk
        cond_printf("exit from failure to disas\n");
        ctx.discard_insns(entry);
        ctx.discard_branches();
    }
    else
    {
        ctx.commit_insns(state);
        ctx.commit_branches();
    }
}

#define ALIGN_PAGE_NUM(n) (((n) + (0x1000u - 1u)) & -0x1000u)
static void disasm_all_branches_from(const u32 start_addr, std::span<const u8> start_code, std::span<const u8> rodata, std::span<const u8> data, const std::string& filename, const bool allow_thumb, const bool do_dummy_save)
{
    ProcessDisasmContext ctx{
        .start_addr = start_addr,
        .start_code_addr = start_addr,
        .start_code = start_code,
        .end_code_addr = (u32)(start_addr + start_code.size()),
        .start_rodata_addr = (u32)(ALIGN_PAGE_NUM(start_addr + start_code.size())),
        .start_rodata = rodata,
        .end_rodata_addr = (u32)(ALIGN_PAGE_NUM(start_addr + start_code.size()) + rodata.size()),
        .start_data_addr = (u32)(ALIGN_PAGE_NUM(ALIGN_PAGE_NUM(start_addr + start_code.size()) + rodata.size())),
        .start_data = data,
        .end_data_addr = (u32)(ALIGN_PAGE_NUM(ALIGN_PAGE_NUM(start_addr + start_code.size()) + rodata.size()) + data.size()),
        .allow_thumb = allow_thumb
    };

    cond_printf("Checking initial pointer: %08x\n", start_addr);
    ctx.add_branch({start_addr, false, false, true});
    ctx.commit_branches();
    do {
        const std::optional<ProcessDisasmContext::BranchDestination> dest = ctx.get_next_branch_if([](const ProcessDisasmContext::BranchDestination& dest) {
            // only want sure ARM branches for the first run
            return !(dest.is_thumb || dest.is_guess);
        });
        if(!dest) break;
        disasm_chunk(ctx, *dest);
    } while(!ctx.branches.empty());

    for(std::size_t i = 0; i < rodata.size(); i += sizeof(u32))
    {
        const u32 analyzed_addr = start_addr + ALIGN_PAGE_NUM(start_code.size()) + i;
        u32 value = 0;
        std::memcpy(&value, &rodata[i], 4);
        if(start_addr + ctx.initial_skip_offset <= value && value < start_addr + start_code.size())
        {
            if((value & 2) && !(value & 1)) // misaligned arm
                continue;

            // printf("Checking rodata pointer (%08x): %08x\n", analyzed_addr, value);
            ctx.add_guess_branch({value, false, false, false});
        }
    }

    for(std::size_t i = 0; i < data.size(); i += sizeof(u32))
    {
        const u32 analyzed_addr = start_addr + ALIGN_PAGE_NUM(start_code.size()) + ALIGN_PAGE_NUM(rodata.size()) + i;
        u32 value = 0;
        std::memcpy(&value, &data[i], sizeof(u32));
        if(start_addr + ctx.initial_skip_offset <= value && value < start_addr + start_code.size())
        {
            if((value & 2) && !(value & 1)) // misaligned arm
                continue;
    
            // printf("Checking data pointer (%08x): %08x\n", analyzed_addr, value);
            ctx.add_guess_branch({value, false, false, false});
        }
    }

    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        if(ctx.analyzed[i * 3].visited || ctx.analyzed[i * 3].tried)
            continue;

        const u32 analyzed_addr = start_addr + i * 4;
        u32 value = 0;
        std::memcpy(&value, &start_code[i * 4], sizeof(u32));
        if(value == 0)
            continue;

        if(start_addr + ctx.initial_skip_offset <= value && value < start_addr + start_code.size())
        {
            if(!((value & 2) == 2 && (value & 1) == 0)) // not misaligned arm
            {
                cond_printf("Checking text pointer (%08x): %08x\n", analyzed_addr, value);
                ctx.add_guess_branch({value, false, false, false});
            }
        }
        value += analyzed_addr;
        if(start_addr + ctx.initial_skip_offset <= value && value < start_addr + start_code.size())
        {
            if(!((value & 2) == 2 && (value & 1) == 0)) // not misaligned arm
            {
                cond_printf("Checking text offset pointer (%08x): %08x\n", analyzed_addr, value);
                ctx.add_guess_branch({value, false, false, false});
            }
        }
    }

    ctx.commit_branches();
    while(!ctx.branches.empty())
    {
        const auto dest = ctx.get_next_branch();
        // no need to check, the non *_if function only returns nullopt on empty (which is invalidated by the while)
        // if(!dest) break;
        disasm_chunk(ctx, *dest);
    } 

    bool had_branches = true;
    while(had_branches)
    {
        for(u32 i = 0; i < start_code.size() / 4; ++i)
        {
            auto& current_mapping = ctx.analyzed[i * 3];
            if(current_mapping.visited || current_mapping.tried)
                continue;

            if(!current_mapping.has_adr_start)
                continue;

            const u32 analyzed_addr = start_addr + i * 4;
            // printf("Doing an ADR-based array starting at 0x%08x (current 0x%08x)\n", current_mapping.has_adr_start, analyzed_addr);

            u32 value = 0;
            std::memcpy(&value, &start_code[i * 4], sizeof(u32));
            value += current_mapping.has_adr_start;
            if(ctx.start_addr + ctx.initial_skip_offset <= value && value < ctx.start_addr + ctx.start_code.size())
            {
                if(!((value & 2) == 2 && (value & 1) == 0)) // not misaligned arm
                {
                    cond_printf("Checking text array pointer with base %08x (%08x): %08x\n", current_mapping.has_adr_start, analyzed_addr, value);
                    if((i + 1) < (start_code.size() / 4))
                    {
                        auto& next_mapping = ctx.analyzed[(i + 1) * 3];
                        if(!next_mapping.has_adr_start)
                            next_mapping.has_adr_start = current_mapping.has_adr_start;
                    }
                    current_mapping.tried = true;
                    ctx.add_guess_branch({value, false, false, false});
                }
            }
        }

        had_branches = !ctx.branches_temp_list.empty();
        cond_printf("had_branches: %d\n", (int)had_branches);
        ctx.commit_branches();
        while(!ctx.branches.empty())
        {
            const auto dest = ctx.get_next_branch();
            // no need to check, the non *_if function only returns nullopt on empty (which is invalidated by the while)
            // if(!dest) break;
            disasm_chunk(ctx, *dest);
        }
    }


    u32 unvisited_start = 0;
    bool unvisited_ongoing = false;
    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        if(ctx.analyzed[i * 3].visited)
        {
            if(unvisited_ongoing)
            {
                unvisited_ongoing = false;
                cond_printf("unvisited: %08x - %08x (length %08x)", unvisited_start, start_addr + i * 4, start_addr + i * 4 - unvisited_start);
                if(ctx.analyzed[i * 3].jumptable_entry)
                {
                    cond_printf(" (is jump table entry)");
                }
                cond_printf("\n");
            }
        }
        else if(!unvisited_ongoing)
        {
            unvisited_start = start_addr + i * 4;
            unvisited_ongoing = true;
        }
    }
    if(unvisited_ongoing)
    {
        unvisited_ongoing = false;
        cond_printf("unvisited: %08x - %08x (length %08x)", unvisited_start, ctx.end_code_addr, (u32)(ctx.end_code_addr - unvisited_start));
        cond_printf("\n");
    }

#if DISASM_LIST_UNIMPL
    for(const auto& name : ctx.insn_unimplemented_list)
    {
        cond_printf("unimplemented: %s\n", name.c_str());
    }
#endif

    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        if(ctx.analyzed[i * 3 + 1].visited)
        {
            cond_printf("visited thumb: %08x\n", start_addr + i * 4);
        }
        if(ctx.analyzed[i * 3 + 2].visited)
        {
            cond_printf("visited thumb: %08x\n", start_addr + i * 4 + 2);
        }
    }

    cond_printf("Final insn_temp_list capacity: %zd\n", ctx.insn_temp_list.capacity());
    cond_printf("Final branches_temp_list capacity: %zd\n", ctx.branches_temp_list.capacity());

    const std::string source_file_path = filename + ".src.c";
    const std::string labels_arm_file_path = filename + ".lab.arm.c";
    const std::string labels_thumb_file_path = filename + ".lab.thumb.c";
    FILE_ptr source_file_ptr{do_dummy_save ? nullptr : fopen(source_file_path.c_str(), "wb")};
    FILE_ptr labels_arm_file_ptr{do_dummy_save ? nullptr : fopen(labels_arm_file_path.c_str(), "wb")};
    FILE_ptr labels_thumb_file_ptr{do_dummy_save ? nullptr : fopen(labels_thumb_file_path.c_str(), "wb")};
    auto source_file = source_file_ptr.get();
    auto labels_arm_file = labels_arm_file_ptr.get();
    auto labels_thumb_file = labels_thumb_file_ptr.get();

    safe_fprintf(source_file, "void ATTR_FASTCALL ATTR_NORETURN ATTR_NO_SAVE_REGS entry(arm_cpu_ctx* const ctx) {\n");
    safe_fprintf(source_file, "goto LABEL_ARM_start;\n");
    safe_fprintf(source_file, "LABEL_ARM_error:\n");
    safe_fprintf(source_file, "LABEL_THUMB_error:\n");
    safe_fprintf(source_file, "arm_cpu_instr_runtime_error(ctx);\n");

    safe_fprintf(source_file, "static const int LABELS_ARM_TABLE[] __attribute__((section(\".rdata\")))  = {\n");
    safe_fprintf(source_file, "#include \"%s.lab.arm.c\"\n", filename.c_str());
    safe_fprintf(source_file, "};\n");

    safe_fprintf(source_file, "static const int LABELS_THUMB_TABLE[] __attribute__((section(\".rdata\"))) = {\n");
    safe_fprintf(source_file, "#include \"%s.lab.thumb.c\"\n", filename.c_str());
    safe_fprintf(source_file, "};\n");

    safe_fprintf(source_file, "LABEL_ARM_start:\n");
    safe_fprintf(source_file, "LABEL_THUMB_start:\n");

    const char* label_kind = "ARM";
    uint64_t insn_addr_previous = start_addr - 4;
    for(const auto& [insn_address, insn_text] : ctx.insn_list)
    {
        if((insn_address & 0x3) != 0)
            continue;

        for(insn_addr_previous += 4; insn_addr_previous < insn_address; insn_addr_previous += 4)
        {
            if(ctx.get_mapping(insn_addr_previous).visited)
            {
                cond_printf("%s @ 0x%08llx visited but no code\n", label_kind, insn_addr_previous);
            }
            safe_fprintf(labels_arm_file, "&&LABEL_%s_error - &&LABEL_%s_start,\n", label_kind, label_kind);
        }

        safe_fprintf(labels_arm_file, "&&LABEL_%s_0x%08llx - &&LABEL_%s_start,\n", label_kind, insn_address, label_kind);
        safe_fprintf(source_file, "LABEL_%s_0x%08llx:\n", label_kind, insn_address);
        safe_fwrite(insn_text.data(), 1, insn_text.size(), source_file);
        safe_fprintf(source_file, "\n");
    }

    label_kind = "THUMB";

    insn_addr_previous = start_addr - 2;
    for(const auto& [insn_address, insn_text] : ctx.insn_list)
    {
        if((insn_address & 0x1) != 1)
            continue;

        const uint64_t active_address = insn_address & ~0x1;
        for(insn_addr_previous += 2; insn_addr_previous < active_address; insn_addr_previous +=2)
        {
            if(ctx.get_mapping(insn_addr_previous + 1).visited)
            {
                cond_printf("%s @ 0x%08llx visited but no code\n", label_kind, insn_addr_previous);
            }
            safe_fprintf(labels_thumb_file, "&&LABEL_%s_error - &&LABEL_%s_start,\n", label_kind, label_kind);
        }

        safe_fprintf(labels_thumb_file, "&&LABEL_%s_0x%08llx - &&LABEL_%s_start,\n", label_kind, active_address, label_kind);
        safe_fprintf(source_file, "LABEL_%s_0x%08llx:\n", label_kind, active_address);
        fwrite(insn_text.data(), 1, insn_text.size(), source_file);
        safe_fprintf(source_file, "\n");
    }

    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        for(int j = 0; j < 2; ++j)
        {
            const u32 insn_address = i * 4 + start_addr + 1 + j * 2;
            if(ctx.analyzed[i * 3 + j + 1].visited)
            {
                safe_fprintf(labels_thumb_file, "&&LABEL_%s_0x%08x - &&LABEL_%s_start,\n", label_kind, insn_address, label_kind);
                safe_fprintf(source_file, "LABEL_%s_0x%08x:\n", label_kind, insn_address);
                if(auto it = ctx.insn_list.find(insn_address); it != ctx.insn_list.end())
                {
                    fwrite(it->second.data(), 1, it->second.size(), source_file);
                    safe_fprintf(source_file, "\n");
                }
                else
                {
                    safe_fprintf(source_file, "// invalid addr, no matching insn\n");
                }
            }
            else
            {
                safe_fprintf(labels_thumb_file, "&&LABEL_%s_error - &&LABEL_%s_start,\n", label_kind, label_kind);
            }
        }
    }

    safe_fprintf(source_file, "arm_cpu_instr_runtime_error(ctx); /* should never get there */\n");
    safe_fprintf(source_file, "}\n");
}

static std::vector<u8> load_data(const std::string& path)
{
    FILE_ptr fh_ptr{fopen(path.c_str(), "rb")};
    if(!fh_ptr) return {};

    auto fh = fh_ptr.get();
    fseek(fh, 0, SEEK_END);
    const long fhsz = ftell(fh);
    if(fhsz <= 0l) return {};

    fseek(fh, 0, SEEK_SET);
    std::vector<u8> data(fhsz);
    if(fread(data.data(), 1, data.size(), fh) != (size_t)fhsz) return {};

    return data;
}

int main(int argc, char** argv)
{
    if(argc < 5)
    {
        fprintf(stderr, "Usage: %s <code binary> <rodata binary> <data binary> <output filename without extension>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // printf("Hello, world!\n");

    auto seg_code = load_data(argv[1]);
    auto seg_rodata = load_data(argv[2]);
    auto seg_data = load_data(argv[3]);

    disasm_all_branches_from(0x0010'0000, seg_code, seg_rodata, seg_data, argv[4], false, false);
}
