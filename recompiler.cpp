extern "C" {
#include "capstone/platform.h"
#include "capstone/capstone.h"
}
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <queue>
#include <memory>
#include <string>
#include <span>
#include <map>
#include <format>

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

struct ProcessDisasmContext {
    const u32 start_addr;
    const std::span<const u8> start_code;

    // mapping goes
    // ((4x) / 4) * 3 -> ARM mapping
    // ((4x + 1) / 4) * 3 + 1 -> THUMB mapping (first)
    // ((4x + 3) / 4) * 3 + 2 -> THUMB mapping (second)
    struct MappingValue {
        bool visited{false};
        bool want_label{false};
        bool have_label{false};
    };
    std::vector<MappingValue> analyzed{(start_code.size() / 4) * 3};

    std::size_t get_offset(const u32 addr)
    {
        return addr - start_addr;
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
    auto& get_mapping(const u32 addr)
    {
        return analyzed[get_mapping_index(addr)];
    }

    std::queue<u32> branches{};

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

    struct State {
        csh* handle;
        const uint8_t* code;
        size_t code_size;
        uint64_t address;
        cs_insn* insn;
    };
};

#define INSN_APPEND_LDREX_TYPE(c_ldr_type) \
    result += std::format("ARM_CPU_PERFORM_LDREX_ALL(ctx, ctx->{}, " #c_ldr_type ", ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].mem.base));

#define INSN_APPEND_LDREXD() \
    result += std::format("ARM_CPU_PERFORM_LDREXD(ctx, ctx->{}, ctx->{}, ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.base));

#define INSN_APPEND_STREX_TYPE(c_str_type, c_str_and) \
    result += std::format("ARM_CPU_PERFORM_STREX_ALL(ctx, ctx->{}, ctx->{}, " #c_str_type ", " #c_str_and ", ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].mem.base));

#define INSN_APPEND_STREXD() \
    result += std::format("ARM_CPU_PERFORM_STREXD(ctx, ctx->{}, ctx->{}, ctx->{}, ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[3].mem.base));

#define INSN_APPEND_LDR_TYPE(c_ldr_type, c_ldr_cast) \
    result += std::format("ARM_CPU_PERFORM_LDR_ALL(ctx, ctx->{}, " #c_ldr_type ", " #c_ldr_cast ", ctx->{}, ", \
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
    result += std::format("), {}, {});\n", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);

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
    result += std::format("), {}, {});\n", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);

#define INSN_APPEND_LDM(c_ldm_type, c_ldm_init, c_ldm_step, c_ldm_final) \
    result += std::format("ARM_CPU_PERFORM_LDM_ALL(ctx, ctx->{}, {}, {}, {}, {}, ", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), (int)insn.detail->writeback, c_ldm_init, c_ldm_step, c_ldm_final); \
    { \
    bool have_pc_in_list = false; \
    for(int reg_idx = 1; reg_idx < insn.detail->arm.op_count; ++reg_idx) { \
        result += std::format("(" #c_ldm_type ", {}, {})", reg_idx - 1, cs_reg_name(*state.handle, insn.detail->arm.operands[reg_idx].reg)); \
        if(insn.detail->arm.operands[reg_idx].reg == arm_reg::ARM_REG_PC) have_pc_in_list = true; \
    } \
    result += std::format(", {});\n", (int)have_pc_in_list); \
    }

#define INSN_APPEND_STM(c_stm_type, c_stm_init, c_stm_step, c_stm_final) \
    result += std::format("ARM_CPU_PERFORM_STM_ALL(ctx, ctx->{}, {}, {}, {}, {}, ", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), (int)insn.detail->writeback, c_stm_init, c_stm_step, c_stm_final); \
    for(int reg_idx = 1; reg_idx < insn.detail->arm.op_count; ++reg_idx) \
        result += std::format("(" #c_stm_type ", {}, {})", reg_idx - 1, cs_reg_name(*state.handle, insn.detail->arm.operands[reg_idx].reg)); \
    result += ");\n";

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
        result += std::format("ARM_CPU_PERFORM_ASR_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    case arm_shifter::ARM_SFT_LSL_REG: \
        result += std::format("ARM_CPU_PERFORM_LSL_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    case arm_shifter::ARM_SFT_LSR_REG: \
        result += std::format("ARM_CPU_PERFORM_LSR_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    case arm_shifter::ARM_SFT_ROR_REG: \
        result += std::format("ARM_CPU_PERFORM_ROR_REG(ctx, ctx->{}, {}, ctx->{} & 0xff)", \
        cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].reg), (int)c_op_updates_flags, cs_reg_name(*state.handle, insn.detail->arm.operands[c_op_idx].shift.value)); \
        break; \
    default: \
        assert(false && "Invalid shift operand2"); \
        break; \
    } else if(insn.detail->arm.operands[c_op_idx].type == arm_op_type::ARM_OP_IMM) result += std::format("{}", insn.detail->arm.operands[c_op_idx].imm);

#define INSN_APPEND_XT_TYPE(c_basic_type, c_extend_type, c_and_mask) \
    result += std::format("ARM_CPU_PERFORM_XT(ctx, ctx->{}, ctx->{}, {}, " #c_and_mask ", " #c_basic_type ", " #c_extend_type ");\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    (insn.detail->arm.operands[1].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0));

#define INSN_APPEND_XTA_TYPE(c_basic_type, c_extend_type, c_and_mask) \
    result += std::format("ARM_CPU_PERFORM_XTA(ctx, ctx->{}, ctx->{}, {}, " #c_and_mask ", " #c_basic_type ", " #c_extend_type ", ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    (insn.detail->arm.operands[2].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));

#define INSN_APPEND_XTB16_TYPE(c_basic_type, c_extend_type) \
    result += std::format("ARM_CPU_PERFORM_XTB16(ctx, ctx->{}, ctx->{}, {}, " #c_basic_type ", " #c_extend_type ");\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    (insn.detail->arm.operands[1].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0));

#define INSN_APPEND_XTAB16_TYPE(c_basic_type, c_extend_type) \
    result += std::format("ARM_CPU_PERFORM_XTAB16(ctx, ctx->{}, ctx->{}, {}, " #c_basic_type ", " #c_extend_type ", ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    (insn.detail->arm.operands[2].shift.type == arm_shifter::ARM_SFT_ROR ? insn.detail->arm.operands[1].shift.value : 0), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));

#define INSN_APPEND_MUL() \
    result += std::format("ARM_CPU_PERFORM_MUL(ctx, {}, ctx->{}, ctx->{}, ctx->{});\n", \
    (int)insn.detail->arm.update_flags, \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));

#define INSN_APPEND_MLA() \
    result += std::format("ARM_CPU_PERFORM_MLA(ctx, {}, ctx->{}, ctx->{}, ctx->{}, ctx->{});\n", \
    (int)insn.detail->arm.update_flags, \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[3].reg));

#define INSN_APPEND_MUL_MLA_LONG_TYPE(c_mul_mla_kind, c_base_type) \
    result += std::format("ARM_CPU_PERFORM_x" #c_mul_mla_kind "L(ctx, " #c_base_type ", {}, ctx->{}, ctx->{}, ctx->{}, ctx->{});\n", \
    (int)insn.detail->arm.update_flags, \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[3].reg));

#define INSN_APPEND_SIMD_N_TYPE(c_base_type, c_bitness, c_operation) \
    result += std::format("ARM_CPU_PERFORM_SIMD_" #c_bitness "_TYPE(ctx, " #c_base_type ", " #c_operation ", ctx->{}, ctx->{}, ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));
    
#define INSN_APPEND_SIMD_16_DUAL_TYPE(c_base_type, c_operation_top, c_operation_bottom) \
    result += std::format("ARM_CPU_PERFORM_SIMD_16_DUAL_TYPE(ctx, " #c_base_type ", " #c_operation_top ", " #c_operation_bottom ", ctx->{}, ctx->{}, ctx->{});\n", \
    cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg), \
    cs_reg_name(*state.handle, insn.detail->arm.operands[2].reg));

static void disasm_chunk(ProcessDisasmContext& ctx, const u32 addr)
{
    bool iter_success = false;
    const bool in_thumb_mode = addr & 1;
    ProcessDisasmContext::State state{
        .handle = in_thumb_mode ? &ctx.handle_thumb.handle : &ctx.handle_arm.handle,
        .code = ctx.start_code.data() + ctx.get_offset(addr & ~1),
        .code_size = ctx.start_code.size() - ctx.get_offset(addr & ~1),
        .address = addr & ~1,
        .insn = in_thumb_mode ? ctx.insn_thumb.get() : ctx.insn_arm.get(),
    };

    const char* label_kind = in_thumb_mode ? "THUMB" : "ARM";
    printf("Entering chunk %08x in %s mode \n", addr, label_kind);

    bool last_cmp = false;
    int last_cmp_reg = arm_reg::ARM_REG_INVALID;
    int64_t last_cmp_imm = 0;
    // pair: value, known unchanged
    // std::map<arm_reg, std::pair<uint32_t, bool>> last_known_reg_value;

    while((iter_success = cs_disasm_iter(*state.handle, &state.code, &state.code_size, &state.address, state.insn)))
    {
        const auto& insn = *state.insn;
        bool uncond_branch = false;
        auto& mapping = ctx.get_mapping(insn.address + (addr & 1));

        // already passed the instruction, thus the chunk
        if(mapping.visited)
        {
            printf("already visited\n");
            break;
        }
        mapping.visited = true;

        printf("0x%08llx (%u/%llu): %s %s\n", insn.address, insn.id, insn.alias_id, insn.mnemonic, insn.op_str);
        if(insn.detail->arm.cc == ARMCC_UNDEF)
        {
            printf("condcode: undefined\n");
        }

        std::string result;
        result += std::format("arm_cpu_update_pc(ctx, 0x{:08x});\n", insn.address);
        if(insn.detail->arm.cc != ARMCC_AL && insn.detail->arm.cc != ARMCC_UNDEF)
        {
            result += std::format("if(arm_cpu_check_cc(ctx, arm_cpu_cc_{}))", ARMCondCodeToString(insn.detail->arm.cc));
            result += " {\n";
        }

        bool got_okay_can_skip = false;
        if(insn.is_alias) switch(insn.alias_id)
        {
        case ARM_INS_ALIAS_POP: {
            // beyond this is code recognition
            for(int i = 1; i < insn.detail->arm.op_count; ++i)
            {
                if(insn.detail->arm.operands[i].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[i].reg == arm_reg::ARM_REG_PC)
                {
                    if(insn.detail->arm.cc == ARMCC_AL)
                    {
                        uncond_branch = true;
                    }
                    else
                    {
                        printf("load to PC but not unconditional\n");
                    }
                    break;
                }
            }
            break;
        }
        case ARM_INS_ALIAS_NOP: {
            got_okay_can_skip = true;
            break;
        }
        default: {
            break;
        }
        }

        const bool last_cmp_used = last_cmp;
        last_cmp = false;
        if(!got_okay_can_skip) switch(insn.id)
        {
        case ARM_INS_B: {
            const auto branch_target = insn.detail->arm.operands[0].imm;
            result += std::format("ARM_CPU_PERFORM_{}_B(ctx, 0x{:08x});\n", label_kind, branch_target);
            ctx.branches.push(branch_target);
            if(insn.detail->arm.cc == ARMCC_AL)
                uncond_branch = true;
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_BX: {
            const auto branch_target_reg = insn.detail->arm.operands[0].reg;
            result += std::format("ARM_CPU_PERFORM_BX(ctx, ctx->{});\n", cs_reg_name(*state.handle, branch_target_reg));
            // if(auto it = last_known_reg_value.find((arm_reg)branch_target_reg); it != last_known_reg_value.end() && it->second.second)
            // {
            //     const auto value = it->second.first;
            //     if (ctx.start_addr <= value && value < ctx.start_addr + ctx.start_code.size())
            //     {
            //         printf("Identified indirect jump to %08x\n", value);
            //         ctx.branches.push(value);
            //     }
            // }
            if(insn.detail->arm.cc == ARMCC_AL)
            {
                uncond_branch = true;
            }
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_BL: {
            const auto branch_target = insn.detail->arm.operands[0].imm;
            result += std::format("ARM_CPU_PERFORM_{}_BL(ctx, 0x{:08x});\n", label_kind, branch_target);
            ctx.branches.push(branch_target);
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_BLX: {
            if(insn.detail->arm.operands[0].type == ARM_OP_REG)
            {
                const auto branch_target_reg = insn.detail->arm.operands[0].reg;
                result += std::format("ARM_CPU_PERFORM_BLX_REG(ctx, ctx->{});\n", cs_reg_name(*state.handle, branch_target_reg));
                // if(auto it = last_known_reg_value.find((arm_reg)branch_target_reg); it != last_known_reg_value.end() && it->second.second)
                // {
                //     const auto value = it->second.first;
                //     if (ctx.start_addr <= value && value < ctx.start_addr + ctx.start_code.size())
                //     {
                //         printf("Identified indirect jump to %08x\n", value);
                //         ctx.branches.push(value);
                //     }
                // }
            }
            else
            {
                const auto branch_target = insn.detail->arm.operands[0].imm;
                result += std::format("ARM_CPU_PERFORM_{}_BLX_IMM(ctx, 0x{:08x});\n", label_kind, branch_target);
                ctx.branches.push(branch_target | (1 ^ (int)(in_thumb_mode)));
            }
            // last_known_reg_value.clear();
            break;
        }
        
        case ARM_INS_SVC: {
            const auto svc_id = insn.detail->arm.operands[0].imm;
            result += std::format("arm_cpu_instr_svc(ctx, {});\n", svc_id);
            // last_known_reg_value.clear();
            break;
        }
        case ARM_INS_UDF: {
            const auto udf_id = insn.detail->arm.operands[0].imm;
            result += std::format("arm_cpu_instr_udf(ctx, {});\n", udf_id);
            break;
        }
        
        case ARM_INS_MCR: {
            result += std::format("ARM_CPU_PERFORM_MCR(ctx, ctx->{}, {}, {}, {}, {}, {});\n",
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
            result += std::format("ARM_CPU_PERFORM_MRC(ctx, ctx->{}, {}, {}, {}, {}, {});\n",
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
            result += std::format("ctx->{} = ctx->{};\n",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            break;
        }

        case ARM_INS_CMP:
            // beyond this is code recognition
            if(insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_IMM)
            {
                last_cmp = true;
                last_cmp_reg = insn.detail->arm.operands[0].reg;
                last_cmp_imm = insn.detail->arm.operands[1].imm;
            }
            [[fallthrough]];
        case ARM_INS_CMN: {
            result += std::format("ARM_CPU_PERFORM_FLAGS_{}(ctx, ctx->{}, ", cs_insn_name(*state.handle, insn.id), cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(0, 1);
            result += ");\n";
            break;
        }
        case ARM_INS_TST:
        case ARM_INS_TEQ: {
            result += std::format("ARM_CPU_PERFORM_FLAGS_{}(ctx, ctx->{}, ", cs_insn_name(*state.handle, insn.id), cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(1, 1);
            result += ");\n";
            break;
        }
        case ARM_INS_REV:
        case ARM_INS_REV16:
        case ARM_INS_REVSH:
        case ARM_INS_CLZ: {
            result += std::format("ctx->{} = ARM_CPU_PERFORM_{}(ctx, ctx->{});\n",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_insn_name(*state.handle, insn.id),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
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
            result += ");\n";
            if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
            {
                if(insn.detail->arm.update_flags)
                    assert(false && "Attempt to use a flag setting arithmetic insn with PC as Rd");
                else
                    result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
            }
            break;
        }

        case ARM_INS_MOV: {
            result += std::format("ctx->{} = ", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 1);
            result += ";\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});\n", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
            break;
        }
        case ARM_INS_MVN: {
            result += std::format("ctx->{} = ~(", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 1);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});\n", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
            break;
        }
        case ARM_INS_AND: {
            result += std::format("ctx->{} = ctx->{} & (",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});\n", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
            break;
        }
        case ARM_INS_ORR: {
            result += std::format("ctx->{} = ctx->{} | (",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});\n", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
            break;
        }
        case ARM_INS_EOR: {
            result += std::format("ctx->{} = ctx->{} ^ (",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});\n", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
            break;
        }
        case ARM_INS_BIC: {
            result += std::format("ctx->{} = ctx->{} & ~(",
                cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg),
                cs_reg_name(*state.handle, insn.detail->arm.operands[1].reg));
            INSN_APPEND_operand2(insn.detail->arm.update_flags, 2);
            result += ");\n";
            if(insn.detail->arm.update_flags)
                result += std::format("arm_cpu_update_flags_NZ_32(ctx, ctx->{});\n", cs_reg_name(*state.handle, insn.detail->arm.operands[0].reg));
            else if(insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC)
                result += std::format("ARM_CPU_PERFORM_BRANCH_REG(ctx, ctx->pc);\n");
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
            result += std::format("ARM_CPU_PERFORM_SEL(ctx, ctx->{}, ctx->{}, ctx->{});\n",
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
            result += "ARM_CPU_PERFORM_CLREX(ctx);\n";
            break;
        }
        
        case ARM_INS_LDRB: {
            INSN_APPEND_LDR_TYPE(uint8_t, (uint32_t));
            break;
        }
        case ARM_INS_LDRSB: {
            INSN_APPEND_LDR_TYPE(int8_t, (int32_t));
            break;
        }
        case ARM_INS_LDRH: {
            INSN_APPEND_LDR_TYPE(uint16_t, (uint32_t));
            break;
        }
        case ARM_INS_LDRSH: {
            INSN_APPEND_LDR_TYPE(int16_t, (int32_t));
            break;
        }
        case ARM_INS_LDR: {
            INSN_APPEND_LDR_TYPE(uint32_t,);

            // beyond this is code recognition
            if(last_cmp_used && insn.detail->arm.cc == ARMCC_LS && insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[0].type == arm_op_type::ARM_OP_REG && insn.detail->arm.operands[0].reg == arm_reg::ARM_REG_PC
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && insn.detail->arm.operands[1].mem.base == arm_reg::ARM_REG_PC
                && insn.detail->arm.operands[1].mem.index == last_cmp_reg
                && insn.detail->arm.operands[1].shift.type == ARM_SFT_LSL
                && insn.detail->arm.operands[1].shift.value == 2
            )
            {
                printf("switch statement detected: %lld entries\n", last_cmp_imm+1);
                for(int64_t index = 0; index <= last_cmp_imm; ++index)
                {
                    u32 value = 0;
                    const u32 pointer = insn.address + 8 + index * 4;
                    std::memcpy(&value, &ctx.start_code[ctx.get_offset(pointer)], 4);
                    printf("Entry %lld: %08x\n", index, value);
                    ctx.get_mapping(pointer).visited = true;
                    ctx.branches.push(value);
                }
            }
            else if(insn.detail->arm.op_count == 2
                && insn.detail->arm.operands[1].type == arm_op_type::ARM_OP_MEM
                && insn.detail->arm.operands[1].mem.base == arm_reg::ARM_REG_PC
                && insn.detail->arm.operands[1].mem.index == arm_reg::ARM_REG_INVALID
            )
            {
                printf("register set detected: from pc[%d:+4]\n", insn.detail->arm.operands[1].mem.disp);
                u32 value = 0;
                const u32 pointer = insn.address + 8 + insn.detail->arm.operands[1].mem.disp;
                std::memcpy(&value, &ctx.start_code[ctx.get_offset(pointer)], 4);
                // last_known_reg_value[(arm_reg)insn.detail->arm.operands[0].reg] = std::make_pair(value, true);
                // HACK: if the set value looks like a pointer to code, add it to the queue
                if (ctx.start_addr + 0x20 <= value && value < ctx.start_addr + ctx.start_code.size())
                {
                    printf("Maybe identified function pointer to %08x\n", value);
                    ctx.branches.push(value);
                }
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
            result += std::format("), {}, {});\n", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);
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
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
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
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
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
            result += std::format("), {}, {});\n", (int)insn.detail->writeback, (int)insn.detail->arm.post_index);
            break;
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
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
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
            else if(insn.detail->arm.operands[0].reg >= arm_reg::ARM_REG_S0 && insn.detail->arm.operands[0].reg <= arm_reg::ARM_REG_S31)
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
            result += std::format("#warning \"unimplemented: {} {}\"\n", insn.mnemonic, insn.op_str);
            break;
        }

        if(insn.detail->arm.cc != ARMCC_AL && insn.detail->arm.cc != ARMCC_UNDEF)
        {
            result += "}\n";
        }

        ctx.insn_list.try_emplace(insn.address, result);
        if(uncond_branch)
            break;
    }

    if(!iter_success)
    {
        printf("exit from failure to disas\n");
    }
}

static void disasm_all_branches_from(const u32 start_addr, std::span<const u8> start_code, std::span<const u8> rodata, std::span<const u8> data, const std::string& filename)
{
    ProcessDisasmContext ctx{.start_addr = start_addr, .start_code = start_code};

    printf("Checking initial pointer: %08x\n", start_addr);
    ctx.branches.push(start_addr);

    printf("\n");
    for(std::size_t i = 0; i < rodata.size(); i += sizeof(u32))
    {
        u32 value = 0;
        std::memcpy(&value, &rodata[i], 4);
        if(start_addr + 0x20 <= value && value < start_addr + start_code.size())
        {
            printf("Checking rodata pointer: %08x\n", value);
            ctx.branches.push(value);
        }
    }
    printf("\n");
    for(std::size_t i = 0; i < data.size(); i += sizeof(u32))
    {
        u32 value = 0;
        std::memcpy(&value, &data[i], 4);
        if(start_addr + 0x20 <= value && value < start_addr + start_code.size())
        {
            printf("Checking data pointer: %08x\n", value);
            ctx.branches.push(value);
        }
    }
    printf("\n");

    while(!ctx.branches.empty())
    {
        const u32 addr = ctx.branches.front();
        ctx.branches.pop();
        disasm_chunk(ctx, addr);
    }

    printf("\n");
    u32 unvisited_start = 0;
    bool unvisited_ongoing = false;
    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        if(ctx.analyzed[i * 3].visited)
        {
            if(unvisited_ongoing)
            {
               unvisited_ongoing = false;
                printf("unvisited: %08x - %08x (length %08x)\n", unvisited_start, start_addr + i * 4, start_addr + i * 4 - unvisited_start);
            }
        }
        else if(!unvisited_ongoing)
        {
            unvisited_start = start_addr + i * 4;
            unvisited_ongoing = true;
        }
    }
    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        if(ctx.analyzed[i * 3 + 1].visited)
        {
            printf("visited thumb: %08x\n", start_addr + i * 4);
        }
        if(ctx.analyzed[i * 3 + 2].visited)
        {
            printf("visited thumb: %08x\n", start_addr + i * 4 + 2);
        }
    }

    const std::string source_file_path = filename + ".src.c";
    const std::string labels_arm_file_path = filename + ".lab.arm.c";
    const std::string labels_thumb_file_path = filename + ".lab.thumb.c";
    FILE_ptr source_file_ptr{fopen(source_file_path.c_str(), "wb")};
    FILE_ptr labels_arm_file_ptr{fopen(labels_arm_file_path.c_str(), "wb")};
    FILE_ptr labels_thumb_file_ptr{fopen(labels_thumb_file_path.c_str(), "wb")};
    auto source_file = source_file_ptr.get();
    auto labels_arm_file = labels_arm_file_ptr.get();
    auto labels_thumb_file = labels_thumb_file_ptr.get();

    fprintf(source_file, "#include \"./include/arm_cpu_ctx.h\"\n\n");
    fprintf(source_file, "void ATTR_FASTCALL ATTR_NORETURN ATTR_NO_SAVE_REGS entry(arm_cpu_ctx* const ctx) {\n");
    fprintf(source_file, "goto LABEL_ARM_start;\n");
    fprintf(source_file, "LABEL_ARM_error:\n");
    fprintf(source_file, "LABEL_THUMB_error:\n");
    fprintf(source_file, "arm_cpu_instr_runtime_error(ctx);\n");

    fprintf(source_file, "static const int LABELS_ARM_TABLE[] = {\n");
    fprintf(source_file, "#include \"%s.lab.arm.c\"\n", filename.c_str());
    fprintf(source_file, "};\n");

    fprintf(source_file, "static const int LABELS_THUMB_TABLE[] = {\n");
    fprintf(source_file, "#include \"%s.lab.thumb.c\"\n", filename.c_str());
    fprintf(source_file, "};\n");

    fprintf(source_file, "LABEL_ARM_start:\n");
    fprintf(source_file, "LABEL_THUMB_start:\n");

    const char* label_kind = "ARM";
    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        const u32 insn_address = i * 4 + start_addr;
        if(ctx.analyzed[i * 3].visited)
        {
            fprintf(labels_arm_file, "&&LABEL_%s_0x%08x - &&LABEL_%s_start,\n", label_kind, insn_address, label_kind);
            fprintf(source_file, "LABEL_%s_0x%08x:\n", label_kind, insn_address);
            if(auto it = ctx.insn_list.find(insn_address); it != ctx.insn_list.end())
            {
                fwrite(it->second.data(), 1, it->second.size(), source_file);
            }
            else
            {
                fprintf(source_file, "// invalid addr, no matching insn\n");
            }
        }
        else
        {
            fprintf(labels_arm_file, "&&LABEL_%s_error - &&LABEL_%s_start,\n", label_kind, label_kind);
        }
    }
    label_kind = "THUMB";
    for(u32 i = 0; i < start_code.size() / 4; ++i)
    {
        for(int j = 0; j < 2; ++j)
        {
            const u32 insn_address = i * 4 + start_addr + 1 + j * 2;
            if(ctx.analyzed[i * 3 + j + 1].visited)
            {
                fprintf(labels_thumb_file, "&&LABEL_%s_0x%08x - &&LABEL_%s_start,\n", label_kind, insn_address, label_kind);
                fprintf(source_file, "LABEL_%s_0x%08x:\n", label_kind, insn_address);
                if(auto it = ctx.insn_list.find(insn_address); it != ctx.insn_list.end())
                {
                    fwrite(it->second.data(), 1, it->second.size(), source_file);
                }
                else
                {
                    fprintf(source_file, "// invalid addr, no matching insn\n");
                }
            }
            else
            {
                fprintf(labels_thumb_file, "&&LABEL_%s_error - &&LABEL_%s_start,\n", label_kind, label_kind);
            }
        }
    }

    fprintf(source_file, "arm_cpu_instr_runtime_error(ctx); /* should never get there */\n");
    fprintf(source_file, "}\n");
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

    printf("Hello, world!\n");

    auto seg_code = load_data(argv[1]);
    auto seg_rodata = load_data(argv[2]);
    auto seg_data = load_data(argv[3]);

    disasm_all_branches_from(0x0010'0000, seg_code, seg_rodata, seg_data, argv[4]);
}
