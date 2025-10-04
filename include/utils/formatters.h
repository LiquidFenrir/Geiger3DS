#pragma once

#include "formatters_base.h"
#include "../capstone_inc.h"
#include "../magic_enum_inc.h"

#include <typedefs.h>

template <> struct fmt::formatter<decltype(cs_arm_op::shift)> : skip_flags_parse {
    format_context::iterator format(const auto& shift, format_context& ctx) const
    {
        auto it = ctx.out();

        if(shift.type > ARM_SFT_REG)
        {
            it = fmt::format_to(it, "{} {}", (arm_shifter)(shift.type - ARM_SFT_REG), (arm_reg)shift.value);
        }
        else
        {
            it = fmt::format_to(it, "{} {}", shift.type, shift.value);
        }

        return fmt::format_to(it, ")");
    }
};

template <> struct fmt::formatter<cs_insn> : skip_flags_parse {
    format_context::iterator format(const cs_insn& insn, format_context& ctx) const
    {
        auto it = ctx.out();
        it = fmt::format_to(it, "insn(");
        it = fmt::format_to(it, "id={} [{}], ", (arm_insn)insn.id, insn.id);
        if(insn.is_alias && insn.alias_id != (u64_t)-1)
        {
            it = fmt::format_to(it, "alias_id={} [{}], ", (arm_insn)insn.alias_id, insn.alias_id);
        }

        const auto& arm = insn.detail->arm;
        if(arm.cc != ARMCC_UNDEF && arm.cc != ARMCC_AL)
        {
            it = fmt::format_to(it, "cc={}, ", arm.cc);
        }
        if(arm.update_flags)
        {
            it = fmt::format_to(it, "setflags=yes, ");
        }

        return fmt::format_to(it, "text=\"{}{}{}\")", insn.mnemonic, insn.op_str[0] == '\0' ? "" : " ", insn.op_str);
    }
};

template <> struct fmt::formatter<cs_arm_op> : skip_flags_parse {
    format_context::iterator format(const cs_arm_op& op, format_context& ctx) const
    {
        auto it = ctx.out();
        it = fmt::format_to(it, "op(type={}, access={}", op.type, (cs_ac_type)op.access);

        switch(op.type)
        {
        case arm_op_type::ARM_OP_IMM:
            it = fmt::format_to(it, ", imm={}", op.imm);
            break;
        case arm_op_type::ARM_OP_REG:
            it = fmt::format_to(it, ", reg={}", (arm_reg)op.reg);
            if(op.shift.value != 0)
            {
                it = fmt::format_to(it, " {}", op.shift);
            }
            break;
        case arm_op_type::ARM_OP_MEM:
            it = fmt::format_to(it, ", mem=(");
            it = fmt::format_to(it, "base={}", op.mem.base);
            if(op.mem.index != ARM_REG_INVALID)
            {
                it = fmt::format_to(it, ", offset_reg={}", op.mem.scale < 0 ? '-' : '+');
                if(op.shift.value != 0)
                {
                    it = fmt::format_to(it, "({} {})", op.mem.index, op.shift);
                }
                else
                {
                    it = fmt::format_to(it, "{}", op.mem.index);
                }
            }
            else if(op.mem.disp != 0)
            {
                it = fmt::format_to(it, ", offset_imm={}{}", op.mem.scale < 0 ? '-' : '+', op.mem.base);
            }
            it = fmt::format_to(it, ")");
            break;
        default:
            assert(0);
        }

        return fmt::format_to(it, ")");
    }
};
