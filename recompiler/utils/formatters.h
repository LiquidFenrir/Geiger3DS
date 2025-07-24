#pragma once

#include "formatters_base.h"
#include "arm_info.h"

#define ENUM_FORMATTER_CS(enum_type) \
template <> struct fmt::formatter<enum_type> : skip_flags_parse { \
    format_context::iterator format(const enum_type& value, format_context& ctx) const { \
        constexpr size_t prefix_length = magic_enum::enum_name<static_cast<enum_type>(0)>().size() - 7; /* 0 -> ..._INVALID */ \
        return fmt::format_to(ctx.out(), "{}", magic_enum::enum_name<enum_type>(value).substr(prefix_length)); \
    } \
};

ENUM_FORMATTER_CS(cs_ac_type)
ENUM_FORMATTER_CS(arm_op_type)
ENUM_FORMATTER_RANGE(arm_reg, 0, ARM_REG_ENDING)
ENUM_FORMATTER_CS(arm_reg)
ENUM_FORMATTER_RANGE(arm_insn, 0, ARM_INS_ALIAS_END)
ENUM_FORMATTER_CS(arm_insn)
ENUM_FORMATTER_CS(arm_shifter)

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
        it = fmt::format_to(it, "id={} ({}), ", insn.id, (arm_insn)insn.id);
        if(insn.is_alias && insn.alias_id != (u64_t)-1)
        {
            it = fmt::format_to(it, "alias_id={} ({}), ", insn.id, (arm_insn)insn.alias_id);
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

// Don't need to customize, the Rx names are already the aliases
/*
// Сustom definitions of names for enum.
// Specialization of `enum_name` must be injected in `namespace magic_enum::customize`.
template <>
constexpr magic_enum::customize::customize_t magic_enum::customize::enum_name<arm_reg>(arm_reg value) noexcept {
    switch (value) {
        case arm_reg::ARM_REG_R13:
        return "ARM_REG_SP";
    case arm_reg::ARM_REG_R14:
        return "ARM_REG_LR";
        case arm_reg::ARM_REG_R15:
        return "ARM_REG_PC";
    }
    return default_tag;
}
*/
