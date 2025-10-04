#pragma once

#define MAGIC_ENUM_ENABLE_HASH
#include <magic_enum/magic_enum.hpp>

#include "capstone_inc.h"

#define ENUM_RANGE_CS(enum_type, base_name, range_start, range_end) \
    template <> \
    struct magic_enum::customize::enum_range<enum_type> { \
        static constexpr std::size_t prefix_length = sizeof(base_name)-1; \
        static constexpr int min = range_start; \
        static constexpr int max = range_end; \
    };

ENUM_RANGE_CS(cs_ac_type, "CS_OP_", CS_AC_INVALID, CS_AC_READ_WRITE)
ENUM_RANGE_CS(arm_op_type, "ARM_OP_", ARM_OP_INVALID, CS_OP_MEM_IMM)
ENUM_RANGE_CS(arm_reg, "ARM_REG_", ARM_REG_INVALID, ARM_REG_ENDING)
ENUM_RANGE_CS(arm_insn, "ARM_INS_", ARM_INS_INVALID, ARM_INS_ALIAS_END)
ENUM_RANGE_CS(arm_insn_group, "ARM_GRP_", ARM_GRP_INVALID, ARM_GRP_ENDING)
ENUM_RANGE_CS(arm_shifter, "ARM_SFT_", ARM_SFT_INVALID, ARM_SFT_ROR_REG)
ENUM_RANGE_CS(ARMCC_CondCodes, "ARMCC_", ARMCC_EQ, ARMCC_Invalid)

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

#include <magic_enum/magic_enum_switch.hpp>
