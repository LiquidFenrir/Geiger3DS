#pragma once

#include <typedefs.h>

#include <memory>
#include "formatters.h"
#include "capstone_inc.h"

namespace recompiler {

struct cs_insn_deleter {
    void operator()(cs_insn* ptr)
    {
        cs_free(ptr, 1);
    }
};
using cs_insn_ptr = std::unique_ptr<cs_insn, cs_insn_deleter>;

struct Handle_csh {
    csh handle;
    Handle_csh(auto&&... args)
    {
        cs_open(args..., &handle);
        // cs_option(handle, CS_OPT_ONLY_OFFSET_BRANCH, CS_OPT_ON); // only affects printing: immediate integer is still absolute
        // cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_CS_REG_ALIAS);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    }
    ~Handle_csh()
    {
        cs_close(&handle);
    }

    cs_insn_ptr alloc_insn() const
    {
        return cs_insn_ptr{cs_malloc(handle)};
    }
};

constexpr int str_access_size(arm_insn id)
{
    switch(id)
    {
    case ARM_INS_STRB:
    case ARM_INS_STRBT:
    case ARM_INS_STREXB:
        return 1;
    case ARM_INS_STRH:
    case ARM_INS_STRHT:
    case ARM_INS_STREXH:
        return 2;
    case ARM_INS_STR:
    case ARM_INS_STRT:
    case ARM_INS_STREX:
        return 4;
    case ARM_INS_STRD:
    case ARM_INS_STREXD:
        return 8;
    default:
        throw std::runtime_error(fmt::format("invalid str insn {}", id));
    }
}
constexpr int ldr_access_size(arm_insn id)
{
    switch(id)
    {
    case ARM_INS_LDRB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSBT:
    case ARM_INS_LDREXB:
        return 1;
    case ARM_INS_LDRH:
    case ARM_INS_LDRHT:
    case ARM_INS_LDRSH:
    case ARM_INS_LDRSHT:
    case ARM_INS_LDREXH:
        return 2;
    case ARM_INS_LDR:
    case ARM_INS_LDRT:
    case ARM_INS_LDREX:
        return 4;
    case ARM_INS_LDRD:
    case ARM_INS_LDREXD:
        return 8;
    default:
        throw std::runtime_error(fmt::format("invalid ldr insn {}", id));
    }
}

bool op_is_a(const cs_arm_op& op, arm_op_type type)
{
    return op.type == type;
}
bool op_is(const cs_arm_op& op, arm_reg reg)
{
    return op.type == ARM_OP_REG && op.reg == reg;
}
bool op_is(const cs_arm_op& op, int64_t imm)
{
    return op.type == ARM_OP_IMM && op.imm == imm;
}

}
