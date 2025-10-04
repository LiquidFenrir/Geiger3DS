#include "arm_cpu_ctx.h"
#include <stddef.h>
#include <assert.h>

static_assert(offsetof(arm_cpu_ctx, cpsr) == 0xC8);
static_assert(offsetof(arm_cpu_ctx, indirect_brancher) == 0xD8);
static_assert(offsetof(arm_cpu_ctx, pc) == 0x3C);
static_assert(offsetof(arm_cpu_ctx, r14) == 0x38);
