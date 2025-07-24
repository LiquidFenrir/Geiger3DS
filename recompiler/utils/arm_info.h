#pragma once

extern "C" {
#include <typedefs.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>
}

#include <memory>

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

    cs_insn_ptr alloc_insn()
    {
        return cs_insn_ptr{cs_malloc(handle)};
    }
};

}
