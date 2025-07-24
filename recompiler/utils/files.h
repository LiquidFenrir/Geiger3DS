#pragma once

#include <cstdio>
#include <memory>

namespace recompiler {

struct FILE_deleter {
    void operator()(std::FILE* ptr)
    {
        std::fclose(ptr);
    }
};
using FILE_ptr = std::unique_ptr<std::FILE, FILE_deleter>;

}
