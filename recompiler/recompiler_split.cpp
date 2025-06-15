#include "recompiler.h"
#include <chrono>
#include <fmt/format.h>
#include <fmt/chrono.h>

struct FILE_deleter {
    void operator()(FILE* ptr)
    {
        fclose(ptr);
    }
};
using FILE_ptr = std::unique_ptr<FILE, FILE_deleter>;

static std::vector<u8_t> load_data(const std::string& path, const size_t align_to_n=0x1000u)
{
    FILE_ptr fh_ptr{fopen(path.c_str(), "rb")};
    if(!fh_ptr) return {};

    auto fh = fh_ptr.get();
    fseek(fh, 0, SEEK_END);
    const long fhsz = ftell(fh);
    if(fhsz <= 0l) return {};

    fseek(fh, 0, SEEK_SET);
    std::vector<u8_t> data(fhsz);
    if(fread(data.data(), 1, data.size(), fh) != (size_t)fhsz) return {};

    // ensure consistent behaviour whether or not the file was zero-padded to be page-aligned
    data.resize(ALIGN_TO_NUM(data.size(), align_to_n));

    return data;
}

int main(int argc, char** argv)
{
    std::string path_code, path_rodata, path_data;

    if(argc == 2)
    {
        std::string_view folder = argv[1];
        while(!folder.empty() && folder.back() == '/')
            folder.remove_suffix(1);

        path_code = fmt::format("{}/code.bin", folder);
        path_rodata = fmt::format("{}/rodata.bin", folder);
        path_data = fmt::format("{}/data.bin", folder);
    }
    else if(argc == 4)
    {
        path_code = argv[1];
        path_rodata = argv[2];
        path_data = argv[3];
    }
    else
    {
        fprintf(stderr, "Usage: %s [<section binaries folder> | <code binary> <rodata binary> <data binary>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    auto sec_code = load_data(path_code);
    auto sec_rodata = load_data(path_rodata);
    auto sec_data = load_data(path_data);
    u32_t code_addr = 0x0010'0000u;
    u32_t bss_size = 0;

    const auto before_time = std::chrono::steady_clock::now();
    recompiler::Program prog(sec_code, sec_rodata, sec_data, code_addr, bss_size);
    analysis(prog);
    const auto after_time = std::chrono::steady_clock::now();
    const auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(after_time - before_time);
    fmt::println("Time taken: {}", dur);
}
