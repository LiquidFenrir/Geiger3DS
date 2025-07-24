#ifndef RECOMPILER_EMBED_HEADER_H
#define RECOMPILER_EMBED_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

extern const char g_embedded_ctx_header[];
extern const unsigned long long g_embedded_ctx_header_size;
extern const char g_embedded_utils_header[];
extern const unsigned long long g_embedded_utils_header_size;
extern const char g_embedded_types_header[];
extern const unsigned long long g_embedded_types_header_size;

#ifdef __cplusplus
}
#else

#if __STDC_VERSION__ < 202311L
#error "Inclusion in a C file must be using the C23 standard."
#endif

const char g_embedded_ctx_header[] = {
#embed "arm_cpu_ctx.h" suffix(,)
'\0' // nul terminator
};
const unsigned long long g_embedded_ctx_header_size = sizeof(g_embedded_ctx_header) - 1;

const char g_embedded_utils_header[] = {
#embed "arm_cpu_utils.h" suffix(,)
'\0' // nul terminator
};
const unsigned long long g_embedded_utils_header_size = sizeof(g_embedded_utils_header) - 1;

const char g_embedded_types_header[] = {
#embed "typedefs.h" suffix(,)
'\0' // nul terminator
};
const unsigned long long g_embedded_types_header_size = sizeof(g_embedded_types_header) - 1;


#endif

#endif
