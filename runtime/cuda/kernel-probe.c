// CUDA Driver API smoke test. No toolkit, Python, network or root required.
// Built for glibc Linux x86-64 (Ubuntu 22.04+/Debian 12+ and compatible images).
#include <dlfcn.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define API(name, signature) typedef int (*name##_fn) signature; name##_fn name = (name##_fn)dlsym(library, #name); if (!name) { fprintf(stderr, "CUDA function unavailable: %s\n", #name); return 2; }
#define CALL(name, ...) do { int result = name(__VA_ARGS__); if (result) { fprintf(stderr, "%s failed with CUDA error %d\n", #name, result); return 3; } } while (0)

int main(void) {
    if (geteuid() == 0 && (setgroups(0, NULL) || setgid(65534) || setuid(65534))) { perror("drop root"); return 2; }
    if (geteuid() == 0) return 2;
    void *library = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "CUDA driver unavailable inside this container: %s\n", dlerror()); return 2; }
    API(cuInit, (unsigned int));
    API(cuDeviceGet, (int *, int));
    API(cuDeviceGetName, (char *, int, int));
    API(cuDevicePrimaryCtxRetain, (void **, int));
    API(cuDevicePrimaryCtxRelease_v2, (int));
    API(cuCtxSetCurrent, (void *));
    API(cuModuleLoadData, (void **, const void *));
    API(cuModuleGetFunction, (void **, void *, const char *));
    API(cuModuleUnload, (void *));
    API(cuMemAlloc_v2, (uint64_t *, size_t));
    API(cuMemFree_v2, (uint64_t));
    API(cuLaunchKernel, (void *, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, void *, void **, void **));
    API(cuCtxSynchronize, (void));
    API(cuMemcpyDtoH_v2, (void *, uint64_t, size_t));
    CALL(cuInit, 0);
    int device = 0;
    CALL(cuDeviceGet, &device, 0);
    char name[256] = {0};
    CALL(cuDeviceGetName, name, sizeof(name)-1, device);
    void *context = NULL, *module = NULL, *kernel = NULL;
    CALL(cuDevicePrimaryCtxRetain, &context, device);
    CALL(cuCtxSetCurrent, context);
    const char *ptx = ".version 6.0\n.target sm_50\n.address_size 64\n"
        ".visible .entry yougori_probe(.param .u64 output) {\n"
        ".reg .b64 %rd, %offset, %addr; .reg .b32 %r, %idx;\n"
        "ld.param.u64 %rd, [output]; mov.u32 %idx, %tid.x;\n"
        "mul.lo.u32 %r, %idx, 7; add.u32 %r, %r, 5;\n"
        "mul.wide.u32 %offset, %idx, 4; add.u64 %addr, %rd, %offset;\n"
        "st.global.u32 [%addr], %r; ret; }\n";
    CALL(cuModuleLoadData, &module, ptx);
    CALL(cuModuleGetFunction, &kernel, module, "yougori_probe");
    uint64_t memory = 0;
    CALL(cuMemAlloc_v2, &memory, 256 * sizeof(uint32_t));
    void *arguments[] = {&memory};
    CALL(cuLaunchKernel, kernel, 1, 1, 1, 256, 1, 1, 0, NULL, arguments, NULL);
    CALL(cuCtxSynchronize);
    uint32_t results[256];
    CALL(cuMemcpyDtoH_v2, results, memory, sizeof(results));
    for (unsigned i=0; i<256; i++) if (results[i] != i*7+5) { fprintf(stderr,"GPU calculation returned an incorrect result\n"); return 4; }
    CALL(cuMemFree_v2, memory);
    CALL(cuModuleUnload, module);
    CALL(cuDevicePrimaryCtxRelease_v2, device);
    printf("CUDA KERNEL PASS: %s; uid=%u; 256 GPU results verified\n", name, (unsigned)geteuid());
    dlclose(library);
    return 0;
}
