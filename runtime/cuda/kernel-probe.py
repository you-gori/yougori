"""Small CUDA Driver API test: JIT a kernel, run it, and verify GPU output.

No toolkit/compiler or Python packages required. Runs INSIDE a test container.
"""
import ctypes as c
import os

# Prove CUDA works without running the workload as root. Container PID 1 may
# still follow the OCI image's default user; this process drops all root groups.
if os.geteuid() == 0:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
assert os.geteuid() != 0

cuda = c.CDLL("libcuda.so.1")


def call(name, *args):
    result = getattr(cuda, name)(*args)
    if result:
        raise RuntimeError(f"{name} failed with CUDA error {result}")


call("cuInit", 0)
device = c.c_int()
call("cuDeviceGet", c.byref(device), 0)
name = c.create_string_buffer(256)
call("cuDeviceGetName", name, len(name), device)
context = c.c_void_p()
call("cuDevicePrimaryCtxRetain", c.byref(context), device)
try:
    call("cuCtxSetCurrent", context)
    module = c.c_void_p()
    ptx = c.create_string_buffer(b"""
.version 8.0
.target sm_75
.address_size 64
.visible .entry yougori_probe(.param .u64 output) {
    .reg .b64 %rd;
    .reg .b32 %r;
    ld.param.u64 %rd, [output];
    mov.u32 %r, %tid.x;
    mul.lo.u32 %r, %r, 7;
    add.u32 %r, %r, 5;
    .reg .b64 %offset, %addr;
    .reg .b32 %idx;
    mov.u32 %idx, %tid.x;
    mul.wide.u32 %offset, %idx, 4;
    add.u64 %addr, %rd, %offset;
    st.global.u32 [%addr], %r;
    ret;
}
""")
    call("cuModuleLoadData", c.byref(module), ptx)
    try:
        kernel = c.c_void_p()
        call("cuModuleGetFunction", c.byref(kernel), module, c.c_char_p(b"yougori_probe"))
        memory = c.c_uint64()
        call("cuMemAlloc_v2", c.byref(memory), c.c_size_t(256 * 4))
        try:
            args = (c.c_void_p * 1)(c.cast(c.byref(memory), c.c_void_p))
            call("cuLaunchKernel", kernel, 1, 1, 1, 256, 1, 1, 0, c.c_void_p(), args, c.c_void_p())
            call("cuCtxSynchronize")
            result = (c.c_uint32 * 256)()
            call("cuMemcpyDtoH_v2", result, memory, c.c_size_t(c.sizeof(result)))
            assert list(result) == [index * 7 + 5 for index in range(256)], list(result)
            print(f"CUDA KERNEL PASS: {name.value.decode()}; uid={os.geteuid()}; 256 GPU results verified")
        finally:
            call("cuMemFree_v2", memory)
    finally:
        call("cuModuleUnload", module)
finally:
    call("cuDevicePrimaryCtxRelease_v2", device)
