// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2026 Yougori
// Yougori's Windows EGL bridge. All non-intercepted exports forward unchanged
// to the bundled ANGLE library. No registry settings or host driver changes.
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_2.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef void *Display;
typedef unsigned int Boolean;
static HMODULE angle;
static INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK load_angle(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    WCHAR path[32768]; HMODULE module = NULL;
    (void)once; (void)parameter; (void)context;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&load_angle, &module)) return FALSE;
    DWORD length = GetModuleFileNameW(module, path, 32768);
    if (!length || length >= 32768) return FALSE;
    WCHAR *slash = wcsrchr(path, L'\\');
    if (!slash || (slash - path) + 19 >= 32768) return FALSE;
    wcscpy_s(slash + 1, 32768 - (slash + 1 - path), L"libEGL_angle.dll");
    angle = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    return angle != NULL;
}

static FARPROC real_proc(const char *name) {
    if (!InitOnceExecuteOnce(&initialized, load_angle, NULL, NULL)) return NULL;
    return GetProcAddress(angle, name);
}

// -1 is malformed (fail closed), 0 Automatic, 1 an exact adapter LUID.
static int selection(LUID *luid) {
    char value[32], extra; unsigned high, low;
    DWORD n = GetEnvironmentVariableA("YOUGORI_GPU_LUID", value, sizeof(value));
    if (!n) return 0;
    if (n >= sizeof(value) || sscanf_s(value, "%8x:%8x%c", &high, &low, &extra, 1) != 2 || (!high && !low)) return -1;
    luid->HighPart = (LONG)high; luid->LowPart = low;
    return 1;
}

static void json_name(FILE *file, const WCHAR *name) {
    fputc('"', file);
    for (; *name; ++name) fprintf(file, "\\u%04x", (unsigned)*name);
    fputc('"', file);
}

static void descriptor(FILE *file, const DXGI_ADAPTER_DESC *desc) {
    fprintf(file, "\"luid\":\"%08x:%08x\",\"vendorId\":%u,\"deviceId\":%u,\"subSysId\":%u,\"revision\":%u,\"memoryBytes\":%llu,\"name\":",
        (unsigned)desc->AdapterLuid.HighPart, desc->AdapterLuid.LowPart, desc->VendorId, desc->DeviceId,
        desc->SubSysId, desc->Revision, (unsigned long long)desc->DedicatedVideoMemory);
    json_name(file, desc->Description);
}

static void report(const DXGI_ADAPTER_DESC *desc, const char *error) {
    WCHAR path[32768];
    DWORD length = GetEnvironmentVariableW(L"YOUGORI_GPU_REPORT", path, 32768);
    if (!length || length >= 32768) return;
    FILE *file = NULL;
    if (_wfopen_s(&file, path, L"wb") || !file) return;
    fprintf(file, "{\"pid\":%lu,\"ok\":%s", GetCurrentProcessId(), error ? "false" : "true");
    if (error) fprintf(file, ",\"error\":\"%s\"", error);
    if (desc) { fputc(',', file); descriptor(file, desc); }
    fputc('}', file); fclose(file);
}

static Display selected_display(void) {
    LUID luid; int selected = selection(&luid);
    if (selected != 1) { report(NULL, "Invalid GPU selection"); return NULL; }
    typedef Display (WINAPI *GetPlatform)(unsigned, void *, const int *);
    GetPlatform get = (GetPlatform)real_proc("eglGetPlatformDisplayEXT");
    if (!get) { report(NULL, "ANGLE cannot select an adapter"); return NULL; }
    // EGL_ANGLE_platform_angle_d3d_luid. ANGLE itself may fall back for a stale
    // LUID; eglInitialize below independently verifies the actual D3D adapter.
    int attributes[] = { 0x3203, 0x3208, 0x3209, 0x320A,
        0x34A0, luid.HighPart, 0x34A1, (int)luid.LowPart, 0x3038 };
    return get(0x3202, NULL, attributes);
}

Display WINAPI eglGetDisplay(void *native) {
    LUID luid;
    if (selection(&luid)) return selected_display();
    typedef Display (WINAPI *Fn)(void *);
    Fn fn = (Fn)real_proc("eglGetDisplay");
    return fn ? fn(native) : NULL;
}

Display WINAPI eglGetPlatformDisplayEXT(unsigned platform, void *native, const int *attributes) {
    LUID luid;
    if (selection(&luid)) return selected_display();
    typedef Display (WINAPI *Fn)(unsigned, void *, const int *);
    Fn fn = (Fn)real_proc("eglGetPlatformDisplayEXT");
    return fn ? fn(platform, native, attributes) : NULL;
}

Display WINAPI eglGetPlatformDisplay(unsigned platform, void *native, const intptr_t *attributes) {
    LUID luid;
    if (selection(&luid)) return selected_display();
    typedef Display (WINAPI *Fn)(unsigned, void *, const intptr_t *);
    Fn fn = (Fn)real_proc("eglGetPlatformDisplay");
    return fn ? fn(platform, native, attributes) : NULL;
}

Boolean WINAPI eglInitialize(Display display, int *major, int *minor) {
    typedef Boolean (WINAPI *Init)(Display, int *, int *);
    typedef Boolean (WINAPI *Query)(void *, int, intptr_t *);
    Init init = (Init)real_proc("eglInitialize");
    if (!init || !init(display, major, minor)) { report(NULL, "The selected GPU could not initialize graphics"); return 0; }
    Query query_display = (Query)real_proc("eglQueryDisplayAttribEXT");
    Query query_device = (Query)real_proc("eglQueryDeviceAttribEXT");
    intptr_t device = 0, d3d = 0;
    IDXGIDevice *dxgi_device = NULL; IDXGIAdapter *adapter = NULL;
    DXGI_ADAPTER_DESC desc; LUID expected;
    int selected = selection(&expected), verified = 0;
    if (query_display && query_device && query_display(display, 0x322C, &device) &&
            query_device((void *)device, 0x33A1, &d3d) && d3d &&
            SUCCEEDED(IUnknown_QueryInterface((IUnknown *)d3d, &IID_IDXGIDevice, (void **)&dxgi_device)) &&
            SUCCEEDED(IDXGIDevice_GetAdapter(dxgi_device, &adapter)) &&
            SUCCEEDED(IDXGIAdapter_GetDesc(adapter, &desc))) verified = 1;
    if (adapter) IDXGIAdapter_Release(adapter);
    if (dxgi_device) IDXGIDevice_Release(dxgi_device);
    const char *error = !verified ? "Could not verify the graphics adapter" :
        selected && (selected < 0 || desc.AdapterLuid.HighPart != expected.HighPart || desc.AdapterLuid.LowPart != expected.LowPart)
            ? "Graphics opened a different GPU; the requested selection was refused" : NULL;
    report(verified ? &desc : NULL, error);
    if (selected && error) {
        typedef Boolean (WINAPI *Terminate)(Display);
        Terminate terminate = (Terminate)real_proc("eglTerminate");
        if (terminate) terminate(display);
        return 0;
    }
    return 1;
}

FARPROC WINAPI eglGetProcAddress(const char *name) {
    if (!name) return NULL;
    if (!strcmp(name, "eglGetDisplay")) return (FARPROC)&eglGetDisplay;
    if (!strcmp(name, "eglInitialize")) return (FARPROC)&eglInitialize;
    if (!strcmp(name, "eglGetPlatformDisplayEXT")) return (FARPROC)&eglGetPlatformDisplayEXT;
    if (!strcmp(name, "eglGetPlatformDisplay")) return (FARPROC)&eglGetPlatformDisplay;
    if (!strcmp(name, "eglGetProcAddress")) return (FARPROC)&eglGetProcAddress;
    typedef FARPROC (WINAPI *Fn)(const char *);
    Fn fn = (Fn)real_proc("eglGetProcAddress");
    return fn ? fn(name) : NULL;
}

#ifdef YOUGORI_GPU_PROBE
int main(void) {
    IDXGIFactory1 *factory = NULL;
    if (FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory))) return 1;
    int first = 1; fputc('[', stdout);
    for (UINT i = 0; i < 64; ++i) {
        IDXGIAdapter1 *adapter = NULL; DXGI_ADAPTER_DESC1 desc1; DXGI_ADAPTER_DESC desc;
        if (IDXGIFactory1_EnumAdapters1(factory, i, &adapter) == DXGI_ERROR_NOT_FOUND) break;
        if (!adapter) break;
        if (SUCCEEDED(IDXGIAdapter1_GetDesc1(adapter, &desc1)) && !(desc1.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) &&
                SUCCEEDED(IDXGIAdapter1_GetDesc(adapter, &desc))) {
            if (!first) fputc(',', stdout); first = 0;
            fputc('{', stdout); descriptor(stdout, &desc); fputc('}', stdout);
        }
        IDXGIAdapter1_Release(adapter);
    }
    fputc(']', stdout); IDXGIFactory1_Release(factory); return 0;
}
#endif
