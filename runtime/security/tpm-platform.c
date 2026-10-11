/* SPDX-License-Identifier: BSD-2-Clause
 * Yougori platform for Microsoft's BSD-licensed TPM 2.0 reference core.
 * Unlike the upstream testing simulator: OS CSPRNG, exclusive per-VM state,
 * bounded I/O, checked durable commits, no debug RPCs or network listeners.
 * Two checksummed slots preserve the previous commit through a torn write.
 * The digest detects corruption; the host user remains trusted, as for qcow2.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include "Platform.h"
#include "tpm-api.h"

#define HEADER_SIZE 64u
#define SLOT_SIZE (HEADER_SIZE + NV_MEMORY_SIZE)
static HANDLE state_file = INVALID_HANDLE_VALUE;
static uint64_t generation;
static int fresh, failed;

static int seek_to(uint64_t offset)
{
    LARGE_INTEGER pos;
    pos.QuadPart = offset;
    return SetFilePointerEx(state_file, pos, NULL, FILE_BEGIN) != 0;
}

static void put64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (i * 8));
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static int slot_digest(uint8_t *slot, uint8_t digest[32])
{
    SHA256_CTX context;
    return SHA256_Init(&context) && SHA256_Update(&context, slot, 32)
        && SHA256_Update(&context, slot + HEADER_SIZE, NV_MEMORY_SIZE)
        && SHA256_Final(digest, &context);
}

static uint64_t read_slot(unsigned index, uint8_t *slot)
{
    DWORD read_size = 0;
    uint8_t digest[32];
    if (!seek_to((uint64_t)index * SLOT_SIZE)
        || !ReadFile(state_file, slot, SLOT_SIZE, &read_size, NULL)
        || read_size != SLOT_SIZE || memcmp(slot, "ODTPM001", 8)
        || get64(slot + 16) != NV_MEMORY_SIZE || get64(slot + 24)
        || !slot_digest(slot, digest) || memcmp(digest, slot + 32, 32)) return 0;
    return get64(slot + 8);
}

int od_nv_open(const char *path, int create)
{
    if (state_file != INVALID_HANDLE_VALUE || !path) return -1;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 1 || count > 32767) return -1;
    wchar_t *wide = malloc((size_t)count * sizeof(wchar_t));
    if (!wide) return -1;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, count)) {
        free(wide);
        return -1;
    }
    /* Zero sharing prevents two VMs using the same TPM identity concurrently.
     * Never follow a reparse point or silently recreate a missing identity. */
    state_file = CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            create ? CREATE_NEW : OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    free(wide);
    if (state_file == INVALID_HANDLE_VALUE) return -1;
    FILE_ATTRIBUTE_TAG_INFO info;
    LARGE_INTEGER size;
    if (!GetFileInformationByHandleEx(state_file, FileAttributeTagInfo, &info, sizeof(info))
        || (info.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
        || !GetFileSizeEx(state_file, &size)) goto error;
    fresh = create;
    failed = 0;
    generation = 0;
    if (fresh) {
        memset(s_NV, 0xff, NV_MEMORY_SIZE);
        if (!seek_to(2u * SLOT_SIZE) || !SetEndOfFile(state_file)) goto error;
    } else {
        if (size.QuadPart != 2u * SLOT_SIZE) goto error;
        uint8_t *slots = malloc(2u * SLOT_SIZE);
        if (!slots) goto error;
        uint64_t a = read_slot(0, slots), b = read_slot(1, slots + SLOT_SIZE);
        if (!a && !b) { free(slots); goto error; }
        generation = a > b ? a : b;
        memcpy(s_NV, slots + (b > a ? SLOT_SIZE : 0) + HEADER_SIZE, NV_MEMORY_SIZE);
        SecureZeroMemory(slots, 2u * SLOT_SIZE);
        free(slots);
    }
    s_NvIsAvailable = TRUE;
    return 0;
error:
    CloseHandle(state_file);
    state_file = INVALID_HANDLE_VALUE;
    return -1;
}

LIB_EXPORT int32_t _plat__GetEntropy(unsigned char *entropy, uint32_t amount)
{
    if (!amount) return 0;
    if (!entropy || amount > INT32_MAX) return -1;
    return BCryptGenRandom(NULL, entropy, amount, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
        ? (int32_t)amount : -1;
}

LIB_EXPORT int _plat__NVEnable(void *parameter, size_t size)
{
    (void)parameter; (void)size;
    s_NV_unrecoverable = failed;
    s_NV_recoverable = FALSE;
    s_NvIsAvailable = state_file != INVALID_HANDLE_VALUE && !failed;
    return s_NvIsAvailable ? 0 : -1;
}

LIB_EXPORT void _plat__NVDisable(void *parameter, size_t size)
{
    (void)parameter; (void)size;
    s_NvIsAvailable = FALSE;
    /* The wrapper owns the file lifetime. Never erase or remanufacture here. */
}

LIB_EXPORT int _plat__NvCommit(void)
{
    if (state_file == INVALID_HANDLE_VALUE || failed || generation == UINT64_MAX) return 1;
    uint8_t *slot = calloc(1, SLOT_SIZE);
    if (!slot) return 1;
    uint64_t next = generation + 1;
    memcpy(slot, "ODTPM001", 8);
    put64(slot + 8, next);
    put64(slot + 16, NV_MEMORY_SIZE);
    memcpy(slot + HEADER_SIZE, s_NV, NV_MEMORY_SIZE);
    DWORD written = 0;
    int ok = slot_digest(slot, slot + 32)
        && seek_to((next & 1) * SLOT_SIZE)
        && WriteFile(state_file, slot, SLOT_SIZE, &written, NULL)
        && written == SLOT_SIZE && FlushFileBuffers(state_file);
    SecureZeroMemory(slot, SLOT_SIZE);
    free(slot);
    if (ok) generation = next;
    else { failed = 1; s_NvIsAvailable = FALSE; }
    return ok ? 0 : 1;
}

static int in_bounds(unsigned offset, unsigned size)
{
    return offset <= NV_MEMORY_SIZE && size <= NV_MEMORY_SIZE - offset;
}

LIB_EXPORT int _plat__NvMemoryRead(unsigned offset, unsigned size, void *data)
{
    if (!in_bounds(offset, size)) return FALSE;
    memcpy(data, s_NV + offset, size);
    return TRUE;
}
LIB_EXPORT int _plat__NvGetChangedStatus(unsigned offset, unsigned size, void *data)
{
    if (!in_bounds(offset, size)) return NV_INVALID_LOCATION;
    return memcmp(data, s_NV + offset, size) != 0;
}
LIB_EXPORT int _plat__NvMemoryWrite(unsigned offset, unsigned size, void *data)
{
    if (!in_bounds(offset, size)) return FALSE;
    memcpy(s_NV + offset, data, size);
    return TRUE;
}
LIB_EXPORT int _plat__NvMemoryClear(unsigned offset, unsigned size)
{
    if (!in_bounds(offset, size)) return FALSE;
    memset(s_NV + offset, 0xff, size);
    return TRUE;
}
LIB_EXPORT int _plat__NvMemoryMove(unsigned source, unsigned dest, unsigned size)
{
    if (!in_bounds(source, size) || !in_bounds(dest, size)) return FALSE;
    memmove(s_NV + dest, s_NV + source, size);
    return TRUE;
}
LIB_EXPORT int _plat__GetNvReadyState(void) { return s_NvIsAvailable && !failed ? NV_READY : NV_WRITEFAILURE; }
LIB_EXPORT int _plat__NVNeedsManufacture(void) { return fresh; }
LIB_EXPORT void _plat__SetNvAvail(void) { s_NvIsAvailable = !failed; }
LIB_EXPORT void _plat__ClearNvAvail(void) { s_NvIsAvailable = FALSE; }
LIB_EXPORT void _plat__NvErrors(int recoverable, int unrecoverable)
{
    s_NV_recoverable = recoverable;
    s_NV_unrecoverable = unrecoverable;
}
LIB_EXPORT void _plat__TearDown(void) {}

void od_nv_close(void)
{
    if (state_file != INVALID_HANDLE_VALUE) CloseHandle(state_file);
    state_file = INVALID_HANDLE_VALUE;
    s_NvIsAvailable = FALSE;
    SecureZeroMemory(s_NV, NV_MEMORY_SIZE);
}
