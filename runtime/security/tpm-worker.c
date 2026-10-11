/* SPDX-License-Identifier: BSD-2-Clause
 * Private TPM service. Only standard TPM command bytes and lifecycle requests
 * cross inherited anonymous pipes. No listening socket or host TPM is used.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "tpm-api.h"

#define WIRE_MAGIC 0x5954504du
#define MAX_PATH_BYTES 32767u

static int transfer(HANDLE handle, void *buffer, uint32_t size, int writing)
{
    uint8_t *bytes = buffer;
    while (size) {
        DWORD count = 0;
        BOOL ok = writing ? WriteFile(handle, bytes, size, &count, NULL)
                          : ReadFile(handle, bytes, size, &count, NULL);
        if (!ok || !count) return -1;
        bytes += count;
        size -= count;
    }
    return 0;
}

int main(void)
{
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(NULL, path, 32768);
    wchar_t *slash = length && length < 32768 ? wcsrchr(path, L'\\') : NULL;
    if (!slash || slash - path > 32700) return 1;
    wcscpy(slash + 1, L"yougori-tpm.dll");
    HMODULE library = LoadLibraryExW(path, NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) return 1;
    OdTpmVersion version = (OdTpmVersion)(void *)GetProcAddress(library, "od_tpm_version");
    OdTpmOpen open_tpm = (OdTpmOpen)(void *)GetProcAddress(library, "od_tpm_open");
    OdTpmReset reset = (OdTpmReset)(void *)GetProcAddress(library, "od_tpm_reset");
    OdTpmExecute execute = (OdTpmExecute)(void *)GetProcAddress(library, "od_tpm_execute");
    OdTpmClose close_tpm = (OdTpmClose)(void *)GetProcAddress(library, "od_tpm_close");
    if (!version || version() != OD_TPM_ABI || !open_tpm || !reset || !execute || !close_tpm) {
        FreeLibrary(library);
        return 1;
    }
    int opened = 0, result = 0;
    uint8_t payload[MAX_PATH_BYTES + 1], reply[OD_TPM_BUFFER];
    for (;;) {
        uint32_t header[4];
        if (transfer(input, header, sizeof(header), 0)) break;
        uint32_t operation = header[1], argument = header[2], size = header[3];
        if (header[0] != WIRE_MAGIC || size > MAX_PATH_BYTES ||
            operation < 1 || operation > 4 ||
            (operation == 3 && size > OD_TPM_BUFFER) ||
            ((operation == 2 || operation == 4) && size != 0)) {
            result = 2;
            break;
        }
        if (transfer(input, payload, size, 0)) break;
        payload[size] = 0;
        uint32_t reply_size = 0;
        int status = -1;
        if (operation == 1 && !opened && argument <= 1 && size && !memchr(payload, 0, size)) {
            status = open_tpm((const char *)payload, argument);
            opened = status == 0;
        } else if (operation == 2 && opened) {
            status = reset();
        } else if (operation == 3 && opened && argument <= 4 && size >= 10) {
            reply_size = sizeof(reply);
            status = execute((uint8_t)argument, payload, size, reply, &reply_size);
            if (status || reply_size > OD_TPM_BUFFER) reply_size = 0;
        } else if (operation == 4) {
            if (opened) close_tpm();
            opened = 0;
            status = 0;
        }
        uint32_t response[4] = { WIRE_MAGIC, (uint32_t)status, reply_size, OD_TPM_ABI };
        if (transfer(output, response, sizeof(response), 1) ||
            transfer(output, reply, reply_size, 1)) break;
        if (operation == 4) break;
    }
    if (opened) close_tpm();
    FreeLibrary(library);
    return result;
}
