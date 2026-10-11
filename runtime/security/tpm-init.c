/* SPDX-License-Identifier: BSD-2-Clause
 * Create only a NEW software TPM identity. No guest or physical TPM access.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "tpm-api.h"
int main(int argc, char **argv)
{
    wchar_t path[32768] = {0};
    DWORD size = GetModuleFileNameW(NULL, path, 32768);
    if (argc != 2 || !size || size >= 32768) return 2;
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash || slash - path > 32700) return 2;
    wcscpy(slash + 1, L"yougori-tpm.dll");
    HMODULE library = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) { fprintf(stderr, "Load virtual TPM library: %lu\n", GetLastError()); return 1; }
    OdTpmVersion version = (OdTpmVersion)(void *)GetProcAddress(library, "od_tpm_version");
    OdTpmOpen open_tpm = (OdTpmOpen)(void *)GetProcAddress(library, "od_tpm_open");
    OdTpmClose close_tpm = (OdTpmClose)(void *)GetProcAddress(library, "od_tpm_close");
    if (!version || !open_tpm || !close_tpm || version() != OD_TPM_ABI || open_tpm(argv[1], 1) != 0) {
        fprintf(stderr, "Cannot create virtual TPM. Existing identities are never overwritten.\n");
        FreeLibrary(library); return 1;
    }
    close_tpm();
    FreeLibrary(library);
    return 0;
}
