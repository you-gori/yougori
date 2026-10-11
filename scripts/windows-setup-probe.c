/* Test-only Windows PE observer. Never installed in user VMs or run on host. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <tbs.h>
static HANDLE output;
static void line(const char *value) {
    DWORD n;
    if (output != INVALID_HANDLE_VALUE) {
        WriteFile(output, value, lstrlenA(value), &n, 0);
        WriteFile(output, "\r\n", 2, &n, 0);
        FlushFileBuffers(output);
    }
}
static BOOL CALLBACK window(HWND hwnd, LPARAM unused) {
    char title[512];
    (void)unused;
    if (IsWindowVisible(hwnd) && GetWindowTextA(hwnd, title, sizeof(title))) {
        line("VISIBLE_WINDOW"); line(title);
    }
    return TRUE;
}
static void security(void) {
    HMODULE tbs = LoadLibraryA("tbs.dll");
    if (tbs) {
        typedef TBS_RESULT (WINAPI *DeviceInfo)(UINT32, PVOID);
#pragma warning(suppress: 4191)
        DeviceInfo info = (DeviceInfo)GetProcAddress(tbs, "Tbsi_GetDeviceInfo");
        TPM_DEVICE_INFO device = {0};
        if (info && info(sizeof(device), &device) == TBS_SUCCESS && device.tpmVersion == TPM_VERSION_20)
            line("TPM_2_0_DETECTED");
        else line("TPM_2_0_NOT_DETECTED");
        FreeLibrary(tbs);
    } else line("TPM_TBS_UNAVAILABLE");
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        TOKEN_PRIVILEGES privileges = {0};
        privileges.PrivilegeCount = 1;
        if (LookupPrivilegeValueA(0, "SeSystemEnvironmentPrivilege", &privileges.Privileges[0].Luid)) {
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), 0, 0);
        }
        CloseHandle(token);
    }
    BYTE secure = 0, setup = 1;
    if (GetFirmwareEnvironmentVariableA("SecureBoot", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &secure, 1) == 1
        && GetFirmwareEnvironmentVariableA("SetupMode", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &setup, 1) == 1
        && secure == 1 && setup == 0) line("SECURE_BOOT_ENFORCED");
    else line("SECURE_BOOT_NOT_ENFORCED");
}
void mainCRTStartup(void) {
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(0, path, MAX_PATH);
    if (!length || length >= MAX_PATH) ExitProcess(2);
    for (int i=(int)length-1; i>=0; i--) if (path[i]=='\\') {
        if (i + 10 >= MAX_PATH) ExitProcess(2);
        lstrcpyA(path+i+1, "probe.log"); break;
    }
    output = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, 0, 0);
    if (output == INVALID_HANDLE_VALUE) ExitProcess(2);
    line("YOUGORI_WINPE_PROBE_STARTED");
    security();
    for (int i=0; i<60; i++) {
        EnumWindows(window, 0);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        static PROCESSENTRY32 entry; entry.dwSize = sizeof(entry);
        if (Process32First(snapshot, &entry)) do {
            if (!lstrcmpiA(entry.szExeFile, "setup.exe") || !lstrcmpiA(entry.szExeFile, "setuphost.exe")) {
                line("SETUP_PROCESS"); line(entry.szExeFile);
            }
        } while (Process32Next(snapshot, &entry));
        CloseHandle(snapshot);
        Sleep(2000);
    }
    CloseHandle(output);
    ExitProcess(0);
}
