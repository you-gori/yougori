/* SPDX-License-Identifier: GPL-2.0-or-later
 * Windows TPM backend using a separate, private helper process. Only standard
 * TPM bytes and lifecycle requests cross anonymous pipes, never QEMU internals.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "system/tpm_backend.h"
#include "system/tpm_util.h"
#include "tpm_int.h"
#include "migration/blocker.h"
#include "tpm-api.h"

#define TYPE_TPM_YOUGORI "tpm-yougori"
OBJECT_DECLARE_SIMPLE_TYPE(TPMYougori, TPM_YOUGORI)
struct TPMYougori {
    TPMBackend parent;
    HANDLE process, job, input, output;
    char *state;
    Error *migration_blocker;
    bool opened;
};

#define OD_WIRE_MAGIC 0x5954504du

static int od_write(TPMYougori *s, const void *buffer, uint32_t size)
{
    const uint8_t *bytes = buffer;
    while (size) {
        DWORD count = 0;
        if (!WriteFile(s->input, bytes, size, &count, NULL) || !count) return -1;
        bytes += count;
        size -= count;
    }
    return 0;
}

static int od_read(TPMYougori *s, void *buffer, uint32_t size)
{
    uint8_t *bytes = buffer;
    ULONGLONG deadline = GetTickCount64() + 30000;
    while (size) {
        DWORD available = 0, count = 0;
        if (!PeekNamedPipe(s->output, NULL, 0, NULL, &available, NULL)) return -1;
        if (!available) {
            if (GetTickCount64() >= deadline || WaitForSingleObject(s->process, 0) != WAIT_TIMEOUT) return -1;
            Sleep(1);
            continue;
        }
        DWORD wanted = MIN(size, available);
        if (!ReadFile(s->output, bytes, wanted, &count, NULL) || !count) return -1;
        bytes += count;
        size -= count;
    }
    return 0;
}

static int od_call(TPMYougori *s, uint32_t operation, uint32_t argument,
                   const void *input, uint32_t input_size, void *output, uint32_t *output_size)
{
    uint32_t request[4] = { OD_WIRE_MAGIC, operation, argument, input_size };
    uint32_t response[4];
    if (od_write(s, request, sizeof(request)) || od_write(s, input, input_size) ||
        od_read(s, response, sizeof(response)) || response[0] != OD_WIRE_MAGIC ||
        response[3] != OD_TPM_ABI || response[2] > (output_size ? *output_size : 0)) return -1;
    if (od_read(s, output, response[2])) return -1;
    if (output_size) *output_size = response[2];
    return (int32_t)response[1];
}

static int od_spawn(TPMYougori *s)
{
    wchar_t path[32768] = {0};
    DWORD length = GetModuleFileNameW(NULL, path, ARRAY_SIZE(path));
    wchar_t *slash = length && length < ARRAY_SIZE(path) ? wcsrchr(path, L'\\') : NULL;
    if (!slash || slash - path > 32700) return -1;
    wcscpy(slash + 1, L"yougori-tpm-worker.exe");
    wchar_t command[32768];
    if (swprintf(command, ARRAY_SIZE(command), L"\"%ls\"", path) < 0) return -1;
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, TRUE };
    HANDLE child_input = NULL, child_output = NULL, errors = INVALID_HANDLE_VALUE;
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION process = {0};
    SIZE_T attribute_size = 0;
    bool attributes_ready = false;
    int result = -1;
    if (!CreatePipe(&child_input, &s->input, &security, 65536) ||
        !CreatePipe(&s->output, &child_output, &security, 65536) ||
        !SetHandleInformation(s->input, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(s->output, HANDLE_FLAG_INHERIT, 0)) goto cleanup;
    errors = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         &security, OPEN_EXISTING, 0, NULL);
    if (errors == INVALID_HANDLE_VALUE) goto cleanup;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    startup.lpAttributeList = g_malloc0(attribute_size);
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size)) goto cleanup;
    attributes_ready = true;
    HANDLE handles[] = { child_input, child_output, errors };
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles, sizeof(handles), NULL, NULL)) goto cleanup;
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_input;
    startup.StartupInfo.hStdOutput = child_output;
    startup.StartupInfo.hStdError = errors;
    s->job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!s->job || !SetInformationJobObject(s->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto cleanup;
    if (!CreateProcessW(path, command, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &startup.StartupInfo, &process)) goto cleanup;
    s->process = process.hProcess;
    if (!AssignProcessToJobObject(s->job, s->process)) goto cleanup;
    if (ResumeThread(process.hThread) == (DWORD)-1) goto cleanup;
    result = 0;
cleanup:
    if (process.hThread) CloseHandle(process.hThread);
    if (result && s->process) TerminateProcess(s->process, 1);
    if (startup.lpAttributeList) {
        if (attributes_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
        g_free(startup.lpAttributeList);
    }
    if (child_input) CloseHandle(child_input);
    if (child_output) CloseHandle(child_output);
    if (errors != INVALID_HANDLE_VALUE) CloseHandle(errors);
    return result;
}

static TPMVersion od_version(TPMBackend *tb) { return TPM_VERSION_2_0; }
static size_t od_buffer_size(TPMBackend *tb) { return OD_TPM_BUFFER; }
/* Commands finish on the backend worker before reset. Cancel is optional in
 * TPM 2.0; no racy shared cancellation flag is passed to the reference core. */
static void od_cancel(TPMBackend *tb) {}
static int od_startup(TPMBackend *tb, size_t size)
{
    TPMYougori *s = TPM_YOUGORI(tb);
    return size > OD_TPM_BUFFER ? -1 : od_call(s, 2, 0, NULL, 0, NULL, NULL);
}
static void od_request(TPMBackend *tb, TPMBackendCmd *cmd, Error **errp)
{
    TPMYougori *s = TPM_YOUGORI(tb);
    uint32_t size = cmd->out_len;
    /* TIS aliases request and response buffers. The request is sent completely
     * before reading the response; never clear that input here. */
    bool selftest = tpm_util_is_selftest(cmd->in, cmd->in_len);
    if (od_call(s, 3, cmd->locty, cmd->in, cmd->in_len, cmd->out, &size) != 0) {
        tpm_util_write_fatal_error_response(cmd->out, cmd->out_len);
        error_setg(errp, "Yougori TPM command failed; state was not reset");
    } else if (selftest && tpm_cmd_get_errcode(cmd->out) == 0) {
        cmd->selftest_done = true;
    }
}
static TpmTypeOptions *od_options(TPMBackend *tb)
{
    TPMYougori *s = TPM_YOUGORI(tb);
    TpmTypeOptions *options = g_new0(TpmTypeOptions, 1);
    options->type = TPM_TYPE_YOUGORI;
    options->u.yougori.data = g_new0(TPMYougoriOptions, 1);
    options->u.yougori.data->state = g_strdup(s->state);
    return options;
}
static void od_finalize(Object *object)
{
    TPMYougori *s = TPM_YOUGORI(object);
    if (s->opened) od_call(s, 4, 0, NULL, 0, NULL, NULL);
    if (s->input) CloseHandle(s->input);
    if (s->output) CloseHandle(s->output);
    if (s->process) {
        if (WaitForSingleObject(s->process, 5000) != WAIT_OBJECT_0) TerminateProcess(s->process, 1);
        CloseHandle(s->process);
    }
    if (s->job) CloseHandle(s->job);
    migrate_del_blocker(&s->migration_blocker);
    g_free(s->state);
}

static TPMBackend *od_create(QemuOpts *opts)
{
    TPMYougori *s = TPM_YOUGORI(object_new(TYPE_TPM_YOUGORI));
    s->state = g_strdup(qemu_opt_get(opts, "state"));
    if (!s->state || !*s->state) {
        error_report("Yougori TPM requires an explicit per-VM state file");
        goto fail;
    }
    if (strlen(s->state) > 32767 || od_spawn(s)) {
        error_report("Cannot start the bundled Yougori TPM worker (%lu)", GetLastError());
        goto fail;
    }
    if (od_call(s, 1, qemu_opt_get_bool(opts, "create", false), s->state, strlen(s->state), NULL, NULL) != 0) {
        error_report("Cannot open TPM state (missing, locked, corrupt, or not writable). Existing identity was preserved.");
        goto fail;
    }
    s->opened = true;
    /* Volatile TPM session state is not serialized. Do not offer misleading
     * RAM snapshots/migration; cold backups include the NV and UEFI state. */
    error_setg(&s->migration_blocker, "Yougori TPM requires a stopped-VM backup; live memory snapshots are not supported");
    if (migrate_add_blocker(&s->migration_blocker, &error_fatal) != 0) goto fail;
    return TPM_BACKEND(s);
fail:
    object_unref(OBJECT(s));
    return NULL;
}

static const QemuOptDesc od_opts[] = {
    TPM_STANDARD_CMDLINE_OPTS,
    { .name = "state", .type = QEMU_OPT_STRING, .help = "Private persistent TPM state file" },
    { .name = "create", .type = QEMU_OPT_BOOL, .help = "Create a NEW identity; fails if the file exists" },
    { }
};
static void od_class_init(ObjectClass *klass, const void *data)
{
    TPMBackendClass *k = TPM_BACKEND_CLASS(klass);
    k->type = TPM_TYPE_YOUGORI;
    k->opts = od_opts;
    k->desc = "Yougori private TPM 2.0 (Microsoft reference core)";
    k->create = od_create;
    k->startup_tpm = od_startup;
    k->cancel_cmd = od_cancel;
    k->get_tpm_version = od_version;
    k->get_buffer_size = od_buffer_size;
    k->get_tpm_options = od_options;
    k->handle_request = od_request;
}
static const TypeInfo od_info = {
    .name = TYPE_TPM_YOUGORI,
    .parent = TYPE_TPM_BACKEND,
    .instance_size = sizeof(TPMYougori),
    .instance_finalize = od_finalize,
    .class_init = od_class_init,
};
static void od_register(void) { type_register_static(&od_info); }
type_init(od_register)
