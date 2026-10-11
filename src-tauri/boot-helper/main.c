/* Yougori installer bootstrap. Runs only inside the VM, from a tiny read-only
 * FAT disk. The normal VM disk is tried first by firmware. For Windows media,
 * invoke Microsoft's existing no-prompt loader instead of racing a keypress.
 * Other x64 UEFI installers retain their original boot loader.
 * This does not install an OS, accept a license, partition a disk, or bypass
 * Windows hardware/security checks. It never modifies the selected ISO. */
#include "uefi.h"
#include <intrin.h>
#pragma intrinsic(__outbyte)
#pragma intrinsic(__halt)

static Guid fs_guid = {0x964e5b22, 0x6459, 0x11d2, {0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static Guid image_guid = {0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static Guid path_guid = {0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};

static void trace(const char *message) {
    while (*message) __outbyte(0xe9, (unsigned char)*message++);
    __outbyte(0xe9, '\n');
}
static void trace_status(Status status) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 60; i >= 0; i -= 4) __outbyte(0xe9, hex[(status >> i) & 15]);
    __outbyte(0xe9, '\n');
}

/* Return a bounded device path prefix, excluding its terminal node. Only the
 * optical installer is eligible: never search host shares or the app disc as
 * a normal hard disk, and never recurse into this bootstrap's own volume. */
static size_t optical_path_size(const uint8_t *path) {
    static const uint8_t udf[16] = {0x42,0x4d,0xbd,0xc5,0x76,0x1a,0x96,0x49,0x89,0x56,0x73,0xcd,0xa3,0x26,0xcd,0x0a};
    size_t size = 0;
    int optical = 0;
    for (unsigned node = 0; node < 64; ++node) {
        const uint8_t *p = path + size;
        size_t length = p[2] | ((size_t)p[3] << 8);
        if (length < 4 || length > 4096 - size) return 0;
        if (p[0] == 0x7f) return p[1] == 0xff && length == 4 && optical ? size : 0;
        if (p[0] == 4 && p[1] == 2) optical = 1; /* CD-ROM device-path node */
        if (p[0] == 4 && p[1] == 3 && length == 20) {
            /* EDK2's full UDF mapping is a vendor media node, not CD-ROM. */
            unsigned equal = 1;
            for (unsigned i = 0; i < 16; ++i) if (p[4 + i] != udf[i]) equal = 0;
            if (equal) optical = 1;
        }
        size += length;
        if (size > 4092) return 0;
    }
    return 0;
}

static uint8_t *cd_mapping(BootServices *bs, const uint8_t *source, Handle *handles, size_t count) {
    size_t prefix = 0, size = optical_path_size(source);
    while (prefix < size && source[prefix] != 4) prefix += source[prefix + 2] | ((size_t)source[prefix + 3] << 8);
    for (size_t i = 0; i < count && i < 128; ++i) {
        uint8_t *candidate = 0;
        if (ERROR(bs->handle_protocol(handles[i], &path_guid, (void **)&candidate))) continue;
        if (optical_path_size(candidate) < prefix + 4 || candidate[prefix] != 4 || candidate[prefix + 1] != 2) continue;
        size_t j = 0;
        while (j < prefix && candidate[j] == source[j]) ++j;
        if (j == prefix) return candidate;
    }
    return 0;
}

static Status launch(BootServices *bs, Handle parent, Handle device, const Char *name, int windows, Handle *handles, size_t count) {
    FileSystem *fs = 0;
    File *root = 0, *file = 0;
    uint8_t *device_path = 0, *path = 0;
    if (ERROR(bs->handle_protocol(device, &fs_guid, (void **)&fs)) ||
        ERROR(bs->handle_protocol(device, &path_guid, (void **)&device_path))) return NOT_FOUND;
    size_t prefix = optical_path_size(device_path);
    if (!prefix || ERROR(fs->open_volume(fs, &root))) return NOT_FOUND;
    Status status = root->open(root, &file, name, 1, 0); /* EFI_FILE_MODE_READ */
    root->close(root);
    if (ERROR(status)) return status;
    void *buffer = 0;
    size_t buffer_size = 0;
    if (windows) {
        /* Microsoft's DVD loader expects its El Torito device identity, not
         * the full UDF mapping used to read cdboot_noprompt.efi. Load the exact
         * unmodified file bytes against the matching CD boot device path. */
        uint8_t *cd = cd_mapping(bs, device_path, handles, count);
        if (!cd) { file->close(file); return NOT_FOUND; }
        device_path = cd;
        prefix = optical_path_size(cd);
        name = L"\\EFI\\BOOT\\BOOTX64.EFI";
        buffer_size = 4 * 1024 * 1024;
        status = bs->allocate_pool(2, buffer_size, &buffer);
        if (ERROR(status)) { file->close(file); return status; }
        status = file->read(file, &buffer_size, buffer);
        if (ERROR(status) || buffer_size < 512 || buffer_size >= 4 * 1024 * 1024) {
            bs->free_pool(buffer); file->close(file); return NOT_FOUND;
        }
    }
    file->close(file);
    size_t chars = 0;
    while (name[chars] && chars < 256) ++chars;
    if (chars == 256) { if (buffer) bs->free_pool(buffer); return NOT_FOUND; }
    size_t file_node = 4 + (chars + 1) * sizeof(Char);
    if (ERROR(bs->allocate_pool(2, prefix + file_node + 4, (void **)&path))) {
        if (buffer) bs->free_pool(buffer);
        return NOT_FOUND;
    }
    for (size_t i = 0; i < prefix; ++i) path[i] = device_path[i];
    uint8_t *p = path + prefix;
    p[0] = 4; p[1] = 4; p[2] = (uint8_t)file_node; p[3] = (uint8_t)(file_node >> 8);
    for (size_t i = 0; i <= chars; ++i) {
        p[4 + i * 2] = (uint8_t)name[i]; p[5 + i * 2] = (uint8_t)(name[i] >> 8);
    }
    p += file_node;
    p[0] = 0x7f; p[1] = 0xff; p[2] = 4; p[3] = 0;
    Handle child = 0;
    status = bs->load_image(0, parent, path, buffer, buffer_size, &child);
    if (buffer) bs->free_pool(buffer);
    bs->free_pool(path);
    if (ERROR(status)) { trace("YOUGORI_BOOT_LOAD_FAILED"); return status; }
    trace(windows ? "YOUGORI_BOOT_WINDOWS_HANDOFF" : "YOUGORI_BOOT_INSTALLER_HANDOFF");
    size_t exit_size = 0;
    Char *exit_data = 0;
    status = bs->start_image(child, &exit_size, &exit_data);
    if (exit_data) bs->free_pool(exit_data);
    bs->unload_image(child);
    trace("YOUGORI_BOOT_INSTALLER_RETURNED");
    trace_status(status);
    return status;
}

Status efi_main(Handle image, SystemTable *system) {
    BootServices *bs = system->boot;
    LoadedImage *self = 0;
    Handle *handles = 0;
    size_t count = 0;
    trace("YOUGORI_BOOT_START");
    bs->set_watchdog(0, 0, 0, 0);
    /* The firmware can launch this USB helper before it has connected the
     * lower-priority CD's UDF filesystem driver. Enumerate devices first. */
    if (!ERROR(bs->locate_handle_buffer(0, 0, 0, &count, &handles))) {
        for (size_t i = 0; i < count && i < 1024; ++i) bs->connect_controller(handles[i], 0, 0, 1);
        bs->free_pool(handles);
        handles = 0;
    }
    if (ERROR(bs->handle_protocol(image, &image_guid, (void **)&self)) ||
        ERROR(bs->locate_handle_buffer(2, &fs_guid, 0, &count, &handles))) return NOT_FOUND;
    system->output->output(system->output, L"Yougori: starting your operating system installer...\r\n");
    /* Search every optical mapping for Windows' no-prompt loader first. The
     * El Torito FAT mapping often comes before the full ISO filesystem. */
    /* UDF names are case-sensitive; Windows ISO releases use lower-case paths,
     * while FAT and some remastered media expose upper-case names. */
    static const Char *names[] = {
        L"\\efi\\microsoft\\boot\\cdboot_noprompt.efi",
        L"\\EFI\\MICROSOFT\\BOOT\\CDBOOT_NOPROMPT.EFI",
        L"\\EFI\\BOOT\\BOOTX64.EFI",
        L"\\efi\\boot\\bootx64.efi"
    };
    for (unsigned pass = 0; pass < 4; ++pass) {
        for (size_t i = 0; i < count && i < 128; ++i) {
            if (handles[i] == self->device) continue;
            Status status = launch(bs, image, handles[i], names[pass], pass < 2, handles, count);
            if (!ERROR(status)) { bs->free_pool(handles); return status; }
        }
    }
    bs->free_pool(handles);
    trace("YOUGORI_BOOT_NO_INSTALLER");
    system->output->output(system->output,
        L"Yougori could not start this installer.\r\nUse a bootable x64 ISO, or select an already-installed VM disk.\r\nYour existing disk has not been erased.\r\n");
    /* Keep actionable text visible instead of dropping beginners into a shell. */
    for (;;) __halt();
}
