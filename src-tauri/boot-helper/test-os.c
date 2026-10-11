/* Disposable EFI test payload: confirms boot ordering without an OS install. */
#include "uefi.h"
#include <intrin.h>
#pragma intrinsic(__outbyte)
#pragma intrinsic(__halt)
Status efi_main(Handle image, SystemTable *system) {
    (void)image;
    system->boot->set_watchdog(0, 0, 0, 0);
    const char *text = "YOUGORI_BOOT_TEST_OS\n";
    while (*text) __outbyte(0xe9, (unsigned char)*text++);
    for (;;) __halt();
}
