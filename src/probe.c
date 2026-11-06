/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Probe payload — reports kernel bases via klog, exits cleanly.
 *
 * No kernel memory reads beyond what the SDK's crt already does during
 * startup, so this is safe to launch in any boot without risk of panic.
 * The payload's job is just to log text_base/data_base so the host can
 * build layout.json with the current boot's ASLR addresses. */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

int main(void) {
    pid_t    my_pid    = getpid();
    uint32_t fw        = kernel_get_fw_version();
    uint64_t text_base = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    uint64_t data_base = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
    uint64_t text_size = data_base - text_base;

    klog_printf("[PROBE] fw=%x.%02x pid=%d\n",
                (fw >> 24) & 0xff, (fw >> 16) & 0xff, (int)my_pid);
    klog_printf("[PROBE] text_base=0x%llx data_base=0x%llx text_size=0x%llx\n",
                (unsigned long long)text_base,
                (unsigned long long)data_base,
                (unsigned long long)text_size);
    klog_printf("[PROBE] done\n");

    /* Give klog time to flush before we return. */
    usleep(500000);
    return 0;
}
