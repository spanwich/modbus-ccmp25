/*
 * WatchdogKicker — Keeps STM32MP25x IWDG from resetting the board
 *
 * U-Boot starts the IWDG with a ~32s timeout. The STM32 IWDG is
 * hardware-unstoppable: once enabled, only a system reset clears it.
 * This component periodically writes 0xAAAA to the Key Register (KR)
 * of both IWDG1 and IWDG2 to reload the countdown.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <camkes.h>
#include <stdint.h>

#define IWDG_KR_OFFSET  0x00
#define KR_RELOAD       0xAAAA

int run(void) {
    volatile uint32_t *iwdg1_kr = (volatile uint32_t *)((uintptr_t)iwdg1_regs);
    volatile uint32_t *iwdg2_kr = (volatile uint32_t *)((uintptr_t)iwdg2_regs);

    printf("WatchdogKicker: started (IWDG1@0x44010000, IWDG2@0x44020000)\n");

    while (1) {
        *iwdg1_kr = KR_RELOAD;
        *iwdg2_kr = KR_RELOAD;

        /* Busy-wait ~5s at ~1GHz. Crude but correct for Phase 1.
         * seL4 preempts this for higher-priority ICS components. */
        for (volatile int i = 0; i < 500000000; i++);
    }
}
