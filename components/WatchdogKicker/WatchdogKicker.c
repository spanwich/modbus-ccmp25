/*
 * WatchdogKicker — Pet IWDG1 via SMC to OP-TEE
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <camkes.h>
#include <sel4/sel4.h>
#include <stdint.h>

/* OP-TEE watchdog SMC */
#define SMCWD_FUNC_ID   0xbc000000
#define SMCWD_PET       3

/*
 * Yield iterations between pets. Each seL4_Yield() is a syscall roundtrip
 * (~1us on Cortex-A35). 10M iterations ≈ a few seconds — well within the
 * 32s IWDG timeout. Exact timing is unimportant; only the upper bound matters.
 */
#define PET_YIELD_COUNT  10000000

int run(void)
{
    seL4_CPtr smc_cap = camkes_get_smc_cap(SMCWD_FUNC_ID);
    if (!smc_cap) {
        while (1) { seL4_Yield(); }
    }

    seL4_ARM_SMCContext args = {0};
    seL4_ARM_SMCContext result = {0};

    /* Initial pet */
    args.x0 = SMCWD_FUNC_ID;
    args.x1 = SMCWD_PET;
    seL4_ARM_SMC_Call(smc_cap, &args, &result);

    volatile uint64_t count = 0;
    while (1) {
        seL4_Yield();
        if (++count >= PET_YIELD_COUNT) {
            args.x0 = SMCWD_FUNC_ID;
            args.x1 = SMCWD_PET;
            seL4_ARM_SMC_Call(smc_cap, &args, &result);
            count = 0;
        }
    }

    return 0;
}
