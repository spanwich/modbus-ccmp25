/*
 * Minimal rootserver for STM32MP25x multikernel bring-up.
 *
 * Prints "[K0]" or "[K1]" forever using seL4_DebugPutChar.
 */

#include <stdint.h>
#include <sel4/sel4.h>

#ifndef KERNEL_ID
#define KERNEL_ID 0
#endif

#ifndef ROOTSERVER_BUILD_ID
#define ROOTSERVER_BUILD_ID "ccwmp25-mk-prepared-secondary-01"
#endif

static void put_str(const char *s)
{
    while (*s) {
        seL4_DebugPutChar(*s++);
    }
}

static void put_dec(uint64_t n)
{
    char buf[24];
    int i = 0;

    if (n == 0) {
        seL4_DebugPutChar('0');
        return;
    }

    while (n != 0 && i < (int)sizeof(buf)) {
        buf[i++] = (char)('0' + (n % 10));
        n /= 10;
    }

    while (i > 0) {
        seL4_DebugPutChar(buf[--i]);
    }
}

static void delay(void)
{
    volatile uint64_t i;

    for (i = 0; i < 100000000ull; i++) {
        asm volatile("" ::: "memory");
    }
}

/*
 * Experiment (Path B): wake core 1 via PSCI CPU_ON from the FULLY-BOOTED K0
 * rootserver, instead of from the early elfloader. This replicates how Linux
 * brings up its secondary (from a running OS), to test whether the RISAB
 * firewall fault during TF-A's warm-boot of core 1 is tied to the minimal
 * elfloader bring-up state. seL4_CapSMC is the global SMC cap (badge 0 = any
 * function id) the kernel hands the root task when KernelAllowSMCCalls=on.
 *
 * The warm-boot fault (if it recurs) fires at IADDR 0x0E002570 regardless of
 * the entry, so the entry only matters for what core 1 does AFTER warm-boot.
 * We aim core 1 at K1's kernel phys entry (0x98000000) which survives in K1's
 * reserved region; if the firewall stays quiet, this path is the fix and we
 * then wire a proper K1 trampoline.
 */
#define PSCI_CPU_ON_AARCH64   0xc4000003ull
#define CORE1_MPIDR           0x1ull
/* Stage 2b: wake core 1 into the real hyp trampoline (mk_core1_trampoline in
 * the elfloader), which enables the EL2 MMU and jumps into K1's seL4 kernel.
 * Address is mk_core1_trampoline's phys addr from the elfloader build (objdump);
 * stable across rootserver rebuilds since the elfloader .text precedes the CPIO.
 * If the elfloader is rebuilt and this shifts, update it (objdump -t elfloader). */
#define K1_CORE1_TRAMPOLINE   0x847260a0ull

static uint64_t dispatch_core1(void)
{
    seL4_ARM_SMCContext req = {0};
    seL4_ARM_SMCContext resp = {0};

    req.x0 = PSCI_CPU_ON_AARCH64;
    req.x1 = CORE1_MPIDR;
    req.x2 = K1_CORE1_TRAMPOLINE;
    req.x3 = 1; /* context id = K1 slot index (trampoline uses multikernel_entries[1]) */

    put_str("[K0] dispatch: PSCI CPU_ON core1 -> trampoline (K1)\n");
    seL4_ARM_SMC_Call(seL4_CapSMC, &req, &resp);
    return resp.x0;   /* printed later, after a quiet window for K1's output */
}

/*
 * Pet IWDG1 via the OP-TEE SMC watchdog interface (same SMCCC id the
 * WatchdogKicker component uses). The hardware watchdog has a 32s timeout and
 * U-Boot stops petting once seL4 takes over, so without this the board resets
 * ~32s into seL4. Issued through the global seL4_CapSMC (badge 0 => any FID).
 */
#define SMCWD_FUNC_ID  0xbc000000ull
#define SMCWD_PET      3ull

static void pet_watchdog(void)
{
    seL4_ARM_SMCContext req = {0};
    seL4_ARM_SMCContext resp = {0};

    req.x0 = SMCWD_FUNC_ID;
    req.x1 = SMCWD_PET;
    seL4_ARM_SMC_Call(seL4_CapSMC, &req, &resp);
}

int main(void)
{
    uint64_t tick = 0;

    put_str("[K");
    put_dec(KERNEL_ID);
    put_str("] hello rootserver up\n");
    put_str("[K");
    put_dec(KERNEL_ID);
    put_str("] ROOTSERVER_BUILD: " ROOTSERVER_BUILD_ID "\n");

#if KERNEL_ID == 0
    uint64_t psci_ret = dispatch_core1();
    /* Quiet window: let core 1's trampoline diagnostic print to the shared UART
     * without K0's ticks overwriting it. Keep petting IWDG1 meanwhile. */
    for (int q = 0; q < 4; q++) {
        pet_watchdog();
        delay();
    }
    put_str("[K0] (resumed) PSCI CPU_ON ret=");
    put_dec(psci_ret);
    put_str("\n");
#endif

    while (1) {
#if KERNEL_ID == 0
        pet_watchdog();   /* K0 owns OP-TEE watchdog SMCs; K1 stays out of secure world. */
#endif
        put_str("[K");
        put_dec(KERNEL_ID);
        put_str("] tick ");
        put_dec(tick++);
        put_str("\n");
        delay();
    }

    return 0;
}
