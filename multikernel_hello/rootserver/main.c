/*
 * Minimal rootserver for STM32MP25x multikernel bring-up.
 *
 * K0 dispatches K1 and dumps a shared handoff timing trace after the critical
 * window. K1 stays out of OP-TEE watchdog SMCs and only prints ticks.
 */

#include <stdint.h>
#include <sel4/sel4.h>

#ifndef KERNEL_ID
#define KERNEL_ID 0
#endif

#ifndef ROOTSERVER_BUILD_ID
#define ROOTSERVER_BUILD_ID "ccwmp25-mk-trace-e100k-s0-01"
#endif

#define MK_TRACE_VADDR 0x41f000ull
#define MK_TRACE_MAX_RECORDS 32u
#define MK_TRACE_RECORD_WORDS 16u

#define MK_TRACE_K0_BEFORE_CPU_ON 1ull
#define MK_TRACE_K0_AFTER_CPU_ON  2ull
#define MK_TRACE_K1_ROOTSERVER    31ull

struct mk_trace_record {
    uint64_t tag;
    uint64_t slot;
    uint64_t cntvct;
    uint64_t cntfrq;
    uint64_t mpidr;
    uint64_t currentel;
    uint64_t sctlr_el2;
    uint64_t hcr_el2;
    uint64_t ttbr0_el2;
    uint64_t tcr_el2;
    uint64_t mair_el2;
    uint64_t esr_el2;
    uint64_t far_el2;
    uint64_t elr_el2;
    uint64_t sp;
    uint64_t reserved;
};

__attribute__((section(".mk_trace"), used, aligned(4096)))
volatile struct mk_trace_record mk_trace_buffer[MK_TRACE_MAX_RECORDS] = {
    [0] = { .tag = 0x4d4b54524345504full } /* "MKTRCEPO" marker-ish */
};

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

static void put_hex64(uint64_t n)
{
    put_str("0x");
    for (int i = 60; i >= 0; i -= 4) {
        uint64_t d = (n >> i) & 0xfu;
        seL4_DebugPutChar((char)(d < 10 ? '0' + d : 'a' + (d - 10)));
    }
}

static inline uint64_t read_cntvct(void)
{
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static inline uint64_t read_cntfrq(void)
{
    uint64_t v;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}

static void trace_clear(void)
{
    volatile uint64_t *p = (volatile uint64_t *)mk_trace_buffer;
    for (uint64_t i = 0; i < (sizeof(mk_trace_buffer) / sizeof(uint64_t)); i++) {
        p[i] = 0;
    }
}

static void trace_record_user(uint64_t slot)
{
    if (slot >= MK_TRACE_MAX_RECORDS) {
        return;
    }

    volatile struct mk_trace_record *r = &mk_trace_buffer[slot];
    r->tag = slot;
    r->slot = slot;
    r->cntvct = read_cntvct();
    r->cntfrq = read_cntfrq();
}

static void trace_dump(void)
{
    put_str("[K0] MK_TRACE_BEGIN vaddr=");
    put_hex64((uint64_t)(uintptr_t)mk_trace_buffer);
    put_str(" records=");
    put_dec(MK_TRACE_MAX_RECORDS);
    put_str("\n");

    for (uint64_t i = 0; i < MK_TRACE_MAX_RECORDS; i++) {
        volatile struct mk_trace_record *r = &mk_trace_buffer[i];
        if (r->tag == 0) {
            continue;
        }
        put_str("[K0] TRACE slot="); put_dec(i);
        put_str(" tag="); put_dec(r->tag);
        put_str(" cnt="); put_dec(r->cntvct);
        put_str(" frq="); put_dec(r->cntfrq);
        put_str(" mpidr="); put_hex64(r->mpidr);
        put_str(" el="); put_hex64(r->currentel);
        put_str(" sctlr="); put_hex64(r->sctlr_el2);
        put_str(" hcr="); put_hex64(r->hcr_el2);
        put_str(" ttbr0="); put_hex64(r->ttbr0_el2);
        put_str(" tcr="); put_hex64(r->tcr_el2);
        put_str(" mair="); put_hex64(r->mair_el2);
        put_str(" esr="); put_hex64(r->esr_el2);
        put_str(" far="); put_hex64(r->far_el2);
        put_str(" elr="); put_hex64(r->elr_el2);
        put_str(" sp="); put_hex64(r->sp);
        put_str("\n");
    }

    put_str("[K0] MK_TRACE_END\n");
}

static void delay(void)
{
    volatile uint64_t i;

    for (i = 0; i < 100000000ull; i++) {
        asm volatile("" ::: "memory");
    }
}

#define PSCI_CPU_ON_AARCH64   0xc4000003ull
#define CORE1_MPIDR           0x1ull
#define K1_CORE1_TRAMPOLINE   0x847260a0ull

static uint64_t dispatch_core1(void)
{
    seL4_ARM_SMCContext req = {0};
    seL4_ARM_SMCContext resp = {0};

    req.x0 = PSCI_CPU_ON_AARCH64;
    req.x1 = CORE1_MPIDR;
    req.x2 = K1_CORE1_TRAMPOLINE;
    req.x3 = 1;

    put_str("[K0] dispatch: PSCI CPU_ON core1 -> trampoline (K1)\n");
    seL4_ARM_SMC_Call(seL4_CapSMC, &req, &resp);
    return resp.x0;
}

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
    trace_clear();
    trace_record_user(MK_TRACE_K0_BEFORE_CPU_ON);
    uint64_t psci_ret = dispatch_core1();
    trace_record_user(MK_TRACE_K0_AFTER_CPU_ON);

    put_str("[K0] post-dispatch no-SMC quiet window\n");
    for (int q = 0; q < 4; q++) {
        delay();
    }
    put_str("[K0] quiet window done\n");
    put_str("[K0] (resumed) PSCI CPU_ON ret=");
    put_dec(psci_ret);
    put_str("\n");
    trace_dump();
#else
    trace_record_user(MK_TRACE_K1_ROOTSERVER);
    put_str("[K1] TRACE_LOCAL slot=31 cnt=");
    put_dec(mk_trace_buffer[MK_TRACE_K1_ROOTSERVER].cntvct);
    put_str(" frq=");
    put_dec(mk_trace_buffer[MK_TRACE_K1_ROOTSERVER].cntfrq);
    put_str("\n");
#endif

    while (1) {
#if KERNEL_ID == 0
        pet_watchdog();
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
