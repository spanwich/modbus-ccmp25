# RIFSC & DWMAC Investigation — STM32MP25x / Digi CCMP25-DVK

**Date**: 2026-03-02
**Purpose**: Determine if seL4 CAmkES at EL2 (non-secure) can directly access the Synopsys DWMAC 5.10a Gigabit Ethernet controller at 0x482C0000 on the Digi ConnectCore MP25 Development Kit.

---

## RIFSC Status

| Field | ETH1 | ETH2 |
|-------|------|------|
| **RIFSC-protected?** | YES (RIFSC-controlled, but configured as **open**) | YES (same) |
| **Peripheral ID** | 60 | 61 |
| **Security attribute** | NSEC (non-secure) | NSEC |
| **Privilege attribute** | NPRIV (non-privileged) | NPRIV |
| **CID filtering** | Disabled (CFDIS) | Disabled |
| **Semaphore** | Disabled (SEM_DIS) | Disabled |
| **Lock** | Unlocked (RIF_UNLOCK) | Unlocked |
| **RISAF coverage** | None | None |

**Evidence source**: OP-TEE device tree (definitive runtime configuration)
- `optee_os/core/arch/arm/dts/ccmp25-dvk-rif.dtsi`, lines 74-75

### RIFSC Configuration Chain

| Boot Stage | Action on ETH1/ETH2 |
|-----------|---------------------|
| **Hardware reset** | SECCFGR=0, PRIVCFGR=0, CIDCFGR=0 (fully open) |
| **TF-A (BL2/BL31)** | No action — ETH not in `rifsc_periph[]` table |
| **OP-TEE (BL32)** | Programs RIFSC: `RIF_NSEC, RIF_NPRIV, RIF_UNLOCK, RIF_CFDIS` — confirms open state |
| **U-Boot** | No action — networking disabled (`# CONFIG_NET is not set`) |
| **Linux** | Checks RIFSC via `access-controllers = <&rifsc 60>` — access granted |

### RIMU (Bus Master DMA) Configuration

ETH1 DMA is RIMU index 6, ETH2 DMA is RIMU index 7. Both configured as:
- `RIF_NSEC, RIF_PRIV, RIF_CIDSEL_P` (inherit CID from RISUP peripheral config)
- Since CID filtering is disabled on the peripherals, DMA transactions are unrestricted
- **RIMU is globally locked** after OP-TEE boot — cannot be reprogrammed

### Contrast with Secure Peripherals

For comparison, IWDG1 is configured as `RIF_LOCK, RIF_SEC, RIF_PRIV, RIF_CID1, RIF_CFEN` — locked, secure, privileged, CID1-only. This is why IWDG requires SMC. ETH is the opposite — maximally permissive.

---

## Access Decision

**Can seL4 at EL2 (non-secure) directly read/write 0x482C0000?**  **YES**

- No SMC required for GMAC access (unlike IWDG)
- No OP-TEE involvement needed for MMIO (only for clock management via SCMI)
- seL4 just needs to map the MMIO region in its device untyped

**Recommended approach**: Direct MMIO access from a native CAmkES component. Map `0x482C0000-0x482C3FFF` (16 KiB) as device untyped memory in the CAmkES assembly.

---

## DWMAC Hardware Details

| Property | ETH1 | ETH2 |
|----------|------|------|
| **IP version** | DWMAC 5.10a (`snps,dwmac-5.10a`) | Same |
| **MMIO base** | `0x482C0000` | `0x482D0000` |
| **MMIO size** | 16 KiB (`0x4000`) | 16 KiB |
| **GIC SPI IRQ** | 130 (macirq) | 133 (macirq) |
| **Wake IRQ** | EXTI1 68 | EXTI1 70 |
| **TX queues** | 4 | 4 |
| **RX queues** | 2 | 2 |
| **DMA width** | 32-bit (likely, read HW_FEATURE1 to confirm) | Same |
| **TSO** | Supported (`snps,tso`) | Supported |
| **HW checksum** | Read from HW_FEATURE0 at runtime | Same |
| **Descriptor type** | Basic 16-byte (`struct dma_desc`) or extended 32-byte | Same |
| **AXI burst** | Mixed burst, PBL=2, max burst 16/8/4 | Same |
| **AXI QoS** | TX=7, RX=7 (highest priority) | Same |
| **PHY mode** | RGMII-ID, 1000 Mbps | RGMII-ID, 1000 Mbps |
| **PHY** | Marvell 88E1512 (`0141.0dd0`) at MDIO addr 0 | Marvell 88E1512 at MDIO addr 1 |
| **PHY reset GPIO** | GPIOB pin 2 (active low) | GPIOG pin 6 (active low) |
| **SYSCFG ETHCR** | SYSCFG + `0x3000` | SYSCFG + `0x3400` |

### Key Registers for Runtime Verification

| Register | Offset | Purpose |
|----------|--------|---------|
| MAC_Version | `0x0110` (or `0x0020` in older docs) | IP version + SNPS version |
| MAC_HW_Feature0 | `0x011C` | Checksum offload, VLAN, timestamps |
| MAC_HW_Feature1 | `0x0120` | DMA width, hash table, L3/L4 filters, FIFO sizes |
| MAC_HW_Feature2 | `0x0124` | TX/RX queue count, channel count |
| MAC_HW_Feature3 | `0x0128` | FPE, TBS, safety features |
| DMA_Mode | `0x1000` | DMA config (base of DMA CSRs) |

### DMA Memory Requirements

| Resource | Size | Notes |
|----------|------|-------|
| TX descriptor ring (per queue) | 8 KiB (512 x 16B) | Must be DMA-coherent DRAM |
| RX descriptor ring (per queue) | 8 KiB (512 x 16B) | Must be DMA-coherent DRAM |
| Total descriptors (4 TX + 2 RX) | ~48 KiB | Contiguous, 32-bit addressable |
| RX packet buffers | ~2 MiB (512 x 2048B x 2 queues) | Can be scattered |
| TX packet buffers | Application-dependent | Mapped from send buffers |

All descriptor and buffer memory must reside in DRAM (no SRAM option). The STM32MP25x has RAM starting at `0x80000000` — well within 32-bit DMA range.

---

## Clock Dependencies

### Clocks Required Before DWMAC Access

| Clock Name | DTS ID | RCC Register | Bit | Parent |
|-----------|--------|-------------|-----|--------|
| `stmmaceth` (MAC) | `CK_ETH1_MAC` (329) | `RCC_ETH1CFGR` (0x7F0) | 1 | ICN_LS_MCU |
| `mac-clk-tx` | `CK_ETH1_TX` (328) | `RCC_ETH1CFGR` | 8 | ICN_LS_MCU |
| `mac-clk-rx` | `CK_ETH1_RX` (327) | `RCC_ETH1CFGR` | 10 | ICN_LS_MCU |
| `ptp_ref` | `CK_KER_ETH1PTP` (318) | (via FLEXGEN_56) | — | PLL divider |
| `ethstp` | `CK_ETH1_STP` (333) | `RCC_ETH1CFGR` | 4 | ICN_LS_MCU |
| `eth-ck` | `CK_KER_ETH1` (316) | `RCC_ETH1CFGR` | 5 | FLEXGEN_54 |

ETH2 uses identical layout in `RCC_ETH2CFGR` at offset `0x7F4`.

### Reset Control

Reset is at bit 0 of `RCC_ETH1CFGR` / `RCC_ETH2CFGR`. Linux does **not** use the reset controller for DWMAC (the DTS has no `resets` property). The driver calls `devm_reset_control_get_optional()` which returns NULL.

### Clock Management Under seL4

| Option | Approach | Complexity | Risk |
|--------|----------|-----------|------|
| **A: SCMI via OP-TEE** | Implement SCMI client, request clock enable through SMC | High | Low — proper integration |
| **B: Direct RCC** | Write `RCC_ETH1CFGR` bits directly | Low | Medium — must verify RCC is not RIFSC-protected |
| **C: Chainload** | Boot from U-Boot with clocks already enabled | Lowest | High — fragile, OP-TEE may gate clocks |

**Recommended**: Start with **Option C** for initial bringup (U-Boot already leaves most clocks on), then implement **Option B** as a fallback. Only pursue Option A if RCC access is RIFSC-restricted.

### Are Clocks Enabled After U-Boot Boot?

**UNKNOWN** — U-Boot has `CONFIG_NET` disabled in this build, so it does not enable ETH clocks. However:
- OP-TEE initializes RCC and may enable some clocks
- The ETH clocks will be OFF after standard boot unless Linux enables them
- **Action required**: Check RCC_ETH1CFGR at runtime via devmem2 before seL4 bringup

---

## Risks and Blockers

### No Blockers for MMIO Access

The RIFSC investigation confirms **no firewall barrier** between seL4 (EL2, non-secure) and the DWMAC. This was the primary concern and it is resolved.

### Remaining Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Clock enablement** | Medium | Verify RCC_ETH1CFGR at runtime; implement direct RCC writes or SCMI client |
| **RCC RIFSC protection** | Low | Check if RCC peripheral is RIFSC-protected (may require SMC for clock control) |
| **SYSCFG access** | Low | SYSCFG at 0x3000/0x3400 needed for PHY mode select; verify RIFSC status |
| **PHY reset GPIO** | Low | GPIOB/GPIOG must be accessible; GPIO controllers may be RIFSC-controlled |
| **Pin muxing** | Low | RGMII pins must be configured; U-Boot/OP-TEE likely leaves them set |
| **DMA coherency** | Medium | seL4 untyped allocator must provide DMA-coherent memory; cache management needed |
| **Marvell 88E1512 PHY driver** | Medium | Need MDIO/MII implementation; PHY init sequence (register 0x0141:0x0DD0) |
| **Interrupt routing** | Low | GIC SPI 130/133 must be routed to the CAmkES component; standard seL4 IRQ binding |

### Not a Risk

| Item | Reason |
|------|--------|
| RIFSC firewall | Confirmed NSEC/NPRIV/unlocked/no-CID for ETH1 and ETH2 |
| RISAF | No RISAF regions cover 0x482C0000 |
| OP-TEE claiming GMAC | OP-TEE has no ETH DTS nodes; only provides SCMI clock service |
| SMC requirement | GMAC does not need SMC (unlike IWDG) |
| DMA master security | RIMU 6/7 configured as NSEC with inherited CID (open) |

---

## Source Files Referenced

| Source | File | Key Lines |
|--------|------|-----------|
| RIFSC IDs | `arm-trusted-firmware/include/dt-bindings/soc/stm32mp25-rif.h` | 70-71 |
| TF-A RIFSC driver | `arm-trusted-firmware/drivers/st/rif/stm32_rifsc.c` | 19-38 (ETH not listed) |
| OP-TEE RIFSC config (definitive) | `optee_os/core/arch/arm/dts/ccmp25-dvk-rif.dtsi` | 74-78, 641-642 |
| OP-TEE RIFSC driver | `optee_os/core/drivers/firewall/stm32_rifsc.c` | 168-174, 487 |
| Linux ETH1 DTS | `linux/arch/arm64/boot/dts/st/stm32mp251.dtsi` | 2285-2338 |
| Linux ETH2 DTS | `linux/arch/arm64/boot/dts/st/stm32mp253.dtsi` | 148-201 |
| Board ETH config | `linux/arch/arm64/boot/dts/digi/ccmp25-dvk.dts` | 321-370 |
| Linux RIFSC driver | `linux/drivers/bus/stm32_rifsc.c` | 677-731 |
| DWMAC platform glue | `linux/drivers/net/ethernet/stmicro/stmmac/dwmac-stm32.c` | 487-579 |
| RCC clock gates | `linux/drivers/clk/stm32/stm32mp25_rcc.h` | 422-423 |
| Clock definitions | `linux/drivers/clk/stm32/clk-stm32mp25.c` | 492-501 |
| U-Boot defconfig | `u-boot/configs/stm32mp25_defconfig` | 34 (`# CONFIG_NET is not set`) |

Evidence excerpts saved to `docs/rifsc_dwmac_evidence/`.
