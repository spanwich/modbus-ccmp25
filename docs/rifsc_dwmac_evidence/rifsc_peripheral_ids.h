/* Extracted from: arm-trusted-firmware/include/dt-bindings/soc/stm32mp25-rif.h, lines 70-77 */

#define STM32MP25_RIFSC_ETH1_ID         60
#define STM32MP25_RIFSC_ETH2_ID         61
#define STM32MP25_RIFSC_ETHSW_CFG_ID    70

/* RIFSC register offsets for ETH1 (peripheral ID 60):
 *   SECCFGR:  0x14  bit 28  (60/32=1 → reg1, 60%32=28)
 *   PRIVCFGR: 0x34  bit 28
 *   CIDCFGR:  0x100 + 0x8*60 = 0x2E0
 *   SEMCR:    0x104 + 0x8*60 = 0x2E4
 *
 * For ETH2 (peripheral ID 61):
 *   SECCFGR:  0x14  bit 29
 *   PRIVCFGR: 0x34  bit 29
 *   CIDCFGR:  0x100 + 0x8*61 = 0x2E8
 *   SEMCR:    0x104 + 0x8*61 = 0x2EC
 */
