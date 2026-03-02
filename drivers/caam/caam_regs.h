/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * Hardware register definitions for NXP CAAM (SEC v4.0+) crypto engine.
 * Derived from the NXP Layerscape LS1046A Security Engine Reference Manual.
 */

#ifndef _CAAM_REGS_H
#define _CAAM_REGS_H

/*
 * CAAM Controller CCSR Registers (relative to controller base, e.g. 0x1700000)
 *
 * Register layout uses 64-bit slots where the upper 32 bits (at offset+0)
 * are often reserved, and the active 32-bit register is at offset+4.
 * 64-bit registers (ring base addresses) use both halves.
 */

/* Basic Configuration */
#define CAAM_MCFGR		0x0004	/* Master Config */
#define CAAM_SCFGR		0x000c	/* Security Config */

/* Job Ring Start */
#define CAAM_JRSTART		0x005c
#define JRSTART_JR0		0x00000001
#define JRSTART_JR1		0x00000002
#define JRSTART_JR2		0x00000004
#define JRSTART_JR3		0x00000008

/* Master Config Register bits */
#define MCFGR_SWRESET		0x80000000
#define MCFGR_WDENABLE		0x40000000
#define MCFGR_LONG_PTR		0x00010000	/* Use >32-bit desc addressing */
#define MCFGR_AWCACHE_SHIFT	8
#define MCFGR_AWCACHE_MASK	0x00000f00	/* AXI write cache attributes */
#define MCFGR_AWCACHE_CACH	0x00000200	/* Cacheable */
#define MCFGR_AWCACHE_BUFF	0x00000100	/* Bufferable */
#define MCFGR_AWCACHE_WALL	0x00000800	/* Write-allocate */
#define MCFGR_LARGE_BURST	0x00000004
#define MCFGR_BURST_64		0x00000001

/* Security Config Register bits */
#define SCFGR_RDBENABLE		0x00000400
#define SCFGR_VIRT_EN		0x00008000

/*
 * DECO Control Registers (controller-relative)
 *
 * DECORSR: selects which JR provides SDID/ICID/TZ for DECO operations.
 * DECORR: enables/confirms direct DECO access for descriptor execution.
 */
#define CAAM_DECORSR		0x0094	/* DECO Request Source */
#define CAAM_DECORR		0x009c	/* DECO Request */

#define DECORSR_JR0		0x00000001	/* Use JR0 as source */
#define DECORSR_VALID		0x80000000	/* DECORSR valid */
#define DECORR_RQD0ENABLE	0x00000001	/* Request DECO0 for direct use */
#define DECORR_DEN0		0x00010000	/* DECO0 available */

/*
 * DECO Register Offsets (relative to DECO0 base)
 *
 * DECO0 base = controller_base + DECO_BLOCK_NUMBER * page_size
 * Page size: 4K (0x1000) or 64K (0x10000), read from CTPR_MS.
 * DECO_BLOCK_NUMBER = 8, so DECO0 is at +0x8000 (4K) or +0x80000 (64K).
 */
#define DECO_BLOCK_NUMBER	8
#define PG_SIZE_4K		0x1000
#define PG_SIZE_64K		0x10000

#define DECO_JR_CTL_HI		0x0800	/* DECO Job Queue Control (upper) */
#define DECO_JR_CTL_LO		0x0804	/* DECO Job Queue Control (lower) */
#define DECO_OP_STATUS_HI	0x0810	/* DECO Operation Status (upper) */
#define DECO_DESCBUF(n)		(0x0a00 + (n) * 4) /* Descriptor buffer */
#define DECO_DESC_DBG		0x0e04	/* DECO Debug Register */

/* DECO JR Control bits */
#define DECO_JQCR_WHL		0x20000000	/* Whole descriptor (not link) */
#define DECO_JQCR_FOUR		0x10000000	/* Descriptor >= 4 words */

/* DECO Operation Status bits */
#define DECO_OP_STATUS_HI_ERR_MASK 0xf00000ff

/* DECO Debug Register bits */
#define DESC_DBG_DECO_STAT_VALID  0x80000000
#define DESC_DBG_DECO_STAT_MASK   0x00f00000
#define DESC_DBG_DECO_STAT_SHIFT  20
#define DECO_STAT_HOST_ERR	0xd

/*
 * Performance Monitor / Hardware Info Registers (base + 0x0f00 to 0x0fff)
 *
 * These are in the "perfmon" region at the end of each 4KB page
 * (controller page and each JR page).
 */

/* CHA Revision Number */
#define CAAM_CRNR_MS		0x0fa0
#define CAAM_CRNR_LS		0x0fa4

/* Compile Time Parameters */
#define CAAM_CTPR_MS		0x0fa8
#define CAAM_CTPR_LS		0x0fac

#define CTPR_MS_QI_MASK		(1U << 25)	/* QI present */
#define CTPR_MS_PS		(1U << 17)	/* Pointer size: 1=64-bit */
#define CTPR_MS_PG_SZ_MASK	0x00000010	/* Page size: 1=64K, 0=4K */
#define CTPR_MS_PG_SZ_SHIFT	4
#define CTPR_MS_DPAA2		(1U << 13)
#define CTPR_MS_VIRT_EN_INCL	0x00000001
#define CTPR_MS_VIRT_EN_POR	0x00000002

/* CAAM Status Register */
#define CAAM_CSTA		0x0fd4
#define CSTA_PLEND		(1U << 10)	/* Platform Little-Endian */
#define CSTA_ALT_PLEND		(1U << 18)
#define CSTA_MOO_MASK		0x00000300
#define CSTA_MOO_SHIFT		8
#define CSTA_MOO_SECURE		1
#define CSTA_MOO_TRUSTED	2

/* CCB Version ID (contains ERA) */
#define CAAM_CCBVID		0x0fe4
#define CCBVID_ERA_MASK		0xff000000
#define CCBVID_ERA_SHIFT	24

/* CHA Version ID */
#define CAAM_CHAVID_MS		0x0fe8
#define CAAM_CHAVID_LS		0x0fec

/* CHA Number */
#define CAAM_CHANUM_MS		0x0ff0
#define CAAM_CHANUM_LS		0x0ff4

/* CAAM Version ID */
#define CAAM_CAAMVID_MS		0x0ff8
#define CAAM_CAAMVID_LS		0x0ffc

/* SEC Version ID fields */
#define SECVID_MS_IPID_MASK	0xffff0000
#define SECVID_MS_IPID_SHIFT	16
#define SECVID_MS_MAJ_REV_MASK	0x0000ff00
#define SECVID_MS_MAJ_REV_SHIFT	8

/*
 * RNG4 Test Registers (base + 0x0600)
 */
#define CAAM_RTMCTL		0x0600	/* RNG Miscellaneous Control */
#define CAAM_RTSDCTL		0x0610	/* RNG Seed Control */
#define CAAM_RTFRQMIN		0x0618	/* RNG Frequency Count Min */
#define CAAM_RTFRQMAX		0x061c	/* RNG Frequency Count Max */
#define CAAM_RTSCMISC		0x0604	/* RNG Statistical Check Misc */
#define CAAM_RTPKRRNG		0x0608	/* RNG Poker Range */
#define CAAM_RTPKRMAX		0x060c	/* RNG Poker Max Limit */
#define CAAM_RTSCML		0x0620	/* RNG Statistical Check Monobit Limit */
#define CAAM_RTSCRL(n)		(0x0624 + (n) * 4)  /* Run Length Limit 0-5 */
#define CAAM_RDSTA		0x06c0	/* RNG DRNG Status */

#define RTMCTL_ACC		(1U << 5)	/* TRNG access mode */
#define RTMCTL_PRGM		(1U << 16)	/* 1=program mode, 0=run mode */
#define RTMCTL_SAMP_MODE_RAW	1

#define RTSDCTL_ENT_DLY_SHIFT	16
#define RTSDCTL_ENT_DLY_MASK	(0xffff << RTSDCTL_ENT_DLY_SHIFT)
#define RTSDCTL_ENT_DLY_MIN	3200
#define RTSDCTL_ENT_DLY_MAX	12800
#define RTSDCTL_SAMP_SIZE_MASK	0xffff
#define RTSDCTL_SAMP_SIZE_VAL	512

#define RTFRQMAX_DISABLE	(1U << 20)

#define RDSTA_SKVN		0x40000000	/* Secure Key Valid Notification */
#define RDSTA_PR0		(1U << 4)
#define RDSTA_PR1		(1U << 5)
#define RDSTA_IF0		0x00000001
#define RDSTA_IF1		0x00000002
#define RDSTA_MASK		(RDSTA_PR1 | RDSTA_PR0 | RDSTA_IF1 | RDSTA_IF0)

/*
 * Job Ring Registers (relative to JR base, e.g. jr@10000)
 *
 * Each Job Ring occupies a 64KB region with registers at low offsets
 * and a perfmon block at offset 0xf00.
 *
 * 64-bit registers: low 32 bits at offset+0, high 32 bits at offset+4
 * on LE platforms (non-iMX). Write to higher address triggers latch.
 */

/* Input Ring */
#define JR_IRBA			0x0000	/* Input Ring Base Address (64-bit) */
#define JR_IRSR			0x000c	/* Input Ring Size */
#define JR_IRSAR		0x0014	/* Input Ring Slots Available */
#define JR_IRJAR		0x001c	/* Input Ring Jobs Added */

/* Output Ring */
#define JR_ORBA			0x0020	/* Output Ring Base Address (64-bit) */
#define JR_ORSR			0x002c	/* Output Ring Size */
#define JR_ORJRR		0x0034	/* Output Ring Jobs Removed */
#define JR_ORSFR		0x003c	/* Output Ring Slots Full (used) */

/* Status / Configuration */
#define JR_JRSTAR		0x0044	/* JR Output Status */
#define JR_JRINTR		0x004c	/* JR Interrupt Status */
#define JR_JRCFGR_MS		0x0050	/* JR Config (high 32) */
#define JR_JRCFGR_LS		0x0054	/* JR Config (low 32) */

/* Indices */
#define JR_IRRIR		0x005c	/* Input Ring Read Index */
#define JR_ORWIR		0x0064	/* Output Ring Write Index */

/* Command / Control */
#define JR_JRCR			0x006c	/* JR Command */

/* JR Interrupt Status Register bits (JRINTR) */
#define JRINT_JR_INT		0x00000001	/* Job ring interrupt */
#define JRINT_JR_ERROR		0x00000002	/* Job ring error */
#define JRINT_ERR_HALT_MASK	0x0000000c
#define JRINT_ERR_HALT_SHIFT	2
#define JRINT_ERR_HALT_INPROGRESS 0x00000004
#define JRINT_ERR_HALT_COMPLETE	0x00000008
#define JRINT_ERR_TYPE_MASK	0x00000f00
#define JRINT_ERR_TYPE_SHIFT	8
#define JRINT_ERR_INDEX_MASK	0x3fff0000
#define JRINT_ERR_INDEX_SHIFT	16

/* JR Config Register LS bits (JRCFGR_LS) */
#define JRCFG_SOE		0x00000004	/* Stop on error */
#define JRCFG_ICEN		0x00000002	/* Interrupt coalescing enable */
#define JRCFG_IMSK		0x00000001	/* Interrupt mask */
#define JRCFG_ICDCT_SHIFT	8		/* Int coalescing descriptor count */
#define JRCFG_ICTT_SHIFT	16		/* Int coalescing timer threshold */

/* JR Command Register bits (JRCR) */
#define JRCR_RESET		0x00000001	/* Reset job ring */

/*
 * Job Ring Output Status (JRSTAR) bits
 */
#define JRSTA_SSRC_SHIFT	28
#define JRSTA_SSRC_MASK		0xf0000000
#define JRSTA_SSRC_NONE		0x00000000
#define JRSTA_SSRC_JUMP_HALT_CC	0x10000000
#define JRSTA_SSRC_CCB_ERROR	0x20000000
#define JRSTA_SSRC_JUMP_HALT_USER 0x30000000
#define JRSTA_SSRC_DECO		0x40000000
#define JRSTA_SSRC_JR		0x60000000
#define JRSTA_SSRC_QI		0x70000000

#define JR_RINGSIZE_MASK	0x000003ff

/*
 * QI (Queue Interface) Control Registers
 *
 * The QI block is at page QI_BLOCK_NUMBER within the CAAM address space.
 * Page size is 4K or 64K depending on the CAAM compile-time parameters
 * (CTPR_MS_PG_SZ).  LS1046A uses 64K pages, so QI is at 7*0x10000=0x70000.
 *
 * Register offsets below are relative to the QI block base (sc_qi_off).
 * Use sc->sc_qi_off + CAAM_QI_xxx to get the absolute offset.
 */
#define QI_BLOCK_NUMBER		7
#define CAAM_QI_CONTROL_HI	0x00	/* QI Control (upper 32-bit, swap cfg) */
#define CAAM_QI_CONTROL_LO	0x04	/* QI Control (lower 32-bit) */
#define CAAM_QI_STATUS		0x0c	/* QI Status */

#define QICTL_DQEN		0x01	/* Enable dequeue (frame pop) */
#define QICTL_STOP		0x02	/* Stop QI */
#define QICTL_SOE		0x04	/* Stop on error */

#define QISTA_PHRDERR		0x01	/* PreHeader Read Error */
#define QISTA_CFRDERR		0x02	/* Compound Frame Read Error */
#define QISTA_OFWRERR		0x04	/* Output Frame Write Error */
#define QISTA_BPDERR		0x08	/* Buffer Pool Depleted */
#define QISTA_BTSERR		0x10	/* Buffer Undersize */
#define QISTA_CFWRERR		0x20	/* Compound Frame Write Error */
#define QISTA_STOPD		0x80000000	/* QI Stopped */

/*
 * Performance Monitor Counters (controller perfmon block, 0x0f00-0x0f9f)
 *
 * 64-bit counters: high 32 bits at offset+0, low 32 bits at offset+4 (BE).
 */
#define CAAM_PC_REQ_DEQ_HI	0x0f00	/* Dequeued Requests (high) */
#define CAAM_PC_REQ_DEQ_LO	0x0f04	/* Dequeued Requests (low) */
#define CAAM_PC_OB_ENC_REQ_HI	0x0f08	/* Outbound Encrypt Requests (high) */
#define CAAM_PC_OB_ENC_REQ_LO	0x0f0c	/* Outbound Encrypt Requests (low) */

/*
 * Fault Address Registers (controller perfmon, 0x0fc0-0x0fcf)
 */
#define CAAM_FAR_HI		0x0fc0	/* Fault Address (high) */
#define CAAM_FAR_LO		0x0fc4	/* Fault Address (low) */
#define CAAM_FALR		0x0fc8	/* Fault Address LIODN */
#define CAAM_FADR		0x0fcc	/* Fault Address Detail */

#endif /* _CAAM_REGS_H */
