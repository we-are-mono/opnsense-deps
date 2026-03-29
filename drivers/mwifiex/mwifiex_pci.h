/*-
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright 2008-2025 NXP
 *
 * NXP 88W9098 PCIe WiFi driver — register definitions and softc.
 */

#ifndef _MWIFIEX_PCI_H_
#define _MWIFIEX_PCI_H_

/* PCI vendor/device IDs */
#define MWIFIEX_VENDOR_ID		0x1b4b
#define MWIFIEX_9098_FN0		0x2b43	/* WiFi */
#define MWIFIEX_9098_FN1		0x2b44	/* Bluetooth */

/* Chip revision IDs (from REV_ID_REG & 0xff) */
#define MWIFIEX_REV_Z1Z2		0x00
#define MWIFIEX_REV_A0			0x01
#define MWIFIEX_REV_A1			0x02
#define MWIFIEX_REV_A2			0x03

/* Control/status registers (BAR 0) */
#define PCIE9098_DEV_ID_REG		0x0000
#define PCIE9098_REV_ID_REG		0x0008
#define PCIE9098_IP_REV_REG		0x1000

/* CPU interrupt registers */
#define PCIE9098_CPU_INT_EVENT		0x1C20
#define PCIE9098_CPU_INT_STATUS		0x1C24

/* Host interrupt registers */
#define PCIE9098_HOST_INT_STATUS	0x1C44
#define PCIE9098_HOST_INT_MASK		0x1C48
#define PCIE9098_HOST_INT_CLR_SEL	0x1C4C
#define PCIE9098_HOST_INT_STATUS_MASK	0x1C50
#define PCIE9098_HOST_INT_SEL		0x1C58

/* Scratch registers */
#define PCIE9098_SCRATCH_0_REG		0x1C60
#define PCIE9098_SCRATCH_2_REG		0x1C68
#define PCIE9098_SCRATCH_6_REG		0x1C78
#define PCIE9098_SCRATCH_7_REG		0x1C7C
#define PCIE9098_HOST_STRAP_REG		0x1C70
#define PCIE9098_MAGIC_REG		0x1C74
#define PCIE9098_DRV_READY		0x1C90
#define PCIE9098_FW_RESET_REG		0x1C94
#define PCIE9098_FW_STUCK_CODE_REG	0x1C98

/* Magic value in MAGIC_REG indicating valid chip info */
#define CHIP_MAGIC_VALUE		0x24

/* Host strap values (secondary interface type) */
#define CARD_TYPE_PCIE_PCIE		2
#define CARD_TYPE_PCIE_UART		3
#define CARD_TYPE_PCIE_USB		7

/* FW reset value */
#define PCIE9098_FW_RESET_VAL		0x98

/* Host interrupt bits */
#define HOST_INTR_DNLD_DONE		(1 << 0)	/* TX data done */
#define HOST_INTR_CMD_DNLD		(1 << 7)	/* CMD download done */
#define HOST_INTR_UPLD_RDY		(1 << 16)	/* RX data ready */
#define HOST_INTR_EVENT_RDY		(1 << 17)	/* Event ready */
#define HOST_INTR_CMD_DONE		(1 << 25)	/* CMD response done */

#define HOST_INTR_MASK	\
	(HOST_INTR_DNLD_DONE | HOST_INTR_UPLD_RDY | \
	 HOST_INTR_CMD_DONE | HOST_INTR_CMD_DNLD | \
	 HOST_INTR_EVENT_RDY)

/* ADMA channel base addresses */
#define ADMA_CHAN0_Q0			0x10000	/* TX data */
#define ADMA_CHAN1_Q0			0x10800	/* RX data */
#define ADMA_CHAN1_Q1			0x10880	/* RX event */
#define ADMA_CHAN2_Q0			0x11000	/* TX command */
#define ADMA_CHAN2_Q1			0x11080	/* CMD response */

/* Forward declaration */
struct mwifiex_handle;

/* Driver softc */
struct mwifiex_softc {
	device_t		sc_dev;

	/* PCI resources */
	struct resource		*sc_bar0;	/* BAR 0 memory */
	int			sc_bar0_rid;
	bus_space_tag_t		sc_bar0_bt;
	bus_space_handle_t	sc_bar0_bh;

	struct resource		*sc_bar2;	/* BAR 2 memory */
	int			sc_bar2_rid;
	bus_space_tag_t		sc_bar2_bt;
	bus_space_handle_t	sc_bar2_bh;

	struct resource		*sc_irq;	/* MSI interrupt */
	int			sc_irq_rid;
	void			*sc_irq_cookie;

	/* Chip info */
	uint16_t		sc_device_id;
	uint8_t			sc_revision;
	uint8_t			sc_strap;
	uint8_t			sc_magic;
	int			sc_is_fn0;	/* WiFi (1) vs BT (0) */

	/* MOAL handle (FN0 only) */
	struct mwifiex_handle	*sc_handle;
};

/* Register access macros — control/status registers are on BAR 2 */
#define MWIFIEX_READ_4(sc, off) \
	bus_space_read_4((sc)->sc_bar2_bt, (sc)->sc_bar2_bh, (off))
#define MWIFIEX_WRITE_4(sc, off, val) \
	bus_space_write_4((sc)->sc_bar2_bt, (sc)->sc_bar2_bh, (off), (val))

#endif /* _MWIFIEX_PCI_H_ */
