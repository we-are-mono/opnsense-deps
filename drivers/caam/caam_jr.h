/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * NXP CAAM Job Ring driver — softc and ring structures.
 */

#ifndef _CAAM_JR_H
#define _CAAM_JR_H

#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>

#include "caam.h"

/* Forward declaration — full definition in caam_crypto.h */
struct caam_request;

/*
 * Ring depth — must be a power of 2, max 1024 per hardware.
 * Linux default is 512 (CONFIG_CRYPTO_DEV_FSL_CAAM_RINGSIZE = 9, 1<<9).
 */
#define CAAM_JR_DEPTH		512
#define CAAM_JR_DEPTH_MASK	(CAAM_JR_DEPTH - 1)

/*
 * Input ring entry: just a 64-bit DMA pointer to a job descriptor.
 * Size per entry: 8 bytes (64-bit pointer mode).
 */
#define CAAM_JR_INPENTRY_SZ	sizeof(uint64_t)

/*
 * Output ring entry: 64-bit DMA pointer + 32-bit status, packed.
 * Size per entry: 12 bytes (64-bit pointer mode).
 *
 * Fields are stored in CAAM byte order (BE on LS1046A).
 */
struct caam_jr_outentry {
	uint64_t	desc_addr;	/* DMA address of completed descriptor */
	uint32_t	jrstatus;	/* CAAM job status */
} __packed;

#define CAAM_JR_OUTENTRY_SZ	sizeof(struct caam_jr_outentry)

/*
 * DMA memory descriptor — tracks tag, map, virtual addr, physical addr.
 */
struct caam_dma_mem {
	bus_dma_tag_t	tag;
	bus_dmamap_t	map;
	void		*vaddr;
	bus_addr_t	paddr;
};

/*
 * Per-slot tracking for in-flight jobs.
 * Shadows each input ring entry with SW metadata.
 */
struct caam_jr_entry {
	bus_addr_t	desc_pa;	/* DMA address (for matching output) */
	uint32_t	*desc_va;	/* Virtual address of descriptor */
	bus_dmamap_t	desc_map;	/* DMA map for this descriptor */
	int		desc_size;	/* Descriptor size in bytes */
	struct cryptop	*crp;		/* Pending crypto request (NULL if none) */
	void		(*callback)(uint32_t status, void *arg);
	void		*cb_arg;
};

/*
 * Job Ring softc — one per JR device (4 on LS1046A).
 */
struct caam_jr_softc {
	device_t		sc_dev;
	int32_t			sc_cid;		/* Opencrypto driver ID (-1 if none) */

	/* JR register resource */
	struct resource		*sc_rres;
	int			sc_rrid;

	/* JR interrupt */
	struct resource		*sc_ires;
	void			*sc_ihand;	/* Interrupt handler cookie */
	int			sc_irid;

	/* Deferred completion taskqueue */
	struct task		sc_task;
	struct taskqueue	*sc_taskq;

	/* Input ring (DMA-mapped array of uint64_t) */
	struct caam_dma_mem	sc_inpring;

	/* Output ring (DMA-mapped array of caam_jr_outentry) */
	struct caam_dma_mem	sc_outring;

	/* Per-slot entry tracking (kernel-allocated, not DMA) */
	struct caam_jr_entry	*sc_entinfo;

	/* Ring indices and lock */
	struct mtx		sc_inplock;
	int			sc_head;	/* Next input slot to fill */
	int			sc_tail;	/* Next output slot to consume */
	int			sc_inpring_avail; /* Free input slots */
	int			sc_out_ridx;	/* Output ring read index */

	/* Crypto request pool (pre-allocated for opencrypto) */
	struct caam_request	*sc_requests;	/* [CAAM_JR_DEPTH] */
	struct caam_dma_mem	sc_desc_bulk;	/* Bulk descriptor DMA */
	struct caam_dma_mem	sc_bounce_bulk;	/* Bulk bounce buffer DMA */
	struct mtx		sc_pool_lock;
	int			sc_pool_head;	/* Free list head (-1 = empty) */
	bool			sc_blocked;	/* ERESTART returned, need unblock */
	bool			sc_polling;	/* Polling mode (RNG dedicated JR) */
};

/*
 * Register access macros for JR (relative to JR register resource).
 * Same CAAM byte-swap as controller registers.
 */
#define JR_READ(sc, off)	caam_to_cpu32(bus_read_4((sc)->sc_rres, (off)))
#define JR_WRITE(sc, off, v)	\
	bus_write_4((sc)->sc_rres, (off), cpu_to_caam32(v))

int	caam_jr_enqueue(struct caam_jr_softc *sc, uint32_t *desc,
	    bus_addr_t desc_pa, int desc_size,
	    void (*callback)(uint32_t status, void *arg), void *cb_arg);
void	caam_jr_poll(struct caam_jr_softc *sc);

#endif /* _CAAM_JR_H */
