/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM hardware entropy source for FreeBSD's kernel random subsystem.
 *
 * Submits RNG descriptors to a Job Ring to generate random data from the
 * CAAM RNG4 hardware block (TRNG + DRBG state handles).  RNG state handles
 * must be instantiated by the controller driver before this module is used.
 *
 * Registered as a RANDOM_PURE_CAAM source via random_source_register().
 * Called from the random kthread — uses a dedicated JR in polling mode.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/random.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/random/randomdev.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"
#include "caam_jr.h"
#include "caam_crypto.h"
#include "caam_rng.h"

/* Generate 32 bytes (256 bits) per CAAM RNG call */
#define CAAM_RNG_OUTSIZE	32

/*
 * Static RNG state — one instance for the whole system.
 * Protected by rng_lock for synchronous read serialization.
 */
static struct {
	struct caam_jr_softc	*jr;		/* JR for descriptor submission */
	struct caam_dma_mem	desc_mem;	/* Pre-mapped descriptor buffer */
	struct caam_dma_mem	out_mem;	/* Pre-mapped RNG output buffer */
	struct mtx		lock;		/* Serializes rs_read calls */
	int			done;		/* Completion flag */
	uint32_t		status;		/* Completion status */
	int			err_count;	/* Consecutive error counter */
	bool			failed;		/* Persistent HW failure detected */
	bool			registered;	/* Source registered with random */
	sbintime_t		last_gen;	/* Timestamp of last generation */
} caam_rng;

static u_int caam_rng_read(void *buf, u_int c);

static const struct random_source caam_rng_source = {
	.rs_ident = "CAAM TRNG",
	.rs_source = RANDOM_PURE_CAAM,
	.rs_read = caam_rng_read,
};

/*
 * JR completion callback for RNG descriptor.
 *
 * Called inline from caam_jr_poll() → caam_jr_task() on the same
 * thread that submitted the descriptor.  No lock needed — the caller
 * already holds caam_rng.lock and this is single-threaded.
 */
static void
caam_rng_done(uint32_t status, void *arg)
{

	caam_rng.status = status;
	caam_rng.done = 1;
}

/*
 * Build and submit an RNG descriptor, wait for completion.
 * Returns the number of random bytes stored at out_mem.vaddr.
 *
 * Descriptor:
 *   [0] HDR:        5 words, one-shot
 *   [1] OPERATION:  Class 1 ALG, RNG, prediction resistance
 *   [2] FIFO STORE: RNGSTORE type, CAAM_RNG_OUTSIZE bytes
 *   [3] PTR high:   output DMA address (upper 32)
 *   [4] PTR low:    output DMA address (lower 32)
 *
 * Caller must hold caam_rng.lock.
 */
static int
caam_rng_generate(void)
{
	uint32_t *desc;
	bus_addr_t out_pa;
	int error;

	desc = caam_rng.desc_mem.vaddr;
	out_pa = caam_rng.out_mem.paddr;

	/* Build RNG descriptor */
	desc[0] = cpu_to_caam32(CAAM_CMD_DESC_HDR | CAAM_HDR_ONE | 5);
	desc[1] = cpu_to_caam32(CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
	    CAAM_OP_ALG_ALGSEL_RNG | CAAM_OP_ALG_PR_ON);
	desc[2] = cpu_to_caam32(CAAM_CMD_FIFO_STORE | CAAM_FIFOST_TYPE_RNGSTORE |
	    CAAM_RNG_OUTSIZE);
	desc[3] = cpu_to_caam32((uint32_t)(out_pa >> 32));
	desc[4] = cpu_to_caam32((uint32_t)out_pa);

	caam_rng.done = 0;
	caam_rng.status = 0;

	error = caam_jr_enqueue(caam_rng.jr, desc, caam_rng.desc_mem.paddr,
	    5 * sizeof(uint32_t), caam_rng_done, NULL);
	if (error != 0)
		return (0);

	/*
	 * Poll for completion inline.  The dedicated RNG JR has IRQs
	 * masked, so we drain the output ring directly.  Hardware
	 * completes in ~microseconds; 100ms timeout is generous.
	 */
	{
		int timeout;

		for (timeout = 100000; timeout > 0; timeout--) {
			caam_jr_poll(caam_rng.jr);
			if (caam_rng.done)
				break;
			DELAY(1);
		}
		if (!caam_rng.done) {
			printf("caam_rng: polling timeout\n");
			return (0);
		}
	}

	/* Check status */
	if (caam_rng.status != 0) {
		uint32_t ssrc = caam_rng.status & JRSTA_SSRC_MASK;
		if (ssrc == JRSTA_SSRC_CCB_ERROR ||
		    ssrc == JRSTA_SSRC_DECO ||
		    ssrc == JRSTA_SSRC_JR) {
			if (++caam_rng.err_count >= 100) {
				printf("caam_rng: %d consecutive errors, "
				    "disabling entropy source\n",
				    caam_rng.err_count);
				caam_rng.failed = true;
			} else if (caam_rng.err_count <= 5) {
				printf("caam_rng: RNG error 0x%08x\n",
				    caam_rng.status);
			} else if (caam_rng.err_count == 6) {
				printf("caam_rng: further errors suppressed\n");
			}
			return (0);
		}
	}

	caam_rng.err_count = 0;
	return (CAAM_RNG_OUTSIZE);
}

/*
 * random_source rs_read callback.
 *
 * Called from the random kthread to harvest entropy.  When Fortuna is
 * unseeded, the kthread calls us 256 times per iteration (~100ms).
 * Each CAAM TRNG call with prediction resistance takes ~100-150us,
 * so without throttling we'd burn ~35% of one core.
 *
 * Rate-limit to at most once per 10ms (100 Hz).  This caps CPU at
 * ~1.5% during the initial health-test phase (1024 samples, ~10s)
 * and drops to <0.2% once Fortuna is seeded (4 calls/iteration).
 */
extern int rebooting;

static u_int
caam_rng_read(void *buf, u_int c)
{
	sbintime_t now;
	int got;

	if (caam_rng.failed || rebooting)
		return (0);

	if (c > CAAM_RNG_OUTSIZE)
		c = CAAM_RNG_OUTSIZE;

	/* Throttle: skip if called within 10ms of last generation */
	now = getsbinuptime();
	if (now - caam_rng.last_gen < SBT_1MS * 10)
		return (0);

	mtx_lock(&caam_rng.lock);
	got = caam_rng_generate();
	if (got == 0) {
		mtx_unlock(&caam_rng.lock);
		return (0);
	}
	if (got > (int)c)
		got = c;
	memcpy(buf, caam_rng.out_mem.vaddr, got);
	mtx_unlock(&caam_rng.lock);

	caam_rng.last_gen = now;

	return (got);
}

/*
 * Initialize and register the CAAM RNG entropy source.
 * Called from the first JR attach.
 */
int
caam_rng_init(struct caam_jr_softc *jr)
{
	struct caam_softc *ctrl;
	device_t parent;
	int error;

	parent = device_get_parent(jr->sc_dev);
	ctrl = device_get_softc(parent);

	/* Only register once, even with multiple JRs */
	if (ctrl->sc_rng_registered)
		return (0);

	/* RNG state handles must be instantiated first */
	if (!ctrl->sc_rng_inited) {
		device_printf(jr->sc_dev,
		    "RNG: skipping entropy source - state handles not ready\n");
		return (ENXIO);
	}

	mtx_init(&caam_rng.lock, "caam_rng", NULL, MTX_DEF);

	/* Pre-allocate DMA memory for descriptor (64 bytes) */
	error = caam_dma_alloc(jr->sc_dev, &caam_rng.desc_mem, 64);
	if (error != 0) {
		device_printf(jr->sc_dev,
		    "RNG: cannot allocate descriptor DMA\n");
		goto fail;
	}

	/* Pre-allocate DMA memory for output (32 bytes) */
	error = caam_dma_alloc(jr->sc_dev, &caam_rng.out_mem,
	    CAAM_RNG_OUTSIZE);
	if (error != 0) {
		device_printf(jr->sc_dev,
		    "RNG: cannot allocate output DMA\n");
		goto fail;
	}

	caam_rng.jr = jr;
	caam_rng.registered = true;
	ctrl->sc_rng_registered = true;

	/*
	 * Dedicate this JR to RNG: mask IRQs permanently and switch
	 * to polling mode.  The output ring is drained inline by
	 * caam_jr_poll() from caam_rng_generate(), eliminating any
	 * dependency on taskqueue scheduling under heavy load.
	 */
	JR_WRITE(jr, JR_JRCFGR_LS,
	    JR_READ(jr, JR_JRCFGR_LS) | JRCFG_IMSK);
	jr->sc_polling = true;

	random_source_register(&caam_rng_source);
	device_printf(jr->sc_dev,
	    "registered CAAM TRNG entropy source (polling mode)\n");

	return (0);

fail:
	caam_dma_free(&caam_rng.out_mem);
	caam_dma_free(&caam_rng.desc_mem);
	mtx_destroy(&caam_rng.lock);
	return (error);
}

/*
 * Deregister and clean up the RNG entropy source.
 */
void
caam_rng_detach(struct caam_jr_softc *jr)
{

	if (!caam_rng.registered || caam_rng.jr != jr)
		return;

	random_source_deregister(&caam_rng_source);

	mtx_lock(&caam_rng.lock);
	caam_rng.jr = NULL;
	caam_rng.registered = false;
	mtx_unlock(&caam_rng.lock);

	caam_dma_free(&caam_rng.out_mem);
	caam_dma_free(&caam_rng.desc_mem);
	mtx_destroy(&caam_rng.lock);
}
