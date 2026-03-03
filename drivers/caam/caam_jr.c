/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * NXP CAAM Job Ring driver.
 *
 * Each Job Ring is a child device of the CAAM controller.  It manages
 * a hardware input/output ring pair for submitting crypto job descriptors
 * and receiving completions.
 *
 * Input ring:  Array of uint64_t — DMA addresses of job descriptors.
 *              Software writes, hardware reads.
 * Output ring: Array of {uint64_t desc_addr, uint32_t status} — packed.
 *              Hardware writes, software reads.
 *
 * Flow: enqueue writes descriptor PA to input ring, wmb(), notifies CAAM.
 *       CAAM completes job, writes result to output ring, fires IRQ.
 *       ISR masks IRQ, schedules taskqueue.  Taskqueue drains output ring
 *       and calls per-job callbacks.
 *
 * Matches: "fsl,sec-v4.0-job-ring"
 *
 * This is a clean-room implementation based on the NXP SEC reference manual.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rman.h>
#include <sys/taskqueue.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"
#include "caam_jr.h"
#include "caam_crypto.h"
#include "caam_rng.h"

#include "cryptodev_if.h"

static MALLOC_DEFINE(M_CAAM, "caam", "CAAM Job Ring");

static struct ofw_compat_data caam_jr_compat[] = {
	{ "fsl,sec-v4.0-job-ring",	1 },
	{ NULL,				0 }
};

/* Forward declarations */
static void	caam_jr_intr(void *arg);
static void	caam_jr_task(void *arg, int pending);
static int	caam_jr_reset(struct caam_jr_softc *sc);
static int	caam_jr_init_rings(struct caam_jr_softc *sc);
static void	caam_jr_free_rings(struct caam_jr_softc *sc);
static int	caam_jr_detach(device_t dev);

/*
 * DMA memory allocation helpers
 */
static void
caam_dma_load_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{

	if (error != 0)
		return;
	KASSERT(nseg == 1, ("%s: nsegs is %d", __func__, nseg));
	*(bus_addr_t *)arg = segs->ds_addr;
}

int
caam_dma_alloc(device_t dev, struct caam_dma_mem *mem, bus_size_t size)
{
	int error;

	error = bus_dma_tag_create(bus_get_dma_tag(dev),	/* parent */
	    PAGE_SIZE, 0,		/* alignment, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr (64-bit CAAM DMA) */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    size, 1, size,		/* maxsize, nsegments, maxsegsz */
	    BUS_DMA_COHERENT,		/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &mem->tag);
	if (error != 0) {
		device_printf(dev, "bus_dma_tag_create failed: %d\n", error);
		return (error);
	}

	error = bus_dmamem_alloc(mem->tag, &mem->vaddr,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO | BUS_DMA_COHERENT, &mem->map);
	if (error != 0) {
		device_printf(dev, "bus_dmamem_alloc failed: %d\n", error);
		bus_dma_tag_destroy(mem->tag);
		mem->tag = NULL;
		return (error);
	}

	error = bus_dmamap_load(mem->tag, mem->map, mem->vaddr, size,
	    caam_dma_load_cb, &mem->paddr, BUS_DMA_NOWAIT);
	if (error != 0) {
		device_printf(dev, "bus_dmamap_load failed: %d\n", error);
		bus_dmamem_free(mem->tag, mem->vaddr, mem->map);
		bus_dma_tag_destroy(mem->tag);
		mem->tag = NULL;
		mem->vaddr = NULL;
		return (error);
	}

	return (0);
}

void
caam_dma_free(struct caam_dma_mem *mem)
{

	if (mem->tag == NULL)
		return;
	bus_dmamap_unload(mem->tag, mem->map);
	bus_dmamem_free(mem->tag, mem->vaddr, mem->map);
	bus_dma_tag_destroy(mem->tag);
	mem->tag = NULL;
	mem->vaddr = NULL;
	mem->paddr = 0;
}

/*
 * Reset the Job Ring hardware.
 * Must be called before configuring ring bases/sizes.
 */
static int
caam_jr_reset(struct caam_jr_softc *sc)
{
	uint32_t status;
	int timeout;

	/* Mask interrupts during reset */
	JR_WRITE(sc, JR_JRCFGR_LS,
	    JR_READ(sc, JR_JRCFGR_LS) | JRCFG_IMSK);

	/* Check if halt is already in progress */
	status = JR_READ(sc, JR_JRINTR);
	if ((status & JRINT_ERR_HALT_MASK) != JRINT_ERR_HALT_INPROGRESS) {
		/* Clear halt status */
		JR_WRITE(sc, JR_JRINTR,
		    status & ~JRINT_ERR_HALT_MASK);
		/* Initiate flush (required before reset) */
		JR_WRITE(sc, JR_JRCR, JRCR_RESET);
	}

	/* Wait for flush/halt to complete */
	for (timeout = 100000; timeout > 0; timeout--) {
		status = JR_READ(sc, JR_JRINTR);
		if ((status & JRINT_ERR_HALT_MASK) == JRINT_ERR_HALT_COMPLETE)
			break;
		DELAY(1);
	}
	if (timeout == 0) {
		device_printf(sc->sc_dev, "flush timeout (jrintr=0x%08x)\n",
		    status);
		return (EIO);
	}

	/* Issue reset */
	JR_WRITE(sc, JR_JRCR, JRCR_RESET);

	/* Wait for reset to complete (JRCR bit clears) */
	for (timeout = 100000; timeout > 0; timeout--) {
		if ((JR_READ(sc, JR_JRCR) & JRCR_RESET) == 0)
			break;
		DELAY(1);
	}
	if (timeout == 0) {
		device_printf(sc->sc_dev, "reset timeout\n");
		return (EIO);
	}

	/*
	 * Leave interrupts masked.  The caller unmasks after the ISR
	 * is installed, preventing stale completion edges from reaching
	 * the GIC before the handler is ready.
	 */

	return (0);
}

/*
 * Allocate and initialize input/output rings and entry tracking.
 */
static int
caam_jr_init_rings(struct caam_jr_softc *sc)
{
	int error, i;

	/* Allocate input ring */
	error = caam_dma_alloc(sc->sc_dev, &sc->sc_inpring,
	    CAAM_JR_INPENTRY_SZ * CAAM_JR_DEPTH);
	if (error != 0)
		return (error);

	/* Allocate output ring */
	error = caam_dma_alloc(sc->sc_dev, &sc->sc_outring,
	    CAAM_JR_OUTENTRY_SZ * CAAM_JR_DEPTH);
	if (error != 0) {
		caam_dma_free(&sc->sc_inpring);
		return (error);
	}

	/* Allocate per-slot entry tracking */
	sc->sc_entinfo = malloc(sizeof(struct caam_jr_entry) * CAAM_JR_DEPTH,
	    M_CAAM, M_WAITOK | M_ZERO);

	/* Mark all entries as unused */
	for (i = 0; i < CAAM_JR_DEPTH; i++)
		sc->sc_entinfo[i].desc_pa = 0;

	/* Initialize ring indices */
	sc->sc_head = 0;
	sc->sc_tail = 0;
	sc->sc_out_ridx = 0;
	sc->sc_inpring_avail = CAAM_JR_DEPTH;

	/*
	 * Program the JR hardware with ring base addresses and sizes.
	 * 64-bit registers use CAAM byte order and word order.
	 */
	caam_write_8(sc->sc_rres, JR_IRBA, sc->sc_inpring.paddr);
	caam_write_8(sc->sc_rres, JR_ORBA, sc->sc_outring.paddr);

	JR_WRITE(sc, JR_IRSR, CAAM_JR_DEPTH);
	JR_WRITE(sc, JR_ORSR, CAAM_JR_DEPTH);

	return (0);
}

static void
caam_jr_free_rings(struct caam_jr_softc *sc)
{

	if (sc->sc_entinfo != NULL) {
		free(sc->sc_entinfo, M_CAAM);
		sc->sc_entinfo = NULL;
	}
	caam_dma_free(&sc->sc_outring);
	caam_dma_free(&sc->sc_inpring);
}

/*
 * Interrupt handler — top half.
 * Mask further interrupts, ACK, and schedule taskqueue for dequeue.
 */
static void
caam_jr_intr(void *arg)
{
	struct caam_jr_softc *sc = arg;
	uint32_t irqstate;

	irqstate = JR_READ(sc, JR_JRINTR);
	if ((irqstate & JRINT_JR_INT) == 0)
		return;

	if (irqstate & JRINT_JR_ERROR)
		device_printf(sc->sc_dev,
		    "job ring error: irqstate=0x%08x\n", irqstate);

	/* Mask interrupts */
	JR_WRITE(sc, JR_JRCFGR_LS,
	    JR_READ(sc, JR_JRCFGR_LS) | JRCFG_IMSK);

	/* ACK the interrupt */
	JR_WRITE(sc, JR_JRINTR, irqstate);

	/* Schedule deferred processing */
	taskqueue_enqueue(sc->sc_taskq, &sc->sc_task);
}

/*
 * Taskqueue handler — drain completed jobs from the output ring.
 */
static void
caam_jr_task(void *arg, int pending)
{
	struct caam_jr_softc *sc = arg;
	struct caam_jr_outentry *outring;
	struct caam_jr_entry *ent;
	uint32_t outused, jrstatus;
	uint64_t desc_pa;
	int hw_idx, sw_idx, head, tail, i;
	void (*callback)(uint32_t status, void *arg);
	void *cb_arg;

	outring = sc->sc_outring.vaddr;

	while ((outused = JR_READ(sc, JR_ORSFR)) != 0) {
		head = sc->sc_head;
		tail = sc->sc_tail;
		hw_idx = sc->sc_out_ridx;

		/* Read completed descriptor address and status (CAAM byte order) */
		desc_pa = caam_to_cpu64(outring[hw_idx].desc_addr);
		jrstatus = caam_to_cpu32(outring[hw_idx].jrstatus);

		/*
		 * Find matching entry in the software ring.
		 * Jobs can complete out of order, so scan from tail.
		 */
		sw_idx = -1;
		for (i = 0; i < CAAM_JR_DEPTH; i++) {
			int idx = (tail + i) & CAAM_JR_DEPTH_MASK;
			if (idx == head)
				break;	/* Reached head, no more in-flight */
			if (sc->sc_entinfo[idx].desc_pa == desc_pa) {
				sw_idx = idx;
				break;
			}
		}

		if (sw_idx < 0) {
			volatile uint8_t *raw =
			    (volatile uint8_t *)&outring[hw_idx];
			device_printf(sc->sc_dev,
			    "completed desc PA 0x%jx not found in ring!\n",
			    (uintmax_t)desc_pa);
			device_printf(sc->sc_dev,
			    "  hw_idx=%d head=%d tail=%d orsfr=%u "
			    "polling=%d curthread=%s\n",
			    hw_idx, head, tail, outused,
			    sc->sc_polling, curthread->td_name);
			device_printf(sc->sc_dev,
			    "  raw=[%02x %02x %02x %02x %02x %02x %02x %02x"
			    " %02x %02x %02x %02x]\n",
			    raw[0], raw[1], raw[2], raw[3],
			    raw[4], raw[5], raw[6], raw[7],
			    raw[8], raw[9], raw[10], raw[11]);
			if (head != tail)
				device_printf(sc->sc_dev,
				    "  entinfo[%d].desc_pa=0x%jx\n",
				    tail,
				    (uintmax_t)sc->sc_entinfo[tail].desc_pa);
			goto ack;
		}

		ent = &sc->sc_entinfo[sw_idx];

		/* Stash callback info */
		callback = ent->callback;
		cb_arg = ent->cb_arg;

		/* Clear entry so it won't match on reuse */
		ent->desc_pa = 0;
		ent->callback = NULL;
		ent->cb_arg = NULL;

		/*
		 * Ensure all data from the completed job is read before
		 * telling CAAM we've consumed the output ring entry.
		 */
		mb();

ack:
		/* Acknowledge one consumed output entry */
		JR_WRITE(sc, JR_ORJRR, 1);

		/* Advance output ring read index */
		sc->sc_out_ridx = (sc->sc_out_ridx + 1) & CAAM_JR_DEPTH_MASK;

		/*
		 * Advance tail past completed entries.
		 * If this job was at the tail, advance past any
		 * subsequent already-completed entries.
		 */
		if (sw_idx >= 0 && sw_idx == tail) {
			do {
				tail = (tail + 1) & CAAM_JR_DEPTH_MASK;
			} while (tail != head &&
			    sc->sc_entinfo[tail].desc_pa == 0);
			sc->sc_tail = tail;
		}

		if (sw_idx >= 0) {
			/* Update available count */
			mtx_lock(&sc->sc_inplock);
			sc->sc_inpring_avail++;
			mtx_unlock(&sc->sc_inplock);

			/* Invoke callback */
			if (callback != NULL)
				callback(jrstatus, cb_arg);
		}
	}

	/* Unmask interrupts (skip for polling-mode JR and during attach) */
	if (!sc->sc_polling && sc->sc_ihand != NULL)
		JR_WRITE(sc, JR_JRCFGR_LS,
		    JR_READ(sc, JR_JRCFGR_LS) & ~JRCFG_IMSK);
}

/*
 * Poll the output ring inline — used by the dedicated RNG JR.
 *
 * Safe ONLY when the JR is in polling mode (sc_polling=true),
 * meaning no concurrent taskqueue processing can occur (IRQs masked,
 * taskqueue idle).
 */
void
caam_jr_poll(struct caam_jr_softc *sc)
{

	if (JR_READ(sc, JR_ORSFR) != 0)
		caam_jr_task(sc, 0);
}

/*
 * Enqueue a job descriptor onto the input ring.
 *
 * The descriptor must already be DMA-mapped.  desc_pa is the physical
 * address CAAM will use to fetch the descriptor.
 *
 * Returns 0 on success, ENOSPC if the ring is full.
 */
int
caam_jr_enqueue(struct caam_jr_softc *sc, uint32_t *desc,
    bus_addr_t desc_pa, int desc_size,
    void (*callback)(uint32_t status, void *arg), void *cb_arg)
{
	struct caam_jr_entry *ent;
	volatile uint64_t *inpring;
	int head;

	mtx_lock(&sc->sc_inplock);

	if (sc->sc_inpring_avail == 0) {
		mtx_unlock(&sc->sc_inplock);
		return (ENOSPC);
	}

	head = sc->sc_head;
	inpring = sc->sc_inpring.vaddr;

	/* Fill the entry info */
	ent = &sc->sc_entinfo[head];
	ent->desc_va = desc;
	ent->desc_pa = desc_pa;
	ent->desc_size = desc_size;
	ent->callback = callback;
	ent->cb_arg = cb_arg;
	ent->crp = NULL;

	/* Write descriptor PA to the input ring (CAAM byte order) */
	inpring[head] = cpu_to_caam64(desc_pa);

	/*
	 * Full system memory barrier — ensures the input ring entry
	 * is visible to CAAM before we notify it.  Under heavy DDR load,
	 * weaker barriers (wmb/dma_wmb) can be insufficient.
	 */
	wmb();

	/* Advance head */
	sc->sc_head = (head + 1) & CAAM_JR_DEPTH_MASK;
	sc->sc_inpring_avail--;

	/* Notify CAAM: one new job added to the input ring */
	JR_WRITE(sc, JR_IRJAR, 1);

	mtx_unlock(&sc->sc_inplock);

	return (0);
}

/*
 * NOP test callback — used during attach to verify ring operation.
 */
struct caam_jr_nop_ctx {
	volatile int		done;
	volatile uint32_t	status;
};

static void
caam_jr_nop_callback(uint32_t status, void *arg)
{
	struct caam_jr_nop_ctx *ctx = arg;

	ctx->status = status;
	ctx->done = 1;
}

/*
 * Submit a NOP descriptor to test ring operation.
 */
static int
caam_jr_test_nop(struct caam_jr_softc *sc)
{
	struct caam_dma_mem desc_mem;
	struct caam_jr_nop_ctx nop_ctx;
	uint32_t *desc;
	int error, timeout;

	/* Allocate DMA memory for a minimal descriptor (1 word) */
	error = caam_dma_alloc(sc->sc_dev, &desc_mem, CAAM_DESC_MAX_BYTES);
	if (error != 0) {
		device_printf(sc->sc_dev, "NOP test: DMA alloc failed\n");
		return (error);
	}

	desc = desc_mem.vaddr;
	caam_desc_build_nop(desc);

	nop_ctx.done = 0;
	nop_ctx.status = 0xdeadbeef;

	error = caam_jr_enqueue(sc, desc, desc_mem.paddr,
	    caam_desc_len(desc) * sizeof(uint32_t),
	    caam_jr_nop_callback, &nop_ctx);
	if (error != 0) {
		device_printf(sc->sc_dev, "NOP test: enqueue failed: %d\n",
		    error);
		caam_dma_free(&desc_mem);
		return (error);
	}

	/*
	 * Poll for completion by draining the output ring directly.
	 *
	 * During device attach, taskqueue threads may not be running yet
	 * (CPU 0 is busy with attach, single-threaded early boot).
	 * Call the task handler inline to process completions.
	 */
	for (timeout = 1000; timeout > 0 && !nop_ctx.done; timeout--) {
		if (JR_READ(sc, JR_ORSFR) != 0)
			caam_jr_task(sc, 0);
		DELAY(1000);	/* 1ms per iteration, 1s total */
	}

	caam_dma_free(&desc_mem);

	if (!nop_ctx.done) {
		device_printf(sc->sc_dev, "NOP test: timeout\n");
		return (ETIMEDOUT);
	}

	/*
	 * Check for error status.  JUMP HALT produces a Condition Code
	 * status (SSRC=7) on SEC v5.4 — this is informational, not an
	 * error.  Only CCB (2), DECO (4), and JR (6) SSRCs are errors.
	 */
	if (nop_ctx.status != 0) {
		uint32_t ssrc;

		ssrc = nop_ctx.status & JRSTA_SSRC_MASK;
		if (ssrc == JRSTA_SSRC_CCB_ERROR ||
		    ssrc == JRSTA_SSRC_DECO ||
		    ssrc == JRSTA_SSRC_JR) {
			device_printf(sc->sc_dev,
			    "NOP test: error status 0x%08x\n",
			    nop_ctx.status);
			return (EIO);
		}
	}

	device_printf(sc->sc_dev, "NOP test: passed\n");
	return (0);
}

/*
 * Probe / Attach / Detach
 */
static int
caam_jr_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, caam_jr_compat)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "NXP CAAM Job Ring");
	return (BUS_PROBE_DEFAULT);
}

static int
caam_jr_attach(device_t dev)
{
	struct caam_jr_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_cid = -1;

	mtx_init(&sc->sc_inplock, "caam_jr", NULL, MTX_DEF);

	/* Map JR register space */
	sc->sc_rrid = 0;
	sc->sc_rres = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &sc->sc_rrid, RF_ACTIVE);
	if (sc->sc_rres == NULL) {
		device_printf(dev, "cannot map registers\n");
		error = ENXIO;
		goto fail;
	}

	/* Allocate interrupt */
	sc->sc_irid = 0;
	sc->sc_ires = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &sc->sc_irid, RF_ACTIVE | RF_SHAREABLE);
	if (sc->sc_ires == NULL) {
		device_printf(dev, "cannot allocate interrupt\n");
		error = ENXIO;
		goto fail;
	}

	/* Reset the JR hardware */
	error = caam_jr_reset(sc);
	if (error != 0)
		goto fail;

	/* Initialize DMA rings */
	error = caam_jr_init_rings(sc);
	if (error != 0)
		goto fail;

	/* Create taskqueue for deferred completion processing */
	sc->sc_taskq = taskqueue_create("caam_jr", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->sc_taskq);
	if (sc->sc_taskq == NULL) {
		device_printf(dev, "cannot create taskqueue\n");
		error = ENOMEM;
		goto fail;
	}
	TASK_INIT(&sc->sc_task, 0, caam_jr_task, sc);
	taskqueue_start_threads(&sc->sc_taskq, 1, PI_NET, "%s",
	    device_get_nameunit(dev));

	device_printf(dev, "ring depth %d, input PA 0x%jx, output PA 0x%jx\n",
	    CAAM_JR_DEPTH,
	    (uintmax_t)sc->sc_inpring.paddr,
	    (uintmax_t)sc->sc_outring.paddr);

	/*
	 * Run NOP test to verify ring operation BEFORE installing the
	 * interrupt handler.  The NOP test polls the output ring inline.
	 * If the ISR is already registered, the CAAM completion interrupt
	 * triggers the taskqueue handler on another CPU, racing with the
	 * inline poll on this CPU.  Both call caam_jr_task() and advance
	 * sc_out_ridx, leaving it permanently off-by-one.  Every subsequent
	 * completion is then read from the wrong slot (zeros), producing
	 * "completed desc PA 0x0 not found in ring" on every RNG attempt.
	 */
	error = caam_jr_test_nop(sc);
	if (error != 0) {
		device_printf(dev, "NOP test failed: %d\n", error);
		goto fail;
	}

	/*
	 * Clear NOP completion interrupt status before unmasking.
	 *
	 * Interrupts have been masked (JRCFG_IMSK) since caam_jr_reset(),
	 * so the NOP completion set JRINT_JR_INT in the status register
	 * but never asserted the interrupt signal to the GIC.  Clear it
	 * now so that unmasking doesn't immediately fire a stale edge.
	 */
	{
		uint32_t jrintr = JR_READ(sc, JR_JRINTR);
		uint32_t jrcfg = JR_READ(sc, JR_JRCFGR_LS);
		device_printf(dev,
		    "pre-ISR: JRINTR=0x%08x JRCFG=0x%08x (IMSK=%s JR_INT=%s)\n",
		    jrintr, jrcfg,
		    (jrcfg & JRCFG_IMSK) ? "yes" : "NO",
		    (jrintr & JRINT_JR_INT) ? "pending" : "clear");
		JR_WRITE(sc, JR_JRINTR, JRINT_JR_INT);
	}

	/* Setup interrupt handler */
	error = bus_setup_intr(dev, sc->sc_ires,
	    INTR_TYPE_NET | INTR_MPSAFE, NULL, caam_jr_intr, sc,
	    &sc->sc_ihand);
	if (error != 0) {
		device_printf(dev, "cannot setup interrupt: %d\n", error);
		goto fail;
	}

	/* Unmask interrupts now that ISR is installed */
	JR_WRITE(sc, JR_JRCFGR_LS,
	    JR_READ(sc, JR_JRCFGR_LS) & ~JRCFG_IMSK);

	/*
	 * Register hardware entropy source (first JR only).
	 * Must happen before crypto init: if this JR is claimed for RNG,
	 * it enters polling mode and skips opencrypto registration.
	 */
	error = caam_rng_init(sc);
	if (error != 0 && error != ENXIO)
		device_printf(dev, "RNG entropy source init failed: %d\n",
		    error);

	/* Initialize opencrypto integration (skip if dedicated to RNG) */
	if (!sc->sc_polling) {
		error = caam_crypto_init(sc);
		if (error != 0)
			device_printf(dev,
			    "opencrypto init failed: %d\n", error);

		/* Register as admin JR for split key derivation (first wins) */
		{
			struct caam_softc *csc;
			csc = device_get_softc(device_get_parent(dev));
			if (csc->sc_admin_jr == NULL)
				csc->sc_admin_jr = dev;
		}
	}

	return (0);

fail:
	caam_jr_detach(dev);
	return (error);
}

static int
caam_jr_detach(device_t dev)
{
	struct caam_jr_softc *sc;

	sc = device_get_softc(dev);

	/* Deregister RNG entropy source if owned by this JR */
	caam_rng_detach(sc);

	/* Unregister from opencrypto and free request pool */
	caam_crypto_detach(sc);

	if (sc->sc_ihand != NULL)
		bus_teardown_intr(dev, sc->sc_ires, sc->sc_ihand);

	if (sc->sc_taskq != NULL) {
		taskqueue_drain(sc->sc_taskq, &sc->sc_task);
		taskqueue_free(sc->sc_taskq);
		sc->sc_taskq = NULL;
	}

	caam_jr_free_rings(sc);

	if (sc->sc_ires != NULL)
		bus_release_resource(dev, SYS_RES_IRQ,
		    sc->sc_irid, sc->sc_ires);

	if (sc->sc_rres != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    sc->sc_rrid, sc->sc_rres);

	mtx_destroy(&sc->sc_inplock);

	return (0);
}

static device_method_t caam_jr_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		caam_jr_probe),
	DEVMETHOD(device_attach,	caam_jr_attach),
	DEVMETHOD(device_detach,	caam_jr_detach),

	/* Cryptodev interface */
	DEVMETHOD(cryptodev_probesession, caam_probesession),
	DEVMETHOD(cryptodev_newsession,	  caam_newsession),
	DEVMETHOD(cryptodev_freesession,  caam_freesession),
	DEVMETHOD(cryptodev_process,	  caam_process),

	DEVMETHOD_END
};

static driver_t caam_jr_driver = {
	"caam_jr",
	caam_jr_methods,
	sizeof(struct caam_jr_softc),
};

DRIVER_MODULE(caam_jr, caam, caam_jr_driver, 0, 0);
MODULE_VERSION(caam_jr, 1);
MODULE_DEPEND(caam_jr, caam, 1, 1, 1);
MODULE_DEPEND(caam_jr, crypto, 1, 1, 1);
