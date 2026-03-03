/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * NXP CAAM (Cryptographic Acceleration and Assurance Module) controller driver.
 *
 * The CAAM controller (SEC v4.0+) acts as a simplebus parent that enumerates
 * Job Ring child devices from the device tree.  It also detects hardware
 * version, register endianness, and DMA pointer size.
 *
 * Child Job Ring devices need to map sub-ranges of the controller's 1MB
 * register space.  Since the controller allocates the full region from the
 * parent bus, we use a local resource manager (rman) to subdivide it for
 * children — the same pattern used by FMan (sys/dev/dpaa/fman.c).
 *
 * Matches: "fsl,sec-v4.0" (broadest compatible for SEC v4.0/v5.0/v5.4)
 * DT node: crypto@1700000 with #address-cells=1, #size-cells=1, ranges
 *
 * This is a clean-room implementation based on the NXP SEC reference manual.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <dev/fdt/simplebus.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"

/*
 * Global endianness flag — set once during controller attach.
 * Used by all CAAM byte-order conversion helpers.
 */
bool caam_big_endian;

static struct ofw_compat_data caam_compat[] = {
	{ "fsl,sec-v4.0",	1 },
	{ NULL,			0 }
};

static int
caam_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, caam_compat)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "NXP CAAM crypto accelerator");
	return (BUS_PROBE_SPECIFIC);
}

/*
 * Run a descriptor on DECO0 directly (without a Job Ring).
 *
 * Used for RNG state handle instantiation during controller attach,
 * before any Job Ring child devices are available.  Follows the same
 * protocol as Linux's run_descriptor_deco0() in ctrl.c.
 *
 * Returns 0 on success; *status receives the DECO operation status.
 */
static int
caam_run_deco0(struct caam_softc *sc, uint32_t *desc, int nwords,
    uint32_t *status)
{
	bus_size_t deco = sc->sc_deco0_off;
	uint32_t val;
	int i, timeout;

	*status = 0;

	/*
	 * Step 1: Acquire DECO0.
	 * Write JR0 as request source, poll for VALID.
	 */
	CAAM_WRITE(sc, CAAM_DECORSR, DECORSR_JR0);
	for (timeout = 10000; timeout > 0; timeout--) {
		val = CAAM_READ(sc, CAAM_DECORSR);
		if (val & DECORSR_VALID)
			break;
		DELAY(10);
	}
	if (timeout <= 0) {
		device_printf(sc->sc_base.dev,
		    "DECO0: timeout waiting for DECORSR VALID\n");
		return (ETIMEDOUT);
	}

	/*
	 * Step 2: Request DECO0 for direct access.
	 * Set RQD0ENABLE, poll for DEN0.
	 */
	CAAM_WRITE(sc, CAAM_DECORR, DECORR_RQD0ENABLE);
	for (timeout = 10000; timeout > 0; timeout--) {
		val = CAAM_READ(sc, CAAM_DECORR);
		if (val & DECORR_DEN0)
			break;
		DELAY(10);
	}
	if (timeout <= 0) {
		device_printf(sc->sc_base.dev,
		    "DECO0: timeout waiting for DECORR DEN0\n");
		/* Release DECORSR */
		CAAM_WRITE(sc, CAAM_DECORSR, 0);
		return (ETIMEDOUT);
	}

	/*
	 * Step 3: Load descriptor into DECO0 descriptor buffer.
	 */
	for (i = 0; i < nwords; i++)
		CAAM_WRITE(sc, deco + DECO_DESCBUF(i), desc[i]);

	/*
	 * Step 4: Trigger execution.
	 * WHL = whole descriptor (not a link), FOUR = descriptor >= 4 words.
	 */
	val = DECO_JQCR_WHL;
	if (nwords >= 4)
		val |= DECO_JQCR_FOUR;
	CAAM_WRITE(sc, deco + DECO_JR_CTL_HI, val);

	/*
	 * Step 5: Poll for completion.
	 * The DESC_DBG register's VALID bit (31) clears when done, or
	 * the status field shows HOST_ERR (0xD) on error.
	 */
	for (timeout = 100000; timeout > 0; timeout--) {
		val = CAAM_READ(sc, deco + DECO_DESC_DBG);
		if (!(val & DESC_DBG_DECO_STAT_VALID))
			break;
		if (((val & DESC_DBG_DECO_STAT_MASK) >>
		    DESC_DBG_DECO_STAT_SHIFT) == DECO_STAT_HOST_ERR)
			break;
		DELAY(10);
	}
	if (timeout <= 0) {
		device_printf(sc->sc_base.dev,
		    "DECO0: timeout waiting for descriptor completion\n");
	}

	/*
	 * Step 6: Read operation status.
	 */
	*status = CAAM_READ(sc, deco + DECO_OP_STATUS_HI);

	/*
	 * Step 7: Release DECO0.
	 */
	val = CAAM_READ(sc, CAAM_DECORR);
	CAAM_WRITE(sc, CAAM_DECORR, val & ~DECORR_RQD0ENABLE);

	return (0);
}

/*
 * Configure the TRNG (True Random Number Generator).
 *
 * Programs entropy sampling delay, frequency count limits, and
 * statistical self-test parameters.  Matches Linux's kick_trng().
 */
static void
caam_kick_trng(struct caam_softc *sc, uint32_t ent_delay)
{
	uint32_t rtsdctl, cur_delay;

	/*
	 * Enter program mode: set PRGM and ACC bits in RTMCTL.
	 * This invalidates current entropy and forces re-generation.
	 */
	CAAM_WRITE(sc, CAAM_RTMCTL,
	    CAAM_READ(sc, CAAM_RTMCTL) | RTMCTL_PRGM | RTMCTL_ACC);

	/*
	 * Only increase the entropy delay — never decrease it,
	 * as the current value may have been raised for good reason.
	 */
	rtsdctl = CAAM_READ(sc, CAAM_RTSDCTL);
	cur_delay = (rtsdctl & RTSDCTL_ENT_DLY_MASK) >> RTSDCTL_ENT_DLY_SHIFT;
	if (ent_delay > cur_delay) {
		cur_delay = ent_delay;
		/* Minimum frequency count = 1/4 of entropy sample length */
		CAAM_WRITE(sc, CAAM_RTFRQMIN, cur_delay >> 2);
		/* Disable maximum frequency count */
		CAAM_WRITE(sc, CAAM_RTFRQMAX, RTFRQMAX_DISABLE);
	}

	CAAM_WRITE(sc, CAAM_RTSDCTL,
	    (cur_delay << RTSDCTL_ENT_DLY_SHIFT) | RTSDCTL_SAMP_SIZE_VAL);

	/*
	 * Program self-test parameters on first call.
	 * Use SAMP_SIZE as indicator: if it hasn't been set to our
	 * value yet, this is the first configuration.
	 */
	if ((rtsdctl & RTSDCTL_SAMP_SIZE_MASK) != RTSDCTL_SAMP_SIZE_VAL) {
		CAAM_WRITE(sc, CAAM_RTSCMISC, (2 << 16) | 32);
		CAAM_WRITE(sc, CAAM_RTPKRRNG, 570);
		CAAM_WRITE(sc, CAAM_RTPKRMAX, 1600);
		CAAM_WRITE(sc, CAAM_RTSCML,   (122 << 16) | 317);
		CAAM_WRITE(sc, CAAM_RTSCRL(0), (80 << 16) | 107);
		CAAM_WRITE(sc, CAAM_RTSCRL(1), (57 << 16) | 62);
		CAAM_WRITE(sc, CAAM_RTSCRL(2), (39 << 16) | 39);
		CAAM_WRITE(sc, CAAM_RTSCRL(3), (27 << 16) | 26);
		CAAM_WRITE(sc, CAAM_RTSCRL(4), (19 << 16) | 18);
		CAAM_WRITE(sc, CAAM_RTSCRL(5), (18 << 16) | 17);
	}

	/*
	 * Exit program mode: clear PRGM and ACC, enable raw sampling
	 * in both entropy shifter and statistical checker.
	 */
	CAAM_WRITE(sc, CAAM_RTMCTL,
	    (CAAM_READ(sc, CAAM_RTMCTL) & ~(RTMCTL_PRGM | RTMCTL_ACC)) |
	    RTMCTL_SAMP_MODE_RAW);
}

/*
 * Build an RNG state handle instantiation descriptor.
 *
 * For SH0 with gen_sk=1: 7 words (also generates secure keys JDKEK/TDKEK/TDSK).
 * For SH1 (or SH0 without gen_sk): 3 words.
 *
 * Returns the number of descriptor words.
 */
static int
caam_build_rng_inst_desc(uint32_t *desc, int handle, int gen_sk)
{
	int idx = 0;

	if (handle == 0 && gen_sk) {
		/* SH0 with secure key generation — 7 words */
		desc[idx++] = CMD_DESC_HDR | HDR_ONE | 7;

		/* Instantiate RNG SH0 with prediction resistance */
		desc[idx++] = OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG |
		    OP_ALG_AS_INIT | OP_ALG_PR_ON;

		/* JUMP: wait for Class 1 done (skip 1 word) */
		desc[idx++] = CMD_JUMP | JUMP_CLASS_CLASS1 | 1;

		/* LOAD IMM: write 1 to CLRW to reset done interrupt */
		desc[idx++] = CMD_LOAD | LDST_CLASS_DECO | LDST_IMM |
		    LDST_SRCDST_WORD_CLRW | sizeof(uint32_t);
		desc[idx++] = 1;

		/* Generate secure keys (JDKEK, TDKEK, TDSK) */
		desc[idx++] = OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG |
		    OP_ALG_AAI_RNG4_SK;

		/* Halt */
		desc[idx++] = CMD_JUMP | JUMP_CLASS_CLASS1 | JUMP_TYPE_HALT;
	} else {
		/* SH0 without gen_sk or SH1 — 3 words */
		desc[idx++] = CMD_DESC_HDR | HDR_ONE | 3;

		/* Instantiate RNG with prediction resistance */
		desc[idx++] = OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG |
		    ((uint32_t)handle << OP_ALG_AAI_SHIFT) |
		    OP_ALG_AS_INIT | OP_ALG_PR_ON;

		/* Halt */
		desc[idx++] = CMD_JUMP | JUMP_CLASS_CLASS1 | JUMP_TYPE_HALT;
	}

	return (idx);
}

/*
 * Build an RNG state handle deinstantiation descriptor.
 *
 * Deinstantiates all state handles indicated by the mask bits.
 * Used when U-Boot instantiated handles without prediction resistance
 * and we need to re-instantiate with PR enabled.
 *
 * Returns the number of descriptor words.
 */
static int
caam_build_rng_deinst_desc(uint32_t *desc, uint32_t sh_mask)
{
	int idx = 0;

	desc[idx++] = CMD_DESC_HDR | HDR_ONE | 3;

	/*
	 * OPERATION: Algorithm RNG, AS=INITFINAL (deinstantiate).
	 * The sh_mask selects which handles to deinstantiate via AAI bits.
	 * No prediction resistance flag for deinstantiation.
	 */
	desc[idx++] = OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG |
	    ((uint32_t)sh_mask << OP_ALG_AAI_SHIFT) |
	    OP_ALG_AS_INITFINAL;

	desc[idx++] = CMD_JUMP | JUMP_CLASS_CLASS1 | JUMP_TYPE_HALT;

	return (idx);
}

/*
 * Initialize the RNG: configure TRNG, instantiate state handles.
 *
 * Called from caam_attach() after JRSTART.  Retry with increasing
 * entropy delay if instantiation fails (3200 -> 6400 -> 12800).
 *
 * If U-Boot already instantiated state handles without prediction
 * resistance, deinstantiate them first, then re-instantiate with PR.
 */
static int
caam_rng_init(struct caam_softc *sc)
{
	uint32_t rdsta, desc[8], status;
	uint32_t ent_delay = RTSDCTL_ENT_DLY_MIN;
	uint32_t rdsta_if, rdsta_pr, deinst_mask;
	int gen_sk, ret, nwords;

	/* Check which state handles are already instantiated */
	rdsta = CAAM_READ(sc, CAAM_RDSTA);
	device_printf(sc->sc_base.dev, "RNG: initial RDSTA = 0x%08x\n", rdsta);

	/* If secure keys not yet valid, first SH0 instantiation must gen them */
	gen_sk = (rdsta & RDSTA_SKVN) ? 0 : 1;

	/*
	 * Check for handles instantiated WITHOUT prediction resistance.
	 * U-Boot typically instantiates SH0/SH1 without PR.  We need PR
	 * for OP_ALG_PR_ON in generate descriptors, so deinstantiate
	 * any handle that has IF set but PR clear.
	 */
	rdsta_if = rdsta & (RDSTA_IF0 | RDSTA_IF1);
	rdsta_pr = rdsta & (RDSTA_PR0 | RDSTA_PR1);

	/* Build mask of handles that need deinstantiation (IF set, PR clear) */
	deinst_mask = 0;
	if ((rdsta_if & RDSTA_IF0) && !(rdsta_pr & RDSTA_PR0))
		deinst_mask |= RDSTA_IF0;	/* SH0 bit = AAI bit 0 */
	if ((rdsta_if & RDSTA_IF1) && !(rdsta_pr & RDSTA_PR1))
		deinst_mask |= RDSTA_IF1;	/* SH1 bit = AAI bit 1 */

	if (deinst_mask != 0) {
		device_printf(sc->sc_base.dev,
		    "RNG: deinstantiating handles without PR (mask 0x%x)\n",
		    deinst_mask);

		nwords = caam_build_rng_deinst_desc(desc, deinst_mask);
		ret = caam_run_deco0(sc, desc, nwords, &status);
		if (ret != 0) {
			device_printf(sc->sc_base.dev,
			    "RNG: DECO0 error during deinstantiation\n");
			return (ret);
		}

		if (status != 0 && status != JRSTA_SSRC_JUMP_HALT_CC) {
			device_printf(sc->sc_base.dev,
			    "RNG: deinstantiation failed, status 0x%08x\n",
			    status);
			return (EIO);
		}

		rdsta = CAAM_READ(sc, CAAM_RDSTA);
		device_printf(sc->sc_base.dev,
		    "RNG: RDSTA after deinstantiation = 0x%08x\n", rdsta);
	}

	do {
		uint32_t inst_handles;

		inst_handles = CAAM_READ(sc, CAAM_RDSTA);
		rdsta_if = inst_handles & (RDSTA_IF0 | RDSTA_IF1);
		rdsta_pr = inst_handles & (RDSTA_PR0 | RDSTA_PR1);
		inst_handles &= RDSTA_MASK;

		/* Configure TRNG if no handles instantiated yet */
		if (rdsta_if == 0) {
			device_printf(sc->sc_base.dev,
			    "RNG: entropy delay = %u\n", ent_delay);
			caam_kick_trng(sc, ent_delay);
			ent_delay *= 2;
		}

		ret = 0;

		/*
		 * Instantiate SH0 if not fully done (need both IF0 and PR0).
		 */
		if (!((rdsta_if & RDSTA_IF0) && (rdsta_pr & RDSTA_PR0))) {
			nwords = caam_build_rng_inst_desc(desc, 0, gen_sk);
			ret = caam_run_deco0(sc, desc, nwords, &status);
			if (ret != 0)
				break;

			if (status != 0 &&
			    status != JRSTA_SSRC_JUMP_HALT_CC) {
				device_printf(sc->sc_base.dev,
				    "RNG: SH0 instantiation failed, "
				    "status 0x%08x\n", status);
				ret = EAGAIN;
				continue;
			}

			/* Verify SH0 instantiated with PR */
			rdsta = CAAM_READ(sc, CAAM_RDSTA);
			if ((rdsta & (RDSTA_IF0 | RDSTA_PR0)) !=
			    (RDSTA_IF0 | RDSTA_PR0)) {
				device_printf(sc->sc_base.dev,
				    "RNG: SH0 not confirmed, RDSTA=0x%08x\n",
				    rdsta);
				ret = EAGAIN;
				continue;
			}
			device_printf(sc->sc_base.dev,
			    "RNG: state handle 0 instantiated (PR)\n");
		}

		/*
		 * Instantiate SH1 if not fully done (need both IF1 and PR1).
		 */
		if (!((rdsta_if & RDSTA_IF1) && (rdsta_pr & RDSTA_PR1))) {
			nwords = caam_build_rng_inst_desc(desc, 1, 0);
			ret = caam_run_deco0(sc, desc, nwords, &status);
			if (ret != 0)
				break;

			if (status != 0 &&
			    status != JRSTA_SSRC_JUMP_HALT_CC) {
				device_printf(sc->sc_base.dev,
				    "RNG: SH1 instantiation failed, "
				    "status 0x%08x\n", status);
				ret = EAGAIN;
				continue;
			}

			/* Verify SH1 instantiated with PR */
			rdsta = CAAM_READ(sc, CAAM_RDSTA);
			if ((rdsta & (RDSTA_IF1 | RDSTA_PR1)) !=
			    (RDSTA_IF1 | RDSTA_PR1)) {
				device_printf(sc->sc_base.dev,
				    "RNG: SH1 not confirmed, RDSTA=0x%08x\n",
				    rdsta);
				ret = EAGAIN;
				continue;
			}
			device_printf(sc->sc_base.dev,
			    "RNG: state handle 1 instantiated (PR)\n");
		}

		break;	/* Both handles fully instantiated with PR */

	} while (ret == EAGAIN && ent_delay <= RTSDCTL_ENT_DLY_MAX);

	if (ret != 0) {
		device_printf(sc->sc_base.dev,
		    "RNG: failed to instantiate state handles\n");
		return (ret);
	}

	rdsta = CAAM_READ(sc, CAAM_RDSTA);
	device_printf(sc->sc_base.dev,
	    "RNG: initialized, RDSTA = 0x%08x\n", rdsta);

	/* Enable RDB for faster RNG operation */
	CAAM_WRITE(sc, CAAM_SCFGR,
	    CAAM_READ(sc, CAAM_SCFGR) | SCFGR_RDBENABLE);

	sc->sc_rng_inited = true;
	return (0);
}

int
caam_attach(device_t dev)
{
	struct caam_softc *sc;
	phandle_t node;
	uint32_t csta, ctpr, ccbvid, chanum_ls;
	pcell_t era;
	int error, maj, min;

	sc = device_get_softc(dev);
	sc->sc_base.dev = dev;

	/* Map CCSR register space (1MB) */
	sc->sc_rrid = 0;
	sc->sc_rres = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &sc->sc_rrid, RF_ACTIVE | RF_SHAREABLE);
	if (sc->sc_rres == NULL) {
		device_printf(dev, "cannot map register space\n");
		return (ENXIO);
	}

	/*
	 * Detect register endianness.
	 *
	 * CAAM's CSTA register contains PLEND/ALT_PLEND bits that indicate
	 * whether the platform is little-endian.  On QorIQ Layerscape SoCs,
	 * CAAM registers are ALWAYS big-endian (legacy from PowerPC era),
	 * regardless of the CPU's byte order.
	 *
	 * The detection matches Linux's approach:
	 *   1. Read CSTA with a BE read (safe default for QorIQ)
	 *   2. If PLEND is set → platform is LE → registers need BE swap
	 *   3. If PLEND not set → platform is BE → native access works
	 *
	 * On LS1046A ARM64 (LE CPU): PLEND=1, caam_big_endian=true → swap
	 * On PowerPC (BE CPU):        PLEND=0, caam_big_endian=false → no swap
	 */
	csta = be32toh(bus_read_4(sc->sc_rres, CAAM_CSTA));
	caam_big_endian = (csta & (CSTA_PLEND | CSTA_ALT_PLEND)) != 0;

	/* Read compile-time parameters */
	ctpr = CAAM_READ(sc, CAAM_CTPR_MS);
	if (ctpr & CTPR_MS_PS)
		device_printf(dev, "64-bit DMA pointer mode\n");

	/* Read ERA from DT (preferred) or from hardware */
	node = ofw_bus_get_node(dev);
	if (OF_getencprop(node, "fsl,sec-era", &era, sizeof(era)) > 0) {
		sc->sc_era = era;
	} else {
		ccbvid = CAAM_READ(sc, CAAM_CCBVID);
		sc->sc_era = (ccbvid & CCBVID_ERA_MASK) >> CCBVID_ERA_SHIFT;
	}

	/* Read version info */
	chanum_ls = CAAM_READ(sc, CAAM_CHANUM_LS);
	ccbvid = CAAM_READ(sc, CAAM_CCBVID);
	maj = (CAAM_READ(sc, CAAM_CAAMVID_MS) & SECVID_MS_MAJ_REV_MASK)
	    >> SECVID_MS_MAJ_REV_SHIFT;
	min = CAAM_READ(sc, CAAM_CAAMVID_MS) & 0xff;

	device_printf(dev, "SEC era %d, version %d.%d, "
	    "CHAs: AES=%u DES=%u MD=%u RNG=%u PK=%u\n",
	    sc->sc_era, maj, min,
	    (chanum_ls >> 0) & 0xf,	/* AES */
	    (chanum_ls >> 4) & 0xf,	/* DES */
	    (chanum_ls >> 12) & 0xf,	/* MDHA */
	    (chanum_ls >> 16) & 0xf,	/* RNG */
	    (chanum_ls >> 24) & 0xf);	/* PKHA */

	/*
	 * Initialize local resource manager (rman) for child devices.
	 *
	 * The controller owns the full 1MB register region.  Child Job
	 * Rings need sub-ranges (e.g. 0x10000-0x1ffff).  A local rman
	 * allows children to allocate from our resource without conflicting
	 * with the parent bus's resource pool.
	 */
	sc->sc_mem_rman.rm_type = RMAN_ARRAY;
	sc->sc_mem_rman.rm_descr = "CAAM memory";
	error = rman_init_from_resource(&sc->sc_mem_rman, sc->sc_rres);
	if (error != 0) {
		device_printf(dev, "rman_init_from_resource failed: %d\n",
		    error);
		bus_release_resource(dev, SYS_RES_MEMORY,
		    sc->sc_rrid, sc->sc_rres);
		return (error);
	}

	/*
	 * Configure Master Config Register for optimal DMA behavior.
	 * Set AXI write cache attributes (cacheable + bufferable),
	 * enable watchdog, and allow large bursts.
	 */
	{
		uint32_t mcr = CAAM_READ(sc, CAAM_MCFGR);
		mcr = (mcr & ~MCFGR_AWCACHE_MASK) |
		    MCFGR_AWCACHE_CACH | MCFGR_AWCACHE_BUFF |
		    MCFGR_WDENABLE | MCFGR_LARGE_BURST;
		CAAM_WRITE(sc, CAAM_MCFGR, mcr);
	}

	/*
	 * Enable Job Ring processing.
	 *
	 * The JRSTART register must be written to start each JR before
	 * child drivers can submit descriptors.  Linux does this in
	 * caam_ctrl_init (drivers/crypto/caam/ctrl.c).
	 */
	CAAM_WRITE(sc, CAAM_JRSTART,
	    JRSTART_JR0 | JRSTART_JR1 | JRSTART_JR2 | JRSTART_JR3);

	/*
	 * Compute page-size-dependent block offsets.
	 * Page size is 4K or 64K, read from CTPR_MS.
	 * DECO block = page 8, QI block = page 7.
	 * LS1046A uses 64K pages: QI at 0x70000, DECO0 at 0x80000.
	 */
	{
		uint32_t pg_size;

		pg_size = (ctpr & CTPR_MS_PG_SZ_MASK) >> CTPR_MS_PG_SZ_SHIFT;
		pg_size = pg_size ? PG_SIZE_64K : PG_SIZE_4K;
		sc->sc_deco0_off = DECO_BLOCK_NUMBER * pg_size;
		sc->sc_qi_off = QI_BLOCK_NUMBER * pg_size;
		/* No debug print needed — page size used internally */
	}

	/*
	 * Initialize RNG: configure TRNG and instantiate state handles.
	 * Must happen before child enumeration since JR crypto operations
	 * that use RNG (e.g. key generation) need instantiated state handles.
	 */
	error = caam_rng_init(sc);
	if (error != 0)
		device_printf(dev, "WARNING: RNG initialization failed: %d\n",
		    error);

	/*
	 * Enable QI (Queue Interface) if hardware supports it.
	 *
	 * QI allows crypto submission via QMan frame queues instead of
	 * Job Rings, eliminating the JR spinlock bottleneck for high
	 * packet-rate workloads.  The child JR driver checks sc_qi_present
	 * to optionally register a QI-based opencrypto backend.
	 */
	if (ctpr & CTPR_MS_QI_MASK) {
		CAAM_WRITE(sc, sc->sc_qi_off + CAAM_QI_CONTROL_LO,
		    QICTL_DQEN);
		sc->sc_qi_present = true;
		device_printf(dev, "QI enabled\n");
	}

	/*
	 * Initialize simplebus and enumerate Job Ring children from DT.
	 * After that, add a QI pseudo-device if the hardware supports it.
	 * The QI device doesn't need DT resources — it communicates
	 * with CAAM entirely through QMan frame queues.
	 * The crypto@1700000 node has ranges + #address-cells + #size-cells,
	 * making it a valid bus for child enumeration.
	 */
	simplebus_init(dev, node);
	simplebus_fill_ranges(node, &sc->sc_base);

	for (node = OF_child(ofw_bus_get_node(dev)); node > 0;
	    node = OF_peer(node)) {
		simplebus_add_device(dev, node, 0, NULL, -1, NULL);
	}

	/* Add QI pseudo-device alongside JR children */
	if (sc->sc_qi_present)
		device_add_child(dev, "caam_qi", -1);

	bus_attach_children(dev);

	return (0);
}

int
caam_detach(device_t dev)
{
	struct caam_softc *sc;

	sc = device_get_softc(dev);

	bus_generic_detach(dev);

	rman_fini(&sc->sc_mem_rman);

	if (sc->sc_rres != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    sc->sc_rrid, sc->sc_rres);

	return (0);
}

/*
 * Bus method: allocate a resource for a child device.
 *
 * For memory resources, allocate from our local rman (backed by the
 * controller's 1MB register region).  For IRQs and other types, pass
 * through to the default simplebus/parent implementation.
 */
static struct resource *
caam_alloc_resource(device_t bus, device_t child, int type, int *rid,
    rman_res_t start, rman_res_t end, rman_res_t count, u_int flags)
{
	struct caam_softc *sc;
	struct resource_list_entry *rle;
	struct resource *res;

	sc = device_get_softc(bus);

	if (type != SYS_RES_MEMORY)
		return (bus_generic_rl_alloc_resource(bus, child, type,
		    rid, start, end, count, flags));

	/* Look up child's resource list entry (populated from DT) */
	rle = resource_list_find(BUS_GET_RESOURCE_LIST(bus, child),
	    type, *rid);
	if (rle == NULL)
		return (NULL);

	if (RMAN_IS_DEFAULT_RANGE(start, end)) {
		start = rle->start;
		count = ulmax(count, rle->count);
		end = ulmax(rle->end, start + count - 1);
	}

	/*
	 * Translate child's bus address to physical address through the
	 * DT "ranges" property — same transform as simplebus_alloc_resource.
	 *
	 * Child addresses (e.g. 0x10000) map to parent physical addresses
	 * (e.g. 0x1710000) via: phys = child_addr - ranges.bus + ranges.host
	 */
	for (int i = 0; i < sc->sc_base.nranges; i++) {
		struct simplebus_range *r = &sc->sc_base.ranges[i];

		if (start >= r->bus && end < r->bus + r->size) {
			start = start - r->bus + r->host;
			end = end - r->bus + r->host;

			res = rman_reserve_resource(&sc->sc_mem_rman,
			    start, end, count, flags & ~RF_ACTIVE, child);
			if (res == NULL)
				return (NULL);

			rman_set_rid(res, *rid);
			rman_set_type(res, type);

			if ((flags & RF_ACTIVE) != 0 &&
			    bus_activate_resource(child, type, *rid,
			    res) != 0) {
				rman_release_resource(res);
				return (NULL);
			}

			rle->res = res;
			return (res);
		}
	}

	return (NULL);
}

/*
 * Bus method: activate a child's memory resource.
 *
 * Create a bus_space subregion of the controller's mapping.
 * The child gets its own bus handle pointing into our VA space.
 */
static int
caam_activate_resource(device_t bus, device_t child, int type, int rid, struct resource *res)
{
	struct caam_softc *sc;
	bus_space_handle_t bh;
	bus_space_tag_t bt;
	int rv;

	sc = device_get_softc(bus);

	if (rman_get_type(res) != SYS_RES_MEMORY)
		return (bus_generic_activate_resource(bus, child, type, rid, res));

	/* Verify the resource belongs to our rman */
	if (rman_is_region_manager(res, &sc->sc_mem_rman) == 0)
		return (bus_generic_activate_resource(bus, child, type, rid, res));

	bt = rman_get_bustag(sc->sc_rres);
	rv = bus_space_subregion(bt, rman_get_bushandle(sc->sc_rres),
	    rman_get_start(res) - rman_get_start(sc->sc_rres),
	    rman_get_size(res), &bh);
	if (rv != 0)
		return (rv);

	rman_set_bustag(res, bt);
	rman_set_bushandle(res, bh);

	return (rman_activate_resource(res));
}

/*
 * Bus method: deactivate a child's resource.
 *
 * Resources from our rman were activated via bus_space_subregion —
 * they share the parent's mapping and must NOT be pmap_unmapdev'd.
 * Just clear the RF_ACTIVE flag.
 */
static int
caam_deactivate_resource(device_t bus, device_t child, int type, int rid, struct resource *res)
{
	struct caam_softc *sc;

	sc = device_get_softc(bus);

	if (rman_get_type(res) != SYS_RES_MEMORY ||
	    rman_is_region_manager(res, &sc->sc_mem_rman) == 0)
		return (bus_generic_deactivate_resource(bus, child, type, rid, res));

	return (rman_deactivate_resource(res));
}

/*
 * Bus method: release a child's resource.
 */
static int
caam_release_resource(device_t bus, device_t child, int type, int rid, struct resource *res)
{
	struct caam_softc *sc;
	struct resource_list_entry *rle;
	int rv;

	sc = device_get_softc(bus);

	if (rman_get_type(res) != SYS_RES_MEMORY ||
	    rman_is_region_manager(res, &sc->sc_mem_rman) == 0)
		return (bus_generic_rl_release_resource(bus, child, type, rid, res));

	if ((rman_get_flags(res) & RF_ACTIVE) != 0) {
		rv = bus_deactivate_resource(child, type, rid, res);
		if (rv != 0)
			return (rv);
	}

	rv = rman_release_resource(res);

	rle = resource_list_find(BUS_GET_RESOURCE_LIST(bus, child),
	    rman_get_type(res), rman_get_rid(res));
	if (rle != NULL)
		rle->res = NULL;

	return (rv);
}

static device_method_t caam_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			caam_probe),
	DEVMETHOD(device_attach,		caam_attach),
	DEVMETHOD(device_detach,		caam_detach),

	/* Bus interface — override simplebus for rman-based allocation */
	DEVMETHOD(bus_alloc_resource,		caam_alloc_resource),
	DEVMETHOD(bus_activate_resource,	caam_activate_resource),
	DEVMETHOD(bus_deactivate_resource,	caam_deactivate_resource),
	DEVMETHOD(bus_release_resource,		caam_release_resource),

	DEVMETHOD_END
};

DEFINE_CLASS_1(caam, caam_driver, caam_methods,
    sizeof(struct caam_softc), simplebus_driver);

EARLY_DRIVER_MODULE(caam, simplebus, caam_driver, 0, 0,
    BUS_PASS_DEFAULT);
MODULE_VERSION(caam, 1);
