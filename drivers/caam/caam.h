/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * NXP CAAM (SEC v4.0+) crypto controller — shared types and accessors.
 */

#ifndef _CAAM_H
#define _CAAM_H

#include <sys/endian.h>
#include <sys/rman.h>

#include <dev/fdt/simplebus.h>

/*
 * CAAM register/DMA endianness.
 *
 * Detected at runtime via the CSTA register's PLEND bit.  On QorIQ
 * Layerscape ARM64 (LS1046A), CAAM is big-endian — same as DPAA1
 * portals.  All register accesses and DMA data (ring entries, descriptors)
 * use CAAM byte order.
 *
 * Set once during controller attach; used by all CAAM subsystems.
 */
extern bool caam_big_endian;

/*
 * Byte-order conversion between CPU and CAAM.
 */
static __inline uint32_t
cpu_to_caam32(uint32_t val)
{

	return (caam_big_endian ? htobe32(val) : val);
}

static __inline uint32_t
caam_to_cpu32(uint32_t val)
{

	return (caam_big_endian ? be32toh(val) : val);
}

static __inline uint64_t
cpu_to_caam64(uint64_t val)
{

	return (caam_big_endian ? htobe64(val) : val);
}

static __inline uint64_t
caam_to_cpu64(uint64_t val)
{

	return (caam_big_endian ? be64toh(val) : val);
}

/*
 * Controller softc.
 */
struct caam_softc {
	struct simplebus_softc	sc_base;	/* Inherits simplebus */
	struct resource		*sc_rres;	/* CCSR register resource */
	int			sc_rrid;
	int			sc_era;		/* SEC era (8 for LS1046A) */
	struct rman		sc_mem_rman;	/* Resource manager for children */
	bus_size_t		sc_deco0_off;	/* DECO0 base offset */
	bus_size_t		sc_qi_off;	/* QI block base offset */
	bool			sc_rng_inited;	/* RNG state handles instantiated */
	bool			sc_rng_registered; /* RNG entropy source registered */
	bool			sc_qi_present;	/* QI (Queue Interface) present */
	device_t		sc_admin_jr;	/* JR device for admin ops (split key) */
};

/*
 * Register access — applies CAAM byte-swap (BE on LS1046A).
 *
 * bus_read_4/bus_write_4 do no byte-swap on LE ARM64.  Since CAAM
 * registers are BE, we must swap explicitly.
 */
#define CAAM_READ(sc, off)	caam_to_cpu32(bus_read_4((sc)->sc_rres, (off)))
#define CAAM_WRITE(sc, off, v)	\
	bus_write_4((sc)->sc_rres, (off), cpu_to_caam32(v))

/*
 * 64-bit register access.
 *
 * CAAM 64-bit registers (e.g. ring base addresses) are two 32-bit halves.
 *   - BE CAAM: high 32 bits at offset+0, low 32 bits at offset+4.
 *   - LE CAAM: low 32 bits at offset+0, high 32 bits at offset+4.
 * Each 32-bit half uses CAAM byte order.
 */
static __inline void
caam_write_8(struct resource *res, bus_size_t off, uint64_t val)
{

	if (caam_big_endian) {
		/* BE: MSB at lower address */
		bus_write_4(res, off,     htobe32((uint32_t)(val >> 32)));
		bus_write_4(res, off + 4, htobe32((uint32_t)val));
	} else {
		/* LE: LSB at lower address */
		bus_write_4(res, off,     (uint32_t)val);
		bus_write_4(res, off + 4, (uint32_t)(val >> 32));
	}
}

static __inline uint64_t
caam_read_8(struct resource *res, bus_size_t off)
{
	uint32_t w0, w1;

	w0 = bus_read_4(res, off);
	w1 = bus_read_4(res, off + 4);
	if (caam_big_endian) {
		/* BE: high 32 at offset+0, low 32 at offset+4 */
		return ((uint64_t)be32toh(w0) << 32) | be32toh(w1);
	} else {
		/* LE: low 32 at offset+0, high 32 at offset+4 */
		return ((uint64_t)w1 << 32) | w0;
	}
}

int	caam_attach(device_t dev);
int	caam_detach(device_t dev);

#endif /* _CAAM_H */
