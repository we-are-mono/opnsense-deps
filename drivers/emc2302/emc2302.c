/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * Microchip EMC2301/2302/2303/2305 RPM-based PWM fan controller driver.
 * Provides per-channel sysctl nodes for PWM duty cycle (RW),
 * tachometer RPM (RO), and drive fault status (RO).
 *
 * Based on Linux hwmon/emc2305.c by Nvidia.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

/* Identification registers */
#define	EMC2305_REG_VENDOR		0xFE
#define	EMC2305_REG_PRODUCT_ID		0xFD
#define	EMC2305_VENDOR_MICROCHIP	0x5D

/* Product IDs */
#define	EMC2305_PID_2305		0x34	/* 5 channels */
#define	EMC2305_PID_2303		0x35	/* 3 channels */
#define	EMC2305_PID_2302		0x36	/* 2 channels */
#define	EMC2305_PID_2301		0x37	/* 1 channel */

/* Global configuration registers */
#define	EMC2305_REG_DRIVE_FAIL		0x27
#define	EMC2305_REG_POLARITY		0x2A
#define	EMC2305_REG_OUTPUT_TYPE		0x2B

/* Per-channel registers (n = 0..4) */
#define	EMC2305_REG_FAN_DRIVE(n)	(0x30 + 0x10 * (n))
#define	EMC2305_REG_FAN_MIN_DRIVE(n)	(0x38 + 0x10 * (n))
#define	EMC2305_REG_FAN_TACH(n)		(0x3E + 0x10 * (n))

/* RPM calculation constants (from datasheet) */
#define	EMC2305_RPM_FACTOR		3932160
#define	EMC2305_TACH_SHIFT		3	/* lower 3 bits unused */
#define	EMC2305_TACH_MULTIPLIER		2
#define	EMC2305_RPM_MIN			1000	/* stalled/missing fans read ~960 */

#define	EMC2305_MAX_FANS		5

struct emc2302_softc {
	device_t		dev;
	int			nfans;
	uint8_t			product_id;
	struct sysctl_ctx_list	sysctl_ctx;
};

/* ================================================================
 * I2C register helpers
 * ================================================================ */

static int
emc2302_read8(device_t dev, uint8_t reg, uint8_t *val)
{

	return (iicdev_readfrom(dev, reg, val, 1, IIC_WAIT));
}

static int
emc2302_write8(device_t dev, uint8_t reg, uint8_t val)
{

	return (iicdev_writeto(dev, reg, &val, 1, IIC_WAIT));
}

static int
emc2302_read16(device_t dev, uint8_t reg, uint16_t *val)
{
	uint8_t buf[2];
	int error;

	error = iicdev_readfrom(dev, reg, buf, 2, IIC_WAIT);
	if (error != 0)
		return (error);
	*val = (buf[0] << 8) | buf[1];
	return (0);
}

/* ================================================================
 * Hardware read helpers
 * ================================================================ */

static int
emc2302_read_rpm(struct emc2302_softc *sc, int ch, int *rpm)
{
	uint16_t raw;
	uint32_t count;
	int error;

	error = emc2302_read16(sc->dev, EMC2305_REG_FAN_TACH(ch), &raw);
	if (error != 0)
		return (error);

	count = raw >> EMC2305_TACH_SHIFT;
	if (count == 0) {
		*rpm = 0;
		return (0);
	}

	*rpm = (EMC2305_RPM_FACTOR / count) * EMC2305_TACH_MULTIPLIER;
	if (*rpm <= EMC2305_RPM_MIN)
		*rpm = 0;

	return (0);
}

/* ================================================================
 * Sysctl handlers
 * ================================================================ */

static int
emc2302_sysctl_pwm(SYSCTL_HANDLER_ARGS)
{
	struct emc2302_softc *sc = arg1;
	int ch = arg2;
	uint8_t reg_val;
	int val, error;

	error = emc2302_read8(sc->dev, EMC2305_REG_FAN_DRIVE(ch), &reg_val);
	if (error != 0)
		return (EIO);
	val = reg_val;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (val < 0)
		val = 0;
	if (val > 255)
		val = 255;

	error = emc2302_write8(sc->dev, EMC2305_REG_FAN_DRIVE(ch),
	    (uint8_t)val);
	if (error != 0)
		return (EIO);

	return (0);
}

static int
emc2302_sysctl_rpm(SYSCTL_HANDLER_ARGS)
{
	struct emc2302_softc *sc = arg1;
	int ch = arg2;
	int val, error;

	if (req->newptr != NULL)
		return (EINVAL);

	error = emc2302_read_rpm(sc, ch, &val);
	if (error != 0)
		return (EIO);

	return (sysctl_handle_int(oidp, &val, 0, req));
}

static int
emc2302_sysctl_fault(SYSCTL_HANDLER_ARGS)
{
	struct emc2302_softc *sc = arg1;
	int ch = arg2;
	uint8_t status;
	int val, error;

	if (req->newptr != NULL)
		return (EINVAL);

	error = emc2302_read8(sc->dev, EMC2305_REG_DRIVE_FAIL, &status);
	if (error != 0)
		return (EIO);

	val = (status >> ch) & 1;

	return (sysctl_handle_int(oidp, &val, 0, req));
}

/* ================================================================
 * DT child node parsing
 * ================================================================ */

static void
emc2302_parse_dt(struct emc2302_softc *sc)
{
	phandle_t node, child;
	uint32_t reg, pwm_args[3];
	uint8_t polarity, output_type;
	int i;

	node = ofw_bus_get_node(sc->dev);
	if (node == 0)
		return;

	polarity = 0;
	output_type = 0;

	for (child = OF_child(node); child != 0; child = OF_peer(child)) {
		if (OF_getencprop(child, "reg", &reg, sizeof(reg)) <= 0)
			continue;
		if ((int)reg >= sc->nfans)
			continue;

		/* Parse pwms = <&ref freq polarity output_type> */
		if (OF_getencprop(child, "pwms", pwm_args,
		    sizeof(pwm_args)) >= (int)(3 * sizeof(uint32_t))) {
			/* pwm_args[0] = phandle (skip) */
			/* pwm_args[1] = polarity */
			if (pwm_args[1])
				polarity |= (1 << reg);
			/* pwm_args[2] = output type (push-pull) */
			if (pwm_args[2])
				output_type |= (1 << reg);
		}
	}

	/* Write polarity and output type registers */
	emc2302_write8(sc->dev, EMC2305_REG_POLARITY, polarity);
	emc2302_write8(sc->dev, EMC2305_REG_OUTPUT_TYPE, output_type);

	/* Set minimum PWM per channel from DT if specified */
	for (child = OF_child(node); child != 0; child = OF_peer(child)) {
		uint32_t min_pwm;

		if (OF_getencprop(child, "reg", &reg, sizeof(reg)) <= 0)
			continue;
		if ((int)reg >= sc->nfans)
			continue;
		if (OF_getencprop(child, "pwm-min", &min_pwm,
		    sizeof(min_pwm)) > 0) {
			if (min_pwm > 255)
				min_pwm = 255;
			emc2302_write8(sc->dev,
			    EMC2305_REG_FAN_MIN_DRIVE(reg), (uint8_t)min_pwm);
		}
	}

	/* Log per-channel labels */
	for (child = OF_child(node); child != 0; child = OF_peer(child)) {
		char label[64];

		if (OF_getencprop(child, "reg", &reg, sizeof(reg)) <= 0)
			continue;
		if ((int)reg >= sc->nfans)
			continue;
		if (OF_getprop(child, "label", label, sizeof(label)) > 0) {
			label[sizeof(label) - 1] = '\0';
			device_printf(sc->dev, "fan%u: %s\n", reg, label);
		}
	}

	i = 0;
	for (child = OF_child(node); child != 0; child = OF_peer(child))
		i++;
	if (i > 0)
		device_printf(sc->dev, "polarity=0x%02x output=0x%02x\n",
		    polarity, output_type);
}

/* ================================================================
 * Probe / Attach / Detach
 * ================================================================ */

static struct ofw_compat_data compat_data[] = {
	{ "microchip,emc2305",	EMC2305_PID_2305 },
	{ "microchip,emc2303",	EMC2305_PID_2303 },
	{ "microchip,emc2302",	EMC2305_PID_2302 },
	{ "microchip,emc2301",	EMC2305_PID_2301 },
	{ NULL,			0 },
};

static const char *
emc2302_chip_name(uint8_t pid)
{

	switch (pid) {
	case EMC2305_PID_2305:	return ("EMC2305");
	case EMC2305_PID_2303:	return ("EMC2303");
	case EMC2305_PID_2302:	return ("EMC2302");
	case EMC2305_PID_2301:	return ("EMC2301");
	default:		return ("EMC23xx");
	}
}

static int
emc2302_nfans_from_pid(uint8_t pid)
{

	switch (pid) {
	case EMC2305_PID_2305:	return (5);
	case EMC2305_PID_2303:	return (3);
	case EMC2305_PID_2302:	return (2);
	case EMC2305_PID_2301:	return (1);
	default:		return (0);
	}
}

static int
emc2302_probe(device_t dev)
{
	const struct ofw_compat_data *cd;
	char desc[80];

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	cd = ofw_bus_search_compatible(dev, compat_data);
	if (cd->ocd_data == 0)
		return (ENXIO);

	snprintf(desc, sizeof(desc), "%s Fan Controller",
	    emc2302_chip_name((uint8_t)cd->ocd_data));
	device_set_desc_copy(dev, desc);

	return (BUS_PROBE_DEFAULT);
}

static int
emc2302_attach(device_t dev)
{
	struct emc2302_softc *sc;
	struct sysctl_oid *tree, *fan_oid;
	uint8_t vendor, pid;
	char fan_name[8];
	int error, i;

	sc = device_get_softc(dev);
	sc->dev = dev;

	/* Verify vendor ID */
	error = emc2302_read8(dev, EMC2305_REG_VENDOR, &vendor);
	if (error != 0) {
		device_printf(dev, "failed to read vendor register\n");
		return (ENXIO);
	}
	if (vendor != EMC2305_VENDOR_MICROCHIP) {
		device_printf(dev, "unexpected vendor ID: 0x%02x\n", vendor);
		return (ENXIO);
	}

	/* Read product ID and determine fan count */
	error = emc2302_read8(dev, EMC2305_REG_PRODUCT_ID, &pid);
	if (error != 0) {
		device_printf(dev, "failed to read product ID\n");
		return (ENXIO);
	}
	sc->product_id = pid;
	sc->nfans = emc2302_nfans_from_pid(pid);
	if (sc->nfans == 0) {
		device_printf(dev, "unknown product ID: 0x%02x\n", pid);
		return (ENXIO);
	}

	device_printf(dev, "%s (product 0x%02x), %d fan channel%s\n",
	    emc2302_chip_name(pid), pid, sc->nfans,
	    sc->nfans > 1 ? "s" : "");

	/* Parse DT child nodes for polarity, output type, min PWM */
	emc2302_parse_dt(sc);

	/* Create sysctl tree */
	sysctl_ctx_init(&sc->sysctl_ctx);
	tree = device_get_sysctl_tree(dev);

	for (i = 0; i < sc->nfans; i++) {
		snprintf(fan_name, sizeof(fan_name), "fan%d", i);

		fan_oid = SYSCTL_ADD_NODE(&sc->sysctl_ctx,
		    SYSCTL_CHILDREN(tree), OID_AUTO, fan_name,
		    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Fan channel");

		SYSCTL_ADD_PROC(&sc->sysctl_ctx,
		    SYSCTL_CHILDREN(fan_oid), OID_AUTO, "pwm",
		    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
		    sc, i, emc2302_sysctl_pwm, "I",
		    "PWM duty cycle (0-255)");

		SYSCTL_ADD_PROC(&sc->sysctl_ctx,
		    SYSCTL_CHILDREN(fan_oid), OID_AUTO, "rpm",
		    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, emc2302_sysctl_rpm, "I",
		    "Fan speed (RPM)");

		SYSCTL_ADD_PROC(&sc->sysctl_ctx,
		    SYSCTL_CHILDREN(fan_oid), OID_AUTO, "fault",
		    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, emc2302_sysctl_fault, "I",
		    "Drive failure (0=ok, 1=fault)");
	}

	return (0);
}

static int
emc2302_detach(device_t dev)
{
	struct emc2302_softc *sc;

	sc = device_get_softc(dev);
	sysctl_ctx_free(&sc->sysctl_ctx);
	return (0);
}

static device_method_t emc2302_methods[] = {
	DEVMETHOD(device_probe,		emc2302_probe),
	DEVMETHOD(device_attach,	emc2302_attach),
	DEVMETHOD(device_detach,	emc2302_detach),
	DEVMETHOD_END
};

static driver_t emc2302_driver = {
	"emc2302",
	emc2302_methods,
	sizeof(struct emc2302_softc),
};

DRIVER_MODULE(emc2302, iicbus, emc2302_driver, NULL, NULL);
MODULE_VERSION(emc2302, 1);
MODULE_DEPEND(emc2302, iicbus, IICBUS_MODVER, IICBUS_MODVER, IICBUS_MODVER);
IICBUS_FDT_PNP_INFO(compat_data);
