/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * Texas Instruments INA219/INA226/INA234 I2C power monitor driver.
 * Reads bus voltage, shunt voltage, current, and power from
 * INA2xx-family digital power monitors over I2C.
 *
 * Based on Linux hwmon/ina2xx.c by Lothar Felten.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

/* INA2xx register addresses */
#define	INA2XX_CONFIG		0x00
#define	INA2XX_SHUNT_VOLTAGE	0x01
#define	INA2XX_BUS_VOLTAGE	0x02
#define	INA2XX_POWER		0x03
#define	INA2XX_CURRENT		0x04
#define	INA2XX_CALIBRATION	0x05

/* Default shunt resistance: 10 mOhm = 10000 uOhm */
#define	INA2XX_RSHUNT_DEFAULT	10000

/* Chip type enumeration */
enum ina2xx_chip { INA219, INA226, INA234 };

/* Per-chip-type configuration constants */
struct ina2xx_config {
	uint16_t	config_default;
	uint16_t	calibration_value;
	int		shunt_div;	/* shunt voltage divider (LSB factor) */
	int		bus_voltage_shift;
	int		bus_voltage_lsb;	/* uV per LSB */
	int		power_lsb_factor;
};

static const struct ina2xx_config ina2xx_configs[] = {
	[INA219] = {
		.config_default		= 0x399F,	/* PGA /8 */
		.calibration_value	= 4096,
		.shunt_div		= 100,
		.bus_voltage_shift	= 3,
		.bus_voltage_lsb	= 4000,		/* 4 mV */
		.power_lsb_factor	= 20,
	},
	[INA226] = {
		.config_default		= 0x4527,	/* avg=16 */
		.calibration_value	= 2048,
		.shunt_div		= 400,
		.bus_voltage_shift	= 0,
		.bus_voltage_lsb	= 1250,		/* 1.25 mV */
		.power_lsb_factor	= 25,
	},
	[INA234] = {
		.config_default		= 0x4527,	/* same as INA226 */
		.calibration_value	= 2048,
		.shunt_div		= 400,
		.bus_voltage_shift	= 4,
		.bus_voltage_lsb	= 25600,	/* 25.6 mV */
		.power_lsb_factor	= 32,
	},
};

struct ina2xx_softc {
	device_t		dev;
	enum ina2xx_chip	chip;
	const struct ina2xx_config *config;
	uint32_t		rshunt;		/* shunt resistance, uOhm */
	long			current_lsb_uA;
	long			power_lsb_uW;
	struct sysctl_ctx_list	sysctl_ctx;
	char			label[64];
};

/* ================================================================
 * I2C register helpers — 16-bit big-endian
 * ================================================================ */

static int
ina2xx_read_reg(device_t dev, uint8_t reg, uint16_t *val)
{
	uint8_t buf[2];
	int error;

	error = iicdev_readfrom(dev, reg, buf, 2, IIC_WAIT);
	if (error != 0)
		return (error);
	*val = (buf[0] << 8) | buf[1];
	return (0);
}

static int
ina2xx_write_reg(device_t dev, uint8_t reg, uint16_t val)
{
	uint8_t buf[2];

	buf[0] = (val >> 8) & 0xFF;
	buf[1] = val & 0xFF;
	return (iicdev_writeto(dev, reg, buf, 2, IIC_WAIT));
}

/* ================================================================
 * Measurement value conversion (matches Linux ina2xx_get_value)
 * ================================================================ */

static int
ina2xx_read_bus_voltage(struct ina2xx_softc *sc, int *millivolts)
{
	uint16_t raw;
	int error;

	error = ina2xx_read_reg(sc->dev, INA2XX_BUS_VOLTAGE, &raw);
	if (error != 0)
		return (error);
	*millivolts = ((raw >> sc->config->bus_voltage_shift) *
	    sc->config->bus_voltage_lsb) / 1000;
	return (0);
}

static int
ina2xx_read_shunt_voltage(struct ina2xx_softc *sc, int *microvolts)
{
	uint16_t raw;
	int error;

	error = ina2xx_read_reg(sc->dev, INA2XX_SHUNT_VOLTAGE, &raw);
	if (error != 0)
		return (error);
	/* Shunt voltage register is signed */
	*microvolts = (int16_t)raw * 1000 / sc->config->shunt_div;
	return (0);
}

static int
ina2xx_read_current(struct ina2xx_softc *sc, int *milliamps)
{
	uint16_t raw;
	int error;

	error = ina2xx_read_reg(sc->dev, INA2XX_CURRENT, &raw);
	if (error != 0)
		return (error);
	/* Current register is signed */
	*milliamps = (int16_t)raw * sc->current_lsb_uA / 1000;
	return (0);
}

static int
ina2xx_read_power(struct ina2xx_softc *sc, int *milliwatts)
{
	uint16_t raw;
	int error;

	error = ina2xx_read_reg(sc->dev, INA2XX_POWER, &raw);
	if (error != 0)
		return (error);
	/* Power register is unsigned */
	*milliwatts = (int)((uint32_t)raw * sc->power_lsb_uW / 1000);
	return (0);
}

/* ================================================================
 * Sysctl handlers
 * ================================================================ */

static int
ina2xx_sysctl_bus_voltage(SYSCTL_HANDLER_ARGS)
{
	struct ina2xx_softc *sc = arg1;
	int val, error;

	if (req->newptr != NULL)
		return (EINVAL);
	error = ina2xx_read_bus_voltage(sc, &val);
	if (error != 0)
		return (error);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

static int
ina2xx_sysctl_shunt_voltage(SYSCTL_HANDLER_ARGS)
{
	struct ina2xx_softc *sc = arg1;
	int val, error;

	if (req->newptr != NULL)
		return (EINVAL);
	error = ina2xx_read_shunt_voltage(sc, &val);
	if (error != 0)
		return (error);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

static int
ina2xx_sysctl_current(SYSCTL_HANDLER_ARGS)
{
	struct ina2xx_softc *sc = arg1;
	int val, error;

	if (req->newptr != NULL)
		return (EINVAL);
	error = ina2xx_read_current(sc, &val);
	if (error != 0)
		return (error);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

static int
ina2xx_sysctl_power(SYSCTL_HANDLER_ARGS)
{
	struct ina2xx_softc *sc = arg1;
	int val, error;

	if (req->newptr != NULL)
		return (EINVAL);
	error = ina2xx_read_power(sc, &val);
	if (error != 0)
		return (error);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

/* ================================================================
 * Probe / Attach / Detach
 * ================================================================ */

static struct ofw_compat_data compat_data[] = {
	{ "ti,ina219",	(uintptr_t)INA219 },
	{ "ti,ina220",	(uintptr_t)INA219 },
	{ "ti,ina226",	(uintptr_t)INA226 },
	{ "ti,ina230",	(uintptr_t)INA226 },
	{ "ti,ina231",	(uintptr_t)INA226 },
	{ "ti,ina234",	(uintptr_t)INA234 },
	{ NULL,		0 },
};

static int
ina2xx_probe(device_t dev)
{
	const struct ofw_compat_data *cd;
	phandle_t node;
	char desc[80];
	char label[64];

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	cd = ofw_bus_search_compatible(dev, compat_data);
	if (cd->ocd_data == 0)
		return (ENXIO);

	node = ofw_bus_get_node(dev);
	if (OF_getprop(node, "label", label, sizeof(label)) > 0)
		snprintf(desc, sizeof(desc), "INA2xx Power Monitor (%s)",
		    label);
	else
		snprintf(desc, sizeof(desc), "INA2xx Power Monitor");
	device_set_desc_copy(dev, desc);

	return (BUS_PROBE_DEFAULT);
}

static int
ina2xx_attach(device_t dev)
{
	struct ina2xx_softc *sc;
	const struct ofw_compat_data *cd;
	phandle_t node;
	struct sysctl_oid *oid;
	uint32_t shunt;
	long dividend;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;

	cd = ofw_bus_search_compatible(dev, compat_data);
	sc->chip = (enum ina2xx_chip)cd->ocd_data;
	sc->config = &ina2xx_configs[sc->chip];

	node = ofw_bus_get_node(dev);

	/* Read shunt resistance from DT (micro-ohms), default 10 mOhm */
	if (OF_getencprop(node, "shunt-resistor", &shunt, sizeof(shunt)) <= 0)
		shunt = INA2XX_RSHUNT_DEFAULT;
	sc->rshunt = shunt;

	/* Read label from DT */
	sc->label[0] = '\0';
	OF_getprop(node, "label", sc->label, sizeof(sc->label));
	sc->label[sizeof(sc->label) - 1] = '\0';

	/* Compute current and power LSBs */
	dividend = 1000000000L / sc->config->shunt_div;
	sc->current_lsb_uA = dividend / (long)sc->rshunt;
	sc->power_lsb_uW = sc->config->power_lsb_factor * sc->current_lsb_uA;

	/* Program configuration register */
	error = ina2xx_write_reg(dev, INA2XX_CONFIG,
	    sc->config->config_default);
	if (error != 0) {
		device_printf(dev, "failed to write config register\n");
		return (ENXIO);
	}

	/* Program calibration register */
	error = ina2xx_write_reg(dev, INA2XX_CALIBRATION,
	    sc->config->calibration_value);
	if (error != 0) {
		device_printf(dev, "failed to write calibration register\n");
		return (ENXIO);
	}

	/* Create sysctl tree */
	sysctl_ctx_init(&sc->sysctl_ctx);
	oid = device_get_sysctl_tree(dev);

	if (sc->label[0] != '\0') {
		SYSCTL_ADD_STRING(&sc->sysctl_ctx, SYSCTL_CHILDREN(oid),
		    OID_AUTO, "label", CTLFLAG_RD, sc->label, 0,
		    "Sensor label");
	}

	SYSCTL_ADD_PROC(&sc->sysctl_ctx, SYSCTL_CHILDREN(oid),
	    OID_AUTO, "bus_voltage",
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, 0, ina2xx_sysctl_bus_voltage, "I",
	    "Bus voltage (mV)");

	SYSCTL_ADD_PROC(&sc->sysctl_ctx, SYSCTL_CHILDREN(oid),
	    OID_AUTO, "shunt_voltage",
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, 0, ina2xx_sysctl_shunt_voltage, "I",
	    "Shunt voltage (uV)");

	SYSCTL_ADD_PROC(&sc->sysctl_ctx, SYSCTL_CHILDREN(oid),
	    OID_AUTO, "current",
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, 0, ina2xx_sysctl_current, "I",
	    "Current (mA)");

	SYSCTL_ADD_PROC(&sc->sysctl_ctx, SYSCTL_CHILDREN(oid),
	    OID_AUTO, "power",
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, 0, ina2xx_sysctl_power, "I",
	    "Power (mW)");

	if (sc->label[0] != '\0')
		device_printf(dev, "%s: shunt=%u uOhm, "
		    "current_lsb=%ld uA, power_lsb=%ld uW\n",
		    sc->label, sc->rshunt,
		    sc->current_lsb_uA, sc->power_lsb_uW);

	return (0);
}

static int
ina2xx_detach(device_t dev)
{
	struct ina2xx_softc *sc;

	sc = device_get_softc(dev);
	sysctl_ctx_free(&sc->sysctl_ctx);
	return (0);
}

static device_method_t ina2xx_methods[] = {
	DEVMETHOD(device_probe,		ina2xx_probe),
	DEVMETHOD(device_attach,	ina2xx_attach),
	DEVMETHOD(device_detach,	ina2xx_detach),
	DEVMETHOD_END
};

static driver_t ina2xx_driver = {
	"ina2xx",
	ina2xx_methods,
	sizeof(struct ina2xx_softc),
};

DRIVER_MODULE(ina2xx, iicbus, ina2xx_driver, NULL, NULL);
MODULE_VERSION(ina2xx, 1);
MODULE_DEPEND(ina2xx, iicbus, IICBUS_MODVER, IICBUS_MODVER, IICBUS_MODVER);
IICBUS_FDT_PNP_INFO(compat_data);
