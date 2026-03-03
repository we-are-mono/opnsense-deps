/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * TI TMP431 dual-channel temperature sensor driver.
 * Each chip has a local (die) and remote (external diode) channel.
 * Readings are exported under sysctl hw.temperature.* in decikelvin.
 *
 * Based on Linux drivers/hwmon/tmp401.c by Hans de Goede and Guenter Roeck.
 */

#include "opt_platform.h"

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

/* Temperature registers (read) */
#define	TMP431_LOCAL_TEMP_MSB		0x00
#define	TMP431_REMOTE_TEMP_MSB		0x01
#define	TMP431_LOCAL_TEMP_LSB		0x15
#define	TMP431_REMOTE_TEMP_LSB		0x10

/* Status register */
#define	TMP431_STATUS			0x02
#define	TMP431_STATUS_REMOTE_OPEN	(1 << 2)

/* Configuration register (different read/write addresses) */
#define	TMP431_CONFIG_R			0x03
#define	TMP431_CONFIG_W			0x09
#define	TMP431_CONFIG_RANGE		(1 << 2)
#define	TMP431_CONFIG_SHUTDOWN		(1 << 6)

/* Conversion rate register (different read/write addresses) */
#define	TMP431_CONV_RATE_W		0x0A
#define	TMP431_CONV_RATE_2HZ		5

/* Identification registers */
#define	TMP431_MANUFACTURER_ID		0xFE
#define	TMP431_DEVICE_ID		0xFF
#define	TMP431_MFR_ID_TI		0x55
#define	TMP431_DEV_ID_TMP431		0x31

/* Channel indices for sysctl arg2 */
#define	TMP431_CHAN_LOCAL		0
#define	TMP431_CHAN_REMOTE		1

struct tmp431_softc {
	device_t		dev;
	struct mtx		mtx;
	bool			extended_range;
	char			label[64];
	char			name_local[80];
	char			name_remote[80];
	struct sysctl_ctx_list	sysctl_ctx;
};

/* ================================================================
 * I2C register helpers
 * ================================================================ */

static int
tmp431_read8(device_t dev, uint8_t reg, uint8_t *val)
{

	return (iicdev_readfrom(dev, reg, val, 1, IIC_WAIT));
}

static int
tmp431_write8(device_t dev, uint8_t reg, uint8_t val)
{

	return (iicdev_writeto(dev, reg, &val, 1, IIC_WAIT));
}

/*
 * Read a 16-bit temperature register atomically.
 * The TMP431 supports SMBus word reads: reading from the MSB register
 * returns MSB in the first byte and LSB in the second byte, all in
 * one I2C transaction.  This avoids torn reads between conversions.
 */
static int
tmp431_read_temp16(device_t dev, uint8_t msb_reg, uint16_t *val)
{
	uint8_t buf[2];
	int error;

	error = iicdev_readfrom(dev, msb_reg, buf, 2, IIC_WAIT);
	if (error != 0)
		return (error);

	*val = ((uint16_t)buf[0] << 8) | buf[1];
	return (0);
}

/* ================================================================
 * Temperature conversion
 * ================================================================ */

/*
 * Convert TMP431 raw 16-bit register value to decikelvin.
 *
 * Raw format: MSB[7:0] << 8 | LSB[7:0], bits [15:4] meaningful.
 * Standard range: unsigned, 0 to 127°C.
 * Extended range: subtract 64*256 for signed, -64 to 191°C.
 *
 * millideg_C = (raw * 125) / 32
 * decikelvin = millideg_C / 100 + 2731
 *            = (raw * 125) / 3200 + 2731
 */
static int
tmp431_raw_to_decikelvin(uint16_t raw, bool extended_range)
{
	int32_t reg, milli;

	reg = (int32_t)(raw & ~0xf);
	if (extended_range)
		reg -= 64 * 256;

	milli = reg * 125;
	if (milli >= 0)
		return ((milli + 1600) / 3200 + 2731);
	else
		return ((milli - 1600) / 3200 + 2731);
}

/* ================================================================
 * Sysctl handler
 * ================================================================ */

static int
tmp431_sysctl_temp(SYSCTL_HANDLER_ARGS)
{
	struct tmp431_softc *sc = arg1;
	int channel = arg2;
	uint8_t status;
	uint8_t msb_reg;
	uint16_t raw;
	int error, val;

	if (req->newptr != NULL)
		return (EINVAL);

	if (channel == TMP431_CHAN_LOCAL)
		msb_reg = TMP431_LOCAL_TEMP_MSB;
	else
		msb_reg = TMP431_REMOTE_TEMP_MSB;

	mtx_lock(&sc->mtx);

	error = tmp431_read_temp16(sc->dev, msb_reg, &raw);
	if (error != 0) {
		mtx_unlock(&sc->mtx);
		return (EIO);
	}

	/*
	 * For the remote channel, check for open/fault diode.
	 * The chip sets STATUS_REMOTE_OPEN when it detects an open circuit,
	 * but doesn't always do so reliably.  A raw reading of 0x0000
	 * (0°C exactly) also indicates no diode is connected — this board
	 * never operates at 0°C ambient so the false positive is acceptable.
	 */
	if (channel == TMP431_CHAN_REMOTE) {
		error = tmp431_read8(sc->dev, TMP431_STATUS, &status);
		if (error != 0) {
			mtx_unlock(&sc->mtx);
			return (EIO);
		}
		if ((status & TMP431_STATUS_REMOTE_OPEN) ||
		    (raw & ~0xf) == 0) {
			mtx_unlock(&sc->mtx);
			return (ENXIO);
		}
	}

	mtx_unlock(&sc->mtx);

	val = tmp431_raw_to_decikelvin(raw, sc->extended_range);

	return (sysctl_handle_int(oidp, &val, 0, req));
}

/* ================================================================
 * Probe / Attach / Detach
 * ================================================================ */

static struct ofw_compat_data compat_data[] = {
	{ "ti,tmp431",	1 },
	{ NULL,		0 },
};

static int
tmp431_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "TI TMP431 Temperature Sensor");

	return (BUS_PROBE_DEFAULT);
}

static int
tmp431_attach(device_t dev)
{
	struct tmp431_softc *sc;
	struct sysctl_oid *temp_oid;
	phandle_t node;
	uint8_t mfr_id = 0, dev_id = 0, config;
	int error, unit;

	sc = device_get_softc(dev);
	sc->dev = dev;

	/* Verify manufacturer and device ID */
	error = tmp431_read8(dev, TMP431_MANUFACTURER_ID, &mfr_id);
	if (error != 0 || mfr_id != TMP431_MFR_ID_TI) {
		device_printf(dev, "unexpected manufacturer ID: 0x%02x\n",
		    mfr_id);
		return (ENXIO);
	}

	error = tmp431_read8(dev, TMP431_DEVICE_ID, &dev_id);
	if (error != 0 || dev_id != TMP431_DEV_ID_TMP431) {
		device_printf(dev, "unexpected device ID: 0x%02x\n", dev_id);
		return (ENXIO);
	}

	mtx_init(&sc->mtx, "tmp431", NULL, MTX_DEF);

	/* Set conversion rate to 2 Hz */
	error = tmp431_write8(dev, TMP431_CONV_RATE_W, TMP431_CONV_RATE_2HZ);
	if (error != 0) {
		device_printf(dev, "failed to set conversion rate\n");
		goto fail;
	}

	/* Clear shutdown bit, optionally enable extended range */
	error = tmp431_read8(dev, TMP431_CONFIG_R, &config);
	if (error != 0) {
		device_printf(dev, "failed to read config\n");
		goto fail;
	}

	config &= ~TMP431_CONFIG_SHUTDOWN;

	node = ofw_bus_get_node(dev);
	if (node > 0 && OF_hasprop(node, "ti,extended-range-enable"))
		config |= TMP431_CONFIG_RANGE;

	sc->extended_range = !!(config & TMP431_CONFIG_RANGE);

	error = tmp431_write8(dev, TMP431_CONFIG_W, config);
	if (error != 0) {
		device_printf(dev, "failed to write config\n");
		goto fail;
	}

	/* Read label from DT, fall back to "tmpN" */
	sc->label[0] = '\0';
	if (node > 0)
		OF_getprop(node, "label", sc->label, sizeof(sc->label));
	sc->label[sizeof(sc->label) - 1] = '\0';

	unit = device_get_unit(dev);
	if (sc->label[0] != '\0') {
		snprintf(sc->name_local, sizeof(sc->name_local),
		    "%s-local", sc->label);
		snprintf(sc->name_remote, sizeof(sc->name_remote),
		    "%s-remote", sc->label);
	} else {
		snprintf(sc->name_local, sizeof(sc->name_local),
		    "tmp%d-local", unit);
		snprintf(sc->name_remote, sizeof(sc->name_remote),
		    "tmp%d-remote", unit);
	}

	/* Create sysctl entries under hw.temperature */
	sysctl_ctx_init(&sc->sysctl_ctx);

	temp_oid = SYSCTL_ADD_NODE(&sc->sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_hw), OID_AUTO, "temperature",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL,
	    "Temperature sensors");
	if (temp_oid == NULL) {
		device_printf(dev, "failed to create hw.temperature node\n");
		goto fail_sysctl;
	}

	SYSCTL_ADD_PROC(&sc->sysctl_ctx,
	    SYSCTL_CHILDREN(temp_oid), OID_AUTO, sc->name_local,
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, TMP431_CHAN_LOCAL, tmp431_sysctl_temp,
	    "IK", "TMP431 local die temperature");

	SYSCTL_ADD_PROC(&sc->sysctl_ctx,
	    SYSCTL_CHILDREN(temp_oid), OID_AUTO, sc->name_remote,
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, TMP431_CHAN_REMOTE, tmp431_sysctl_temp,
	    "IK", "TMP431 remote diode temperature");

	device_printf(dev, "TMP431 %s, %s range\n",
	    sc->label[0] != '\0' ? sc->label : "unlabeled",
	    sc->extended_range ? "extended" : "standard");

	return (0);

fail_sysctl:
	sysctl_ctx_free(&sc->sysctl_ctx);
fail:
	mtx_destroy(&sc->mtx);
	return (ENXIO);
}

static int
tmp431_detach(device_t dev)
{
	struct tmp431_softc *sc;
	uint8_t config;

	sc = device_get_softc(dev);

	/* Remove sysctl entries first to drain any in-progress readers */
	sysctl_ctx_free(&sc->sysctl_ctx);

	/* Put chip in shutdown mode */
	if (tmp431_read8(dev, TMP431_CONFIG_R, &config) == 0) {
		config |= TMP431_CONFIG_SHUTDOWN;
		tmp431_write8(dev, TMP431_CONFIG_W, config);
	}

	mtx_destroy(&sc->mtx);

	return (0);
}

/* ================================================================
 * Module registration
 * ================================================================ */

static device_method_t tmp431_methods[] = {
	DEVMETHOD(device_probe,		tmp431_probe),
	DEVMETHOD(device_attach,	tmp431_attach),
	DEVMETHOD(device_detach,	tmp431_detach),
	DEVMETHOD_END
};

static driver_t tmp431_driver = {
	"tmp431",
	tmp431_methods,
	sizeof(struct tmp431_softc),
};

DRIVER_MODULE(tmp431, iicbus, tmp431_driver, NULL, NULL);
MODULE_VERSION(tmp431, 1);
MODULE_DEPEND(tmp431, iicbus, IICBUS_MODVER, IICBUS_MODVER, IICBUS_MODVER);
IICBUS_FDT_PNP_INFO(compat_data);
