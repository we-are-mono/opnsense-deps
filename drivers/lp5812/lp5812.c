/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 * Author: Tomaz Zaman <tomaz@mono.si>
 *
 * TI LP5812 I2C LED Driver for FreeBSD
 *
 * Controls up to 12 LED channels via I2C in direct (non-multiplexed) mode.
 * Each LED is exposed as /dev/led/<label> for on/off/blink control and as
 * a sysctl node (dev.lp5812.N.<label>) for PWM brightness (0-255).
 *
 * The LP5812 uses a non-standard I2C addressing scheme where register
 * address bits [9:8] are encoded in the I2C slave address field:
 *   slave = base_addr | (reg[9:8] << 1)    (FreeBSD 8-bit addressing)
 *   data  = { reg[7:0], value }
 *
 * Device tree binding:
 *   lp5812@6c {
 *       compatible = "ti,lp5812";
 *       reg = <0x6c>;
 *       #address-cells = <1>;
 *       #size-cells = <0>;
 *
 *       led@0 {
 *           reg = <0>;
 *           label = "status:white";
 *           led-max-microamp = <25500>;
 *       };
 *       // ... more LED children
 *   };
 */

#include <sys/cdefs.h>
#include "opt_platform.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include <dev/led/led.h>

#ifdef FDT
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include "iicbus_if.h"

/* ----------------------------------------------------------------
 * LP5812 Register definitions (from leds-lp5812.h)
 * ---------------------------------------------------------------- */

#define	LP5812_REG_ENABLE		0x0000
#define	LP5812_DEV_CONFIG1		0x0002
#define	LP5812_DEV_CONFIG2		0x0003
#define	LP5812_DEV_CONFIG3		0x0004
#define	LP5812_DEV_CONFIG4		0x0005
#define	LP5812_DEV_CONFIG12		0x000D
#define	LP5812_CMD_UPDATE		0x0010
#define	LP5812_LED_EN_1			0x0020
#define	LP5812_LED_EN_2			0x0021
#define	LP5812_MANUAL_DC_BASE		0x0030
#define	LP5812_MANUAL_PWM_BASE		0x0040
#define	LP5812_AUTO_DC_BASE		0x0050
#define	LP5812_TSD_CONFIG_STATUS	0x0300

#define	LP5812_UPDATE_CMD_VAL		0x55
#define	LP5812_LSD_LOD_START_UP		0x0B
#define	LP5812_LEDS_PER_EN_REG		8

#define	LP5812_MAX_LEDS			12

/* ----------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------- */

struct lp5812_led {
	struct lp5812_softc *sc;
	struct cdev	*leddev;	/* /dev/led/ handle */
	char		 name[32];	/* DT label, e.g. "status:white" */
	int		 channel;	/* LP5812 channel (0-11) */
	uint8_t		 max_current;	/* led-max-microamp / 100 */
	uint8_t		 brightness;	/* current PWM value 0-255 */
};

struct lp5812_softc {
	device_t	 sc_dev;
	uint16_t	 sc_addr;	/* 8-bit base I2C address */
	int		 sc_nleds;
	struct lp5812_led sc_leds[LP5812_MAX_LEDS];
};

/* ----------------------------------------------------------------
 * I2C register access
 *
 * LP5812 encodes register address bits [9:8] into the I2C slave
 * address.  FreeBSD uses 8-bit addresses (7-bit << 1), so the
 * page bits go into bits [2:1] of the slave field.
 * ---------------------------------------------------------------- */

static int
lp5812_write_reg(struct lp5812_softc *sc, uint16_t reg, uint8_t val)
{
	uint8_t buf[2];
	struct iic_msg msg;

	buf[0] = reg & 0xFF;
	buf[1] = val;

	msg.slave = sc->sc_addr | (((reg >> 8) & 0x3) << 1);
	msg.flags = IIC_M_WR;
	msg.len = 2;
	msg.buf = buf;

	return (iicbus_transfer_excl(sc->sc_dev, &msg, 1, IIC_WAIT));
}

static int
lp5812_read_reg(struct lp5812_softc *sc, uint16_t reg, uint8_t *val)
{
	uint8_t regbyte;
	uint16_t slave;
	struct iic_msg msgs[2];

	slave = sc->sc_addr | (((reg >> 8) & 0x3) << 1);
	regbyte = reg & 0xFF;

	msgs[0].slave = slave;
	msgs[0].flags = IIC_M_WR | IIC_M_NOSTOP;
	msgs[0].len = 1;
	msgs[0].buf = &regbyte;

	msgs[1].slave = slave;
	msgs[1].flags = IIC_M_RD;
	msgs[1].len = 1;
	msgs[1].buf = val;

	return (iicbus_transfer_excl(sc->sc_dev, msgs, 2, IIC_WAIT));
}

/* ----------------------------------------------------------------
 * Chip control helpers
 * ---------------------------------------------------------------- */

static int
lp5812_update_config(struct lp5812_softc *sc)
{
	uint8_t status;
	int err;

	err = lp5812_write_reg(sc, LP5812_CMD_UPDATE, LP5812_UPDATE_CMD_VAL);
	if (err != 0)
		return (err);

	err = lp5812_read_reg(sc, LP5812_TSD_CONFIG_STATUS, &status);
	if (err != 0)
		return (err);

	if (status & 0x01) {
		device_printf(sc->sc_dev, "config error (status=0x%02x)\n",
		    status);
		return (EIO);
	}

	return (0);
}

static int
lp5812_init_device(struct lp5812_softc *sc)
{
	int err;

	/* Stabilization delay (1ms, matches Linux driver) */
	DELAY(1100);

	/* Enable chip */
	err = lp5812_write_reg(sc, LP5812_REG_ENABLE, 0x01);
	if (err != 0) {
		device_printf(sc->sc_dev, "chip enable failed: %d\n", err);
		return (err);
	}

	/* Configure LSD/LOD startup detection */
	err = lp5812_write_reg(sc, LP5812_DEV_CONFIG12, LP5812_LSD_LOD_START_UP);
	if (err != 0) {
		device_printf(sc->sc_dev, "DEV_CONFIG12 write failed: %d\n",
		    err);
		return (err);
	}

	/* Direct mode: drive_mode = 0, scan_order = 0 */
	err = lp5812_write_reg(sc, LP5812_DEV_CONFIG1, 0x00);
	if (err != 0)
		return (err);

	err = lp5812_write_reg(sc, LP5812_DEV_CONFIG2, 0x00);
	if (err != 0)
		return (err);

	/* Apply configuration */
	err = lp5812_update_config(sc);
	if (err != 0) {
		device_printf(sc->sc_dev, "config update failed: %d\n", err);
		return (err);
	}

	return (0);
}

static void
lp5812_deinit_device(struct lp5812_softc *sc)
{

	lp5812_write_reg(sc, LP5812_LED_EN_1, 0x00);
	lp5812_write_reg(sc, LP5812_LED_EN_2, 0x00);
	lp5812_write_reg(sc, LP5812_REG_ENABLE, 0x00);
}

static int
lp5812_set_brightness(struct lp5812_softc *sc, int channel, uint8_t pwm)
{

	return (lp5812_write_reg(sc, LP5812_MANUAL_PWM_BASE + channel, pwm));
}

static int
lp5812_setup_led(struct lp5812_softc *sc, struct lp5812_led *led)
{
	uint16_t en_reg;
	uint16_t mode_reg;
	uint8_t reg_val;
	int ch = led->channel;
	int err;

	/* Set auto-DC (autonomous mode current limit) */
	err = lp5812_write_reg(sc, LP5812_AUTO_DC_BASE + ch, led->max_current);
	if (err != 0)
		return (err);

	/* Set manual-DC (manual mode current) */
	err = lp5812_write_reg(sc, LP5812_MANUAL_DC_BASE + ch, led->max_current);
	if (err != 0)
		return (err);

	/* Set manual mode: clear the bit for this LED in DEV_CONFIG3/4 */
	mode_reg = (ch < LP5812_LEDS_PER_EN_REG) ?
	    LP5812_DEV_CONFIG3 : LP5812_DEV_CONFIG4;

	err = lp5812_read_reg(sc, mode_reg, &reg_val);
	if (err != 0)
		return (err);

	reg_val &= ~(1 << (ch % LP5812_LEDS_PER_EN_REG));
	err = lp5812_write_reg(sc, mode_reg, reg_val);
	if (err != 0)
		return (err);

	err = lp5812_update_config(sc);
	if (err != 0)
		return (err);

	/* Enable this LED channel */
	en_reg = (ch < LP5812_LEDS_PER_EN_REG) ?
	    LP5812_LED_EN_1 : LP5812_LED_EN_2;

	err = lp5812_read_reg(sc, en_reg, &reg_val);
	if (err != 0)
		return (err);

	reg_val |= (1 << (ch % LP5812_LEDS_PER_EN_REG));
	err = lp5812_write_reg(sc, en_reg, reg_val);
	if (err != 0)
		return (err);

	/* Set initial brightness to 0 (off) */
	err = lp5812_set_brightness(sc, ch, 0);
	if (err != 0)
		return (err);

	led->brightness = 0;

	return (0);
}

/* ----------------------------------------------------------------
 * /dev/led/ callback
 * ---------------------------------------------------------------- */

static void
lp5812_led_control(void *priv, int onoff)
{
	struct lp5812_led *led = priv;
	uint8_t pwm;

	pwm = onoff ? 255 : 0;
	if (lp5812_set_brightness(led->sc, led->channel, pwm) == 0)
		led->brightness = pwm;
}

/* ----------------------------------------------------------------
 * Sysctl brightness handler
 * ---------------------------------------------------------------- */

static int
lp5812_brightness_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct lp5812_led *led = (struct lp5812_led *)arg1;
	unsigned int val;
	int err;

	val = led->brightness;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val > 255)
		val = 255;

	err = lp5812_set_brightness(led->sc, led->channel, (uint8_t)val);
	if (err != 0)
		return (EIO);

	led->brightness = (uint8_t)val;
	return (0);
}

/* ----------------------------------------------------------------
 * Deferred init (called after I2C bus is fully ready)
 * ---------------------------------------------------------------- */

static void
lp5812_start(void *arg)
{
	device_t dev = arg;
	struct lp5812_softc *sc = device_get_softc(dev);
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	phandle_t node, child;
	pcell_t reg;
	uint32_t max_microamp;
	char *label;
	char sysctl_name[32];
	int nleds, i, err;

	/* Initialize the chip */
	err = lp5812_init_device(sc);
	if (err != 0) {
		device_printf(dev, "device init failed: %d\n", err);
		return;
	}

	/* Count and parse DT LED children */
	node = ofw_bus_get_node(dev);
	nleds = 0;

	for (child = OF_child(node); child != 0; child = OF_peer(child)) {
		if (nleds >= LP5812_MAX_LEDS)
			break;

		if (OF_getencprop(child, "reg", &reg, sizeof(reg)) <= 0)
			continue;

		struct lp5812_led *led = &sc->sc_leds[nleds];

		led->sc = sc;
		led->channel = (int)reg;

		/* Read label */
		label = NULL;
		if (OF_getprop_alloc(child, "label", (void **)&label) == -1)
			OF_getprop_alloc(child, "name", (void **)&label);

		if (label != NULL) {
			strlcpy(led->name, label, sizeof(led->name));
			OF_prop_free(label);
		} else {
			snprintf(led->name, sizeof(led->name), "lp5812_%d",
			    led->channel);
		}

		/* Read max current (microamps → value/100 for register) */
		max_microamp = 25500;	/* default */
		OF_getencprop(child, "led-max-microamp", &max_microamp,
		    sizeof(max_microamp));
		led->max_current = (uint8_t)(max_microamp / 100);

		/* Configure this LED channel on the chip */
		err = lp5812_setup_led(sc, led);
		if (err != 0) {
			device_printf(dev, "%s: setup failed: %d\n",
			    led->name, err);
			continue;
		}

		/* Create /dev/led/<label> */
		led->leddev = led_create_state(lp5812_led_control, led,
		    led->name, 0);
		if (led->leddev == NULL)
			device_printf(dev, "%s: led_create failed\n",
			    led->name);

		nleds++;
	}

	sc->sc_nleds = nleds;

	/* Create sysctl brightness nodes */
	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);

	for (i = 0; i < sc->sc_nleds; i++) {
		struct lp5812_led *led = &sc->sc_leds[i];

		/* Convert "status:red" → "status_red" for sysctl name */
		strlcpy(sysctl_name, led->name, sizeof(sysctl_name));
		for (char *p = sysctl_name; *p != '\0'; p++) {
			if (*p == ':' || *p == '-' || *p == '.')
				*p = '_';
		}

		SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
		    sysctl_name,
		    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
		    led, 0, lp5812_brightness_sysctl, "IU",
		    "LED brightness (0-255)");
	}

	device_printf(dev, "%d LED(s) configured\n", sc->sc_nleds);
}

/* ----------------------------------------------------------------
 * Device methods
 * ---------------------------------------------------------------- */

#ifdef FDT
static struct ofw_compat_data compat_data[] = {
	{ "ti,lp5812",	1 },
	{ NULL,		0 }
};
#endif

static int
lp5812_probe(device_t dev)
{

#ifdef FDT
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);
	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);
#endif

	device_set_desc(dev, "TI LP5812 LED Controller");
	return (BUS_PROBE_DEFAULT);
}

static int
lp5812_attach(device_t dev)
{
	struct lp5812_softc *sc;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_addr = iicbus_get_addr(dev);

	/* Defer init until I2C bus is fully operational */
	config_intrhook_oneshot(lp5812_start, dev);

	return (0);
}

static int
lp5812_detach(device_t dev)
{
	struct lp5812_softc *sc = device_get_softc(dev);
	int i;

	/* Destroy /dev/led/ devices */
	for (i = 0; i < sc->sc_nleds; i++) {
		if (sc->sc_leds[i].leddev != NULL)
			led_destroy(sc->sc_leds[i].leddev);
	}

	/* Turn off all LEDs and disable chip */
	lp5812_deinit_device(sc);

	device_printf(dev, "detached\n");
	return (0);
}

static device_method_t lp5812_methods[] = {
	DEVMETHOD(device_probe,		lp5812_probe),
	DEVMETHOD(device_attach,	lp5812_attach),
	DEVMETHOD(device_detach,	lp5812_detach),
	DEVMETHOD_END
};

static driver_t lp5812_driver = {
	"lp5812",
	lp5812_methods,
	sizeof(struct lp5812_softc),
};

DRIVER_MODULE(lp5812, iicbus, lp5812_driver, NULL, NULL);
MODULE_VERSION(lp5812, 1);
MODULE_DEPEND(lp5812, iicbus, IICBUS_MINVER, IICBUS_PREFVER, IICBUS_MAXVER);
#ifdef FDT
IICBUS_FDT_PNP_INFO(compat_data);
#endif
