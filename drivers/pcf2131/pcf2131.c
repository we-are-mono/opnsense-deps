/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
/*
 * Driver for the NXP PCF2131 real-time clock.
 *
 * The PCF2131 is an enhanced RTC with TCXO, 4 tamper-detect inputs, dual
 * interrupt outputs, and a 1/4 Hz watchdog.  Its register layout is NOT
 * compatible with the older PCF2127/2129 — time registers start at 0x07
 * (not 0x03), extra control registers occupy 0x03-0x05, and watchdog/clkout
 * addresses are completely different.  A previous attempt to use the nxprtc
 * driver (which targets PCF2127/2129) wrote to wrong registers and bricked
 * the chip, so this is a standalone driver.
 *
 * Reference: NXP PCF2131 datasheet (Rev. 2, 2022-06-17) and
 *            Linux rtc-pcf2127.c (PCF2131 support by Hugo Villeneuve).
 */

#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/clock.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/module.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#ifdef FDT
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include "clock_if.h"
#include "iicbus_if.h"

/*
 * PCF2131 register map.
 */
#define	PCF2131_R_CTRL1		0x00
#define	PCF2131_R_CTRL2		0x01
#define	PCF2131_R_CTRL3		0x02
#define	PCF2131_R_CTRL4		0x03
#define	PCF2131_R_CTRL5		0x04
#define	PCF2131_R_SR_RESET	0x05

#define	PCF2131_R_SECOND	0x07	/* Time registers 0x07-0x0D */
#define	PCF2131_R_CLKOUT	0x13
#define	PCF2131_R_WD_CTL	0x35
#define	PCF2131_R_WD_VAL	0x36

/* Interrupt mask registers (write 0 to unmask → enable on INT_A). */
#define	PCF2131_R_INT_A_MASK1	0x31
#define	PCF2131_R_INT_A_MASK2	0x32
#define	PCF2131_R_INT_B_MASK1	0x33
#define	PCF2131_R_INT_B_MASK2	0x34

/* CTRL1 bits */
#define	PCF2131_B_CTRL1_POR_OVRD	0x08	/* Power-On Reset Override */
#define	PCF2131_B_CTRL1_STOP		0x20	/* Stop clock */

/* CTRL3 bits (battery management) */
#define	PCF2131_B_CTRL3_BLF		0x04	/* Battery Low Flag */
#define	PCF2131_B_CTRL3_BF		0x08	/* Battery switch-over Flag */
#define	PCF2131_B_CTRL3_BTSE		0x10	/* Battery timestamp enable */
#define	PCF2131_B_CTRL3_BIE		0x02	/* Battery interrupt enable */
#define	PCF2131_B_CTRL3_BLIE		0x01	/* Battery low int enable */

/* SR_RESET: CPR (Clear Prescaler) command */
#define	PCF2131_CPR_CMD		0xa4	/* BIT(7)|BIT(5)|BIT(2) */

/* CLKOUT bits */
#define	PCF2131_B_CLKOUT_OTPR	0x20	/* OTP refresh */
#define	PCF2131_B_CLKOUT_HIGHZ	0x07	/* Clock output disabled */

/* Seconds register: oscillator stopped flag */
#define	PCF2131_B_SC_OSF	0x80

/* Watchdog control bits */
#define	PCF2131_B_WD_CD1	0x80	/* Watchdog counter disabled / reset */
#define	PCF2131_B_WD_TF1	0x02	/* Timer source flag 1 (1/4 Hz) */

/* BCD time field masks */
#define	PCF2131_M_SECOND	0x7f
#define	PCF2131_M_MINUTE	0x7f
#define	PCF2131_M_24HOUR	0x3f
#define	PCF2131_M_DAY		0x3f
#define	PCF2131_M_MONTH		0x1f
#define	PCF2131_M_YEAR		0xff

/*
 * I2C wait flags: wait for bus, but allow recursive locking so we can
 * do multi-register sequences under a single bus reservation.
 */
#define	WAITFLAGS	(IIC_WAIT | IIC_RECURSIVE)

struct time_regs {
	uint8_t sec, min, hour, day, wday, month, year;
};

struct pcf2131_softc {
	device_t	dev;
	device_t	busdev;
	struct intr_config_hook	config_hook;
};

/*
 * I2C helpers.  The PCF2131 (like PCF2127) requires a STOP condition between
 * the register address write and the data read — no repeated START.
 */
static int
pcf2131_readfrom(device_t slavedev, uint8_t regaddr, void *buffer,
    uint16_t buflen, int waithow)
{
	struct iic_msg msg;
	int err;
	uint8_t slaveaddr;

	slaveaddr = iicbus_get_addr(slavedev);

	msg.slave = slaveaddr;
	msg.flags = IIC_M_WR;
	msg.len   = 1;
	msg.buf   = &regaddr;

	if ((err = iicbus_transfer_excl(slavedev, &msg, 1, waithow)) != 0)
		return (err);

	msg.slave = slaveaddr;
	msg.flags = IIC_M_RD;
	msg.len   = buflen;
	msg.buf   = buffer;

	return (iicbus_transfer_excl(slavedev, &msg, 1, waithow));
}

static int
read_reg(struct pcf2131_softc *sc, uint8_t reg, uint8_t *val)
{

	return (pcf2131_readfrom(sc->dev, reg, val, sizeof(*val), WAITFLAGS));
}

static int
write_reg(struct pcf2131_softc *sc, uint8_t reg, uint8_t val)
{

	return (iicdev_writeto(sc->dev, reg, &val, sizeof(val), WAITFLAGS));
}

static int
read_timeregs(struct pcf2131_softc *sc, struct time_regs *tregs)
{

	return (pcf2131_readfrom(sc->dev, PCF2131_R_SECOND, tregs,
	    sizeof(*tregs), WAITFLAGS));
}

static int
write_timeregs(struct pcf2131_softc *sc, struct time_regs *tregs)
{

	return (iicdev_writeto(sc->dev, PCF2131_R_SECOND, tregs,
	    sizeof(*tregs), WAITFLAGS));
}

/*
 * Chip initialization, called via config_intrhook once interrupts are up.
 */
static void
pcf2131_start(void *arg)
{
	struct pcf2131_softc *sc;
	device_t dev;
	int clockflags, err;
	uint8_t ctrl1, sec, clkout;

	dev = (device_t)arg;
	sc = device_get_softc(dev);
	config_intrhook_disestablish(&sc->config_hook);

	/*
	 * Read CTRL1 and seconds to check for oscillator stop / clock halt.
	 */
	if ((err = read_reg(sc, PCF2131_R_CTRL1, &ctrl1)) != 0) {
		device_printf(dev, "cannot read CTRL1\n");
		return;
	}
	if ((err = read_reg(sc, PCF2131_R_SECOND, &sec)) != 0) {
		device_printf(dev, "cannot read seconds register\n");
		return;
	}

	if ((ctrl1 & PCF2131_B_CTRL1_STOP) || (sec & PCF2131_B_SC_OSF)) {
		device_printf(dev,
		    "WARNING: RTC battery failed; time is invalid\n");

		/*
		 * Clear POR Override bit (used for manufacturing test only).
		 */
		ctrl1 &= ~PCF2131_B_CTRL1_POR_OVRD;
		ctrl1 &= ~PCF2131_B_CTRL1_STOP;
		if ((err = write_reg(sc, PCF2131_R_CTRL1, ctrl1)) != 0) {
			device_printf(dev, "cannot write CTRL1\n");
			return;
		}
	} else {
		/*
		 * Normal operation — still clear POR Override if set.
		 */
		if (ctrl1 & PCF2131_B_CTRL1_POR_OVRD) {
			ctrl1 &= ~PCF2131_B_CTRL1_POR_OVRD;
			if ((err = write_reg(sc, PCF2131_R_CTRL1,
			    ctrl1)) != 0) {
				device_printf(dev, "cannot write CTRL1\n");
				return;
			}
		}
	}

	/*
	 * OTP refresh: trigger if OTPR bit is not set.
	 */
	if ((err = read_reg(sc, PCF2131_R_CLKOUT, &clkout)) != 0) {
		device_printf(dev, "cannot read CLKOUT\n");
		return;
	}
	if (!(clkout & PCF2131_B_CLKOUT_OTPR)) {
		err = write_reg(sc, PCF2131_R_CLKOUT,
		    clkout | PCF2131_B_CLKOUT_OTPR);
		if (err != 0) {
			device_printf(dev, "cannot trigger OTP refresh\n");
			return;
		}
		pause_sbt("pcfotp", mstosbt(100), mstosbt(10), 0);
	}

	/*
	 * Disable battery low/switch-over timestamp and interrupts.
	 * Clear pending battery flags.
	 */
	err = write_reg(sc, PCF2131_R_CTRL3,
	    PCF2131_B_CTRL3_BTSE | PCF2131_B_CTRL3_BIE |
	    PCF2131_B_CTRL3_BLIE);
	/* Clear by writing 0 to BLF/BF while keeping disables set — actually
	 * Linux clears BTSE/BIE/BLIE to 0 (disable all battery interrupts). */
	write_reg(sc, PCF2131_R_CTRL3, 0);

	/*
	 * Route all interrupts to INT_A pin (mask = 0 means enabled).
	 * Mask everything on INT_B.
	 */
	write_reg(sc, PCF2131_R_INT_A_MASK1, 0);
	write_reg(sc, PCF2131_R_INT_A_MASK2, 0);
	write_reg(sc, PCF2131_R_INT_B_MASK1, 0xff);
	write_reg(sc, PCF2131_R_INT_B_MASK2, 0xff);

	/*
	 * Configure watchdog: enable reset output (CD1), 1/4 Hz clock (TF1).
	 * Don't start it (value register = 0).
	 */
	write_reg(sc, PCF2131_R_WD_CTL, PCF2131_B_WD_CD1 | PCF2131_B_WD_TF1);
	write_reg(sc, PCF2131_R_WD_VAL, 0);

	/*
	 * Register as an RTC.  No fractional-second timer on PCF2131, so
	 * resolution is 500ms (half-second rounding like nxprtc without timer).
	 */
	clockflags = CLOCKF_GETTIME_NO_ADJ | CLOCKF_SETTIME_NO_TS;
	clock_register_flags(dev, 1000000 / 2, clockflags);
	clock_schedule(dev, 495000000);

	/*
	 * This driver attaches via config_intrhook, which runs after
	 * inittodr() has already failed with ENXIO (no clock registered).
	 * Re-invoke inittodr() now that the clock is registered so the
	 * system time gets set from the RTC.
	 */
	inittodr(0);
}

static int
pcf2131_gettime(device_t dev, struct timespec *ts)
{
	struct bcd_clocktime bct;
	struct time_regs tregs;
	struct pcf2131_softc *sc;
	int err;
	uint8_t ctrl1;

	sc = device_get_softc(dev);

	if ((err = iicbus_request_bus(sc->busdev, sc->dev, IIC_WAIT)) != 0)
		return (err);
	if ((err = read_timeregs(sc, &tregs)) == 0)
		err = read_reg(sc, PCF2131_R_CTRL1, &ctrl1);
	iicbus_release_bus(sc->busdev, sc->dev);

	if (err != 0)
		return (err);

	if ((tregs.sec & PCF2131_B_SC_OSF) ||
	    (ctrl1 & PCF2131_B_CTRL1_STOP)) {
		device_printf(dev, "RTC clock not running\n");
		return (EINVAL);
	}

	bct.nsec = 0;
	bct.ispm = false;
	bct.sec  = tregs.sec   & PCF2131_M_SECOND;
	bct.min  = tregs.min   & PCF2131_M_MINUTE;
	bct.hour = tregs.hour  & PCF2131_M_24HOUR;
	bct.day  = tregs.day   & PCF2131_M_DAY;
	bct.mon  = tregs.month & PCF2131_M_MONTH;
	bct.year = tregs.year  & PCF2131_M_YEAR;
	bct.dow  = tregs.wday  & 0x07;

	clock_dbgprint_bcd(sc->dev, CLOCK_DBG_READ, &bct);
	err = clock_bcd_to_ts(&bct, ts, false);
	ts->tv_sec += utc_offset();

	return (err);
}

static int
pcf2131_settime(device_t dev, struct timespec *ts)
{
	struct bcd_clocktime bct;
	struct time_regs tregs;
	struct pcf2131_softc *sc;
	int err;
	uint8_t ctrl1;

	sc = device_get_softc(dev);

	if ((err = iicbus_request_bus(sc->busdev, sc->dev, IIC_WAIT)) != 0)
		return (err);

	/*
	 * PCF2131 time write sequence:
	 *   1. Set STOP bit in CTRL1
	 *   2. Write CPR (Clear Prescaler) command to SR_RESET
	 *   3. Write time registers
	 *   4. Clear STOP bit
	 */
	if ((err = read_reg(sc, PCF2131_R_CTRL1, &ctrl1)) != 0)
		goto errout;
	ctrl1 |= PCF2131_B_CTRL1_STOP;
	if ((err = write_reg(sc, PCF2131_R_CTRL1, ctrl1)) != 0)
		goto errout;

	if ((err = write_reg(sc, PCF2131_R_SR_RESET, PCF2131_CPR_CMD)) != 0)
		goto errout;

	/* Grab a fresh post-sleep idea of what time it is. */
	getnanotime(ts);
	ts->tv_sec -= utc_offset();
	ts->tv_nsec = 0;
	clock_ts_to_bcd(ts, &bct, false);
	clock_dbgprint_bcd(sc->dev, CLOCK_DBG_WRITE, &bct);

	tregs.sec   = bct.sec;
	tregs.min   = bct.min;
	tregs.hour  = bct.hour;
	tregs.day   = bct.day;
	tregs.month = bct.mon;
	tregs.year  = bct.year & 0xff;
	tregs.wday  = bct.dow;

	if ((err = write_timeregs(sc, &tregs)) != 0)
		goto errout;

	/* Clear STOP to resume clock. */
	ctrl1 &= ~PCF2131_B_CTRL1_STOP;
	err = write_reg(sc, PCF2131_R_CTRL1, ctrl1);

errout:
	iicbus_release_bus(sc->busdev, sc->dev);

	if (err != 0)
		device_printf(dev, "cannot write RTC time\n");

	return (err);
}

/*
 * FDT compatible strings.
 */
#ifdef FDT
static struct ofw_compat_data compat_data[] = {
	{"nxp,pcf2131",	1},
	{NULL,			0},
};
#endif

static int
pcf2131_probe(device_t dev)
{

#ifdef FDT
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);
	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);
#else
	return (ENXIO);	/* FDT only */
#endif
	device_set_desc(dev, "NXP PCF2131 RTC");
	return (BUS_PROBE_GENERIC);
}

static int
pcf2131_attach(device_t dev)
{
	struct pcf2131_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->busdev = device_get_parent(dev);

	/* Defer init until interrupts are available. */
	sc->config_hook.ich_func = pcf2131_start;
	sc->config_hook.ich_arg = dev;
	if (config_intrhook_establish(&sc->config_hook) != 0)
		return (ENOMEM);

	return (0);
}

static int
pcf2131_detach(device_t dev)
{

	clock_unregister(dev);
	return (0);
}

static device_method_t pcf2131_methods[] = {
	DEVMETHOD(device_probe,		pcf2131_probe),
	DEVMETHOD(device_attach,	pcf2131_attach),
	DEVMETHOD(device_detach,	pcf2131_detach),

	DEVMETHOD(clock_gettime,	pcf2131_gettime),
	DEVMETHOD(clock_settime,	pcf2131_settime),

	DEVMETHOD_END
};

static driver_t pcf2131_driver = {
	"pcf2131",
	pcf2131_methods,
	sizeof(struct pcf2131_softc),
};

DRIVER_MODULE(pcf2131, iicbus, pcf2131_driver, NULL, NULL);
MODULE_VERSION(pcf2131, 1);
MODULE_DEPEND(pcf2131, iicbus, IICBUS_MINVER, IICBUS_PREFVER, IICBUS_MAXVER);
#ifdef FDT
IICBUS_FDT_PNP_INFO(compat_data);
#endif
