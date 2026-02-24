/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 * Author: Tomaz Zaman <tomaz@mono.si>
 *
 * SFP LED Control Driver for FreeBSD (Passive Monitor)
 *
 * Controls SFP port LEDs based on module presence and link state.
 * This driver passively monitors GPIO signals and network interface
 * state without interfering with the SFP subsystem or MAC driver.
 *
 * Detection method:
 *   - Module presence: mod-def0 GPIO (active-low, directly from SFP cage)
 *   - Link state: LOS GPIO (fiber) and/or netdev link state (DAC)
 *   - Activity: Poll netdev tx/rx packet counters
 *   - Cable type: I2C EEPROM bytes 3/8 for DAC vs fiber classification
 *
 * LED behavior:
 *   State                      | Green (Link) | Orange (Activity)
 *   ---------------------------|--------------|-------------------
 *   No module                  | OFF          | OFF
 *   Module present, no link    | OFF          | ON (solid)
 *   Module present, link up    | ON           | Blinks on traffic
 *
 * Device tree binding:
 *   sfp-led-controller {
 *       compatible = "mono,sfp-led";
 *       sfp-ports = <&sfp_xfi0>, <&sfp_xfi1>;
 *   };
 *
 *   // SFP nodes must have leds, mod-def0-gpios, los-gpios, i2c-bus
 *   // LED nodes must have gpios property
 *   // MAC nodes must have sfp = <&sfp_xfiN> for netdev association
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/taskqueue.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/gpio.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/vnet.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

#include <dev/gpio/gpiobusvar.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>

#define	SFPLED_POLL_MS		100
#define	SFPLED_MAX_PORTS	2
#define	SFPLED_MAX_IFP_RETRIES	60	/* 6 seconds at 100ms */

/* SFP EEPROM A0h (address 0x50 = 0xA0 in 8-bit) */
#define	SFP_I2C_ADDR		0xA0
#define	SFP_COMPLIANCE_3	3	/* 10G/1G Ethernet compliance */
#define	SFP_COMPLIANCE_8	8	/* SFP+ cable technology */

/* Byte 3 bits */
#define	SFP_IF_1X_COPPER_PASSIVE	0x01
#define	SFP_IF_1X_COPPER_ACTIVE		0x02

/* Byte 8 bits */
#define	SFP_CT_PASSIVE		0x04
#define	SFP_CT_ACTIVE		0x08

struct sfp_led_port {
	struct sfp_led_softc *sc;
	phandle_t	sfp_node;	/* SFP DT node handle */
	pcell_t		sfp_xref;	/* SFP DT xref (raw phandle value) */

	/* GPIO pins (acquired lazily from SFP + LED DT nodes) */
	gpio_pin_t	mod_def0;	/* module present (active-low) */
	gpio_pin_t	los;		/* loss of signal (active-high) */
	gpio_pin_t	link_led;	/* green LED */
	gpio_pin_t	activity_led;	/* orange LED */
	bool		gpio_acquired;
	bool		gpio_failed;	/* permanent failure, stop retrying */

	/* LED DT node phandles (read at attach, used for GPIO acquisition) */
	pcell_t		link_led_xref;
	pcell_t		activity_led_xref;

	/* I2C bus (resolved lazily from SFP node's i2c-bus property) */
	pcell_t		i2c_xref;	/* i2c-bus phandle from DT */
	device_t	iicbus;		/* resolved I2C bus device */
	bool		i2c_resolved;
	bool		i2c_valid;	/* true if i2c_xref was found in DT */

	/* Network interface (resolved lazily) */
	if_t		ifp;
	int		ifp_retries;

	/* Cached state */
	bool		last_present;
	bool		last_link;
	bool		is_dac;
	uint64_t	last_tx_pkts;
	uint64_t	last_rx_pkts;
	bool		activity_on;

	int		index;
};

struct sfp_led_softc {
	device_t		dev;
	int			nports;
	struct sfp_led_port	ports[SFPLED_MAX_PORTS];
	struct timeout_task	poll_task;
};

static int sfpled_probe(device_t dev);
static int sfpled_attach(device_t dev);
static int sfpled_detach(device_t dev);
static void sfpled_poll(void *arg, int pending);

/* ----------------------------------------------------------------
 * GPIO acquisition (lazy — gpiobus may not be ready at attach time)
 * ---------------------------------------------------------------- */

static bool
sfpled_acquire_gpios(struct sfp_led_port *port)
{
	device_t dev = port->sc->dev;
	phandle_t led_node;
	int err;

	/* Acquire mod-def0 GPIO from SFP node */
	err = gpio_pin_get_by_ofw_property(dev, port->sfp_node,
	    "mod-def0-gpios", &port->mod_def0);
	if (err != 0) {
		if (err == ENODEV)
			return (false);	/* gpiobus not ready, retry later */
		device_printf(dev, "sfp%d: mod-def0 GPIO error: %d\n",
		    port->index, err);
		port->gpio_failed = true;
		return (false);
	}

	/* Acquire LOS GPIO from SFP node */
	err = gpio_pin_get_by_ofw_property(dev, port->sfp_node,
	    "los-gpios", &port->los);
	if (err != 0) {
		device_printf(dev, "sfp%d: los GPIO error: %d\n",
		    port->index, err);
		gpio_pin_release(port->mod_def0);
		port->mod_def0 = NULL;
		port->gpio_failed = true;
		return (false);
	}

	/* Acquire link LED GPIO from LED DT node */
	led_node = OF_node_from_xref(port->link_led_xref);
	err = gpio_pin_get_by_ofw_idx(dev, led_node, 0, &port->link_led);
	if (err != 0) {
		device_printf(dev, "sfp%d: link LED GPIO error: %d\n",
		    port->index, err);
		gpio_pin_release(port->los);
		port->los = NULL;
		gpio_pin_release(port->mod_def0);
		port->mod_def0 = NULL;
		port->gpio_failed = true;
		return (false);
	}
	gpio_pin_setflags(port->link_led, GPIO_PIN_OUTPUT);

	/* Acquire activity LED GPIO from LED DT node */
	led_node = OF_node_from_xref(port->activity_led_xref);
	err = gpio_pin_get_by_ofw_idx(dev, led_node, 0, &port->activity_led);
	if (err != 0) {
		device_printf(dev, "sfp%d: activity LED GPIO error: %d\n",
		    port->index, err);
		gpio_pin_release(port->link_led);
		port->link_led = NULL;
		gpio_pin_release(port->los);
		port->los = NULL;
		gpio_pin_release(port->mod_def0);
		port->mod_def0 = NULL;
		port->gpio_failed = true;
		return (false);
	}
	gpio_pin_setflags(port->activity_led, GPIO_PIN_OUTPUT);

	port->gpio_acquired = true;
	device_printf(dev, "sfp%d: GPIOs acquired\n", port->index);

	return (true);
}

/* ----------------------------------------------------------------
 * I2C helpers (for DAC cable detection)
 * ---------------------------------------------------------------- */

static void
sfpled_resolve_i2c(struct sfp_led_port *port)
{
	port->i2c_resolved = true;

	if (!port->i2c_valid)
		return;

	port->iicbus = OF_device_from_xref(port->i2c_xref);
	if (port->iicbus == NULL) {
		device_printf(port->sc->dev,
		    "sfp%d: i2c-bus not yet available\n", port->index);
		port->i2c_resolved = false;	/* retry next poll */
	}
}

static int
sfpled_i2c_read_byte(struct sfp_led_port *port, uint8_t reg, uint8_t *val)
{
	struct iic_msg msgs[2];
	int err;

	if (port->iicbus == NULL)
		return (ENXIO);

	msgs[0].slave = SFP_I2C_ADDR;
	msgs[0].flags = IIC_M_WR | IIC_M_NOSTOP;
	msgs[0].len = 1;
	msgs[0].buf = &reg;

	msgs[1].slave = SFP_I2C_ADDR;
	msgs[1].flags = IIC_M_RD;
	msgs[1].len = 1;
	msgs[1].buf = val;

	err = iicbus_request_bus(port->iicbus, port->sc->dev, IIC_WAIT);
	if (err != 0)
		return (err);

	err = iicbus_transfer(port->iicbus, msgs, 2);

	iicbus_release_bus(port->iicbus, port->sc->dev);
	return (err);
}

static bool
sfpled_is_dac(struct sfp_led_port *port)
{
	uint8_t byte3, byte8;

	if (sfpled_i2c_read_byte(port, SFP_COMPLIANCE_3, &byte3) != 0)
		return (false);

	if (sfpled_i2c_read_byte(port, SFP_COMPLIANCE_8, &byte8) != 0)
		return (false);

	return ((byte3 & (SFP_IF_1X_COPPER_PASSIVE | SFP_IF_1X_COPPER_ACTIVE)) ||
	    (byte8 & (SFP_CT_PASSIVE | SFP_CT_ACTIVE)));
}

/* ----------------------------------------------------------------
 * Network interface lookup (lazy — dtsec may not be ready yet)
 *
 * Must be called outside NET_EPOCH or will wrap internally.
 * ---------------------------------------------------------------- */

static void
sfpled_find_ifp(struct sfp_led_port *port)
{
	devclass_t dc;
	device_t dev;
	phandle_t node;
	pcell_t sfp_ref;
	char ifname[IFNAMSIZ];
	if_t ifp;
	int unit, maxunit;

	/*
	 * The DPAA dtsec driver registers as devclass "dtsec" but names
	 * its interfaces "ethN".  Walk the dtsec devclass to find the
	 * device whose DT node has an "sfp" property matching our SFP
	 * phandle, then look up the interface by constructed name.
	 */
	dc = devclass_find("dtsec");
	if (dc == NULL)
		return;

	maxunit = devclass_get_maxunit(dc);
	for (unit = 0; unit < maxunit; unit++) {
		dev = devclass_get_device(dc, unit);
		if (dev == NULL)
			continue;

		node = ofw_bus_get_node(dev);
		if (node <= 0)
			continue;

		if (OF_getencprop(node, "sfp", &sfp_ref,
		    sizeof(sfp_ref)) <= 0)
			continue;

		if (OF_node_from_xref(sfp_ref) != port->sfp_node)
			continue;

		/* Found matching device — look up its network interface.
		 * ifunit_ref needs CURVNET context (VIMAGE taskqueue
		 * threads have curvnet=NULL). */
		snprintf(ifname, sizeof(ifname), "%s%d",
		    device_get_name(dev), device_get_unit(dev));
		CURVNET_SET(vnet0);
		ifp = ifunit_ref(ifname);
		CURVNET_RESTORE();
		if (ifp != NULL) {
			port->ifp = ifp;
			device_printf(port->sc->dev,
			    "sfp%d: associated with %s\n",
			    port->index, ifname);
		}
		return;
	}
}

/* ----------------------------------------------------------------
 * LED control helpers
 * ---------------------------------------------------------------- */

static void
sfpled_set_link(struct sfp_led_port *port, bool on)
{

	if (port->link_led != NULL)
		gpio_pin_set_active(port->link_led, on);
}

static void
sfpled_set_activity(struct sfp_led_port *port, bool on)
{

	if (port->activity_led != NULL)
		gpio_pin_set_active(port->activity_led, on);
}

/* ----------------------------------------------------------------
 * Poll handler — runs every 100ms in taskqueue_thread
 * ---------------------------------------------------------------- */

static void
sfpled_poll_port(struct sfp_led_port *port)
{
	bool present, link;

	/* Lazy GPIO acquisition */
	if (!port->gpio_acquired) {
		if (port->gpio_failed)
			return;
		if (!sfpled_acquire_gpios(port))
			return;
	}

	/* Module presence via mod-def0 GPIO (active-low: active=true means
	 * present, because gpio_pin_is_active accounts for GPIO_ACTIVE_LOW) */
	gpio_pin_is_active(port->mod_def0, &present);

	/* Handle module insertion/removal */
	if (present != port->last_present) {
		port->last_present = present;

		if (!present) {
			/* Module removed */
			sfpled_set_link(port, false);
			sfpled_set_activity(port, false);
			port->last_link = false;
			port->is_dac = false;
			port->activity_on = false;
			port->last_tx_pkts = 0;
			port->last_rx_pkts = 0;
		} else {
			/* Module inserted — detect cable type, show present */
			sfpled_set_link(port, false);
			sfpled_set_activity(port, true);

			/* Lazy I2C resolution */
			if (!port->i2c_resolved)
				sfpled_resolve_i2c(port);

			if (port->iicbus != NULL) {
				port->is_dac = sfpled_is_dac(port);
				device_printf(port->sc->dev,
				    "sfp%d: module inserted (%s)\n",
				    port->index,
				    port->is_dac ? "DAC" : "fiber");
			} else {
				device_printf(port->sc->dev,
				    "sfp%d: module inserted (no I2C)\n",
				    port->index);
			}
		}
	}

	if (!present)
		return;

	/* Lazy netdev lookup */
	if (port->ifp == NULL && port->ifp_retries < SFPLED_MAX_IFP_RETRIES) {
		sfpled_find_ifp(port);
		port->ifp_retries++;
	}

	/*
	 * Link detection:
	 * - Fiber: LOS GPIO (active-high, so active=true means signal LOST)
	 * - DAC: netdev link state (LOS may not be connected on DAC cables)
	 * - Combined: link if LOS clear OR netdev reports LINK_STATE_UP
	 */
	link = false;

	/* Check LOS GPIO — works reliably for fiber */
	{
		bool los_active;
		gpio_pin_is_active(port->los, &los_active);
		if (!los_active)
			link = true;	/* LOS not asserted = signal present */
	}

	/* Also check netdev link state — covers DAC and all cases */
	if (!link && port->ifp != NULL) {
		if (if_getlinkstate(port->ifp) == LINK_STATE_UP)
			link = true;
	}

	/* Handle link state changes */
	if (link != port->last_link) {
		port->last_link = link;
		sfpled_set_link(port, link);

		if (link) {
			/* Link up — start activity monitoring */
			sfpled_set_activity(port, false);
			port->last_tx_pkts = 0;
			port->last_rx_pkts = 0;
			port->activity_on = false;
		} else {
			/* Link down — solid activity to show module present */
			sfpled_set_activity(port, true);
			port->activity_on = false;
		}
	}

	if (!link)
		return;

	/* Activity monitoring — blink on traffic */
	if (port->ifp != NULL &&
	    (if_getflags(port->ifp) & IFF_UP) != 0) {
		uint64_t tx = if_getcounter(port->ifp, IFCOUNTER_OPACKETS);
		uint64_t rx = if_getcounter(port->ifp, IFCOUNTER_IPACKETS);

		if (tx != port->last_tx_pkts || rx != port->last_rx_pkts) {
			/* Traffic — toggle LED for visible blink */
			port->activity_on = !port->activity_on;
			sfpled_set_activity(port, port->activity_on);
			port->last_tx_pkts = tx;
			port->last_rx_pkts = rx;
		} else if (port->activity_on) {
			/* No traffic — turn off */
			port->activity_on = false;
			sfpled_set_activity(port, false);
		}
	}
}

static void
sfpled_poll(void *arg, int pending)
{
	struct sfp_led_softc *sc = arg;
	int i;

	for (i = 0; i < sc->nports; i++)
		sfpled_poll_port(&sc->ports[i]);

	taskqueue_enqueue_timeout(taskqueue_thread, &sc->poll_task,
	    hz / (1000 / SFPLED_POLL_MS));
}

/* ----------------------------------------------------------------
 * Device methods
 * ---------------------------------------------------------------- */

static int
sfpled_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);
	if (!ofw_bus_is_compatible(dev, "mono,sfp-led"))
		return (ENXIO);

	device_set_desc(dev, "SFP LED Controller");
	return (BUS_PROBE_DEFAULT);
}

static int
sfpled_attach(device_t dev)
{
	struct sfp_led_softc *sc;
	phandle_t node;
	pcell_t sfp_phandles[SFPLED_MAX_PORTS];
	pcell_t led_phandles[2];
	ssize_t len;
	int nports, i, registered;

	sc = device_get_softc(dev);
	sc->dev = dev;

	node = ofw_bus_get_node(dev);

	/* Read sfp-ports phandle array */
	len = OF_getencprop(node, "sfp-ports", sfp_phandles,
	    sizeof(sfp_phandles));
	if (len <= 0) {
		device_printf(dev, "no sfp-ports property\n");
		return (ENXIO);
	}
	nports = len / sizeof(pcell_t);
	if (nports > SFPLED_MAX_PORTS)
		nports = SFPLED_MAX_PORTS;

	registered = 0;
	for (i = 0; i < nports; i++) {
		struct sfp_led_port *port = &sc->ports[i];

		port->sc = sc;
		port->index = i;
		port->sfp_xref = sfp_phandles[i];
		port->sfp_node = OF_node_from_xref(sfp_phandles[i]);

		if (port->sfp_node <= 0) {
			device_printf(dev, "sfp%d: invalid phandle\n", i);
			continue;
		}

		/* Read LED phandles from SFP node's "leds" property */
		len = OF_getencprop(port->sfp_node, "leds", led_phandles,
		    sizeof(led_phandles));
		if (len < (ssize_t)(2 * sizeof(pcell_t))) {
			device_printf(dev,
			    "sfp%d: need 2 LED phandles in leds property\n",
			    i);
			continue;
		}
		port->link_led_xref = led_phandles[0];
		port->activity_led_xref = led_phandles[1];

		/* Read i2c-bus phandle from SFP node */
		if (OF_getencprop(port->sfp_node, "i2c-bus",
		    &port->i2c_xref, sizeof(port->i2c_xref)) > 0) {
			port->i2c_valid = true;
		}

		registered++;
	}

	if (registered == 0) {
		device_printf(dev, "no valid SFP ports\n");
		return (ENXIO);
	}

	sc->nports = nports;

	/* Start polling */
	TIMEOUT_TASK_INIT(taskqueue_thread, &sc->poll_task, 0,
	    sfpled_poll, sc);
	taskqueue_enqueue_timeout(taskqueue_thread, &sc->poll_task, hz);

	device_printf(dev, "%d SFP port(s) registered\n", registered);
	return (0);
}

static int
sfpled_detach(device_t dev)
{
	struct sfp_led_softc *sc = device_get_softc(dev);
	int i;

	/* Stop polling */
	taskqueue_drain_timeout(taskqueue_thread, &sc->poll_task);

	for (i = 0; i < sc->nports; i++) {
		struct sfp_led_port *port = &sc->ports[i];

		/* Turn off LEDs */
		sfpled_set_link(port, false);
		sfpled_set_activity(port, false);

		/* Release GPIO pins */
		if (port->activity_led != NULL)
			gpio_pin_release(port->activity_led);
		if (port->link_led != NULL)
			gpio_pin_release(port->link_led);
		if (port->los != NULL)
			gpio_pin_release(port->los);
		if (port->mod_def0 != NULL)
			gpio_pin_release(port->mod_def0);

		/* Release network interface reference */
		if (port->ifp != NULL)
			if_rele(port->ifp);
	}

	device_printf(dev, "detached\n");
	return (0);
}

static device_method_t sfpled_methods[] = {
	DEVMETHOD(device_probe,		sfpled_probe),
	DEVMETHOD(device_attach,	sfpled_attach),
	DEVMETHOD(device_detach,	sfpled_detach),
	DEVMETHOD_END
};

DEFINE_CLASS_0(sfpled, sfpled_driver, sfpled_methods,
    sizeof(struct sfp_led_softc));

DRIVER_MODULE(sfpled, simplebus, sfpled_driver, 0, 0);
DRIVER_MODULE(sfpled, ofwbus, sfpled_driver, 0, 0);
MODULE_DEPEND(sfpled, gpiobus, 1, 1, 1);
MODULE_DEPEND(sfpled, iicbus, 1, 1, 1);
