/*
 * FCI (Fast Control Interface) — FreeBSD kernel module
 *
 * Provides /dev/fci char device with ioctl for synchronous commands
 * and kqueue/kevent for async event delivery from CDX.
 *
 * Replaces the Linux netlink-based fci.c.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/event.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/uio.h>
#include <sys/proc.h>

#include "fci_freebsd.h"

MALLOC_DEFINE(M_FCI, "fci", "Fast Control Interface");

/* Forward declarations */
static d_open_t		fci_open;
static d_close_t	fci_close;
static d_ioctl_t	fci_ioctl;
static d_kqfilter_t	fci_kqfilter;

static struct cdevsw fci_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	fci_open,
	.d_close =	fci_close,
	.d_ioctl =	fci_ioctl,
	.d_kqfilter =	fci_kqfilter,
	.d_name =	"fci",
};

/*
 * Per-device softc.
 */
struct fci_softc {
	struct cdev	*sc_cdev;
	struct sx	 sc_lock;		/* protects event ring */
	struct selinfo	 sc_selinfo;		/* for kqueue */

	/* Event ring buffer (CDX → userspace) */
	struct fci_event sc_events[FCI_MAX_EVENTS];
	int		 sc_ev_head;		/* next write position */
	int		 sc_ev_tail;		/* next read position */

	/* CDX interface — registered at CDX load time */
	fci_send_command_fn sc_send_command;	/* dispatch to CDX */
	fci_event_cb_fn	    sc_event_cb;		/* CDX sets this for event delivery */

	/* Stats (exported via sysctl) */
	unsigned long	 stat_tx_msg;
	unsigned long	 stat_rx_msg;
	unsigned long	 stat_tx_err;
	unsigned long	 stat_rx_err;
	unsigned long	 stat_mem_err;
};

static struct fci_softc *fci_sc;

/* ----------------------------------------------------------------
 * Event ring buffer helpers
 * ---------------------------------------------------------------- */
static inline int
fci_ev_count(struct fci_softc *sc)
{
	return ((sc->sc_ev_head - sc->sc_ev_tail + FCI_MAX_EVENTS)
	    % FCI_MAX_EVENTS);
}

static inline int
fci_ev_full(struct fci_softc *sc)
{
	return (fci_ev_count(sc) == FCI_MAX_EVENTS - 1);
}

static inline int
fci_ev_empty(struct fci_softc *sc)
{
	return (sc->sc_ev_head == sc->sc_ev_tail);
}

/* ----------------------------------------------------------------
 * sx lock wrappers for knlist — knlist_init_sx doesn't exist in
 * FreeBSD 15, so we provide generic callbacks.
 * ---------------------------------------------------------------- */
static void
fci_kl_sx_lock(void *arg)
{
	sx_xlock((struct sx *)arg);
}

static void
fci_kl_sx_unlock(void *arg)
{
	sx_xunlock((struct sx *)arg);
}

static void
fci_kl_sx_assert(void *arg, int what)
{
	if (what == LA_LOCKED)
		sx_assert((struct sx *)arg, SA_LOCKED);
	else
		sx_assert((struct sx *)arg, SA_UNLOCKED);
}

/* ----------------------------------------------------------------
 * CDX → FCI event delivery callback
 *
 * Called from CDX (possibly in interrupt context) when an async
 * event needs to be delivered to userspace listeners.
 * ---------------------------------------------------------------- */
static int
fci_event_deliver(uint16_t fcode, uint16_t length, uint16_t *payload)
{
	struct fci_softc *sc = fci_sc;
	struct fci_event *ev;

	if (sc == NULL)
		return (-1);

	sx_xlock(&sc->sc_lock);

	if (fci_ev_full(sc)) {
		static struct timeval lastlog;
		static int curpps;

		if (ppsratecheck(&lastlog, &curpps, 1))
			printf("fci: event ring full, dropping event "
			    "(total drops: %lu)\n", sc->stat_mem_err + 1);
		sc->stat_mem_err++;
		sx_xunlock(&sc->sc_lock);
		return (-ENOMEM);
	}

	ev = &sc->sc_events[sc->sc_ev_head];
	ev->fcode = fcode;
	ev->length = (length > FCI_MSG_MAX_PAYLOAD) ?
	    FCI_MSG_MAX_PAYLOAD : length;
	memcpy(ev->payload, payload, ev->length);

	sc->sc_ev_head = (sc->sc_ev_head + 1) % FCI_MAX_EVENTS;
	sc->stat_tx_msg++;

	sx_xunlock(&sc->sc_lock);

	/* Wake kqueue listeners */
	KNOTE_UNLOCKED(&sc->sc_selinfo.si_note, 0);

	return (0);
}

/* ----------------------------------------------------------------
 * cdevsw entry points
 * ---------------------------------------------------------------- */
static int
fci_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return (0);
}

static int
fci_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	return (0);
}

static int
fci_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int fflag,
    struct thread *td)
{
	struct fci_softc *sc = fci_sc;
	int error;

	switch (cmd) {
	case FCI_IOC_CMD: {
		struct fci_ioc_msg *msg = (struct fci_ioc_msg *)addr;
		uint16_t rep_len;

		sc->stat_rx_msg++;

		if (sc->sc_send_command != NULL) {
			rep_len = msg->rep_len;
			error = sc->sc_send_command(msg->fcode, msg->cmd_len,
			    (uint16_t *)msg->payload, &rep_len,
			    (uint16_t *)msg->payload);
			msg->rep_len = rep_len;
			msg->status = (error == 0) ? 0 : (uint16_t)error;
		} else {
			/*
			 * CDX not loaded — return NO_ERR stub response.
			 * This allows testing FCI in isolation.
			 */
			msg->payload[0] = 0;	/* NO_ERR */
			msg->payload[1] = 0;
			msg->rep_len = 2;
			msg->status = 0;
		}

		return (0);
	}

	case FCI_IOC_READ_EVT: {
		struct fci_event *dst = (struct fci_event *)addr;
		struct fci_event *ev;

		sx_xlock(&sc->sc_lock);

		if (fci_ev_empty(sc)) {
			sx_xunlock(&sc->sc_lock);
			return (EAGAIN);
		}

		ev = &sc->sc_events[sc->sc_ev_tail];
		memcpy(dst, ev, sizeof(*dst));
		sc->sc_ev_tail = (sc->sc_ev_tail + 1) % FCI_MAX_EVENTS;

		sx_xunlock(&sc->sc_lock);
		return (0);
	}

	default:
		return (ENOTTY);
	}
}

/* ----------------------------------------------------------------
 * kqueue support — allows userspace to poll for async events
 * ---------------------------------------------------------------- */
static void fci_kq_detach(struct knote *kn);
static int  fci_kq_event(struct knote *kn, long hint);

static struct filterops fci_filterops = {
	.f_isfd =	1,
	.f_detach =	fci_kq_detach,
	.f_event =	fci_kq_event,
};

static int
fci_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct fci_softc *sc = fci_sc;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &fci_filterops;
		kn->kn_hook = sc;
		knlist_add(&sc->sc_selinfo.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static void
fci_kq_detach(struct knote *kn)
{
	struct fci_softc *sc = kn->kn_hook;

	knlist_remove(&sc->sc_selinfo.si_note, kn, 0);
}

static int
fci_kq_event(struct knote *kn, long hint)
{
	struct fci_softc *sc = kn->kn_hook;
	int count;

	/* Lock already held by knlist via fci_kl_sx_lock */
	count = fci_ev_count(sc);
	kn->kn_data = count;
	return (count > 0);
}

/* ----------------------------------------------------------------
 * Cross-module registration API
 *
 * CDX calls these at load time to connect itself to FCI.
 * ---------------------------------------------------------------- */

/*
 * Register CDX's command dispatch function.
 * FCI will call this for every FCI_IOC_CMD ioctl.
 */
void
fci_register_send_command(fci_send_command_fn fn)
{
	if (fci_sc != NULL)
		fci_sc->sc_send_command = fn;
}

/*
 * Give CDX a pointer to our event callback so CDX can set it.
 * (Unused in the simple design — we use fci_event_deliver directly.)
 */
void
fci_register_event_cb(fci_event_cb_fn *cb_ptr)
{
	if (fci_sc != NULL && cb_ptr != NULL)
		*cb_ptr = fci_event_deliver;
}

/*
 * Legacy API: comcerto_fpp_send_command
 *
 * In the Linux code, this is defined in CDX (cdx_cmdhandler.c) and
 * called by FCI. On FreeBSD, the CDX module calls
 * fci_register_send_command() to register its handler, and FCI
 * dispatches through the function pointer.
 *
 * This wrapper is provided so that code still calling the old name
 * (e.g., CDX internal code) continues to work.
 */
int
comcerto_fpp_send_command(uint16_t fcode, uint16_t length,
    uint16_t *payload, uint16_t *rlen, uint16_t *rbuf)
{
	if (fci_sc != NULL && fci_sc->sc_send_command != NULL)
		return (fci_sc->sc_send_command(fcode, length, payload,
		    rlen, rbuf));

	/* Stub: no CDX loaded */
	rbuf[0] = 0;	/* NO_ERR */
	*rlen = 2;
	return (0);
}

/*
 * Legacy API: comcerto_fpp_register_event_cb
 *
 * In the Linux code, FCI calls this (defined in CDX) to register
 * its event callback. On FreeBSD, we store the callback pointer
 * directly. CDX calls this at init time with fci_outbound_fe_data
 * equivalent.
 */
int
comcerto_fpp_register_event_cb(void *cb)
{
	/* On FreeBSD, this is handled by fci_register_event_cb.
	 * Keep this as a no-op for source compat. */
	(void)cb;
	return (0);
}

/* ----------------------------------------------------------------
 * Sysctl stats — defined in fci_sysctl.c
 * ---------------------------------------------------------------- */
extern void fci_sysctl_init(unsigned long *tx_msg, unsigned long *rx_msg,
    unsigned long *tx_err, unsigned long *rx_err, unsigned long *mem_err);
extern void fci_sysctl_fini(void);

/* ----------------------------------------------------------------
 * Module load / unload
 * ---------------------------------------------------------------- */
static int
fci_modevent(module_t mod, int type, void *unused)
{
	struct fci_softc *sc;

	switch (type) {
	case MOD_LOAD:
		sc = malloc(sizeof(*sc), M_FCI, M_WAITOK | M_ZERO);

		sx_init(&sc->sc_lock, "fci_lock");
		knlist_init(&sc->sc_selinfo.si_note, &sc->sc_lock,
		    fci_kl_sx_lock, fci_kl_sx_unlock, fci_kl_sx_assert);

		sc->sc_cdev = make_dev(&fci_cdevsw, 0,
		    UID_ROOT, GID_WHEEL, 0600, "fci");
		if (sc->sc_cdev == NULL) {
			knlist_destroy(&sc->sc_selinfo.si_note);
			sx_destroy(&sc->sc_lock);
			free(sc, M_FCI);
			return (ENXIO);
		}

		fci_sc = sc;

		fci_sysctl_init(&sc->stat_tx_msg, &sc->stat_rx_msg,
		    &sc->stat_tx_err, &sc->stat_rx_err, &sc->stat_mem_err);

		printf("fci: Fast Control Interface loaded\n");
		return (0);

	case MOD_UNLOAD:
		sc = fci_sc;
		if (sc == NULL)
			return (0);

		fci_sc = NULL;

		fci_sysctl_fini();

		if (sc->sc_cdev != NULL)
			destroy_dev(sc->sc_cdev);

		knlist_destroy(&sc->sc_selinfo.si_note);
		sx_destroy(&sc->sc_lock);
		free(sc, M_FCI);

		printf("fci: Fast Control Interface unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

DEV_MODULE(fci, fci_modevent, NULL);
MODULE_VERSION(fci, 1);
