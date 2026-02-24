/*
 * pf_notify.c — PF state change notification kernel module
 *
 * Hooks into PF's pfnotify_*_state_ptr callbacks to push state
 * lifecycle events (insert/ready/delete) to userspace via a
 * character device (/dev/pfnotify).  CMM reads events to drive
 * hardware flow offload without polling the full state table.
 *
 * Follows the auto_bridge chardev + ring buffer + kqueue pattern.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/pfvar.h>
#include <netinet/tcp_fsm.h>

#include "pf_notify.h"

/* --- Ring buffer -------------------------------------------------- */

#define PFN_RING_SIZE		4096	/* must be power of 2 */
#define PFN_RING_MASK		(PFN_RING_SIZE - 1)

struct pfn_ring {
	struct pfn_event	events[PFN_RING_SIZE];
	volatile uint32_t	head;
	volatile uint32_t	tail;
};

static inline int
ring_empty(const struct pfn_ring *r)
{

	return (r->head == r->tail);
}

static inline int
ring_full(const struct pfn_ring *r)
{

	return (((r->head + 1) & PFN_RING_MASK) == r->tail);
}

static inline uint32_t
ring_count(const struct pfn_ring *r)
{

	return ((r->head - r->tail) & PFN_RING_MASK);
}

static int
ring_put(struct pfn_ring *r, const struct pfn_event *ev)
{

	if (ring_full(r))
		return (ENOSPC);
	r->events[r->head] = *ev;
	r->head = (r->head + 1) & PFN_RING_MASK;
	return (0);
}

static int
ring_get(struct pfn_ring *r, struct pfn_event *ev)
{

	if (ring_empty(r))
		return (EAGAIN);
	*ev = r->events[r->tail];
	r->tail = (r->tail + 1) & PFN_RING_MASK;
	return (0);
}

/* --- One-shot notification tracker -------------------------------- */

/*
 * Module-local hash for UPDATE one-shot tracking.
 * Indexed by state ID — prevents re-queuing READY events for
 * already-notified states (UPDATE hooks fire per-packet).
 * Collisions overwrite silently; worst case is a harmless
 * duplicate READY event that CMM handles idempotently.
 */
#define PFN_NOTIFIED_SIZE	16384
#define PFN_NOTIFIED_MASK	(PFN_NOTIFIED_SIZE - 1)

static uint64_t pfn_notified[PFN_NOTIFIED_SIZE];

static inline int
pfn_is_notified(uint64_t id)
{

	return (pfn_notified[id & PFN_NOTIFIED_MASK] == id);
}

static inline void
pfn_mark_notified(uint64_t id)
{

	pfn_notified[id & PFN_NOTIFIED_MASK] = id;
}

static inline void
pfn_clear_notified(uint64_t id)
{

	if (pfn_notified[id & PFN_NOTIFIED_MASK] == id)
		pfn_notified[id & PFN_NOTIFIED_MASK] = 0;
}

/* --- Global state ------------------------------------------------- */

static struct mtx	pfn_mtx;
static struct pfn_ring	pfn_ring;
static struct selinfo	pfn_rsel;
static int		pfn_open;	/* only one client */
static struct cdev	*pfn_cdev;

/* Statistics */
static uint64_t		pfn_events_total;
static uint64_t		pfn_events_dropped;

static struct sysctl_ctx_list	pfn_sysctl_ctx;

/* --- Event construction ------------------------------------------- */

static void
pfn_fill_event(struct pfn_event *ev, uint8_t type, struct pf_kstate *s)
{

	memset(ev, 0, sizeof(*ev));
	ev->type = type;
	ev->direction = s->direction;
	ev->src_state = s->src.state;
	ev->dst_state = s->dst.state;
	ev->id = s->id;
	ev->creatorid = s->creatorid;
	ev->state_flags = s->state_flags;
	strlcpy(ev->ifname, s->kif->pfik_name, sizeof(ev->ifname));

	/* Wire key (PF_SK_WIRE = 0) */
	memcpy(ev->key[0].addr[0], &s->key[PF_SK_WIRE]->addr[0],
	    sizeof(ev->key[0].addr[0]));
	memcpy(ev->key[0].addr[1], &s->key[PF_SK_WIRE]->addr[1],
	    sizeof(ev->key[0].addr[1]));
	ev->key[0].port[0] = s->key[PF_SK_WIRE]->port[0];
	ev->key[0].port[1] = s->key[PF_SK_WIRE]->port[1];
	ev->key[0].af = s->key[PF_SK_WIRE]->af;
	ev->key[0].proto = s->key[PF_SK_WIRE]->proto;

	/* Stack key (PF_SK_STACK = 1) */
	memcpy(ev->key[1].addr[0], &s->key[PF_SK_STACK]->addr[0],
	    sizeof(ev->key[1].addr[0]));
	memcpy(ev->key[1].addr[1], &s->key[PF_SK_STACK]->addr[1],
	    sizeof(ev->key[1].addr[1]));
	ev->key[1].port[0] = s->key[PF_SK_STACK]->port[0];
	ev->key[1].port[1] = s->key[PF_SK_STACK]->port[1];
	ev->key[1].af = s->key[PF_SK_STACK]->af;
	ev->key[1].proto = s->key[PF_SK_STACK]->proto;
}

static void
pfn_queue_event(struct pfn_event *ev)
{

	mtx_lock(&pfn_mtx);
	if (ring_put(&pfn_ring, ev) == 0) {
		pfn_events_total++;
		selwakeup(&pfn_rsel);
		KNOTE_LOCKED(&pfn_rsel.si_note, 0);
		wakeup(&pfn_ring);
	} else {
		pfn_events_dropped++;
	}
	mtx_unlock(&pfn_mtx);
}

/* --- PF hook implementations ------------------------------------- */

/*
 * INSERT hook — called from pf_state_insert().
 * Context: PF_HASHROW_LOCK held, NET_EPOCH.
 */
static void
pfn_insert_state(struct pf_kstate *s)
{
	struct pfn_event ev;

	if (!pfn_open)
		return;

	pfn_fill_event(&ev, PFN_EVENT_INSERT, s);
	pfn_queue_event(&ev);
}

/*
 * UPDATE hook — called from pf_test() on every packet matching
 * an existing state.  We only queue a READY event once per state,
 * when the connection first becomes offload-ready:
 *   TCP: both src and dst are ESTABLISHED (and not in FIN states)
 *   UDP: both src and dst have seen traffic (state > 0)
 *
 * Context: PF_RULES_RLOCK + PF_STATE_LOCK(s) held, NET_EPOCH.
 * The one-shot pfn_notified[] tracker prevents per-packet flooding.
 */
static void
pfn_update_state(struct pf_kstate *s)
{
	struct pfn_event ev;
	uint8_t proto, src_st, dst_st;
	int ready;

	if (!pfn_open)
		return;

	proto = s->key[PF_SK_WIRE]->proto;
	src_st = s->src.state;
	dst_st = s->dst.state;

	ready = 0;
	if (proto == IPPROTO_TCP) {
		if (src_st >= TCPS_ESTABLISHED &&
		    src_st < TCPS_FIN_WAIT_1 &&
		    dst_st >= TCPS_ESTABLISHED &&
		    dst_st < TCPS_FIN_WAIT_1)
			ready = 1;
	} else if (proto == IPPROTO_UDP) {
		if (src_st > 0 && dst_st > 0)
			ready = 1;
	}

	if (!ready)
		return;

	/* One-shot: skip if already notified for this state */
	if (pfn_is_notified(s->id))
		return;
	pfn_mark_notified(s->id);

	pfn_fill_event(&ev, PFN_EVENT_READY, s);
	pfn_queue_event(&ev);
}

/*
 * DELETE hook — called from pf_unlink_state().
 * Context: NET_EPOCH.
 */
static void
pfn_delete_state(struct pf_kstate *s)
{

	/* Clear one-shot tracker regardless of consumer */
	pfn_clear_notified(s->id);

	if (!pfn_open)
		return;

	{
		struct pfn_event ev;
		pfn_fill_event(&ev, PFN_EVENT_DELETE, s);
		pfn_queue_event(&ev);
	}
}

/* --- Character device --------------------------------------------- */

static int
pfn_dev_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	mtx_lock(&pfn_mtx);
	if (pfn_open) {
		mtx_unlock(&pfn_mtx);
		return (EBUSY);
	}
	pfn_open = 1;
	/* Reset ring on new open */
	pfn_ring.head = 0;
	pfn_ring.tail = 0;
	memset(pfn_notified, 0, sizeof(pfn_notified));
	mtx_unlock(&pfn_mtx);
	return (0);
}

static int
pfn_dev_close(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	mtx_lock(&pfn_mtx);
	pfn_open = 0;
	mtx_unlock(&pfn_mtx);
	return (0);
}

static int
pfn_dev_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct pfn_event ev;
	int error;

	if (uio->uio_resid < (ssize_t)sizeof(ev))
		return (EINVAL);

	mtx_lock(&pfn_mtx);
	while (ring_empty(&pfn_ring)) {
		if (ioflag & FNONBLOCK) {
			mtx_unlock(&pfn_mtx);
			return (EAGAIN);
		}
		error = msleep(&pfn_ring, &pfn_mtx, PCATCH, "pfnrd", 0);
		if (error) {
			mtx_unlock(&pfn_mtx);
			return (error);
		}
	}

	/* Drain as many events as will fit */
	while (uio->uio_resid >= (ssize_t)sizeof(ev) &&
	    ring_get(&pfn_ring, &ev) == 0) {
		mtx_unlock(&pfn_mtx);
		error = uiomove(&ev, sizeof(ev), uio);
		if (error)
			return (error);
		mtx_lock(&pfn_mtx);
	}

	mtx_unlock(&pfn_mtx);
	return (0);
}

static int
pfn_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	int revents = 0;

	mtx_lock(&pfn_mtx);
	if (events & (POLLIN | POLLRDNORM)) {
		if (!ring_empty(&pfn_ring))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &pfn_rsel);
	}
	mtx_unlock(&pfn_mtx);
	return (revents);
}

/* --- kqueue support ---------------------------------------------- */

static int	pfn_kqread(struct knote *kn, long hint);
static void	pfn_kqdetach(struct knote *kn);

static const struct filterops pfn_read_filterops = {
	.f_isfd =	1,
	.f_detach =	pfn_kqdetach,
	.f_event =	pfn_kqread,
#if __FreeBSD_version >= 1500000
	.f_copy =	knote_triv_copy,
#endif
};

/*
 * Called with pfn_mtx held (via knlist association).
 * Returns 1 if data available, 0 if not.
 */
static int
pfn_kqread(struct knote *kn, long hint)
{

	kn->kn_data = ring_count(&pfn_ring) * sizeof(struct pfn_event);
	return (!ring_empty(&pfn_ring));
}

static void
pfn_kqdetach(struct knote *kn)
{

	knlist_remove(&pfn_rsel.si_note, kn, 0);
}

static int
pfn_dev_kqfilter(struct cdev *dev __unused, struct knote *kn)
{

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &pfn_read_filterops;
		break;
	default:
		return (EINVAL);
	}
	knlist_add(&pfn_rsel.si_note, kn, 0);
	return (0);
}

static struct cdevsw pfn_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	pfn_dev_open,
	.d_close =	pfn_dev_close,
	.d_read =	pfn_dev_read,
	.d_poll =	pfn_dev_poll,
	.d_kqfilter =	pfn_dev_kqfilter,
	.d_name =	PFN_DEV_NAME,
};

/* --- Sysctl ------------------------------------------------------- */

static void
pfn_sysctl_init(void)
{
	struct sysctl_oid *parent;

	sysctl_ctx_init(&pfn_sysctl_ctx);

	parent = SYSCTL_ADD_NODE(&pfn_sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_net), OID_AUTO,
	    "pfnotify", CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
	    "PF state change notification");

	SYSCTL_ADD_INT(&pfn_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "ring_size", CTLFLAG_RD,
	    SYSCTL_NULL_INT_PTR, PFN_RING_SIZE,
	    "Ring buffer capacity (events)");

	SYSCTL_ADD_U64(&pfn_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "events_total", CTLFLAG_RD,
	    &pfn_events_total, 0,
	    "Total events queued");

	SYSCTL_ADD_U64(&pfn_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "events_dropped", CTLFLAG_RD,
	    &pfn_events_dropped, 0,
	    "Events dropped (ring full)");
}

static void
pfn_sysctl_fini(void)
{

	sysctl_ctx_free(&pfn_sysctl_ctx);
}

/* --- Module init/fini --------------------------------------------- */

static int
pfn_load(void)
{

	mtx_init(&pfn_mtx, "pfnotify", NULL, MTX_DEF);
	knlist_init_mtx(&pfn_rsel.si_note, &pfn_mtx);

	pfn_ring.head = 0;
	pfn_ring.tail = 0;
	pfn_open = 0;
	pfn_events_total = 0;
	pfn_events_dropped = 0;
	memset(pfn_notified, 0, sizeof(pfn_notified));

	/* Create /dev/pfnotify */
	pfn_cdev = make_dev(&pfn_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600,
	    PFN_DEV_NAME);
	if (pfn_cdev == NULL) {
		printf("pf_notify: failed to create /dev/%s\n",
		    PFN_DEV_NAME);
		mtx_destroy(&pfn_mtx);
		return (ENXIO);
	}

	pfn_sysctl_init();

	/* Register hooks */
	PF_RULES_WLOCK();
	V_pfnotify_insert_state_ptr = pfn_insert_state;
	V_pfnotify_update_state_ptr = pfn_update_state;
	V_pfnotify_delete_state_ptr = pfn_delete_state;
	PF_RULES_WUNLOCK();

	printf("pf_notify: loaded (ring_size=%d)\n", PFN_RING_SIZE);
	return (0);
}

static void
pfn_unload(void)
{

	/* Unregister hooks first */
	PF_RULES_WLOCK();
	V_pfnotify_insert_state_ptr = NULL;
	V_pfnotify_update_state_ptr = NULL;
	V_pfnotify_delete_state_ptr = NULL;
	PF_RULES_WUNLOCK();

	pfn_sysctl_fini();

	if (pfn_cdev != NULL)
		destroy_dev(pfn_cdev);

	seldrain(&pfn_rsel);
	knlist_clear(&pfn_rsel.si_note, 0);
	knlist_destroy(&pfn_rsel.si_note);
	mtx_destroy(&pfn_mtx);

	printf("pf_notify: unloaded\n");
}

static int
pf_notify_modevent(module_t mod __unused, int type, void *unused __unused)
{

	switch (type) {
	case MOD_LOAD:
		return (pfn_load());
	case MOD_UNLOAD:
		pfn_unload();
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t pf_notify_mod = {
	"pf_notify",
	pf_notify_modevent,
	NULL
};

DECLARE_MODULE(pf_notify, pf_notify_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(pf_notify, 1);
MODULE_DEPEND(pf_notify, pf, 1, 1, 1);
