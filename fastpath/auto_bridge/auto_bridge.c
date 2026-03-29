/*
 * auto_bridge.c — L2 flow detection kernel module for bridge offload
 *
 * Hooks into FreeBSD's if_bridge via bridge_l2flow_hook to detect
 * L2 flows crossing bridge ports.  Maintains a flow state machine
 * and communicates with userspace (CMM) via /dev/autobridge.
 *
 * FreeBSD port of the Linux auto_bridge kernel module.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2015-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/callout.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/event.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_bridgevar.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "auto_bridge.h"
#include "auto_bridge_private.h"

MALLOC_DEFINE(M_ABM, "autobridge", "auto_bridge flow entries");

/* --- Global state ------------------------------------------------- */

static struct mtx		abm_mtx;
static struct abm_hash_head	abm_table[ABM_HASH_SIZE];
static struct abm_hash_head	abm_by_src[ABM_MAC_HASH_SIZE];
static struct abm_hash_head	abm_by_dst[ABM_MAC_HASH_SIZE];
static unsigned int		abm_count;

/* Ring buffer + consumer wakeup */
static struct abm_ring		abm_ring;
static struct selinfo		abm_rsel;
static int			abm_open;	/* only one client */

/* Character device */
static struct cdev		*abm_cdev;

/* Tunables */
static int	abm_l3_filtering;
static int	abm_timeout_confirmed = ABM_TIMEOUT_CONFIRMED;
static int	abm_timeout_dying     = ABM_TIMEOUT_DYING;
static int	abm_max_entries       = ABM_MAX_ENTRIES;

static struct sysctl_ctx_list	abm_sysctl_ctx;
static struct sysctl_oid	*abm_sysctl_tree;

/* Flow state timeouts (seconds) */
static int abm_timeouts[] = {
	[ABM_STATE_CONFIRMED]	= ABM_TIMEOUT_CONFIRMED,
	[ABM_STATE_LINUX]	= 10,
	[ABM_STATE_DYING]	= ABM_TIMEOUT_DYING,
};

/* --- Ring buffer -------------------------------------------------- */

static inline int
ring_empty(const struct abm_ring *r)
{

	return (r->head == r->tail);
}

static inline int
ring_full(const struct abm_ring *r)
{

	return (((r->head + 1) % ABM_RING_SIZE) == r->tail);
}

static int
ring_put(struct abm_ring *r, const struct abm_event *ev)
{

	if (ring_full(r))
		return (ENOSPC);
	r->events[r->head] = *ev;
	r->head = (r->head + 1) % ABM_RING_SIZE;
	return (0);
}

static int
ring_get(struct abm_ring *r, struct abm_event *ev)
{

	if (ring_empty(r))
		return (EAGAIN);
	*ev = r->events[r->tail];
	r->tail = (r->tail + 1) % ABM_RING_SIZE;
	return (0);
}

/* --- Entry management --------------------------------------------- */

static struct abm_entry *
abm_find(const struct abm_l2flow *flow)
{
	struct abm_entry *e;
	uint32_t h;

	h = abm_flow_hash(flow);
	LIST_FOREACH(e, &abm_table[h], hash_entry) {
		if (memcmp(&e->flow, flow, sizeof(*flow)) == 0)
			return (e);
	}
	return (NULL);
}

static void abm_entry_timeout(void *arg);

static struct abm_entry *
abm_add(const struct abm_l2flow *flow, uint32_t iif, uint32_t oif,
    uint16_t mark)
{
	struct abm_entry *e;
	uint32_t h, sh, dh;

	if (abm_count >= (unsigned int)abm_max_entries)
		return (NULL);

	e = malloc(sizeof(*e), M_ABM, M_NOWAIT | M_ZERO);
	if (e == NULL)
		return (NULL);

	e->flow = *flow;
	e->iif_index = iif;
	e->oif_index = oif;
	e->mark = mark;
	e->state = ABM_STATE_CONFIRMED;
	e->flags = 0;

	callout_init_mtx(&e->timer, &abm_mtx, 0);

	h = abm_flow_hash(flow);
	LIST_INSERT_HEAD(&abm_table[h], e, hash_entry);

	sh = abm_mac_hash(flow->saddr);
	LIST_INSERT_HEAD(&abm_by_src[sh], e, src_mac_entry);

	dh = abm_mac_hash(flow->daddr);
	LIST_INSERT_HEAD(&abm_by_dst[dh], e, dst_mac_entry);

	abm_count++;
	return (e);
}

static void
abm_remove(struct abm_entry *e)
{

	callout_stop(&e->timer);
	LIST_REMOVE(e, hash_entry);
	LIST_REMOVE(e, src_mac_entry);
	LIST_REMOVE(e, dst_mac_entry);
	abm_count--;
	free(e, M_ABM);
}

/* --- Event posting ------------------------------------------------ */

static void
abm_post_event(struct abm_entry *e, uint8_t type)
{
	struct abm_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = type;
	ev.flow = e->flow;
	ev.iif_index = e->iif_index;
	ev.oif_index = e->oif_index;
	ev.mark = e->mark;

	if (ring_put(&abm_ring, &ev) == 0) {
		selwakeup(&abm_rsel);
		KNOTE_LOCKED(&abm_rsel.si_note, 0);
		wakeup(&abm_ring);
	}
}

static void
abm_post_reset(void)
{
	struct abm_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = ABM_EVENT_RESET;

	if (ring_put(&abm_ring, &ev) == 0) {
		selwakeup(&abm_rsel);
		KNOTE_LOCKED(&abm_rsel.si_note, 0);
		wakeup(&abm_ring);
	}
}

/* --- State machine ------------------------------------------------ */

/*
 * Timer callback — move to DYING or delete.
 * Called with abm_mtx held (callout_init_mtx).
 */
static void
abm_entry_timeout(void *arg)
{
	struct abm_entry *e = arg;

	mtx_assert(&abm_mtx, MA_OWNED);

	if (e->state == ABM_STATE_DYING) {
		/* Second timeout in DYING — delete for real */
		abm_post_event(e, ABM_EVENT_FLOW_DEL);
		abm_remove(e);
		return;
	}

	/* Move to DYING, set final timeout */
	e->state = ABM_STATE_DYING;
	abm_post_event(e, ABM_EVENT_FLOW_DEL);
	callout_reset(&e->timer, abm_timeouts[ABM_STATE_DYING] * hz,
	    abm_entry_timeout, e);
}

/*
 * Process a CMM response (from write() on /dev/autobridge).
 */
static void
abm_handle_response(const struct abm_response *resp)
{
	struct abm_entry *e;

	mtx_lock(&abm_mtx);
	e = abm_find(&resp->flow);
	if (e == NULL) {
		mtx_unlock(&abm_mtx);
		return;
	}

	if (resp->flags & ABM_FLAG_OFFLOADED) {
		e->state = ABM_STATE_FF;
		callout_stop(&e->timer);
	} else if (resp->flags & ABM_FLAG_DENIED) {
		e->state = ABM_STATE_LINUX;
		callout_reset(&e->timer, abm_timeouts[ABM_STATE_LINUX] * hz,
		    abm_entry_timeout, e);
	}

	e->flags &= ~ABM_FL_WAIT_ACK;
	mtx_unlock(&abm_mtx);
}

/* --- Flush all flows ---------------------------------------------- */

static void
abm_flush_all(void)
{
	struct abm_entry *e, *tmp;
	int i;

	mtx_assert(&abm_mtx, MA_OWNED);

	for (i = 0; i < ABM_HASH_SIZE; i++) {
		LIST_FOREACH_SAFE(e, &abm_table[i], hash_entry, tmp) {
			abm_remove(e);
		}
	}
}

/* --- Bridge hooks ------------------------------------------------- */

/*
 * Called from bridge_forward() for every unicast frame with a known
 * destination port.  Both src_if and dst_if are bridge member ports.
 *
 * Context: network stack (interrupt or thread), must be fast.
 */
static void
abm_l2flow_hook(struct ifnet *bridge_ifp __unused, struct mbuf *m,
    struct ifnet *src_if, struct ifnet *dst_if)
{
	struct ether_header *eh;
	struct abm_l2flow flow;
	struct abm_entry *e;
	int new_flow = 0;

	if (m->m_len < sizeof(*eh))
		return;

	eh = mtod(m, struct ether_header *);

	/* Build L2 flow tuple */
	memset(&flow, 0, sizeof(flow));
	memcpy(flow.saddr, eh->ether_shost, ETHER_ADDR_LEN);
	memcpy(flow.daddr, eh->ether_dhost, ETHER_ADDR_LEN);
	flow.ethertype = eh->ether_type;
	flow.svlan_tag = 0xFFFF;
	flow.cvlan_tag = 0xFFFF;

	/*
	 * Extract VLAN tags if present.
	 * FreeBSD strips VLAN tags into m_pkthdr before bridge_forward(),
	 * so check the pkthdr for in-band VLAN info.
	 */
	if (m->m_flags & M_VLANTAG) {
		flow.svlan_tag = m->m_pkthdr.ether_vtag;
	}

	/*
	 * Optional L3/L4 extraction (when sysctl enabled).
	 */
	if (abm_l3_filtering) {
		int hlen = sizeof(*eh);
		uint16_t etype = ntohs(eh->ether_type);

		if (etype == ETHERTYPE_IP && m->m_pkthdr.len >= hlen + 20) {
			struct ip iph;

			m_copydata(m, hlen, sizeof(iph), (caddr_t)&iph);
			flow.sip[0] = iph.ip_src.s_addr;
			flow.dip[0] = iph.ip_dst.s_addr;
			flow.proto = iph.ip_p;

			/* L4 ports if not fragmented */
			if ((ntohs(iph.ip_off) & (IP_MF | IP_OFFMASK)) == 0 &&
			    (iph.ip_p == IPPROTO_TCP ||
			     iph.ip_p == IPPROTO_UDP)) {
				int l4off = hlen + (iph.ip_hl << 2);
				uint16_t ports[2];

				if (m->m_pkthdr.len >= l4off + 4) {
					m_copydata(m, l4off, 4,
					    (caddr_t)ports);
					flow.sport = ports[0];
					flow.dport = ports[1];
				}
			}
		} else if (etype == ETHERTYPE_IPV6 &&
		    m->m_pkthdr.len >= hlen + 40) {
			struct ip6_hdr ip6h;

			m_copydata(m, hlen, sizeof(ip6h), (caddr_t)&ip6h);
			memcpy(flow.sip, &ip6h.ip6_src, 16);
			memcpy(flow.dip, &ip6h.ip6_dst, 16);
			flow.proto = ip6h.ip6_nxt;

			if (flow.proto == IPPROTO_TCP ||
			    flow.proto == IPPROTO_UDP) {
				int l4off = hlen + 40;
				uint16_t ports[2];

				if (m->m_pkthdr.len >= l4off + 4) {
					m_copydata(m, l4off, 4,
					    (caddr_t)ports);
					flow.sport = ports[0];
					flow.dport = ports[1];
				}
			}
		}
	}

	mtx_lock(&abm_mtx);

	e = abm_find(&flow);
	if (e == NULL) {
		/* New flow */
		e = abm_add(&flow, if_getindex(src_if),
		    if_getindex(dst_if), 0);
		if (e == NULL) {
			mtx_unlock(&abm_mtx);
			return;
		}
		new_flow = 1;
		/* Set confirmed timeout */
		callout_reset(&e->timer,
		    abm_timeouts[ABM_STATE_CONFIRMED] * hz,
		    abm_entry_timeout, e);
	} else {
		/* Existing flow — check if interfaces changed */
		if (e->iif_index != (uint32_t)if_getindex(src_if) ||
		    e->oif_index != (uint32_t)if_getindex(dst_if)) {
			e->iif_index = if_getindex(src_if);
			e->oif_index = if_getindex(dst_if);
			if (e->state != ABM_STATE_DYING) {
				abm_post_event(e, ABM_EVENT_FLOW_UPDATE);
			}
		}
	}

	if (new_flow && abm_open)
		abm_post_event(e, ABM_EVENT_FLOW_NEW);

	mtx_unlock(&abm_mtx);
}

/*
 * Called from bridge_rtage() before destroying a dynamic FDB entry.
 * Returns 0 to prevent expiry (MAC belongs to an offloaded flow),
 * or 1 to allow normal expiry.
 *
 * NOTE: bridge_ifp is the bridge interface, not the member port.
 */
static int
abm_fdb_can_expire(const uint8_t *mac, struct ifnet *bridge_ifp __unused)
{
	struct abm_entry *e;
	uint32_t h;

	h = abm_mac_hash(mac);

	mtx_lock(&abm_mtx);
	LIST_FOREACH(e, &abm_by_src[h], src_mac_entry) {
		if (memcmp(mac, e->flow.saddr, ETHER_ADDR_LEN) == 0 &&
		    e->state == ABM_STATE_FF) {
			mtx_unlock(&abm_mtx);
			return (0);	/* don't expire */
		}
	}
	mtx_unlock(&abm_mtx);
	return (1);	/* allow expiry */
}

/* --- Character device --------------------------------------------- */

static int
abm_dev_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	mtx_lock(&abm_mtx);
	if (abm_open) {
		mtx_unlock(&abm_mtx);
		return (EBUSY);
	}
	abm_open = 1;
	/* Reset ring on new open */
	abm_ring.head = 0;
	abm_ring.tail = 0;
	mtx_unlock(&abm_mtx);
	return (0);
}

static int
abm_dev_close(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	mtx_lock(&abm_mtx);
	abm_open = 0;

	/*
	 * Move all FF flows to DYING — traffic will revert to
	 * software bridge after CDX flows time out.
	 */
	{
		struct abm_entry *e;
		int i;

		for (i = 0; i < ABM_HASH_SIZE; i++) {
			LIST_FOREACH(e, &abm_table[i], hash_entry) {
				if (e->state == ABM_STATE_FF) {
					e->state = ABM_STATE_DYING;
					callout_reset(&e->timer,
					    abm_timeouts[ABM_STATE_DYING] * hz,
					    abm_entry_timeout, e);
				}
			}
		}
	}

	mtx_unlock(&abm_mtx);
	return (0);
}

static int
abm_dev_read(struct cdev *dev __unused, struct uio *uio,
    int ioflag)
{
	struct abm_event ev;
	int error;

	if (uio->uio_resid < (ssize_t)sizeof(ev))
		return (EINVAL);

	mtx_lock(&abm_mtx);
	while (ring_empty(&abm_ring)) {
		if (ioflag & FNONBLOCK) {
			mtx_unlock(&abm_mtx);
			return (EAGAIN);
		}
		error = msleep(&abm_ring, &abm_mtx, PCATCH, "abmrd", 0);
		if (error) {
			mtx_unlock(&abm_mtx);
			return (error);
		}
	}

	/* Drain as many events as will fit */
	while (uio->uio_resid >= (ssize_t)sizeof(ev) &&
	    ring_get(&abm_ring, &ev) == 0) {
		mtx_unlock(&abm_mtx);
		error = uiomove(&ev, sizeof(ev), uio);
		if (error)
			return (error);
		mtx_lock(&abm_mtx);
	}

	mtx_unlock(&abm_mtx);
	return (0);
}

static int
abm_dev_write(struct cdev *dev __unused, struct uio *uio,
    int ioflag __unused)
{
	struct abm_response resp;
	int error;

	while (uio->uio_resid >= (ssize_t)sizeof(resp)) {
		error = uiomove(&resp, sizeof(resp), uio);
		if (error)
			return (error);
		abm_handle_response(&resp);
	}
	return (0);
}

static int
abm_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	int revents = 0;

	mtx_lock(&abm_mtx);
	if (events & (POLLIN | POLLRDNORM)) {
		if (!ring_empty(&abm_ring))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &abm_rsel);
	}
	mtx_unlock(&abm_mtx);
	return (revents);
}

/* --- kqueue support ---------------------------------------------- */

static int	abm_kqread(struct knote *kn, long hint);
static void	abm_kqdetach(struct knote *kn);

static const struct filterops abm_read_filterops = {
	.f_isfd =	1,
	.f_detach =	abm_kqdetach,
	.f_event =	abm_kqread,
#if __FreeBSD_version >= 1500000
	.f_copy =	knote_triv_copy,
#endif
};

static int
abm_kqread(struct knote *kn, long hint)
{
	unsigned int count;

	count = (abm_ring.head - abm_ring.tail + ABM_RING_SIZE) %
	    ABM_RING_SIZE;
	kn->kn_data = count * sizeof(struct abm_event);
	return (count > 0);
}

static void
abm_kqdetach(struct knote *kn)
{

	knlist_remove(&abm_rsel.si_note, kn, 0);
}

static int
abm_dev_kqfilter(struct cdev *dev __unused, struct knote *kn)
{

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &abm_read_filterops;
		break;
	default:
		return (EINVAL);
	}
	knlist_add(&abm_rsel.si_note, kn, 0);
	return (0);
}

static struct cdevsw abm_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	abm_dev_open,
	.d_close =	abm_dev_close,
	.d_read =	abm_dev_read,
	.d_write =	abm_dev_write,
	.d_poll =	abm_dev_poll,
	.d_kqfilter =	abm_dev_kqfilter,
	.d_name =	ABM_DEV_NAME,
};

/* --- Sysctl ------------------------------------------------------- */

static int
abm_sysctl_l3_filtering(SYSCTL_HANDLER_ARGS)
{
	int error, old;

	old = abm_l3_filtering;
	error = sysctl_handle_int(oidp, &abm_l3_filtering, 0, req);
	if (error || req->newptr == NULL)
		return (error);

	/* State change → flush all flows and notify CMM */
	if (old != abm_l3_filtering) {
		mtx_lock(&abm_mtx);
		abm_flush_all();
		if (abm_open)
			abm_post_reset();
		mtx_unlock(&abm_mtx);
	}
	return (0);
}

static void
abm_sysctl_init(void)
{
	struct sysctl_oid *parent;

	sysctl_ctx_init(&abm_sysctl_ctx);

	/*
	 * Create our own top-level node: net.autobridge
	 * (net.link.bridge is static within if_bridge.c and
	 * not accessible from loadable modules)
	 */
	parent = SYSCTL_ADD_NODE(&abm_sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_net), OID_AUTO,
	    "autobridge", CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Auto-bridge L2 flow detection");
	abm_sysctl_tree = parent;

	SYSCTL_ADD_PROC(&abm_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "l3_filtering",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    NULL, 0, abm_sysctl_l3_filtering, "I",
	    "Enable L3/L4 field extraction (0=off, 1=on)");

	SYSCTL_ADD_INT(&abm_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "timeout_confirmed", CTLFLAG_RW,
	    &abm_timeout_confirmed, 0,
	    "Confirmed state timeout (seconds)");

	SYSCTL_ADD_INT(&abm_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "timeout_dying", CTLFLAG_RW,
	    &abm_timeout_dying, 0,
	    "Dying state timeout (seconds)");

	SYSCTL_ADD_INT(&abm_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "max_entries", CTLFLAG_RW,
	    &abm_max_entries, 0,
	    "Maximum number of tracked flows");

	SYSCTL_ADD_UINT(&abm_sysctl_ctx, SYSCTL_CHILDREN(parent),
	    OID_AUTO, "count", CTLFLAG_RD,
	    &abm_count, 0,
	    "Current number of tracked flows");
}

static void
abm_sysctl_fini(void)
{

	sysctl_ctx_free(&abm_sysctl_ctx);
}

/* --- Module init/fini --------------------------------------------- */

static int
abm_load(void)
{
	int i;

	mtx_init(&abm_mtx, "autobridge", NULL, MTX_DEF);
	knlist_init_mtx(&abm_rsel.si_note, &abm_mtx);

	for (i = 0; i < ABM_HASH_SIZE; i++)
		LIST_INIT(&abm_table[i]);
	for (i = 0; i < ABM_MAC_HASH_SIZE; i++) {
		LIST_INIT(&abm_by_src[i]);
		LIST_INIT(&abm_by_dst[i]);
	}
	abm_count = 0;
	abm_open = 0;
	abm_ring.head = 0;
	abm_ring.tail = 0;

	/* Sync sysctl values into timeouts array */
	abm_timeouts[ABM_STATE_CONFIRMED] = abm_timeout_confirmed;
	abm_timeouts[ABM_STATE_DYING] = abm_timeout_dying;

	/* Create /dev/autobridge */
	abm_cdev = make_dev(&abm_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600,
	    ABM_DEV_NAME);
	if (abm_cdev == NULL) {
		printf("auto_bridge: failed to create /dev/%s\n",
		    ABM_DEV_NAME);
		mtx_destroy(&abm_mtx);
		return (ENXIO);
	}

	abm_sysctl_init();

	/* Register bridge hooks */
	bridge_l2flow_hook = abm_l2flow_hook;
	bridge_fdb_can_expire_hook = abm_fdb_can_expire;

	printf("auto_bridge: loaded (max_entries=%d, l3_filtering=%d)\n",
	    abm_max_entries, abm_l3_filtering);
	return (0);
}

static void
abm_unload(void)
{

	/* Unregister hooks first */
	bridge_l2flow_hook = NULL;
	bridge_fdb_can_expire_hook = NULL;

	/* Flush all entries */
	mtx_lock(&abm_mtx);
	abm_flush_all();
	mtx_unlock(&abm_mtx);

	abm_sysctl_fini();

	if (abm_cdev != NULL)
		destroy_dev(abm_cdev);

	seldrain(&abm_rsel);
	knlist_destroy(&abm_rsel.si_note);
	mtx_destroy(&abm_mtx);

	printf("auto_bridge: unloaded\n");
}

static int
auto_bridge_modevent(module_t mod __unused, int type, void *unused __unused)
{

	switch (type) {
	case MOD_LOAD:
		return (abm_load());
	case MOD_UNLOAD:
		abm_unload();
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t auto_bridge_mod = {
	"auto_bridge",
	auto_bridge_modevent,
	NULL
};

DECLARE_MODULE(auto_bridge, auto_bridge_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(auto_bridge, 1);
MODULE_DEPEND(auto_bridge, if_bridge, 1, 1, 1);
