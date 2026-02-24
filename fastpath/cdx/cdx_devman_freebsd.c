/*
 * cdx_devman_freebsd.c — Interface management for FreeBSD CDX port
 *
 * Replaces the Linux devman.c which is deeply coupled to Linux netdev
 * structures.  On FreeBSD, interface discovery uses the dtsec newbus
 * driver (via cdx_dpa_bridge helpers) and the dpa_iface_info linked
 * list is populated from dtsec_softc data.
 *
 * On Linux, interfaces are registered when CMM sends FCI commands via
 * cdx_add_eth_onif().  The same flow applies here: CMM sends the command,
 * FCI dispatches to cdx_add_eth_onif(), which calls dpa_add_eth_if() to
 * discover the dtsec and populate the interface list.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021-2022 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "cdx_dpa_bridge.h"
#include "control_ipv4.h"
#include "layer2.h"
#include "module_qm.h"

/* FreeBSD DPAA1 driver headers — need net/if_var.h for if_t first */
#include <contrib/ncsw/inc/integrations/dpaa_integration_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_port_ext.h>
#include <dev/dpaa/if_dtsec.h>

/* NCSW public QMan API — for QM_FQR_GetFqid, t_QmContextA */
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>

/* FreeBSD QMan wrapper — for qman_fqr_create_ctx */
extern t_Handle qman_fqr_create_ctx(uint32_t fqids_num,
    e_QmFQChannel channel, uint8_t wq, bool force_fqid,
    uint32_t fqid_or_align, bool prefer_in_cache,
    t_QmContextA *p_context_a, t_QmContextB *p_context_b);
extern t_Error qman_fqr_free(t_Handle fqr);
extern uint32_t qman_fqr_get_counter(t_Handle fqr, uint32_t fqid_off,
    e_QmFqrCounters counter);

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

MALLOC_DEFINE(M_CDX_DEVMAN, "cdx_devman", "CDX interface management");

/*
 * CDX forwarding TX FQ handles — stored for cleanup.
 * One FQR per physical ethernet port, indexed by port_idx.
 * Each FQR contains DPAA_FWD_TX_QUEUES individual FQs so that
 * offloaded flows can be distributed across multiple QMan FQs,
 * avoiding single-FQ serialization at 10 GbE rates.
 */
#define	CDX_MAX_ETH_PORTS	8
static t_Handle cdx_fwd_tx_fqr[CDX_MAX_ETH_PORTS];

/* ================================================================
 * Globals — defined in cdx_dpa_stub.c
 * ================================================================ */

extern struct dpa_iface_info *dpa_interface_info;
extern spinlock_t dpa_devlist_lock;

/* ================================================================
 * Private helpers
 * ================================================================ */

/*
 * Lookup dpa_iface_info by interface ID (itf_id == FreeBSD if_index).
 */
static struct dpa_iface_info *
devman_find_by_itfid(uint32_t itf_id)
{
	struct dpa_iface_info *p;

	for (p = dpa_interface_info; p != NULL; p = p->next) {
		if (p->itf_id == itf_id)
			return (p);
	}
	return (NULL);
}

/*
 * Lookup dpa_iface_info by interface name.
 */
static struct dpa_iface_info *
devman_find_by_name(const char *name)
{
	struct dpa_iface_info *p;

	for (p = dpa_interface_info; p != NULL; p = p->next) {
		if (strcmp((char *)p->name, name) == 0)
			return (p);
	}
	return (NULL);
}

/*
 * Map dtsec device type to CDX port speed constant.
 */
static uint32_t
devman_speed_from_type(enum eth_dev_type type)
{

	return (type == ETH_10GSEC) ? PORT_10G_SPEED : PORT_1G_SPEED;
}

/*
 * Map dtsec eth_id to the CDX portid from cdx_dpa_init port layout.
 * On the Mono Gateway, eth_id == portid for physical ports.
 */
static uint32_t
devman_ethid_to_portid(uint8_t eth_id, enum eth_dev_type type)
{

	if (type == ETH_10GSEC)
		return (6 + (uint32_t)eth_id);	/* 10G/0=6, 10G/1=7 */
	return ((uint32_t)eth_id);
}

/* ================================================================
 * dpa_add_port_to_list — Insert into global linked list
 * ================================================================ */

int
dpa_add_port_to_list(struct dpa_iface_info *iface_info)
{

	spin_lock(&dpa_devlist_lock);
	iface_info->next = dpa_interface_info;
	dpa_interface_info = iface_info;
	spin_unlock(&dpa_devlist_lock);
	return (0);
}

/* ================================================================
 * dpa_add_eth_if — Register a physical ethernet interface
 * ================================================================ */

int
dpa_add_eth_if(char *name, struct _itf *itf, struct _itf *phys_itf)
{
	struct dtsec_softc *sc;
	struct dpa_iface_info *iface;
	struct eth_iface_info *eth;
	uint32_t tx_fqid;

	/* Find the dtsec device by interface name */
	sc = cdx_dpa_bridge_find_dtsec(name);
	if (sc == NULL) {
		DPA_ERROR("cdx: devman: dtsec '%s' not found\n", name);
		return (-1);
	}

	/* Allocate and zero the interface info struct */
	iface = kzalloc(sizeof(*iface), GFP_KERNEL);
	if (iface == NULL)
		return (-1);

	/* Basic interface info */
	strlcpy((char *)iface->name, name, IF_NAME_SIZE);
	iface->itf_id = itf->index;
	iface->if_flags = itf->type;
	iface->mtu = if_getmtu(sc->sc_ifnet);

	/* Populate eth_iface_info from dtsec_softc */
	eth = &iface->eth_info;
	eth->speed = devman_speed_from_type(sc->sc_eth_dev_type);
	eth->fman_idx = 0;	/* LS1046A has one FMan */
	eth->port_idx = sc->sc_eth_id;
	eth->portid = devman_ethid_to_portid(sc->sc_eth_id,
	    sc->sc_eth_dev_type);
	memcpy(eth->mac_addr, sc->sc_mac_addr, 6);

	/* TX channel for QMan enqueue */
	eth->tx_channel_id = sc->sc_port_tx_qman_chan;

	/*
	 * Create DPAA_FWD_TX_QUEUES dedicated TX forwarding FQs with
	 * contextA set for hardware flow offload:
	 *   hi = 0x9a000000: OVFQ=1, A2V=1, A0V=1, OVOM=1
	 *   lo = 0xC0000000: EBD=1 (Enqueue Buffer Deallocate)
	 *
	 * Multiple FQs are needed to avoid single-FQ QMan serialization
	 * which caps offloaded throughput well below 10 GbE line rate.
	 * Each offloaded flow is assigned to a specific FQ based on its
	 * conntrack hash, distributing traffic across QMan scheduling slots.
	 */
	{
		t_QmContextA ctx_a;
		t_Handle fqr;
		uint32_t port = eth->port_idx;
		uint32_t i;

		ctx_a.res[0] = 0x9a000000;	/* OVFQ|A2V|A0V|OVOM */
		ctx_a.res[1] = 0xC0000000;	/* EBD=1 */

		fqr = qman_fqr_create_ctx(DPAA_FWD_TX_QUEUES,
		    (e_QmFQChannel)sc->sc_port_tx_qman_chan, 0,
		    false, 0, true, &ctx_a, NULL);
		if (fqr != NULL) {
			tx_fqid = QM_FQR_GetFqid(fqr);
			for (i = 0; i < DPAA_FWD_TX_QUEUES; i++)
				eth->fwd_tx_fqinfo[i].fqid = tx_fqid + i;

			if (port < CDX_MAX_ETH_PORTS)
				cdx_fwd_tx_fqr[port] = fqr;

			DPA_INFO("cdx: devman: %s fwd_tx_fqid=0x%x..0x%x "
			    "(%d FQs, EBD=1)\n", name, tx_fqid,
			    tx_fqid + DPAA_FWD_TX_QUEUES - 1,
			    DPAA_FWD_TX_QUEUES);
		} else {
			DPA_ERROR("cdx: devman: %s failed to create "
			    "fwd TX FQs, falling back to dtsec FQR\n",
			    name);
			if (sc->sc_tx_fqs[0] != NULL) {
				tx_fqid = QM_FQR_GetFqid(sc->sc_tx_fqs[0]);
				for (i = 0; i < DPAA_FWD_TX_QUEUES; i++)
					eth->fwd_tx_fqinfo[i].fqid = tx_fqid;
			}
		}
	}

	/* RX default FQID (for diagnostics) */
	eth->fqinfo[RX_DEFA_FQ].fq_base = sc->sc_rx_fqid;
	eth->fqinfo[RX_DEFA_FQ].num_fqs = 1;

	/* RX pool info */
	eth->num_pools = 1;
	eth->pool_info[0].pool_id = sc->sc_rx_bpid;
	eth->pool_info[0].buf_size = FM_PORT_BUFFER_SIZE;

	/* Allocate per-interface MURAM stats */
#ifdef INCLUDE_ETHER_IFSTATS
	if (alloc_iface_stats(itf->type, iface) == SUCCESS) {
		iface->if_flags |= IF_STATS_ENABLED;
		/*
		 * Mark TX port as "up" in the MURAM stats/portinfo union.
		 * The PREEMPT_TX_VALIDATE microcode opcode reads
		 * txpinfo.port_info; if 0, it drops all offloaded packets.
		 */
		((struct en_ehash_ifportinfo *)iface->stats)->
		    txpinfo.port_info = cpu_to_be32(1);
	}
#endif

	/* Link into the global list */
	dpa_add_port_to_list(iface);

	return (0);
}

/* ================================================================
 * dpa_add_vlan_if — Register a VLAN sub-interface
 * ================================================================ */

int
dpa_add_vlan_if(char *name, struct _itf *itf, struct _itf *phys_itf,
    uint16_t vlan_id, uint8_t *mac_addr)
{
	struct dpa_iface_info *iface, *parent;

	parent = devman_find_by_itfid(phys_itf->index);
	if (parent == NULL) {
		DPA_ERROR("cdx: devman: VLAN parent itf_id=%u not found\n",
		    phys_itf->index);
		return (-1);
	}

	iface = kzalloc(sizeof(*iface), GFP_KERNEL);
	if (iface == NULL)
		return (-1);

	strlcpy((char *)iface->name, name, IF_NAME_SIZE);
	iface->itf_id = itf->index;
	iface->if_flags = itf->type;
	iface->mtu = parent->mtu - 4;	/* VLAN overhead */

	iface->vlan_info.parent = parent;
	iface->vlan_info.vlan_id = vlan_id;
	if (mac_addr)
		memcpy(iface->vlan_info.mac_addr, mac_addr, 6);

#ifdef INCLUDE_VLAN_IFSTATS
	if (alloc_iface_stats(itf->type, iface) == SUCCESS)
		iface->if_flags |= IF_STATS_ENABLED;
#endif

	dpa_add_port_to_list(iface);

	DPA_INFO("cdx: devman: registered VLAN %s — itf_id=%u vlan=%u "
	    "parent=%s\n", name, iface->itf_id, vlan_id,
	    (char *)parent->name);

	return (0);
}

/* ================================================================
 * dpa_add_pppoe_if — Register a PPPoE sub-interface
 * ================================================================ */

int
dpa_add_pppoe_if(char *name, struct _itf *itf, struct _itf *phys_itf,
    uint8_t *mac_addr, uint16_t session_id)
{
	struct dpa_iface_info *iface, *parent;

	parent = devman_find_by_itfid(phys_itf->index);
	if (parent == NULL) {
		DPA_ERROR("cdx: devman: PPPoE parent itf_id=%u not found\n",
		    phys_itf->index);
		return (-1);
	}

	iface = kzalloc(sizeof(*iface), GFP_KERNEL);
	if (iface == NULL)
		return (-1);

	strlcpy((char *)iface->name, name, IF_NAME_SIZE);
	iface->itf_id = itf->index;
	iface->if_flags = itf->type;
	iface->mtu = parent->mtu - 8;	/* PPPoE overhead */

	iface->pppoe_info.parent = parent;
	iface->pppoe_info.session_id = session_id;
	if (mac_addr)
		memcpy(iface->pppoe_info.mac_addr, mac_addr, 6);

#ifdef INCLUDE_PPPoE_IFSTATS
	if (alloc_iface_stats(itf->type, iface) == SUCCESS)
		iface->if_flags |= IF_STATS_ENABLED;
#endif

	dpa_add_port_to_list(iface);

	DPA_INFO("cdx: devman: registered PPPoE %s — itf_id=%u sess=%u "
	    "parent=%s\n", name, iface->itf_id, session_id,
	    (char *)parent->name);

	return (0);
}

/* ================================================================
 * Interface lookup functions
 * ================================================================ */

/*
 * dpa_get_ifinfo_by_itfid — Find interface by ID.
 * Called from cdx_ehash.c and dpa_get_tx_info_by_itf.
 */
struct dpa_iface_info *
dpa_get_ifinfo_by_itfid(uint32_t itf_id)
{
	struct dpa_iface_info *p;

	spin_lock(&dpa_devlist_lock);
	p = devman_find_by_itfid(itf_id);
	spin_unlock(&dpa_devlist_lock);
	return (p);
}

struct dpa_iface_info *
dpa_get_ifinfo_by_name(char *name)
{
	struct dpa_iface_info *p;

	spin_lock(&dpa_devlist_lock);
	p = devman_find_by_name(name);
	spin_unlock(&dpa_devlist_lock);
	return (p);
}

/*
 * Walk the interface hierarchy to find the physical ethernet parent.
 * Traverses VLAN → parent and PPPoE → parent until an ethernet
 * interface (IF_TYPE_ETHERNET) is found.
 *
 * Returns the dpa_iface_info of the physical port, or NULL.
 */
static struct dpa_iface_info *
devman_find_eth_parent(struct dpa_iface_info *iface)
{
	int depth = 0;

	while (iface != NULL && depth < 8) {
		if (iface->if_flags & IF_TYPE_ETHERNET)
			return (iface);
		if (iface->if_flags & IF_TYPE_VLAN)
			iface = iface->vlan_info.parent;
		else if (iface->if_flags & IF_TYPE_PPPOE)
			iface = iface->pppoe_info.parent;
		else
			break;
		depth++;
	}
	return (NULL);
}

struct dpa_iface_info *
dpa_get_iface_by_name(char *name)
{

	return (devman_find_by_name(name));
}

/*
 * Walk interface hierarchy to find the physical ethernet parent.
 * Used by Tier 1 devman code during interface registration.
 */
struct dpa_iface_info *
dpa_get_phys_iface(struct dpa_iface_info *iface_info)
{

	return (devman_find_eth_parent(iface_info));
}

/* ================================================================
 * OH port interface management
 * ================================================================ */

/*
 * dpa_get_ohifinfo_by_portid — Find OH port interface by portid.
 * Portids for OH ports come from cdx_cfg_dgw.xml (9=IPsec, 10=WiFi).
 */
struct dpa_iface_info *
dpa_get_ohifinfo_by_portid(uint32_t portid)
{
	struct dpa_iface_info *p;

	for (p = dpa_interface_info; p != NULL; p = p->next) {
		if ((p->if_flags & IF_TYPE_OFPORT) &&
		    p->oh_info.portid == portid)
			return (p);
	}
	return (NULL);
}

/*
 * dpaa_is_oh_port — Check if a portid belongs to an active OH port.
 */
int
dpaa_is_oh_port(uint32_t portid)
{

	return (dpa_get_ohifinfo_by_portid(portid) != NULL) ? 1 : 0;
}

/*
 * get_dpa_oh_iface_info declared in portdefs.h, implemented in cdx_dpa_cfg.c
 */
extern int get_dpa_oh_iface_info(struct oh_iface_info *, char *);

/*
 * dpa_add_oh_if — Register an offline handler port.
 *
 * Parses the "dpa-fman%d-oh@%d" name, retrieves channel/FQID from the
 * FreeBSD dpaa_oh driver (via cdx_dpa_bridge helpers), loads portid
 * from fman_info->portinfo[], and adds to the global interface list.
 */
int
dpa_add_oh_if(char *name)
{
	struct dpa_iface_info *iface;
	uint32_t fman_idx, port_idx;
	int cdx_number;

	if (sscanf(name, "dpa-fman%u-oh@%u", &fman_idx, &port_idx) != 2) {
		DPA_ERROR("cdx: dpa_add_oh_if: invalid name '%s'\n", name);
		return (-1);
	}

	/*
	 * CDX bridge OH port numbering is 1-based:
	 *   oh@2 → cdx_number 1 (IPsec, cell-index 3)
	 *   oh@3 → cdx_number 2 (WiFi, cell-index 4)
	 */
	cdx_number = port_idx - 1;

	if (cdx_dpa_bridge_get_oh_dev(cdx_number) == NULL) {
		DPA_ERROR("cdx: dpa_add_oh_if: OH port %d not found\n",
		    cdx_number);
		return (-1);
	}

	iface = kzalloc(sizeof(*iface), GFP_KERNEL);
	if (iface == NULL)
		return (-1);

	strlcpy((char *)iface->name, name, IF_NAME_SIZE);
	iface->if_flags = IF_TYPE_OFPORT;
	iface->oh_info.fman_idx = fman_idx;
	iface->oh_info.port_idx = port_idx - 1;	/* 0-based */
	iface->oh_info.channel_id =
	    cdx_dpa_bridge_get_oh_channel(cdx_number);
	iface->oh_info.fqinfo[RX_DEFA_FQ].fq_base =
	    cdx_dpa_bridge_get_oh_dflt_fqid(cdx_number);
	iface->oh_info.fqinfo[RX_DEFA_FQ].num_fqs = 1;

	/* Load portid + dist_info from fman_info->portinfo[] */
	get_dpa_oh_iface_info(&iface->oh_info, name);

	dpa_add_port_to_list(iface);

	DPA_INFO("cdx: devman: registered OH %s — portid=%u channel=0x%x "
	    "dflt_fqid=0x%x\n", name, iface->oh_info.portid,
	    iface->oh_info.channel_id,
	    iface->oh_info.fqinfo[RX_DEFA_FQ].fq_base);

	return (0);
}

/*
 * cdx_add_oh_iface — Top-level wrapper for OH port registration.
 * Called from dpa_cfg initialization loop for each OH port.
 */
int
cdx_add_oh_iface(char *name)
{

	if (dpa_add_oh_if(name) != 0) {
		DPA_ERROR("cdx: cdx_add_oh_iface: failed for %s\n",
		    name ? name : "(null)");
		return (-EIO);
	}
	return (0);
}

/* ================================================================
 * dpa_get_fm_port_index — Map interface to FMan/port indices
 *
 * Used by cdx_ehash.c before every hash table insertion to determine
 * which FMan port the ingress interface belongs to.
 * ================================================================ */

int
dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index,
    uint32_t *fm_index, uint32_t *port_index, uint32_t *portid)
{
	struct dpa_iface_info *iface, *eth_iface;

	spin_lock(&dpa_devlist_lock);

	iface = devman_find_by_itfid(itf_index);
	if (iface == NULL) {
		spin_unlock(&dpa_devlist_lock);
		return (-1);
	}

	eth_iface = devman_find_eth_parent(iface);
	if (eth_iface == NULL) {
		spin_unlock(&dpa_devlist_lock);
		return (-1);
	}

	*fm_index = eth_iface->eth_info.fman_idx;
	*port_index = eth_iface->eth_info.port_idx;
	*portid = eth_iface->eth_info.portid;

	spin_unlock(&dpa_devlist_lock);
	return (0);
}

/* ================================================================
 * dpa_get_tx_info_by_itf — Full L2/L3 transmit info for a route
 *
 * Walks the interface hierarchy from the route's output interface
 * to the physical port, collecting VLAN, PPPoE, MAC, and FQID info.
 * This data is used by cdx_ehash.c fill_actions() to build the
 * header modification opcode chain.
 * ================================================================ */

int
dpa_get_tx_info_by_itf(PRouteEntry rt_entry,
    struct dpa_l2hdr_info *l2_info,
    struct dpa_l3hdr_info *l3_info,
    PRouteEntry tnl_route, uint32_t *qosmark, uint32_t hash)
{
	struct dpa_iface_info *iface, *cur;
	int depth;

	if (rt_entry == NULL || rt_entry->itf == NULL)
		return (-1);

	spin_lock(&dpa_devlist_lock);

	iface = devman_find_by_itfid(rt_entry->itf->index);
	if (iface == NULL) {
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("cdx: devman: tx_info: itf_id=%u not found\n",
		    rt_entry->itf->index);
		return (-1);
	}

	/* Clear output structures */
	memset(l2_info, 0, sizeof(*l2_info));
	memset(l3_info, 0, sizeof(*l3_info));

	/* Walk the interface hierarchy */
	cur = iface;
	depth = 0;
	while (cur != NULL && depth < 8) {
		if (cur->if_flags & IF_TYPE_VLAN) {
			l2_info->vlan_present = 1;
			if (l2_info->num_egress_vlan_hdrs < DPA_CLS_HM_MAX_VLANs) {
				l2_info->egress_vlan_hdrs[l2_info->num_egress_vlan_hdrs].tci =
				    cur->vlan_info.vlan_id;
				l2_info->egress_vlan_hdrs[l2_info->num_egress_vlan_hdrs].tpid =
				    0x8100;
				l2_info->num_egress_vlan_hdrs++;
			}
			cur = cur->vlan_info.parent;
		} else if (cur->if_flags & IF_TYPE_PPPOE) {
			l2_info->pppoe_present = 1;
			l2_info->pppoe_sess_id = cur->pppoe_info.session_id;
			cur = cur->pppoe_info.parent;
		} else if (cur->if_flags & IF_TYPE_ETHERNET) {
			/* Reached physical port — extract TX info */
			struct eth_iface_info *eth = &cur->eth_info;

			/* L2 header: dst MAC from route, src MAC from port */
			memcpy(l2_info->l2hdr, rt_entry->dstmac, 6);
			memcpy(l2_info->l2hdr + 6, eth->mac_addr, 6);

			l2_info->mtu = cur->mtu;

			/* TX FQID — distribute across forwarding queues */
			l2_info->fqid = eth->fwd_tx_fqinfo[
			    hash % DPAA_FWD_TX_QUEUES].fqid;

#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset =
			    cur->txstats_index;
#endif
			break;
		} else {
			break;
		}
		depth++;
	}

	spin_unlock(&dpa_devlist_lock);

	if (l2_info->fqid == 0) {
		DPA_ERROR("cdx: devman: tx_info: no TX FQID for itf_id=%u\n",
		    rt_entry->itf->index);
		return (-1);
	}

	return (0);
}

/* ================================================================
 * dpa_get_tx_l2info_by_itf — L2-only transmit info
 *
 * Simplified version used by layer2 bridge flows.
 * ================================================================ */

int
dpa_get_tx_l2info_by_itf(struct dpa_l2hdr_info *l2_info,
    POnifDesc itf, uint32_t hash)
{
	struct dpa_iface_info *iface, *eth_parent;

	if (itf == NULL)
		return (-1);

	spin_lock(&dpa_devlist_lock);

	iface = devman_find_by_itfid(itf->itf->index);
	if (iface == NULL) {
		spin_unlock(&dpa_devlist_lock);
		return (-1);
	}

	memset(l2_info, 0, sizeof(*l2_info));

	eth_parent = devman_find_eth_parent(iface);
	if (eth_parent != NULL) {
		struct eth_iface_info *eth = &eth_parent->eth_info;

		memcpy(l2_info->l2hdr + 6, eth->mac_addr, 6);
		l2_info->mtu = eth_parent->mtu;
		l2_info->fqid = eth->fwd_tx_fqinfo[
		    hash % DPAA_FWD_TX_QUEUES].fqid;
#ifdef INCLUDE_ETHER_IFSTATS
		l2_info->ether_stats_offset =
		    eth_parent->txstats_index;
#endif
	}

	spin_unlock(&dpa_devlist_lock);
	return (0);
}

/* ================================================================
 * add_incoming_iface_info — Extract input interface info for entry
 *
 * Called at the start of insert_entry_in_classif_table() to record
 * the ingress interface index in the conntrack entry.
 * ================================================================ */

int
add_incoming_iface_info(PCtEntry entry)
{

	if (entry == NULL || entry->pRtEntry == NULL)
		return (-1);

	if (entry->pRtEntry->itf == NULL)
		return (-1);

	entry->inPhyPortNum = entry->pRtEntry->input_itf ?
	    entry->pRtEntry->input_itf->index : 0;

	return (0);
}

/* ================================================================
 * cdx_add_eth_onif — Register a physical ethernet interface
 *
 * Allocates a phy_port slot, registers in gOnif_DB[] via add_onif(),
 * which in turn calls dpa_add_eth_if() to populate the DPA interface
 * list from dtsec_softc data.
 *
 * Called during CDX module init for each dtsec interface, and also
 * available as an FCI command handler.
 * ================================================================ */

int
cdx_add_eth_onif(char *name)
{
	uint32_t ii;

	/* Find free slot in phy_port[] */
	for (ii = 0; ii < MAX_PHY_PORTS; ii++) {
		if (!phy_port[ii].flags) {
			phy_port[ii].id = ii;
			phy_port[ii].flags =
			    (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
			break;
		}
	}
	if (ii == MAX_PHY_PORTS) {
		DPA_ERROR("cdx: devman: phy_port limit reached for %s\n",
		    name);
		return (-EINVAL);
	}

	/* Register in gOnif_DB[] — calls dpa_add_eth_if() internally */
	if (add_onif((U8 *)name, &phy_port[ii].itf, NULL,
	    (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL)) == NULL) {
		memset(&phy_port[ii], 0, sizeof(struct physical_port));
		DPA_ERROR("cdx: devman: add_onif failed for %s\n", name);
		return (-EIO);
	}

	/* Fill MAC address in phy_port */
	dpa_get_mac_addr(name, (char *)&phy_port[ii].mac_addr[0]);
	return (0);
}

/* ================================================================
 * Query / lookup functions
 * ================================================================ */

int
dpa_get_tx_fqid_by_name(char *name, uint32_t *fqid,
    uint8_t *is_dscp_fq_map, uint32_t hash)
{
	struct dpa_iface_info *iface, *eth_parent;

	spin_lock(&dpa_devlist_lock);

	iface = devman_find_by_name(name);
	if (iface == NULL) {
		spin_unlock(&dpa_devlist_lock);
		return (-1);
	}

	eth_parent = devman_find_eth_parent(iface);
	if (eth_parent == NULL) {
		spin_unlock(&dpa_devlist_lock);
		return (-1);
	}

	*fqid = eth_parent->eth_info.fwd_tx_fqinfo[
	    hash % DPAA_FWD_TX_QUEUES].fqid;
	if (is_dscp_fq_map)
		*is_dscp_fq_map = 0;

	spin_unlock(&dpa_devlist_lock);
	return (0);
}

int
dpa_get_mac_addr(char *name, char *mac_addr)
{
	struct dpa_iface_info *iface, *eth_parent;

	spin_lock(&dpa_devlist_lock);

	iface = devman_find_by_name(name);
	if (iface == NULL) {
		spin_unlock(&dpa_devlist_lock);
		return (-1);
	}

	eth_parent = devman_find_eth_parent(iface);
	if (eth_parent != NULL) {
		memcpy(mac_addr, eth_parent->eth_info.mac_addr, 6);
		spin_unlock(&dpa_devlist_lock);
		return (0);
	}

	spin_unlock(&dpa_devlist_lock);
	return (-1);
}

int
dpa_get_itfid_by_fman_params(uint32_t fman_index, uint32_t portid)
{
	struct dpa_iface_info *p;

	spin_lock(&dpa_devlist_lock);

	for (p = dpa_interface_info; p != NULL; p = p->next) {
		if ((p->if_flags & IF_TYPE_ETHERNET) &&
		    p->eth_info.fman_idx == fman_index &&
		    p->eth_info.portid == portid) {
			int id = p->itf_id;
			spin_unlock(&dpa_devlist_lock);
			return (id);
		}
	}

	spin_unlock(&dpa_devlist_lock);
	return (-1);
}

struct net_device *
find_osdev_by_fman_params(uint32_t fm_idx, uint32_t port_idx,
    uint32_t speed)
{

	/* FreeBSD doesn't use net_device — return NULL */
	return (NULL);
}

/* ================================================================
 * cdx_get_txfq — Select TX frame queue for QoS mark
 *
 * When CEETM QoS is enabled on the egress port, route through
 * ceetm_get_egressfq() which selects the CEETM class queue based
 * on the connection's QoS mark (channel + queue).  Otherwise fall
 * back to the regular forwarding TX FQ array.
 * ================================================================ */

/* ceetm_get_egressfq — defined in cdx_ceetm_freebsd.c */
extern struct qman_fq *ceetm_get_egressfq(void *ctx, uint32_t channel,
    uint32_t classque, uint32_t ff);

struct qman_fq *
cdx_get_txfq(struct eth_iface_info *eth_info, void *info)
{
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)info;
	uint32_t quenum;

#ifdef ENABLE_EGRESS_QOS
	PQM_context_ctl qm_ctx;
	struct qman_fq *egress_fq;

	qm_ctx = QM_GET_CONTEXT(eth_info->portid);
	if (qm_ctx->qos_enabled) {
		egress_fq = ceetm_get_egressfq(qm_ctx,
		    qosmark->chnl_id, qosmark->queue, 1);
		if (!egress_fq) {
			DPA_ERROR("%s: unable to get ceetm fqid for "
			    "markval %x\n", __func__, qosmark->markval);
			return (NULL);
		}
		return (egress_fq);
	}
#endif
	/* QOS not enabled on this interface */
	quenum = (qosmark->queue & (DPAA_FWD_TX_QUEUES - 1));
	return (&eth_info->fwd_tx_fqinfo[quenum]);
}

int
cdx_get_tx_dscp_fq_map(struct eth_iface_info *eth_info,
    uint8_t *is_dscp_fq_map, void *info)
{

#ifdef ENABLE_EGRESS_QOS
	if (is_dscp_fq_map) {
		uint32_t mark = 0;
		union ctentry_qosmark *qosmark =
		    (union ctentry_qosmark *)&mark;
		PQM_context_ctl qm_ctx;

		if (info)
			qosmark = info;

		qm_ctx = QM_GET_CONTEXT(eth_info->portid);
		if (qm_ctx->qos_enabled) {
			if ((!qosmark->markval) && qm_ctx->dscp_fq_map)
				*is_dscp_fq_map = 1;
			else
				*is_dscp_fq_map = 0;
		} else {
			*is_dscp_fq_map = 0;
		}
	}
#else
	if (is_dscp_fq_map)
		*is_dscp_fq_map = 0;
#endif
	return (0);
}

/* ================================================================
 * Interface release / cleanup
 * ================================================================ */

void
dpa_release_interface(uint32_t itf_id)
{
	struct dpa_iface_info **pp, *p;

	spin_lock(&dpa_devlist_lock);

	for (pp = &dpa_interface_info; *pp != NULL; pp = &(*pp)->next) {
		if ((*pp)->itf_id == itf_id) {
			p = *pp;
			*pp = p->next;
			spin_unlock(&dpa_devlist_lock);
#ifdef INCLUDE_IFSTATS_SUPPORT
			if (p->if_flags & IF_STATS_ENABLED)
				free_iface_stats(p->if_flags, p);
#endif
			kfree(p);
			DPA_INFO("cdx: devman: released itf_id=%u\n", itf_id);
			return;
		}
	}

	spin_unlock(&dpa_devlist_lock);
}

void
dpa_release_iflist(void)
{
	struct dpa_iface_info *p, *next;
	int i;

	/* Free CDX forwarding TX FQRs */
	for (i = 0; i < CDX_MAX_ETH_PORTS; i++) {
		if (cdx_fwd_tx_fqr[i] != NULL) {
			qman_fqr_free(cdx_fwd_tx_fqr[i]);
			cdx_fwd_tx_fqr[i] = NULL;
		}
	}

	spin_lock(&dpa_devlist_lock);

	p = dpa_interface_info;
	dpa_interface_info = NULL;

	spin_unlock(&dpa_devlist_lock);

	while (p != NULL) {
		next = p->next;
#ifdef INCLUDE_IFSTATS_SUPPORT
		if (p->if_flags & IF_STATS_ENABLED)
			free_iface_stats(p->if_flags, p);
#endif
		kfree(p);
		p = next;
	}
}

/* ================================================================
 * cdx_diag_dump_fwd_fqs — Diagnostic: dump forwarding FQ stats
 *
 * Queries QMan frame counters for each forwarding TX FQ to
 * determine whether the FMan microcode's ENQUEUE_PKT opcode
 * actually enqueued frames.  If enq_frames=0, the opcode chain
 * never reached ENQUEUE_PKT (issue in hash entry / opcodes).
 * If enq_frames>0, frames were enqueued and the issue is
 * downstream (FMan TX port or wire).
 * ================================================================ */

void
cdx_diag_dump_fwd_fqs(void)
{
	struct dpa_iface_info *p;
	int port, i;
	uint32_t base, frames, bytes;

	printf("cdx: === Forwarding TX FQ Diagnostics ===\n");
	for (port = 0; port < CDX_MAX_ETH_PORTS; port++) {
		if (cdx_fwd_tx_fqr[port] == NULL)
			continue;
		base = QM_FQR_GetFqid(cdx_fwd_tx_fqr[port]);
		for (i = 0; i < DPAA_FWD_TX_QUEUES; i++) {
			frames = qman_fqr_get_counter(cdx_fwd_tx_fqr[port],
			    i, e_QM_FQR_COUNTERS_FRAME);
			bytes = qman_fqr_get_counter(cdx_fwd_tx_fqr[port],
			    i, e_QM_FQR_COUNTERS_BYTE);
			if (frames > 0 || i == 0)
				printf("cdx:   port%d fq[%d] fqid=0x%x "
				    "frames=%u bytes=%u\n",
				    port, i, base + i, frames, bytes);
		}
	}

	/*
	 * Dump TX port BMI counters for each registered interface.
	 * These tell us whether FMan TX port actually transmitted
	 * frames after the forwarding FQ delivered them.
	 */
	printf("cdx: === TX Port BMI Counters ===\n");
	spin_lock(&dpa_devlist_lock);
	for (p = dpa_interface_info; p != NULL; p = p->next) {
		struct dtsec_softc *sc;
		t_FmPortBmiStats bmi;
		t_Error err;

		sc = cdx_dpa_bridge_find_dtsec_by_ethid(
		    p->eth_info.port_idx);
		if (sc == NULL || sc->sc_txph == NULL)
			continue;
		err = FM_PORT_GetBmiCounters(sc->sc_txph, &bmi);
		if (err != E_OK)
			continue;
		printf("cdx:   %s tx: frames=%u discard=%u "
		    "len_err=%u unsup_fmt=%u\n",
		    p->name, bmi.cntFrame, bmi.cntDiscardFrame,
		    bmi.cntLengthErr, bmi.cntUnsupportedFormat);
	}
	/*
	 * Dump FMan QMI counters — total enqueue/dequeue across all
	 * ports.  If enq_total increases after offload but TX port
	 * frames don't, the FQ→port delivery is broken.
	 */
	if (dpa_interface_info != NULL) {
		struct dtsec_softc *sc0;

		sc0 = cdx_dpa_bridge_find_dtsec_by_ethid(
		    dpa_interface_info->eth_info.port_idx);
		if (sc0 != NULL && sc0->sc_fmh != NULL) {
			printf("cdx: === FMan QMI Counters ===\n");
			printf("cdx:   enq_total=%u deq_total=%u "
			    "deq_from_ctx=%u deq_from_fd=%u "
			    "deq_confirm=%u\n",
			    FM_GetCounter(sc0->sc_fmh,
			        e_FM_COUNTERS_ENQ_TOTAL_FRAME),
			    FM_GetCounter(sc0->sc_fmh,
			        e_FM_COUNTERS_DEQ_TOTAL_FRAME),
			    FM_GetCounter(sc0->sc_fmh,
			        e_FM_COUNTERS_DEQ_FROM_CONTEXT),
			    FM_GetCounter(sc0->sc_fmh,
			        e_FM_COUNTERS_DEQ_FROM_FD),
			    FM_GetCounter(sc0->sc_fmh,
			        e_FM_COUNTERS_DEQ_CONFIRM));
		}
	}
	spin_unlock(&dpa_devlist_lock);
	printf("cdx: === End Diagnostics ===\n");
}

/* ================================================================
 * devman_init_linux_stats — Module init
 *
 * Called from cdx_module_init().  Initializes the devlist lock.
 * ================================================================ */

int
devman_init_linux_stats(void)
{

	spin_lock_init(&dpa_devlist_lock);
	return (0);
}

/* ================================================================
 * Tunnel interface management
 *
 * Registers and updates GRE/IPinIP/6in4/4in6 tunnel virtual
 * interfaces.  Called by Tier 1 control_tunnel.c when CMM
 * notifies CDX about tunnel creation/update.
 * ================================================================ */

#include "control_tunnel.h"

static uint8_t tunnel_iface_count;

int
dpa_add_tunnel_if(itf_t *itf, itf_t *phys_itf, PTnlEntry pTunnelEntry)
{
#ifdef TUNNEL_IF_SUPPORT
	struct dpa_iface_info *iface_info;
	struct dpa_iface_info *parent;

	if (tunnel_iface_count >= (MAX_LOGICAL_INTERFACES -
	    MAX_PPPoE_INTERFACES)) {
		DPA_ERROR("cdx: dpa_add_tunnel_if: max interfaces (%d) "
		    "reached\n",
		    MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES);
		return (FAILURE);
	}

	if (itf == NULL) {
		DPA_ERROR("cdx: dpa_add_tunnel_if: null itf\n");
		return (FAILURE);
	}

	iface_info = kzalloc(sizeof(struct dpa_iface_info), GFP_KERNEL);
	if (iface_info == NULL) {
		DPA_ERROR("cdx: dpa_add_tunnel_if: no memory\n");
		return (FAILURE);
	}

	iface_info->itf_id = itf->index;
	iface_info->if_flags = itf->type;
	strncpy((char *)iface_info->name, pTunnelEntry->tnl_name,
	    IF_NAME_SIZE);
	iface_info->name[IF_NAME_SIZE - 1] = '\0';

	iface_info->tunnel_info.mode = pTunnelEntry->mode;
	if (iface_info->tunnel_info.mode == TNL_MODE_6O4)
		iface_info->tunnel_info.proto = PROTO_IPV4;
	if (iface_info->tunnel_info.mode == TNL_MODE_4O6) {
		iface_info->tunnel_info.proto = PROTO_IPV6;
		iface_info->tunnel_info.flags = pTunnelEntry->flags;
	}
	iface_info->tunnel_info.header_size = pTunnelEntry->header_size;
	memcpy(&iface_info->tunnel_info.local_ip, pTunnelEntry->local,
	    IPV6_ADDRESS_LENGTH);
	memcpy(&iface_info->tunnel_info.remote_ip, pTunnelEntry->remote,
	    IPV6_ADDRESS_LENGTH);
	memcpy(&iface_info->tunnel_info.header, pTunnelEntry->header,
	    pTunnelEntry->header_size);

	spin_lock(&dpa_devlist_lock);
	if (phys_itf != NULL) {
		parent = devman_find_by_itfid(phys_itf->index);
		if (parent == NULL || parent == iface_info) {
			DPA_ERROR("cdx: dpa_add_tunnel_if: no ifinfo for "
			    "parent idx %d\n", phys_itf->index);
			spin_unlock(&dpa_devlist_lock);
			goto err_ret;
		}
		iface_info->tunnel_info.parent = parent;
		/* Inherit parent's MTU as default */
		iface_info->mtu = parent->mtu;

		if (pTunnelEntry->pRtEntry != NULL)
			memcpy(&iface_info->tunnel_info.dstmac,
			    pTunnelEntry->pRtEntry->dstmac, ETH_ALEN);
	} else {
		iface_info->tunnel_info.parent = NULL;
		iface_info->mtu = pTunnelEntry->tnl_mtu;
	}
	spin_unlock(&dpa_devlist_lock);

#ifdef INCLUDE_TUNNEL_IFSTATS
	if (alloc_iface_stats(itf->type, iface_info) == SUCCESS)
		iface_info->if_flags |= IF_STATS_ENABLED;
#endif

	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("cdx: dpa_add_tunnel_if: "
		    "dpa_add_port_to_list failed\n");
		goto err_ret;
	}
	tunnel_iface_count++;

	DPA_INFO("cdx: devman: registered tunnel %s — itf_id=%u "
	    "mode=%u proto=%u\n",
	    (char *)iface_info->name, iface_info->itf_id,
	    iface_info->tunnel_info.mode, iface_info->tunnel_info.proto);

	return (SUCCESS);
err_ret:
	kfree(iface_info);
	return (FAILURE);
#else
	DPA_ERROR("cdx: dpa_add_tunnel_if: tunnel not supported\n");
	return (FAILURE);
#endif
}

int
dpa_update_tunnel_if(itf_t *itf, itf_t *phys_itf, PTnlEntry pTunnelEntry)
{
#ifdef TUNNEL_IF_SUPPORT
	struct dpa_iface_info *iface_info;
	struct dpa_iface_info *parent;

	if (itf == NULL) {
		DPA_ERROR("cdx: dpa_update_tunnel_if: null itf\n");
		return (FAILURE);
	}

	spin_lock(&dpa_devlist_lock);
	iface_info = devman_find_by_itfid(itf->index);
	if (iface_info == NULL) {
		DPA_ERROR("cdx: dpa_update_tunnel_if: iface not found "
		    "for itf_id=%u\n", itf->index);
		spin_unlock(&dpa_devlist_lock);
		return (FAILURE);
	}

	iface_info->tunnel_info.mode = pTunnelEntry->mode;
	if (iface_info->tunnel_info.mode == TNL_MODE_6O4)
		iface_info->tunnel_info.proto = PROTO_IPV4;
	if (iface_info->tunnel_info.mode == TNL_MODE_4O6) {
		iface_info->tunnel_info.proto = PROTO_IPV6;
		iface_info->tunnel_info.flags = pTunnelEntry->flags;
	}
	iface_info->tunnel_info.header_size = pTunnelEntry->header_size;
	memcpy(&iface_info->tunnel_info.local_ip, pTunnelEntry->local,
	    IPV6_ADDRESS_LENGTH);
	memcpy(&iface_info->tunnel_info.remote_ip, pTunnelEntry->remote,
	    IPV6_ADDRESS_LENGTH);
	memcpy(&iface_info->tunnel_info.header, pTunnelEntry->header,
	    pTunnelEntry->header_size);

	if (phys_itf != NULL) {
		parent = devman_find_by_itfid(phys_itf->index);
		if (parent == NULL) {
			DPA_ERROR("cdx: dpa_update_tunnel_if: no ifinfo for "
			    "parent idx %d\n", phys_itf->index);
			spin_unlock(&dpa_devlist_lock);
			return (FAILURE);
		}
		iface_info->tunnel_info.parent = parent;
		/* Inherit parent's MTU as default */
		iface_info->mtu = parent->mtu;

		if (pTunnelEntry->pRtEntry != NULL)
			memcpy(&iface_info->tunnel_info.dstmac,
			    pTunnelEntry->pRtEntry->dstmac, ETH_ALEN);
	} else {
		iface_info->tunnel_info.parent = NULL;
		iface_info->mtu = pTunnelEntry->tnl_mtu;
	}

	spin_unlock(&dpa_devlist_lock);
	return (SUCCESS);
#else
	DPA_ERROR("cdx: dpa_update_tunnel_if: tunnel not supported\n");
	return (FAILURE);
#endif
}

/* ================================================================
 * VLAN interface type check — used by cdx_ehash.c RTP relay path
 * to decide whether to insert VLAN strip header manipulation.
 * ================================================================ */

/*
 * cdx_check_rx_iface_type_vlan — Count VLAN nesting depth.
 *
 * Returns the number of stacked VLAN layers (0 if not a VLAN).
 * Used by cdx_rtpflow_fill_actions() as a boolean to decide
 * whether to insert VLAN strip header manipulation opcodes.
 */
int
cdx_check_rx_iface_type_vlan(struct _itf *input_itf)
{
	struct dpa_iface_info *iface_info, *parent;
	int num_vlan_entries;

	if (input_itf == NULL)
		return (0);

	iface_info = devman_find_by_itfid(input_itf->index);
	if (iface_info == NULL)
		return (0);

	if (!(iface_info->if_flags & IF_TYPE_VLAN))
		return (0);

	num_vlan_entries = 1;
	parent = iface_info->vlan_info.parent;
	while (parent != NULL) {
		if (parent->if_flags & IF_TYPE_VLAN) {
			num_vlan_entries++;
			parent = parent->vlan_info.parent;
		} else {
			break;
		}
	}

	return (num_vlan_entries);
}

/* ================================================================
 * Remaining stubs — WiFi/bridge not in scope for this platform
 * ================================================================ */

int
dpa_add_wlan_if(char *name, struct _itf *itf, uint32_t vap_id,
    unsigned char *mac)
{
	return (-1);
}

int
dpa_update_wlan_if(struct _itf *itf, unsigned char *mac)
{
	return (-1);
}

int
dpa_set_bridged_itf(uint8_t *ifname, uint8_t is_bridged,
    uint8_t *br_mac_addr)
{
	return (0);
}

void
display_iface_info(struct dpa_iface_info *iface_info)
{
	/* Debug display — stub */
}

/* ================================================================
 * Interface statistics hierarchy walkers
 *
 * These walk the dpa_iface_info chain from a given interface up
 * to its physical parent, counting VLAN levels and extracting
 * stats indices for use by cdx_ehash.c Action Descriptor generation.
 * ================================================================ */

/*
 * dpa_get_num_vlan_iface_stats_entries — Count VLAN nesting depth.
 *
 * Walks from iif_index up through VLAN/PPPoE/tunnel parents,
 * incrementing *num_entries for each VLAN layer encountered.
 */
int
dpa_get_num_vlan_iface_stats_entries(uint32_t iif_index,
    uint32_t underlying_iif_index, uint32_t *num_entries)
{
	struct dpa_iface_info *iface_info, *parent;

	iface_info = devman_find_by_itfid(iif_index);
	*num_entries = 0;

	while (iface_info != NULL) {
		if (iface_info->if_flags & IF_TYPE_ETHERNET)
			return (SUCCESS);
		if (iface_info->if_flags & IF_TYPE_WLAN)
			return (SUCCESS);
		if (iface_info->if_flags & IF_TYPE_VLAN) {
			(*num_entries)++;
			iface_info = iface_info->vlan_info.parent;
			continue;
		}
		if (iface_info->if_flags & IF_TYPE_PPPOE) {
			iface_info = iface_info->pppoe_info.parent;
			continue;
		}
		if ((iface_info->if_flags & IF_TYPE_TUNNEL) &&
		    underlying_iif_index != 0) {
			parent = devman_find_by_itfid(underlying_iif_index);
			if (parent == NULL || parent == iface_info)
				return (FAILURE);
			iface_info = parent;
			continue;
		}
		DPA_ERROR("cdx: dpa_get_num_vlan_iface_stats_entries: "
		    "unsupported type 0x%x\n", iface_info->if_flags);
		break;
	}
	return (FAILURE);
}

/*
 * dpa_get_iface_stats — Extract stats index from interface info.
 *
 * Helper for dpa_get_iface_stats_entries().  Stores the rxstats or
 * txstats index into *offset, advancing the pointer for VLAN chains.
 */
static int
dpa_get_iface_stats(struct dpa_iface_info *iface_info,
    uint8_t **offset, uint32_t stats_type, uint32_t iface_type)
{

	if (stats_type == TX_IFSTATS) {
		**offset = iface_info->txstats_index;
		if (iface_type == IF_TYPE_VLAN)
			(*offset)--;
	} else {
		**offset = iface_info->rxstats_index;
		if (iface_type == IF_TYPE_VLAN)
			(*offset)++;
	}
	return (SUCCESS);
}

/*
 * dpa_get_iface_stats_entries — Walk interface hierarchy to find
 * stats indices for a given interface type.
 *
 * Called by cdx_ehash.c during flow insertion to populate stats_ptr
 * fields in the Action Descriptor.
 */
int
dpa_get_iface_stats_entries(uint32_t iif_index,
    uint32_t underlying_iif_index, uint8_t *offset,
    uint32_t stats_type, uint32_t iface_type)
{
	struct dpa_iface_info *iface_info, *parent;

	iface_info = devman_find_by_itfid(iif_index);
	if (iface_info == NULL) {
		DPA_ERROR("cdx: dpa_get_iface_stats_entries: "
		    "iface is NULL for iif 0x%x\n", iif_index);
		return (FAILURE);
	}

	switch (iface_type) {
	case IF_TYPE_PPPOE:
		if (iface_info->if_flags & IF_TYPE_PPPOE) {
			dpa_get_iface_stats(iface_info, &offset,
			    stats_type, iface_type);
			return (SUCCESS);
		}
		return (FAILURE);

	case IF_TYPE_TUNNEL:
		if (iface_info->if_flags & IF_TYPE_TUNNEL) {
			dpa_get_iface_stats(iface_info, &offset,
			    stats_type, iface_type);
			return (SUCCESS);
		}
		return (FAILURE);

	case IF_TYPE_ETHERNET:
	case IF_TYPE_WLAN:
	case IF_TYPE_VLAN:
		break;

	default:
		return (FAILURE);
	}

	/* Walk hierarchy for ETHERNET/WLAN/VLAN types */
	while (iface_info != NULL) {
		if (iface_info->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_WLAN)) {
			if (iface_type == IF_TYPE_ETHERNET ||
			    iface_type == IF_TYPE_WLAN) {
				dpa_get_iface_stats(iface_info, &offset,
				    stats_type, iface_type);
			}
			return (SUCCESS);
		}
		if (iface_info->if_flags & IF_TYPE_VLAN) {
			if (iface_type == IF_TYPE_VLAN) {
				dpa_get_iface_stats(iface_info, &offset,
				    stats_type, iface_type);
			}
			iface_info = iface_info->vlan_info.parent;
			continue;
		}
		if (iface_info->if_flags & IF_TYPE_PPPOE) {
			iface_info = iface_info->pppoe_info.parent;
			continue;
		}
		if ((iface_info->if_flags & IF_TYPE_TUNNEL) &&
		    underlying_iif_index != 0) {
			parent = devman_find_by_itfid(underlying_iif_index);
			if (parent == NULL || parent == iface_info) {
				DPA_ERROR("cdx: dpa_get_iface_stats_entries: "
				    "invalid parent for tunnel\n");
				return (FAILURE);
			}
			iface_info = parent;
			continue;
		}
		DPA_ERROR("cdx: dpa_get_iface_stats_entries: "
		    "unsupported type 0x%x\n", iface_info->if_flags);
		break;
	}
	return (FAILURE);
}

/*
 * dpa_check_for_logical_iface_types — Discover logical interface
 * types in the ingress path.
 *
 * Walks from input_itf up the hierarchy to discover VLAN, PPPoE, and
 * tunnel encapsulations present on the ingress side.  This information
 * is used by cdx_ehash.c to determine which header modification and
 * stats opcodes to insert.
 */
int
dpa_check_for_logical_iface_types(struct _itf *input_itf,
    struct _itf *underlying_input_itf,
    struct dpa_l2hdr_info *l2_info,
    struct dpa_l3hdr_info *l3_info)
{
	struct dpa_iface_info *iface_info, *parent;

	l2_info->vlan_present = 0;
	l2_info->pppoe_present = 0;

	iface_info = devman_find_by_itfid(input_itf->index);
	while (iface_info != NULL) {
		if (iface_info->if_flags & IF_TYPE_ETHERNET)
			return (SUCCESS);
		if (iface_info->if_flags & IF_TYPE_WLAN)
			return (SUCCESS);
		if (iface_info->if_flags & IF_TYPE_VLAN) {
			l2_info->vlan_present = 1;
			if (l2_info->num_ingress_vlan_hdrs >=
			    DPA_CLS_HM_MAX_VLANs) {
				DPA_INFO("cdx: dpa_check_for_logical: "
				    "too many VLAN headers\n");
				break;
			}
			l2_info->ingress_vlan_hdrs[l2_info->num_ingress_vlan_hdrs].tpid =
			    ETHERTYPE_VLAN;
			l2_info->ingress_vlan_hdrs[l2_info->num_ingress_vlan_hdrs].tci =
			    iface_info->vlan_info.vlan_id;
			l2_info->num_ingress_vlan_hdrs++;
			iface_info = iface_info->vlan_info.parent;
			continue;
		}
		if (iface_info->if_flags & IF_TYPE_PPPOE) {
			l2_info->pppoe_present = 1;
			l2_info->pppoe_sess_id =
			    iface_info->pppoe_info.session_id;
			memcpy(l2_info->ac_mac_addr,
			    iface_info->pppoe_info.mac_addr, ETH_ALEN);
			iface_info = iface_info->pppoe_info.parent;
			continue;
		}
		if ((iface_info->if_flags & IF_TYPE_TUNNEL) &&
		    underlying_input_itf != NULL) {
			l3_info->tnl_header_present = 1;
			l3_info->header_size =
			    iface_info->tunnel_info.header_size;
			l3_info->proto = iface_info->tunnel_info.proto;
			l3_info->mode = iface_info->tunnel_info.mode;
			l3_info->tunnel_flags =
			    iface_info->tunnel_info.flags;
			memcpy(l3_info->local_ip,
			    iface_info->tunnel_info.local_ip,
			    IPV6_ADDRESS_LENGTH);
			memcpy(l3_info->remote_ip,
			    iface_info->tunnel_info.remote_ip,
			    IPV6_ADDRESS_LENGTH);
			parent = devman_find_by_itfid(
			    underlying_input_itf->index);
			if (parent == NULL || parent == iface_info) {
				DPA_ERROR("cdx: dpa_check_for_logical: "
				    "invalid tunnel parent\n");
				return (FAILURE);
			}
			iface_info = parent;
			continue;
		}
		DPA_ERROR("cdx: dpa_check_for_logical: "
		    "unsupported type 0x%x\n", iface_info->if_flags);
		break;
	}
	return (FAILURE);
}

/* From control_tx.c (Tier 1) */
extern bool cdx_get_tx_dscp_vlanpcp_map_enable(uint32_t portid);

/*
 * dpa_get_l2l3_info_by_itf_id — Collect L2/L3 header info for an
 * interface, walking up the hierarchy through VLAN, PPPoE, and tunnel
 * encapsulations.  Used by IPsec SA descriptor building to know what
 * L2/L3 headers to insert/strip.
 *
 * dir_in != NULL means inbound direction (populates ingress VLAN info).
 * dir_in == NULL means outbound (populates egress VLAN info).
 */
int
dpa_get_l2l3_info_by_itf_id(uint32_t itf_id,
    struct dpa_l2hdr_info *l2_info, struct dpa_l3hdr_info *l3_info,
    uint32_t *dir_in)
{
	struct dpa_iface_info *iface_info;
	int retval = FAILURE;

	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l3hdr_info));

	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
	while (1) {
		if (!iface_info)
			break;

		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			l2_info->mtu = iface_info->mtu;
			l2_info->dscp_vlanpcp_map_enable =
			    cdx_get_tx_dscp_vlanpcp_map_enable(
			    iface_info->eth_info.portid);
			if (l2_info->dscp_vlanpcp_map_enable &&
			    !l2_info->num_egress_vlan_hdrs) {
				l2_info->egress_vlan_hdrs[
				    l2_info->num_egress_vlan_hdrs].tpid =
				    ETHERTYPE_VLAN;
				l2_info->egress_vlan_hdrs[
				    l2_info->num_egress_vlan_hdrs].tci = 0;
				l2_info->num_egress_vlan_hdrs++;
			}
#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset =
			    iface_info->txstats_index;
#endif
			retval = SUCCESS;
			break;
		}
		if (iface_info->if_flags & IF_TYPE_WLAN) {
			l2_info->mtu = iface_info->mtu;
			l2_info->is_wlan_iface = 1;
			retval = SUCCESS;
			break;
		}
		if (iface_info->if_flags & IF_TYPE_VLAN) {
			if (dir_in) {
				l2_info->vlan_present = 1;
				if (l2_info->num_ingress_vlan_hdrs >=
				    DPA_CLS_HM_MAX_VLANs) {
					DPA_INFO("cdx: dpa_get_l2l3: "
					    "too many VLAN headers\n");
					retval = FAILURE;
					break;
				}
				l2_info->ingress_vlan_hdrs[
				    l2_info->num_ingress_vlan_hdrs].tpid =
				    ETHERTYPE_VLAN;
				l2_info->ingress_vlan_hdrs[
				    l2_info->num_ingress_vlan_hdrs].tci =
				    iface_info->vlan_info.vlan_id;
				l2_info->num_ingress_vlan_hdrs++;
			} else {
				if (l2_info->num_egress_vlan_hdrs >=
				    DPA_CLS_HM_MAX_VLANs) {
					DPA_INFO("cdx: dpa_get_l2l3: "
					    "too many VLAN headers\n");
					retval = FAILURE;
					break;
				}
				l2_info->egress_vlan_hdrs[
				    l2_info->num_egress_vlan_hdrs].tpid =
				    ETHERTYPE_VLAN;
				l2_info->egress_vlan_hdrs[
				    l2_info->num_egress_vlan_hdrs].tci =
				    iface_info->vlan_info.vlan_id;
				l2_info->num_egress_vlan_hdrs++;
			}
			iface_info = iface_info->vlan_info.parent;
			continue;
		}
		if (iface_info->if_flags & IF_TYPE_PPPOE) {
			if (dir_in)
				l2_info->pppoe_present = 1;
			else
				l2_info->add_pppoe_hdr = 1;
			l2_info->pppoe_sess_id =
			    iface_info->pppoe_info.session_id;
			memcpy(l2_info->ac_mac_addr,
			    iface_info->pppoe_info.mac_addr, ETH_ALEN);
			iface_info = iface_info->pppoe_info.parent;
			continue;
		}
		if (iface_info->if_flags & IF_TYPE_TUNNEL) {
			if (dir_in)
				l3_info->tnl_header_present = 1;
			else
				l3_info->add_tnl_header = 1;
			l3_info->header_size =
			    iface_info->tunnel_info.header_size;
			l3_info->proto = iface_info->tunnel_info.proto;
			l3_info->mode = iface_info->tunnel_info.mode;
			l3_info->tunnel_flags =
			    iface_info->tunnel_info.flags;
			memcpy(l3_info->local_ip,
			    iface_info->tunnel_info.local_ip,
			    IPV6_ADDRESS_LENGTH);
			memcpy(l3_info->remote_ip,
			    iface_info->tunnel_info.remote_ip,
			    IPV6_ADDRESS_LENGTH);
			iface_info = iface_info->tunnel_info.parent;
			continue;
		}
		DPA_INFO("cdx: dpa_get_l2l3: iface type 0x%x "
		    "not supported\n", iface_info->if_flags);
		break;
	}
	spin_unlock(&dpa_devlist_lock);
	return (retval);
}

int
dpa_get_out_tx_info_by_itf_id(PRouteEntry rt_entry,
    struct dpa_l2hdr_info *l2_info,
    struct dpa_l3hdr_info *l3_info)
{
	return (-1);
}

int
dpa_get_iface_info_by_ipaddress(int sa_family, uint32_t *daddr,
    uint32_t *tx_fqid, uint32_t *itf_id, uint32_t *portid,
    void **netdev, uint32_t hash)
{
	return (-1);
}

/* fm_ehash_freebsd.c timestamp accessors */
extern uint32_t cdx_ehash_get_timestamp_addr(uint32_t id);

uint32_t
dpa_get_timestamp_addr(uint32_t id)
{

	return (cdx_ehash_get_timestamp_addr(id));
}
