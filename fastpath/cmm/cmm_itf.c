/*
 * cmm_itf.c — Interface monitoring
 *
 * Discovers and tracks network interfaces using getifaddrs(3) for
 * initial enumeration and PF_ROUTE socket for change notification.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/if_vlan_var.h>
#include <net/if_lagg.h>
#include <net/if_media.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_itf.h"
#include "cmm_vlan.h"
#include "cmm_tunnel.h"
#include "cmm_bridge.h"
#include "cmm_wifi.h"
#include "cmm_pppoe.h"
#include "cmm_lagg.h"

static struct list_head itf_hash[ITF_HASH_SIZE];

static inline unsigned int
itf_hash_index(int ifindex)
{
	return ((unsigned int)ifindex % ITF_HASH_SIZE);
}

struct cmm_interface *
cmm_itf_find_by_index(int ifindex)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	unsigned int h;

	h = itf_hash_index(ifindex);
	bucket = &itf_hash[h];

	for (pos = list_first(bucket); pos != bucket; pos = list_next(pos)) {
		itf = container_of(pos, struct cmm_interface, entry);
		if (itf->ifindex == ifindex)
			return (itf);
	}
	return (NULL);
}

struct cmm_interface *
cmm_itf_find_by_name(const char *name)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (strcmp(itf->ifname, name) == 0)
				return (itf);
		}
	}
	return (NULL);
}

static struct cmm_interface *
itf_create(const char *name, int ifindex)
{
	struct cmm_interface *itf;
	unsigned int h;

	itf = calloc(1, sizeof(*itf));
	if (itf == NULL)
		return (NULL);

	strlcpy(itf->ifname, name, sizeof(itf->ifname));
	itf->ifindex = ifindex;
	list_head_init(&itf->addrs);
	itf->entry.next = NULL;
	itf->entry.prev = NULL;

	h = itf_hash_index(ifindex);
	list_add(&itf_hash[h], &itf->entry);

	return (itf);
}

static void
itf_add_addr(struct cmm_interface *itf, sa_family_t family,
    const void *addr, uint8_t prefixlen)
{
	struct cmm_ifaddr *ifa;

	ifa = calloc(1, sizeof(*ifa));
	if (ifa == NULL)
		return;

	ifa->family = family;
	if (family == AF_INET)
		memcpy(&ifa->addr.v4, addr, sizeof(struct in_addr));
	else
		memcpy(&ifa->addr.v6, addr, sizeof(struct in6_addr));
	ifa->prefixlen = prefixlen;
	ifa->entry.next = NULL;
	ifa->entry.prev = NULL;

	list_add(&itf->addrs, &ifa->entry);
}

static uint8_t
mask_to_prefixlen(sa_family_t af, const void *mask)
{
	const uint8_t *p;
	int len, bits;

	len = (af == AF_INET) ? 4 : 16;
	p = mask;
	bits = 0;
	for (int i = 0; i < len; i++) {
		if (p[i] == 0xff) {
			bits += 8;
		} else {
			uint8_t b = p[i];
			while (b & 0x80) {
				bits++;
				b <<= 1;
			}
			break;
		}
	}
	return ((uint8_t)bits);
}

/*
 * Probe an interface for 802.1Q VLAN membership using SIOCGETVLAN.
 * If successful, populates vlan_id, parent_ifindex, and sets ITF_F_VLAN.
 */
/*
 * Detect WiFi VAP interfaces by name prefix.
 * mwifiex creates "uap0", "uap1", etc.
 */
static void
itf_detect_wifi(struct cmm_interface *itf)
{
	if (strncmp(itf->ifname, "uap", 3) == 0 ||
	    strncmp(itf->ifname, "wlan", 4) == 0) {
		itf->itf_flags |= ITF_F_WIFI;
		cmm_print(CMM_LOG_INFO,
		    "itf: %s is WiFi VAP", itf->ifname);
	}
}

static void
itf_detect_vlan(struct cmm_interface *itf, int sd)
{
	struct ifreq ifr;
	struct vlanreq vlr;

	memset(&ifr, 0, sizeof(ifr));
	memset(&vlr, 0, sizeof(vlr));
	strlcpy(ifr.ifr_name, itf->ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&vlr;

	if (ioctl(sd, SIOCGETVLAN, &ifr) < 0)
		return;		/* Not a VLAN interface */
	if (vlr.vlr_tag == 0)
		return;

	itf->vlan_id = vlr.vlr_tag;
	itf->parent_ifindex = if_nametoindex(vlr.vlr_parent);
	itf->itf_flags |= ITF_F_VLAN;

	cmm_print(CMM_LOG_INFO,
	    "itf: %s is VLAN %u on %s (parent idx=%d)",
	    itf->ifname, itf->vlan_id, vlr.vlr_parent,
	    itf->parent_ifindex);
}

/*
 * Probe an interface for LAGG membership using SIOCGLAGG.
 * If successful, records the first ACTIVE member port name and
 * its ifindex as parent_ifindex, and sets ITF_F_LAGG.
 */
#define	LAGG_DETECT_MAX_PORTS	8

static void
itf_detect_lagg(struct cmm_interface *itf, int sd)
{
	struct lagg_reqall ra;
	struct lagg_reqport rp[LAGG_DETECT_MAX_PORTS];
	int i, found;

	memset(&ra, 0, sizeof(ra));
	memset(rp, 0, sizeof(rp));
	strlcpy(ra.ra_ifname, itf->ifname, sizeof(ra.ra_ifname));
	ra.ra_size = sizeof(rp);
	ra.ra_port = rp;

	if (ioctl(sd, SIOCGLAGG, &ra) < 0)
		return;		/* Not a LAGG interface */

	itf->itf_flags |= ITF_F_LAGG;

	if (ra.ra_ports < 1) {
		cmm_print(CMM_LOG_INFO,
		    "itf: %s is LAGG (no member ports)", itf->ifname);
		return;
	}

	/* Collect all member ports and find the first ACTIVE one */
	found = (ra.ra_ports < LAGG_DETECT_MAX_PORTS) ?
	    ra.ra_ports : LAGG_DETECT_MAX_PORTS;
	itf->lagg_num_members = 0;
	for (i = 0; i < found; i++) {
		cmm_print(CMM_LOG_DEBUG,
		    "itf: %s member[%d]=%s flags=0x%x",
		    itf->ifname, i, rp[i].rp_portname, rp[i].rp_flags);

		/* Record all member port names */
		if (itf->lagg_num_members < 8)
			strlcpy(itf->lagg_members[itf->lagg_num_members++],
			    rp[i].rp_portname, IFNAMSIZ);

		if ((rp[i].rp_flags & LAGG_PORT_ACTIVE) &&
		    itf->lagg_active_port[0] == '\0') {
			strlcpy(itf->lagg_active_port, rp[i].rp_portname,
			    sizeof(itf->lagg_active_port));
			itf->parent_ifindex =
			    if_nametoindex(rp[i].rp_portname);
		}
	}

	/* Fallback: if no ACTIVE flag found, use first port */
	if (itf->lagg_active_port[0] == '\0' && found > 0) {
		strlcpy(itf->lagg_active_port, rp[0].rp_portname,
		    sizeof(itf->lagg_active_port));
		itf->parent_ifindex = if_nametoindex(rp[0].rp_portname);
		cmm_print(CMM_LOG_INFO,
		    "itf: %s no ACTIVE member, using first: %s",
		    itf->ifname, itf->lagg_active_port);
	}

	cmm_print(CMM_LOG_INFO,
	    "itf: %s is LAGG (active=%s parent idx=%d, %d members)",
	    itf->ifname,
	    itf->lagg_active_port[0] ? itf->lagg_active_port : "(none)",
	    itf->parent_ifindex, itf->lagg_num_members);
}

int
cmm_itf_init(void)
{
	struct ifaddrs *ifap, *ifa;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++)
		list_head_init(&itf_hash[i]);

	if (getifaddrs(&ifap) < 0) {
		cmm_print(CMM_LOG_ERR, "itf: getifaddrs: %s",
		    strerror(errno));
		return (-1);
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		/* Create interface entry on AF_LINK (one per interface) */
		if (ifa->ifa_addr->sa_family == AF_LINK) {
			struct sockaddr_dl *sdl;
			int idx;

			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			idx = sdl->sdl_index;

			itf = cmm_itf_find_by_index(idx);
			if (itf != NULL)
				continue;

			itf = itf_create(ifa->ifa_name, idx);
			if (itf == NULL)
				continue;

			itf->flags = ifa->ifa_flags;

			/* Extract MAC address */
			if (sdl->sdl_alen == ETHER_ADDR_LEN)
				memcpy(itf->macaddr, LLADDR(sdl),
				    ETHER_ADDR_LEN);

			/* Detect bridge by link-layer type */
			if (sdl->sdl_type == IFT_BRIDGE)
				itf->itf_flags |= ITF_F_BRIDGE;

			/* Get MTU and detect VLAN via ioctl */
			{
				struct ifreq ifr;
				int sd;

				sd = socket(AF_INET, SOCK_DGRAM, 0);
				if (sd >= 0) {
					memset(&ifr, 0, sizeof(ifr));
					strlcpy(ifr.ifr_name, ifa->ifa_name,
					    sizeof(ifr.ifr_name));
					if (ioctl(sd, SIOCGIFMTU, &ifr) == 0)
						itf->mtu = ifr.ifr_mtu;
					itf_detect_lagg(itf, sd);
					itf_detect_vlan(itf, sd);
					itf_detect_tunnel(itf, sd);

					/* Init link_state from media status */
					{
						struct ifmediareq ifmr;

						memset(&ifmr, 0, sizeof(ifmr));
						strlcpy(ifmr.ifm_name,
						    ifa->ifa_name,
						    sizeof(ifmr.ifm_name));
						if (ioctl(sd, SIOCGIFMEDIA,
						    &ifmr) == 0)
							itf->link_state =
							    (ifmr.ifm_status &
							    IFM_ACTIVE) ?
							    LINK_STATE_UP :
							    LINK_STATE_DOWN;
					}
					close(sd);
				}
				itf_detect_wifi(itf);
				itf_detect_pppoe(itf);
			}

			cmm_print(CMM_LOG_INFO,
			    "itf: %s idx=%d mac=%02x:%02x:%02x:%02x:%02x:%02x "
			    "mtu=%u flags=0x%x ls=%d%s",
			    itf->ifname, itf->ifindex,
			    itf->macaddr[0], itf->macaddr[1],
			    itf->macaddr[2], itf->macaddr[3],
			    itf->macaddr[4], itf->macaddr[5],
			    itf->mtu, itf->flags, itf->link_state,
			    (itf->itf_flags & ITF_F_WIFI) ? " WIFI" : "");
			continue;
		}

		/* Add IP addresses */
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin, *mask;
			uint8_t plen = 32;

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			itf = cmm_itf_find_by_name(ifa->ifa_name);
			if (itf == NULL)
				continue;

			if (ifa->ifa_netmask) {
				mask = (struct sockaddr_in *)ifa->ifa_netmask;
				plen = mask_to_prefixlen(AF_INET,
				    &mask->sin_addr);
			}

			itf_add_addr(itf, AF_INET, &sin->sin_addr, plen);
			cmm_print(CMM_LOG_DEBUG, "itf: %s addr %s/%u",
			    itf->ifname, inet_ntoa(sin->sin_addr), plen);

		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6, *mask6;
			uint8_t plen = 128;

			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			itf = cmm_itf_find_by_name(ifa->ifa_name);
			if (itf == NULL)
				continue;

			if (ifa->ifa_netmask) {
				mask6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
				plen = mask_to_prefixlen(AF_INET6,
				    &mask6->sin6_addr);
			}

			itf_add_addr(itf, AF_INET6, &sin6->sin6_addr, plen);
		}
	}

	freeifaddrs(ifap);
	return (0);
}

void
cmm_itf_fini(void)
{
	struct cmm_interface *itf;
	struct cmm_ifaddr *ifa;
	struct list_head *pos, *tmp, *apos, *atmp;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		pos = list_first(&itf_hash[i]);
		while (pos != &itf_hash[i]) {
			tmp = list_next(pos);
			itf = container_of(pos, struct cmm_interface, entry);

			/* Free addresses */
			apos = list_first(&itf->addrs);
			while (apos != &itf->addrs) {
				atmp = list_next(apos);
				ifa = container_of(apos, struct cmm_ifaddr,
				    entry);
				list_del(&ifa->entry);
				free(ifa);
				apos = atmp;
			}

			list_del(&itf->entry);
			free(itf);
			pos = tmp;
		}
	}
}

void
cmm_itf_handle_ifinfo(struct cmm_global *g, void *msg, int msglen)
{
	struct if_msghdr *ifm = msg;
	struct cmm_interface *itf;

	(void)msglen;

	itf = cmm_itf_find_by_index(ifm->ifm_index);
	if (itf == NULL) {
		char ifname[IFNAMSIZ];

		if (if_indextoname(ifm->ifm_index, ifname) == NULL)
			return;

		itf = itf_create(ifname, ifm->ifm_index);
		if (itf == NULL)
			return;

		/* Detect bridge by interface type */
		if (ifm->ifm_data.ifi_type == IFT_BRIDGE)
			itf->itf_flags |= ITF_F_BRIDGE;

		/* Extract MAC from RTM_IFINFO sockaddr_dl */
		if (ifm->ifm_addrs & RTA_IFP) {
			struct sockaddr_dl *sdl;

			sdl = (struct sockaddr_dl *)(ifm + 1);
			if (sdl->sdl_family == AF_LINK &&
			    sdl->sdl_alen == ETHER_ADDR_LEN)
				memcpy(itf->macaddr, LLADDR(sdl),
				    ETHER_ADDR_LEN);
		}

		/* Populate MTU and detect VLAN/tunnel/WiFi */
		{
			struct ifreq ifr;
			int sd;

			sd = socket(AF_INET, SOCK_DGRAM, 0);
			if (sd >= 0) {
				memset(&ifr, 0, sizeof(ifr));
				strlcpy(ifr.ifr_name, ifname,
				    sizeof(ifr.ifr_name));
				if (ioctl(sd, SIOCGIFMTU, &ifr) == 0)
					itf->mtu = ifr.ifr_mtu;
				itf_detect_lagg(itf, sd);
				itf_detect_vlan(itf, sd);
				itf_detect_tunnel(itf, sd);
				close(sd);
			}
			itf_detect_wifi(itf);
			itf_detect_pppoe(itf);
		}

		cmm_print(CMM_LOG_INFO,
		    "itf: new %s idx=%d mac=%02x:%02x:%02x:%02x:%02x:%02x "
		    "mtu=%u flags=0x%x%s",
		    itf->ifname, itf->ifindex,
		    itf->macaddr[0], itf->macaddr[1],
		    itf->macaddr[2], itf->macaddr[3],
		    itf->macaddr[4], itf->macaddr[5],
		    itf->mtu, ifm->ifm_flags,
		    (itf->itf_flags & ITF_F_WIFI) ? " WIFI" : "");
	}

	if (itf->flags != (uint32_t)ifm->ifm_flags) {
		cmm_print(CMM_LOG_INFO, "itf: %s flags 0x%x -> 0x%x%s%s",
		    itf->ifname, itf->flags, ifm->ifm_flags,
		    (ifm->ifm_flags & IFF_UP) ? " UP" : " DOWN",
		    (ifm->ifm_flags & IFF_RUNNING) ? " RUNNING" : "");
		itf->flags = ifm->ifm_flags;
	}

	/*
	 * Check link state changes (ifi_link_state, not IFF_RUNNING).
	 * On FreeBSD, IFF_DRV_RUNNING stays set when a cable is unplugged;
	 * only ifi_link_state transitions to LINK_STATE_DOWN.
	 * If link state changed on a non-LAGG interface, it may be a
	 * LAGG member port — trigger failover check on all LAGGs.
	 */
	if (itf->link_state != ifm->ifm_data.ifi_link_state) {
		cmm_print(CMM_LOG_INFO,
		    "itf: %s link_state %d -> %d",
		    itf->ifname, itf->link_state,
		    ifm->ifm_data.ifi_link_state);
		itf->link_state = ifm->ifm_data.ifi_link_state;

		/*
		 * If link state changed on a non-LAGG interface, it may
		 * be a LAGG member — trigger failover check on all LAGGs.
		 */
		if (!(itf->itf_flags & ITF_F_LAGG))
			cmm_lagg_member_check(g, itf);
	}

	if (ifm->ifm_data.ifi_mtu != 0 &&
	    itf->mtu != (uint32_t)ifm->ifm_data.ifi_mtu) {
		cmm_print(CMM_LOG_INFO, "itf: %s mtu %u -> %u",
		    itf->ifname, itf->mtu,
		    (unsigned int)ifm->ifm_data.ifi_mtu);
		itf->mtu = ifm->ifm_data.ifi_mtu;
	}

	/* Notify LAGG, VLAN, tunnel, WiFi, PPPoE, and bridge modules of flag changes */
	cmm_lagg_notify(g, itf);
	cmm_vlan_notify(g, itf);
	cmm_tunnel_notify(g, itf);
	cmm_wifi_notify(g, itf);
	cmm_pppoe_notify(g, itf);

	/* If this is a bridge or a potential bridge member, rescan */
	if ((itf->itf_flags & ITF_F_BRIDGE) ||
	    ifm->ifm_data.ifi_type == IFT_BRIDGE)
		cmm_bridge_itf_update(g);
}

void
cmm_itf_handle_newaddr(struct cmm_global *g, void *msg, int msglen)
{
	struct ifa_msghdr *ifam = msg;
	struct cmm_interface *itf;
	struct sockaddr *sa;
	char *cp;
	int i;

	(void)msglen;

	itf = cmm_itf_find_by_index(ifam->ifam_index);
	if (itf == NULL)
		return;

	/* Parse sockaddrs to find the address */
	cp = (char *)(ifam + 1);
	for (i = 0; i < RTAX_MAX; i++) {
		if (!(ifam->ifam_addrs & (1 << i)))
			continue;
		sa = (struct sockaddr *)cp;
		if (i == RTAX_IFA) {
			if (sa->sa_family == AF_INET) {
				struct sockaddr_in *sin;
				sin = (struct sockaddr_in *)sa;
				itf_add_addr(itf, AF_INET,
				    &sin->sin_addr, 0);
				cmm_print(CMM_LOG_INFO,
				    "itf: %s new addr %s",
				    itf->ifname,
				    inet_ntoa(sin->sin_addr));
			} else if (sa->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin6;
				sin6 = (struct sockaddr_in6 *)sa;
				itf_add_addr(itf, AF_INET6,
				    &sin6->sin6_addr, 0);
				cmm_print(CMM_LOG_INFO,
				    "itf: %s new IPv6 addr", itf->ifname);
			}
			break;
		}
		cp += (sa->sa_len ?
		    (1 + ((sa->sa_len - 1) | (sizeof(long) - 1))) :
		    sizeof(long));
	}
}

void
cmm_itf_handle_deladdr(struct cmm_global *g, void *msg, int msglen)
{
	struct ifa_msghdr *ifam = msg;
	struct cmm_interface *itf;
	struct sockaddr *sa;
	char *cp;
	int i;

	(void)g;
	(void)msglen;

	itf = cmm_itf_find_by_index(ifam->ifam_index);
	if (itf == NULL)
		return;

	/* Parse sockaddrs to find the deleted address */
	cp = (char *)(ifam + 1);
	for (i = 0; i < RTAX_MAX; i++) {
		if (!(ifam->ifam_addrs & (1 << i)))
			continue;
		sa = (struct sockaddr *)cp;
		if (i == RTAX_IFA) {
			struct list_head *pos, *tmp;
			struct cmm_ifaddr *ifa;

			for (pos = list_first(&itf->addrs);
			    pos != &itf->addrs; ) {
				tmp = list_next(pos);
				ifa = container_of(pos, struct cmm_ifaddr,
				    entry);
				if (ifa->family != sa->sa_family) {
					pos = tmp;
					continue;
				}
				int match = 0;
				if (sa->sa_family == AF_INET) {
					struct sockaddr_in *sin;
					sin = (struct sockaddr_in *)sa;
					match = memcmp(&ifa->addr.v4,
					    &sin->sin_addr, 4) == 0;
				} else if (sa->sa_family == AF_INET6) {
					struct sockaddr_in6 *sin6;
					sin6 = (struct sockaddr_in6 *)sa;
					match = memcmp(&ifa->addr.v6,
					    &sin6->sin6_addr, 16) == 0;
				}
				if (match) {
					cmm_print(CMM_LOG_INFO,
					    "itf: %s del addr",
					    itf->ifname);
					list_del(&ifa->entry);
					free(ifa);
					break;
				}
				pos = tmp;
			}
			break;
		}
		cp += (sa->sa_len ?
		    (1 + ((sa->sa_len - 1) | (sizeof(long) - 1))) :
		    sizeof(long));
	}
}

int
cmm_itf_is_local_addr(sa_family_t af, const void *addr)
{
	struct cmm_interface *itf;
	struct cmm_ifaddr *ifa;
	struct list_head *bucket, *pos, *apos;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			for (apos = list_first(&itf->addrs);
			    apos != &itf->addrs;
			    apos = list_next(apos)) {
				ifa = container_of(apos, struct cmm_ifaddr,
				    entry);
				if (ifa->family != af)
					continue;
				if (af == AF_INET) {
					if (memcmp(&ifa->addr.v4, addr, 4) == 0)
						return (1);
				} else {
					if (memcmp(&ifa->addr.v6, addr, 16) == 0)
						return (1);
				}
			}
		}
	}
	return (0);
}

void
cmm_itf_foreach_vlan(struct cmm_global *g, cmm_itf_vlan_fn fn)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (itf->itf_flags & ITF_F_VLAN)
				fn(g, itf);
		}
	}
}

void
cmm_itf_foreach_lagg(struct cmm_global *g, cmm_itf_lagg_fn fn)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (itf->itf_flags & ITF_F_LAGG)
				fn(g, itf);
		}
	}
}

void
cmm_itf_foreach_tunnel(struct cmm_global *g, cmm_itf_tunnel_fn fn)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (itf->itf_flags & ITF_F_TUNNEL)
				fn(g, itf);
		}
	}
}

void
cmm_itf_foreach_l2tp(struct cmm_global *g, cmm_itf_l2tp_fn fn)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (itf->itf_flags & ITF_F_L2TP)
				fn(g, itf);
		}
	}
}

void
cmm_itf_foreach_wifi(struct cmm_global *g, cmm_itf_wifi_fn fn)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (itf->itf_flags & ITF_F_WIFI)
				fn(g, itf);
		}
	}
}

void
cmm_itf_foreach_pppoe(struct cmm_global *g, cmm_itf_pppoe_fn fn)
{
	struct list_head *bucket, *pos;
	struct cmm_interface *itf;
	int i;

	for (i = 0; i < ITF_HASH_SIZE; i++) {
		bucket = &itf_hash[i];
		for (pos = list_first(bucket); pos != bucket;
		    pos = list_next(pos)) {
			itf = container_of(pos, struct cmm_interface, entry);
			if (itf->itf_flags & ITF_F_PPPOE)
				fn(g, itf);
		}
	}
}
