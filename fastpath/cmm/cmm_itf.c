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
#include <net/if_vlan_var.h>
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
					itf_detect_vlan(itf, sd);
					itf_detect_tunnel(itf, sd);
					close(sd);
				}
			}

			cmm_print(CMM_LOG_INFO,
			    "itf: %s idx=%d mac=%02x:%02x:%02x:%02x:%02x:%02x "
			    "mtu=%u flags=0x%x",
			    itf->ifname, itf->ifindex,
			    itf->macaddr[0], itf->macaddr[1],
			    itf->macaddr[2], itf->macaddr[3],
			    itf->macaddr[4], itf->macaddr[5],
			    itf->mtu, itf->flags);
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

		/* Populate MTU, MAC, and detect VLAN via ioctl */
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
				itf_detect_vlan(itf, sd);
				itf_detect_tunnel(itf, sd);
				close(sd);
			}
		}

		cmm_print(CMM_LOG_INFO,
		    "itf: new %s idx=%d mtu=%u",
		    itf->ifname, itf->ifindex, itf->mtu);
	}

	if (itf->flags != (uint32_t)ifm->ifm_flags) {
		cmm_print(CMM_LOG_INFO, "itf: %s flags 0x%x -> 0x%x%s%s",
		    itf->ifname, itf->flags, ifm->ifm_flags,
		    (ifm->ifm_flags & IFF_UP) ? " UP" : " DOWN",
		    (ifm->ifm_flags & IFF_RUNNING) ? " RUNNING" : "");
		itf->flags = ifm->ifm_flags;
	}

	if (ifm->ifm_data.ifi_mtu != 0 &&
	    itf->mtu != (uint32_t)ifm->ifm_data.ifi_mtu) {
		cmm_print(CMM_LOG_INFO, "itf: %s mtu %u -> %u",
		    itf->ifname, itf->mtu,
		    (unsigned int)ifm->ifm_data.ifi_mtu);
		itf->mtu = ifm->ifm_data.ifi_mtu;
	}

	/* Notify VLAN, tunnel, and bridge modules of flag changes */
	cmm_vlan_notify(g, itf);
	cmm_tunnel_notify(g, itf);

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
