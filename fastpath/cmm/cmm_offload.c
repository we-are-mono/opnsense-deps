/*
 * cmm_offload.c — Offload eligibility decisions
 *
 * Determines whether a PF state is eligible for hardware offload.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#define COMPAT_FREEBSD14	/* pf_state_export, pfioc_states_v2 */
#include <net/pfvar.h>
#include <netinet/in.h>
#include <netinet/tcp_fsm.h>
#include <arpa/inet.h>

#include "cmm.h"
#include "cmm_offload.h"
#include "cmm_itf.h"

/*
 * Check offload eligibility from pf_state_export (poll path).
 * A parallel version pfn_event_eligible() in cmm_conn.c mirrors
 * this logic for pfn_event (push path).  Changes to eligibility
 * criteria must be applied to BOTH functions.
 */
int
cmm_offload_eligible(const struct pf_state_export *pfs)
{
	uint8_t proto;
	sa_family_t af;
	const struct pf_state_key_export *stack;

	proto = pfs->proto;
	af = pfs->af;
	stack = &pfs->key[PF_SK_STACK];

	/* Only TCP and UDP */
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return (0);

	/* Only IPv4 and IPv6 */
	if (af != AF_INET && af != AF_INET6)
		return (0);

	/* Skip loopback */
	if (strncmp(pfs->ifname, "lo", 2) == 0)
		return (0);

	/* Skip multicast destinations */
	int didx = (pfs->direction == PF_IN) ? 1 : 0;
	if (af == AF_INET) {
		uint32_t daddr;
		memcpy(&daddr, &stack->addr[didx].v4, 4);
		if (IN_MULTICAST(ntohl(daddr)))
			return (0);
	} else {
		if (IN6_IS_ADDR_MULTICAST(&stack->addr[didx].v6))
			return (0);
	}

	/*
	 * For TCP: require ESTABLISHED state.
	 * PF state peer values are in network byte order.
	 */
	if (proto == IPPROTO_TCP) {
		uint8_t src_state, dst_state;

		src_state = pfs->src.state;
		dst_state = pfs->dst.state;

		/*
		 * PF TCP state values:
		 * TCPS_ESTABLISHED = 4 on FreeBSD.
		 * Both sides must be at least ESTABLISHED.
		 */
		if (src_state < TCPS_ESTABLISHED ||
		    dst_state < TCPS_ESTABLISHED)
			return (0);

		/* Don't offload connections in FIN/CLOSE states */
		if (src_state >= TCPS_FIN_WAIT_1 ||
		    dst_state >= TCPS_FIN_WAIT_1)
			return (0);
	}

	/*
	 * For UDP: require bidirectional traffic (both PF peers
	 * have seen packets — indicated by non-zero state).
	 */
	if (proto == IPPROTO_UDP) {
		if (pfs->src.state == 0 || pfs->dst.state == 0)
			return (0);
	}

	/*
	 * Skip connections where either endpoint is a local address.
	 *
	 * Use the STACK key (not wire key) because for NAT connections
	 * created PF_OUT, the wire key contains the NAT'd address
	 * (which IS local) but the stack key has the real endpoints.
	 * For non-NAT states, wire == stack so this is equivalent.
	 */
	if (af == AF_INET) {
		if (cmm_itf_is_local_addr(AF_INET, &stack->addr[0].v4) ||
		    cmm_itf_is_local_addr(AF_INET, &stack->addr[1].v4))
			return (0);
	} else {
		if (cmm_itf_is_local_addr(AF_INET6, &stack->addr[0].v6) ||
		    cmm_itf_is_local_addr(AF_INET6, &stack->addr[1].v6))
			return (0);
	}

	/*
	 * For NAT connections, PF creates two states: one on PF_IN
	 * (wire == stack, no NAT info) and one on PF_OUT (wire != stack,
	 * has NAT info).  Only offload the PF_OUT state which has the
	 * correct wire-side addresses for both directions.
	 */
	if (memcmp(&pfs->key[PF_SK_WIRE], &pfs->key[PF_SK_STACK],
	    sizeof(struct pf_state_key_export)) != 0) {
		/* NAT state (wire != stack) — eligible */
		return (1);
	}

	/*
	 * wire == stack: either non-NAT (offload) or PF_IN side of a
	 * NAT connection (skip — the PF_OUT state has correct info).
	 * Heuristic: if direction is PF_OUT, it's a non-NAT outbound
	 * state (rare for forwarded traffic).  If PF_IN and there's a
	 * nat rule, we can't tell here — accept it and let the hash
	 * entry be harmlessly redundant.  The PF_OUT state's correct
	 * entry will be the one that actually matches.
	 */
	return (1);
}
