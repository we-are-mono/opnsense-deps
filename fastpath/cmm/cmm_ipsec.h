/*
 * cmm_ipsec.h -- IPsec SA management via PF_KEY
 *
 * Monitors PF_KEY socket for SA events (add/delete/expire),
 * translates them into FCI commands for CDX hardware offload.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_IPSEC_H
#define CMM_IPSEC_H

#include "cmm.h"
#include <net/pfkeyv2.h>

/* SA state constants (must match CDX control_ipsec.c) */
#define SA_STATE_INIT	0x1
#define SA_STATE_VALID	0x2
#define SA_STATE_DEAD	0x3

/* SA flags */
#define NLKEY_SAFLAGS_ESN	0x1
#define NLKEY_SAFLAGS_INBOUND	0x2

/* Protocol family (must match CDX fpp.h / keytrack.h) */
#define PROTO_FAMILY_IPV4	2
#define PROTO_FAMILY_IPV6	10

/* Limits */
#define IPSEC_MAX_KEY_SIZE	64	/* must match CDX control_ipsec.h (512/8) */
#define IPSEC_MAX_NUM_KEYS	2

/* SA hash table */
#define CMM_SA_HASH_BITS	5
#define CMM_SA_HASH_SIZE	(1 << CMM_SA_HASH_BITS)

/*
 * FCI command payload structures.
 * Binary layout must match CDX control_ipsec.c expectations exactly.
 * Copied from ASK/cmm-17.03.1/src/module_ipsec.h.
 */

typedef struct {
	unsigned char	Version_IHL;
	unsigned char	TypeOfService;
	unsigned short	TotalLength;
	unsigned short	Identification;
	unsigned short	Flags_FragmentOffset;
	unsigned char	TTL;
	unsigned char	Protocol;
	unsigned short	HeaderChksum;
	unsigned int	SourceAddress;
	unsigned int	DestinationAddress;
} ipv4_hdr_t;

typedef struct {
	unsigned short	Version_TC_FLHi;
	unsigned short	FlowLabelLo;
	unsigned short	TotalLength;
	unsigned char	NextHeader;
	unsigned char	HopLimit;
	unsigned int	SourceAddress[4];
	unsigned int	DestinationAddress[4];
} ipv6_hdr_t;

typedef struct {
	unsigned int	spi;
	unsigned char	sa_type;
	unsigned char	proto_family;
	unsigned char	replay_window;
	unsigned char	flags;
	unsigned int	dst_ip[4];
	unsigned int	src_ip[4];
	unsigned short	mtu;
	unsigned short	dev_mtu;
} IPSec_said;

typedef struct {
	unsigned short	key_bits;
	unsigned char	key_alg;
	unsigned char	key_type;
	unsigned char	key[IPSEC_MAX_KEY_SIZE];
} IPSec_key_desc;

typedef struct {
	unsigned short	sagd;
	unsigned short	rsvd;
	IPSec_said	said;
} CommandIPSecCreateSA;

typedef struct {
	unsigned short	sagd;
	unsigned short	rsvd;
} CommandIPSecDeleteSA;

typedef struct {
	unsigned short	sagd;
	unsigned short	rsvd;
	unsigned short	num_keys;
	unsigned short	rsvd2;
	IPSec_key_desc	keys[IPSEC_MAX_NUM_KEYS];
} CommandIPSecSetKey;

typedef struct {
	unsigned short	sagd;
	unsigned char	rsvd;
	unsigned char	proto_family;
	union {
		ipv4_hdr_t	ipv4h;
		ipv6_hdr_t	ipv6h;
	} h;
} CommandIPSecSetTunnel;

typedef struct {
	unsigned short	sagd;
	unsigned short	parent_sa_sagd;
	unsigned short	state;
	unsigned short	rsvd2;
} CommandIPSecSetState;

/* Local SA entry */
struct cmm_sa_entry {
	struct list_head	list;
	uint16_t		sagd;
	uint32_t		spi;		/* network byte order */
	sa_family_t		af;
	uint8_t			dst_addr[16];	/* IPv4 in first 4 bytes */
	int			offloaded;
};

/* PF_KEY parsed extensions */
struct pfkey_parsed {
	const struct sadb_sa		*sa;
	const struct sadb_address	*addr_src;
	const struct sadb_address	*addr_dst;
	const struct sadb_key		*key_auth;
	const struct sadb_key		*key_enc;
	const struct sadb_x_sa2		*sa2;
};

/* Subsystem init/fini */
int	cmm_ipsec_init(void);
void	cmm_ipsec_fini(struct cmm_global *g);

/* PF_KEY socket */
int	cmm_pfkey_open(void);
void	cmm_pfkey_dispatch(struct cmm_global *g);

/* Flush all offloaded SAs */
void	cmm_sa_flush_all(struct cmm_global *g);

#endif /* CMM_IPSEC_H */
