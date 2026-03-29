/*
 * cmm_ipsec.c -- IPsec SA management via PF_KEY
 *
 * Monitors PF_KEY socket for SA events from setkey(8) / strongswan,
 * translates them into FCI commands for CDX hardware offload.
 *
 * Flow: setkey(8) -> PF_KEY socket -> CMM -> fci_write() -> CDX -> CAAM HW
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfkeyv2.h>
#include <netipsec/ipsec.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_ipsec.h"
#include "cmm_itf.h"

/* SA hash table */
static struct list_head	sa_hash[CMM_SA_HASH_SIZE];
static uint16_t		next_sagd = 1;

static uint32_t
sa_hash_fn(uint32_t spi, const uint8_t *dst, sa_family_t af)
{
	uint32_t h;

	h = spi;
	if (af == AF_INET)
		h ^= *(const uint32_t *)dst;
	else
		h ^= *(const uint32_t *)dst ^
		    *(const uint32_t *)(dst + 4) ^
		    *(const uint32_t *)(dst + 8) ^
		    *(const uint32_t *)(dst + 12);
	return (h & (CMM_SA_HASH_SIZE - 1));
}

static struct cmm_sa_entry *
sa_find(uint32_t spi, sa_family_t af, const uint8_t *dst)
{
	uint32_t bucket;
	struct list_head *pos, *head;

	bucket = sa_hash_fn(spi, dst, af);
	head = &sa_hash[bucket];
	for (pos = list_first(head); pos != head; pos = list_next(pos)) {
		struct cmm_sa_entry *sa;

		sa = container_of(pos, struct cmm_sa_entry, list);
		if (sa->spi == spi && sa->af == af &&
		    memcmp(sa->dst_addr, dst,
		    af == AF_INET ? 4 : 16) == 0)
			return (sa);
	}
	return (NULL);
}

static int
sa_sagd_in_use(uint16_t sagd)
{
	int i;

	for (i = 0; i < CMM_SA_HASH_SIZE; i++) {
		struct list_head *pos, *head;

		head = &sa_hash[i];
		for (pos = list_first(head); pos != head;
		    pos = list_next(pos)) {
			struct cmm_sa_entry *sa;

			sa = container_of(pos, struct cmm_sa_entry, list);
			if (sa->sagd == sagd)
				return (1);
		}
	}
	return (0);
}

static uint16_t
sa_alloc_sagd(void)
{
	uint16_t sagd;
	int tries;

	for (tries = 0; tries < 65534; tries++) {
		sagd = next_sagd++;
		if (next_sagd == 0 || next_sagd == 0xFFFF)
			next_sagd = 1;
		if (!sa_sagd_in_use(sagd))
			return (sagd);
	}
	return (0);	/* exhausted */
}

static void
pfkey_parse_extensions(const struct sadb_msg *msg, struct pfkey_parsed *p)
{
	const struct sadb_ext *ext;
	const uint8_t *end;
	size_t msglen;

	memset(p, 0, sizeof(*p));

	msglen = PFKEY_UNUNIT64(msg->sadb_msg_len);
	end = (const uint8_t *)msg + msglen;
	ext = (const struct sadb_ext *)(msg + 1);

	while ((const uint8_t *)ext + sizeof(*ext) <= end) {
		size_t extlen;

		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);
		if (extlen < sizeof(*ext) ||
		    (const uint8_t *)ext + extlen > end)
			break;

		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			p->sa = (const struct sadb_sa *)ext;
			break;
		case SADB_EXT_ADDRESS_SRC:
			p->addr_src = (const struct sadb_address *)ext;
			break;
		case SADB_EXT_ADDRESS_DST:
			p->addr_dst = (const struct sadb_address *)ext;
			break;
		case SADB_EXT_KEY_AUTH:
			p->key_auth = (const struct sadb_key *)ext;
			break;
		case SADB_EXT_KEY_ENCRYPT:
			p->key_enc = (const struct sadb_key *)ext;
			break;
		case SADB_X_EXT_SA2:
			p->sa2 = (const struct sadb_x_sa2 *)ext;
			break;
		}

		ext = (const struct sadb_ext *)
		    ((const uint8_t *)ext + extlen);
	}
}

/*
 * Extract sockaddr from a PF_KEY address extension.
 */
static const struct sockaddr *
pfkey_addr_sa(const struct sadb_address *addr)
{

	return ((const struct sockaddr *)(addr + 1));
}

/*
 * Copy address bytes (4 for IPv4, 16 for IPv6) from a sockaddr.
 */
static void
pfkey_copy_addr(const struct sockaddr *sa, uint8_t *out)
{

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin =
		    (const struct sockaddr_in *)sa;
		memcpy(out, &sin->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 =
		    (const struct sockaddr_in6 *)sa;
		memcpy(out, &sin6->sin6_addr, 16);
	}
}

/*
 * Copy address bytes into a uint32_t[4] array for FCI command structures.
 * IPv4: first element only, rest zero.
 */
static void
pfkey_copy_addr_u32(const struct sockaddr *sa, unsigned int *out)
{

	memset(out, 0, 16);
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin =
		    (const struct sockaddr_in *)sa;
		memcpy(&out[0], &sin->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 =
		    (const struct sockaddr_in6 *)sa;
		memcpy(out, &sin6->sin6_addr, 16);
	}
}

static void
handle_sadb_add(struct cmm_global *g, const struct sadb_msg *msg)
{
	struct pfkey_parsed p;
	const struct sockaddr *sa_src, *sa_dst;
	struct cmm_sa_entry *sa;
	CommandIPSecCreateSA cmd_create;
	CommandIPSecSetKey cmd_keys;
	CommandIPSecSetTunnel cmd_tunnel;
	CommandIPSecSetState cmd_state;
	uint16_t sagd;
	uint32_t spi;
	uint8_t dst_addr[16];
	sa_family_t af;
	int is_inbound, is_tunnel;
	int rc;

	pfkey_parse_extensions(msg, &p);

	/* Validate required extensions */
	if (p.sa == NULL || p.addr_src == NULL || p.addr_dst == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "ipsec: SADB_ADD missing required extensions");
		return;
	}
	if (p.key_enc == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "ipsec: SADB_ADD missing encryption key");
		return;
	}

	sa_src = pfkey_addr_sa(p.addr_src);
	sa_dst = pfkey_addr_sa(p.addr_dst);
	af = sa_dst->sa_family;
	spi = p.sa->sadb_sa_spi;	/* network byte order */

	memset(dst_addr, 0, sizeof(dst_addr));
	pfkey_copy_addr(sa_dst, dst_addr);

	/* Check for existing SA */
	sa = sa_find(spi, af, dst_addr);
	if (sa != NULL) {
		if (msg->sadb_msg_type != SADB_UPDATE) {
			cmm_print(CMM_LOG_DEBUG,
			    "ipsec: SA SPI=0x%x already tracked, ignoring",
			    ntohl(spi));
			return;
		}
		/* Rekey: delete old SA from CDX, then recreate with new keys */
		cmm_print(CMM_LOG_INFO,
		    "ipsec: rekey SPI=0x%x, deleting sagd=0x%04x",
		    ntohl(spi), sa->sagd);
		if (sa->offloaded) {
			CommandIPSecDeleteSA cmd_del;
			memset(&cmd_del, 0, sizeof(cmd_del));
			cmd_del.sagd = sa->sagd;
			fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_DELETE,
			    sizeof(cmd_del), (unsigned short *)&cmd_del);
		}
		list_del(&sa->list);
		free(sa);
	}

	/* Allocate SAGD */
	sagd = sa_alloc_sagd();
	if (sagd == 0) {
		cmm_print(CMM_LOG_ERR, "ipsec: SAGD space exhausted");
		return;
	}

	/* Direction: if dst is one of our addresses, it's inbound */
	is_inbound = cmm_itf_is_local_addr(af,
	    af == AF_INET ?
	    (const void *)&((const struct sockaddr_in *)sa_dst)->sin_addr :
	    (const void *)&((const struct sockaddr_in6 *)sa_dst)->sin6_addr);

	/* Tunnel mode? */
	is_tunnel = (p.sa2 != NULL &&
	    p.sa2->sadb_x_sa2_mode == IPSEC_MODE_TUNNEL);

	cmm_print(CMM_LOG_INFO,
	    "ipsec: SADB_ADD ESP SPI=0x%x sagd=0x%04x %s %s",
	    ntohl(spi), sagd,
	    is_inbound ? "inbound" : "outbound",
	    is_tunnel ? "tunnel" : "transport");

	/*
	 * FCI 1: SA_ADD — create the SA in CDX
	 */
	memset(&cmd_create, 0, sizeof(cmd_create));
	cmd_create.sagd = sagd;
	cmd_create.said.spi = spi;
	cmd_create.said.sa_type = 0;	/* ESP */
	cmd_create.said.proto_family =
	    (af == AF_INET) ? PROTO_FAMILY_IPV4 : PROTO_FAMILY_IPV6;
	cmd_create.said.replay_window = p.sa->sadb_sa_replay;
	cmd_create.said.flags = is_inbound ? NLKEY_SAFLAGS_INBOUND : 0;
	pfkey_copy_addr_u32(sa_dst, cmd_create.said.dst_ip);
	pfkey_copy_addr_u32(sa_src, cmd_create.said.src_ip);
	cmd_create.said.mtu = 1500;
	cmd_create.said.dev_mtu = 1500;

	rc = fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_ADD,
	    sizeof(cmd_create), (unsigned short *)&cmd_create);
	if (rc != 0) {
		cmm_print(CMM_LOG_ERR,
		    "ipsec: SA_ADD failed: %d (SPI=0x%x sagd=0x%04x)",
		    rc, ntohl(spi), sagd);
		return;
	}

	/*
	 * FCI 2: SA_SET_KEYS
	 */
	memset(&cmd_keys, 0, sizeof(cmd_keys));
	cmd_keys.sagd = sagd;

	if (p.key_auth != NULL && p.key_auth->sadb_key_bits > 0) {
		size_t auth_len, enc_len;

		/* CBC + HMAC: 2 keys (auth + cipher) */
		cmd_keys.num_keys = 2;

		auth_len = (p.key_auth->sadb_key_bits + 7) / 8;
		if (auth_len > IPSEC_MAX_KEY_SIZE) {
			cmm_print(CMM_LOG_ERR,
			    "ipsec: auth key too large (%zu > %d)",
			    auth_len, IPSEC_MAX_KEY_SIZE);
			goto fail_delete;
		}

		enc_len = (p.key_enc->sadb_key_bits + 7) / 8;
		if (enc_len > IPSEC_MAX_KEY_SIZE) {
			cmm_print(CMM_LOG_ERR,
			    "ipsec: cipher key too large (%zu > %d)",
			    enc_len, IPSEC_MAX_KEY_SIZE);
			goto fail_delete;
		}

		/* Key 0: auth key */
		cmd_keys.keys[0].key_bits = p.key_auth->sadb_key_bits;
		cmd_keys.keys[0].key_alg = p.sa->sadb_sa_auth;
		cmd_keys.keys[0].key_type = 1;	/* auth */
		memcpy(cmd_keys.keys[0].key,
		    (const uint8_t *)(p.key_auth + 1), auth_len);

		/* Key 1: cipher key */
		cmd_keys.keys[1].key_bits = p.key_enc->sadb_key_bits;
		cmd_keys.keys[1].key_alg = p.sa->sadb_sa_encrypt;
		cmd_keys.keys[1].key_type = 0;	/* cipher */
		memcpy(cmd_keys.keys[1].key,
		    (const uint8_t *)(p.key_enc + 1), enc_len);
	} else {
		size_t enc_len;

		/* GCM: 1 key (cipher only, includes 4-byte salt) */
		enc_len = (p.key_enc->sadb_key_bits + 7) / 8;
		if (enc_len > IPSEC_MAX_KEY_SIZE) {
			cmm_print(CMM_LOG_ERR,
			    "ipsec: cipher key too large (%zu > %d)",
			    enc_len, IPSEC_MAX_KEY_SIZE);
			goto fail_delete;
		}

		cmd_keys.num_keys = 1;
		cmd_keys.keys[0].key_bits = p.key_enc->sadb_key_bits;
		cmd_keys.keys[0].key_alg = p.sa->sadb_sa_encrypt;
		cmd_keys.keys[0].key_type = 0;	/* cipher */
		memcpy(cmd_keys.keys[0].key,
		    (const uint8_t *)(p.key_enc + 1), enc_len);
	}

	rc = fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_SET_KEYS,
	    sizeof(cmd_keys), (unsigned short *)&cmd_keys);
	if (rc != 0) {
		cmm_print(CMM_LOG_ERR,
		    "ipsec: SA_SET_KEYS failed: %d (sagd=0x%04x)",
		    rc, sagd);
		goto fail_delete;
	}

	/*
	 * FCI 3: SA_SET_TUNNEL (if tunnel mode)
	 */
	if (is_tunnel) {
		memset(&cmd_tunnel, 0, sizeof(cmd_tunnel));
		cmd_tunnel.sagd = sagd;
		cmd_tunnel.proto_family =
		    (af == AF_INET) ? PROTO_FAMILY_IPV4 : PROTO_FAMILY_IPV6;

		if (af == AF_INET) {
			const struct sockaddr_in *sin_src =
			    (const struct sockaddr_in *)sa_src;
			const struct sockaddr_in *sin_dst =
			    (const struct sockaddr_in *)sa_dst;

			cmd_tunnel.h.ipv4h.Version_IHL = 0x45;
			cmd_tunnel.h.ipv4h.TTL = 64;
			cmd_tunnel.h.ipv4h.Protocol = 50;	/* ESP */
			memcpy(&cmd_tunnel.h.ipv4h.SourceAddress,
			    &sin_src->sin_addr, 4);
			memcpy(&cmd_tunnel.h.ipv4h.DestinationAddress,
			    &sin_dst->sin_addr, 4);
		} else {
			const struct sockaddr_in6 *sin6_src =
			    (const struct sockaddr_in6 *)sa_src;
			const struct sockaddr_in6 *sin6_dst =
			    (const struct sockaddr_in6 *)sa_dst;

			cmd_tunnel.h.ipv6h.Version_TC_FLHi = htons(0x6000);
			cmd_tunnel.h.ipv6h.NextHeader = 50;	/* ESP */
			cmd_tunnel.h.ipv6h.HopLimit = 64;
			memcpy(cmd_tunnel.h.ipv6h.SourceAddress,
			    &sin6_src->sin6_addr, 16);
			memcpy(cmd_tunnel.h.ipv6h.DestinationAddress,
			    &sin6_dst->sin6_addr, 16);
		}

		rc = fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_SET_TUNNEL,
		    sizeof(cmd_tunnel), (unsigned short *)&cmd_tunnel);
		if (rc != 0) {
			cmm_print(CMM_LOG_ERR,
			    "ipsec: SA_SET_TUNNEL failed: %d (sagd=0x%04x)",
			    rc, sagd);
			goto fail_delete;
		}
	}

	/*
	 * FCI 4: SA_SET_STATE -> VALID
	 */
	memset(&cmd_state, 0, sizeof(cmd_state));
	cmd_state.sagd = sagd;
	cmd_state.state = SA_STATE_VALID;

	rc = fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_SET_STATE,
	    sizeof(cmd_state), (unsigned short *)&cmd_state);
	if (rc != 0) {
		cmm_print(CMM_LOG_ERR,
		    "ipsec: SA_SET_STATE failed: %d (sagd=0x%04x)",
		    rc, sagd);
		goto fail_delete;
	}

	/* Add to local SA table */
	sa = malloc(sizeof(*sa));
	if (sa == NULL) {
		cmm_print(CMM_LOG_ERR, "ipsec: malloc failed");
		goto fail_delete;
	}
	memset(sa, 0, sizeof(*sa));
	sa->sagd = sagd;
	sa->spi = spi;
	sa->af = af;
	memcpy(sa->dst_addr, dst_addr, sizeof(sa->dst_addr));
	sa->offloaded = 1;

	{
		uint32_t bucket = sa_hash_fn(spi, dst_addr, af);
		list_add(&sa_hash[bucket], &sa->list);
	}

	cmm_print(CMM_LOG_INFO,
	    "ipsec: SA offloaded SPI=0x%x sagd=0x%04x",
	    ntohl(spi), sagd);
	explicit_bzero(&cmd_keys, sizeof(cmd_keys));
	return;

fail_delete:
	/* Roll back: delete the SA we partially created */
	{
		CommandIPSecDeleteSA cmd_del;
		memset(&cmd_del, 0, sizeof(cmd_del));
		cmd_del.sagd = sagd;
		fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_DELETE,
		    sizeof(cmd_del), (unsigned short *)&cmd_del);
	}
	explicit_bzero(&cmd_keys, sizeof(cmd_keys));
}

static void
handle_sadb_delete(struct cmm_global *g, const struct sadb_msg *msg)
{
	struct pfkey_parsed p;
	const struct sockaddr *sa_dst;
	struct cmm_sa_entry *sa;
	uint8_t dst_addr[16];
	sa_family_t af;
	uint32_t spi;
	int rc;

	pfkey_parse_extensions(msg, &p);

	if (p.sa == NULL || p.addr_dst == NULL) {
		cmm_print(CMM_LOG_DEBUG,
		    "ipsec: SADB_DELETE missing SA or DST");
		return;
	}

	sa_dst = pfkey_addr_sa(p.addr_dst);
	af = sa_dst->sa_family;
	spi = p.sa->sadb_sa_spi;

	memset(dst_addr, 0, sizeof(dst_addr));
	pfkey_copy_addr(sa_dst, dst_addr);

	sa = sa_find(spi, af, dst_addr);
	if (sa == NULL) {
		cmm_print(CMM_LOG_DEBUG,
		    "ipsec: SADB_DELETE SPI=0x%x not tracked",
		    ntohl(spi));
		return;
	}

	if (sa->offloaded) {
		CommandIPSecDeleteSA cmd_del;

		memset(&cmd_del, 0, sizeof(cmd_del));
		cmd_del.sagd = sa->sagd;
		rc = fci_write(g->fci_handle, FPP_CMD_IPSEC_SA_DELETE,
		    sizeof(cmd_del), (unsigned short *)&cmd_del);
		if (rc != 0)
			cmm_print(CMM_LOG_WARN,
			    "ipsec: SA_DELETE failed: %d (sagd=0x%04x)",
			    rc, sa->sagd);
	}

	cmm_print(CMM_LOG_INFO,
	    "ipsec: SA removed SPI=0x%x sagd=0x%04x",
	    ntohl(spi), sa->sagd);

	list_del(&sa->list);
	free(sa);
}

int
cmm_pfkey_open(void)
{
	struct sadb_msg msg;
	int fd, flags;
	ssize_t n;

	fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (fd < 0) {
		cmm_print(CMM_LOG_ERR, "ipsec: PF_KEY socket: %s",
		    strerror(errno));
		return (-1);
	}

	/* Set non-blocking */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	/* Register for ESP SA events */
	memset(&msg, 0, sizeof(msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_REGISTER;
	msg.sadb_msg_satype = SADB_SATYPE_ESP;
	msg.sadb_msg_len = PFKEY_UNIT64(sizeof(msg));
	msg.sadb_msg_pid = getpid();

	if (write(fd, &msg, sizeof(msg)) < 0) {
		cmm_print(CMM_LOG_WARN, "ipsec: SADB_REGISTER: %s",
		    strerror(errno));
		/* Non-fatal — we can still receive SA events */
	}

	/* Drain the register reply */
	{
		uint8_t buf[4096];
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			;
	}

	cmm_print(CMM_LOG_INFO, "ipsec: PF_KEY socket opened (fd=%d)", fd);
	return (fd);
}

void
cmm_pfkey_dispatch(struct cmm_global *g)
{
	uint8_t buf[4096];
	ssize_t n;
	const struct sadb_msg *msg;

	while ((n = read(g->pfkey_fd, buf, sizeof(buf))) > 0) {
		if ((size_t)n < sizeof(struct sadb_msg))
			continue;

		msg = (const struct sadb_msg *)buf;

		/* Ignore our own messages */
		if (msg->sadb_msg_pid == (uint32_t)getpid())
			continue;

		/* Only handle ESP */
		if (msg->sadb_msg_satype != SADB_SATYPE_ESP)
			continue;

		/* Check message length consistency */
		if ((size_t)PFKEY_UNUNIT64(msg->sadb_msg_len) > (size_t)n)
			continue;

		switch (msg->sadb_msg_type) {
		case SADB_ADD:
		case SADB_UPDATE:
			handle_sadb_add(g, msg);
			break;
		case SADB_DELETE:
			handle_sadb_delete(g, msg);
			break;
		case SADB_EXPIRE:
			/* Treat hard expire as delete */
			if (msg->sadb_msg_errno == 0)
				handle_sadb_delete(g, msg);
			break;
		default:
			cmm_print(CMM_LOG_TRACE,
			    "ipsec: PF_KEY msg type=%d ignored",
			    msg->sadb_msg_type);
			break;
		}
	}

	explicit_bzero(buf, sizeof(buf));
}

int
cmm_ipsec_init(void)
{
	int i;

	for (i = 0; i < CMM_SA_HASH_SIZE; i++)
		list_head_init(&sa_hash[i]);

	next_sagd = 1;

	cmm_print(CMM_LOG_DEBUG, "ipsec: SA table initialized (%d buckets)",
	    CMM_SA_HASH_SIZE);
	return (0);
}

void
cmm_sa_flush_all(struct cmm_global *g)
{
	int i;

	for (i = 0; i < CMM_SA_HASH_SIZE; i++) {
		struct list_head *pos, *tmp, *head;

		head = &sa_hash[i];
		pos = list_first(head);
		while (pos != head) {
			struct cmm_sa_entry *sa;

			tmp = list_next(pos);
			sa = container_of(pos, struct cmm_sa_entry, list);

			if (sa->offloaded && g->fci_handle != NULL) {
				CommandIPSecDeleteSA cmd_del;

				memset(&cmd_del, 0, sizeof(cmd_del));
				cmd_del.sagd = sa->sagd;
				fci_write(g->fci_handle,
				    FPP_CMD_IPSEC_SA_DELETE,
				    sizeof(cmd_del),
				    (unsigned short *)&cmd_del);

				cmm_print(CMM_LOG_DEBUG,
				    "ipsec: flushed sagd=0x%04x",
				    sa->sagd);
			}
			list_del(&sa->list);
			free(sa);
			pos = tmp;
		}
	}
}

void
cmm_ipsec_fini(struct cmm_global *g __unused)
{

	cmm_print(CMM_LOG_DEBUG, "ipsec: subsystem finalized");
}
