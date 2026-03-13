/*
 * cmm_deny.c — Deny-rule filtering for offload eligibility
 *
 * Parses /usr/local/etc/cmm_deny.conf (or a user-specified path)
 * and maintains a linked list of deny rules.  Each rule is a set
 * of AND'd conditions.  If ANY rule matches a PF state, the
 * connection is denied offload and stays in the software path.
 *
 * Config file format:
 *   # comment
 *   field=value [field=value ...]
 *
 * Supported fields:
 *   proto=tcp|udp|<number>
 *   src=<addr>[/<prefix>]
 *   dst=<addr>[/<prefix>]
 *   sport=<port>
 *   dport=<port>
 *   iface=<name>
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#define COMPAT_FREEBSD14
#include <net/pfvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmm.h"
#include "cmm_deny.h"

static struct cmm_deny_list deny_rules = STAILQ_HEAD_INITIALIZER(deny_rules);
static int deny_count;

/*
 * Compare the first prefixlen bits of two addresses.
 * Returns 1 if they match, 0 otherwise.
 */
static int
addr_match(sa_family_t af, const void *addr,
    const struct in6_addr *rule_addr, uint8_t prefixlen)
{
	const uint8_t *a = (const uint8_t *)addr;
	const uint8_t *r = (const uint8_t *)rule_addr;
	int alen, full_bytes, remaining;

	alen = (af == AF_INET) ? 4 : 16;
	if (prefixlen > (uint8_t)(alen * 8))
		prefixlen = (uint8_t)(alen * 8);

	full_bytes = prefixlen / 8;
	remaining = prefixlen % 8;

	if (full_bytes > 0 && memcmp(a, r, full_bytes) != 0)
		return (0);

	if (remaining > 0) {
		uint8_t mask = (uint8_t)(0xFF << (8 - remaining));
		if ((a[full_bytes] & mask) != (r[full_bytes] & mask))
			return (0);
	}

	return (1);
}

/*
 * Parse an address with optional /prefix.
 * Sets addr (stored in in6_addr, v4-mapped for IPv4) and prefixlen.
 * Returns the detected address family, or 0 on error.
 */
static sa_family_t
parse_addr(const char *s, struct in6_addr *out, uint8_t *prefixlen)
{
	char buf[INET6_ADDRSTRLEN + 4];
	char *slash;
	struct in_addr v4;

	strlcpy(buf, s, sizeof(buf));
	slash = strchr(buf, '/');
	if (slash != NULL)
		*slash = '\0';

	/* Try IPv4 first */
	if (inet_pton(AF_INET, buf, &v4) == 1) {
		memset(out, 0, sizeof(*out));
		memcpy(out, &v4, 4);
		if (slash != NULL) {
			int p = atoi(slash + 1);
			if (p < 0 || p > 32)
				return (0);
			*prefixlen = (uint8_t)p;
		} else {
			*prefixlen = 32;
		}
		return (AF_INET);
	}

	/* Try IPv6 */
	if (inet_pton(AF_INET6, buf, out) == 1) {
		if (slash != NULL) {
			int p = atoi(slash + 1);
			if (p < 0 || p > 128)
				return (0);
			*prefixlen = (uint8_t)p;
		} else {
			*prefixlen = 128;
		}
		return (AF_INET6);
	}

	return (0);
}

/*
 * Parse a single config line into a deny rule.
 * Returns 0 on success, -1 on parse error.
 */
static int
parse_rule(char *line, struct cmm_deny_rule *r)
{
	char *tok, *saveptr;

	memset(r, 0, sizeof(*r));

	for (tok = strtok_r(line, " \t", &saveptr);
	    tok != NULL;
	    tok = strtok_r(NULL, " \t", &saveptr)) {
		char *eq;

		eq = strchr(tok, '=');
		if (eq == NULL)
			return (-1);
		*eq = '\0';

		if (strcmp(tok, "proto") == 0) {
			if (strcmp(eq + 1, "tcp") == 0)
				r->proto = IPPROTO_TCP;
			else if (strcmp(eq + 1, "udp") == 0)
				r->proto = IPPROTO_UDP;
			else {
				int p = atoi(eq + 1);
				if (p <= 0 || p > 255)
					return (-1);
				r->proto = (uint8_t)p;
			}
		} else if (strcmp(tok, "src") == 0) {
			sa_family_t af;
			af = parse_addr(eq + 1, &r->src.addr,
			    &r->src.prefixlen);
			if (af == 0)
				return (-1);
			if (r->af == 0)
				r->af = af;
			else if (r->af != af)
				return (-1);
		} else if (strcmp(tok, "dst") == 0) {
			sa_family_t af;
			af = parse_addr(eq + 1, &r->dst.addr,
			    &r->dst.prefixlen);
			if (af == 0)
				return (-1);
			if (r->af == 0)
				r->af = af;
			else if (r->af != af)
				return (-1);
		} else if (strcmp(tok, "sport") == 0) {
			int p = atoi(eq + 1);
			if (p <= 0 || p > 65535)
				return (-1);
			r->sport = htons((uint16_t)p);
		} else if (strcmp(tok, "dport") == 0) {
			int p = atoi(eq + 1);
			if (p <= 0 || p > 65535)
				return (-1);
			r->dport = htons((uint16_t)p);
		} else if (strcmp(tok, "iface") == 0) {
			strlcpy(r->ifname, eq + 1, sizeof(r->ifname));
		} else {
			return (-1);
		}
	}

	return (0);
}

int
cmm_deny_init(const char *confpath)
{
	FILE *f;
	char line[256];
	int lineno;

	if (confpath == NULL)
		confpath = CMM_DENY_CONF;

	f = fopen(confpath, "r");
	if (f == NULL) {
		if (errno == ENOENT) {
			cmm_print(CMM_LOG_INFO,
			    "deny: no config file %s — all flows eligible",
			    confpath);
			return (0);
		}
		cmm_print(CMM_LOG_ERR, "deny: open %s: %s",
		    confpath, strerror(errno));
		return (-1);
	}

	lineno = 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		struct cmm_deny_rule *r;
		struct cmm_deny_rule tmp;
		char *p;

		lineno++;

		/* Strip newline */
		p = strchr(line, '\n');
		if (p != NULL)
			*p = '\0';

		/* Skip leading whitespace */
		p = line;
		while (isspace((unsigned char)*p))
			p++;

		/* Skip empty lines and comments */
		if (*p == '\0' || *p == '#')
			continue;

		if (parse_rule(p, &tmp) < 0) {
			cmm_print(CMM_LOG_WARN,
			    "deny: %s:%d: parse error, skipping",
			    confpath, lineno);
			continue;
		}

		r = malloc(sizeof(*r));
		if (r == NULL) {
			cmm_print(CMM_LOG_ERR, "deny: malloc: %s",
			    strerror(errno));
			fclose(f);
			return (-1);
		}
		*r = tmp;
		STAILQ_INSERT_TAIL(&deny_rules, r, entry);
		deny_count++;
	}

	fclose(f);
	cmm_print(CMM_LOG_INFO, "deny: loaded %d rule%s from %s",
	    deny_count, deny_count == 1 ? "" : "s", confpath);
	return (0);
}

void
cmm_deny_fini(void)
{
	struct cmm_deny_rule *r;

	while ((r = STAILQ_FIRST(&deny_rules)) != NULL) {
		STAILQ_REMOVE_HEAD(&deny_rules, entry);
		free(r);
	}
	deny_count = 0;
}

/*
 * Check deny rules against extracted tuple fields.
 * Used by both poll path (pf_state_export) and push path (pfn_event).
 * Returns 1 if denied, 0 if allowed.
 */
int
cmm_deny_check_tuple(sa_family_t af, uint8_t proto,
    const void *saddr, const void *daddr,
    uint16_t sport, uint16_t dport, const char *ifname)
{
	struct cmm_deny_rule *r;

	if (deny_count == 0)
		return (0);

	STAILQ_FOREACH(r, &deny_rules, entry) {
		/* Protocol */
		if (r->proto != 0 && r->proto != proto)
			continue;

		/* Address family */
		if (r->af != 0 && r->af != af)
			continue;

		/* Source port */
		if (r->sport != 0 && r->sport != sport)
			continue;

		/* Destination port */
		if (r->dport != 0 && r->dport != dport)
			continue;

		/* Source address */
		if (r->src.prefixlen != 0 &&
		    !addr_match(af, saddr,
		    &r->src.addr, r->src.prefixlen))
			continue;

		/* Destination address */
		if (r->dst.prefixlen != 0 &&
		    !addr_match(af, daddr,
		    &r->dst.addr, r->dst.prefixlen))
			continue;

		/* Interface */
		if (r->ifname[0] != '\0' &&
		    strcmp(r->ifname, ifname) != 0)
			continue;

		/* All conditions matched — deny offload */
		cmm_print(CMM_LOG_DEBUG, "deny: rule matched, "
		    "proto=%u iface=%s", proto, ifname);
		return (1);
	}

	return (0);
}

int
cmm_deny_check(const struct pf_state_export *pfs)
{
	const struct pf_state_key_export *sk;
	int sidx, didx;

	sk = &pfs->key[PF_SK_STACK];
	sidx = (pfs->direction == PF_IN) ? 0 : 1;
	didx = 1 - sidx;

	return (cmm_deny_check_tuple(pfs->af, pfs->proto,
	    &sk->addr[sidx], &sk->addr[didx],
	    sk->port[sidx], sk->port[didx],
	    pfs->ifname));
}

int
cmm_deny_count(void)
{

	return (deny_count);
}
