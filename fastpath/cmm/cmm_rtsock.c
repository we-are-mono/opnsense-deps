/*
 * cmm_rtsock.c — PF_ROUTE socket wrapper
 *
 * Provides route socket open/dispatch/query for monitoring
 * routes, interfaces, and neighbor changes on FreeBSD.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_rtsock.h"
#include "cmm_itf.h"
#include "cmm_route.h"

int cmm_rtsock_seq;

int
cmm_rtsock_open(void)
{
	int s, n;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0)
		return (-1);

	/* Enable error reporting on reads */
	n = 1;
	setsockopt(s, SOL_SOCKET, SO_RERROR, &n, sizeof(n));

	return (s);
}

/*
 * Round up sockaddr length to next long boundary.
 * This is the standard FreeBSD SA_SIZE macro pattern.
 */
#define SA_RLEN(sa)	\
    ((sa)->sa_len ? (1 + (((sa)->sa_len - 1) | (sizeof(long) - 1))) : \
     sizeof(long))

void
cmm_rtsock_parse_addrs(struct rt_msghdr *rtm, size_t msglen,
    struct cmm_rtsock_addrs *addrs)
{
	struct sockaddr *sa;
	char *cp, *end;
	int i;

	memset(addrs, 0, sizeof(*addrs));
	cp = (char *)(rtm + 1);
	end = (char *)rtm + msglen;

	for (i = 0; i < RTAX_MAX; i++) {
		if (!(rtm->rtm_addrs & (1 << i)))
			continue;
		/* Bounds check: need at least sa_len to read */
		if (cp + sizeof(struct sockaddr) > end)
			break;
		sa = (struct sockaddr *)cp;
		if (cp + SA_RLEN(sa) > end)
			break;
		switch (i) {
		case RTAX_DST:
			addrs->dst = sa;
			break;
		case RTAX_GATEWAY:
			addrs->gateway = sa;
			break;
		case RTAX_NETMASK:
			addrs->netmask = sa;
			break;
		case RTAX_IFP:
			if (sa->sa_family == AF_LINK)
				addrs->ifp = (struct sockaddr_dl *)sa;
			break;
		case RTAX_IFA:
			addrs->ifa = sa;
			break;
		}
		cp += SA_RLEN(sa);
	}
}

int
cmm_rtsock_get(int fd, struct sockaddr *dst, int flags,
    void *reply, size_t *replylen)
{
	struct {
		struct rt_msghdr	hdr;
		char			data[512];
	} msg;
	struct rt_msghdr *rtm;
	pid_t pid;
	int seq, n;

	pid = getpid();
	seq = ++cmm_rtsock_seq;

	memset(&msg, 0, sizeof(msg));
	rtm = &msg.hdr;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = flags;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = pid;
	rtm->rtm_seq = seq;

	/* Copy destination sockaddr after header */
	memcpy(rtm + 1, dst, dst->sa_len);
	rtm->rtm_msglen = sizeof(struct rt_msghdr) + SA_RLEN(dst);

	if (write(fd, rtm, rtm->rtm_msglen) < 0) {
		cmm_print(CMM_LOG_DEBUG, "rtsock: RTM_GET write: %s",
		    strerror(errno));
		return (-1);
	}

	/* Read replies until we find ours */
	for (;;) {
		n = read(fd, reply, *replylen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			cmm_print(CMM_LOG_DEBUG, "rtsock: RTM_GET read: %s",
			    strerror(errno));
			return (-1);
		}
		rtm = (struct rt_msghdr *)reply;
		if (rtm->rtm_seq == seq && rtm->rtm_pid == pid)
			break;
	}

	if (rtm->rtm_errno != 0) {
		errno = rtm->rtm_errno;
		return (-1);
	}

	*replylen = n;
	return (0);
}

void
cmm_rtsock_dispatch(struct cmm_global *g)
{
	char buf[2048];
	struct rt_msghdr *rtm;
	int n;

	n = read(g->rtsock_fd, buf, sizeof(buf));
	if (n < (int)sizeof(struct rt_msghdr))
		return;

	rtm = (struct rt_msghdr *)buf;

	/* Skip our own messages */
	if (rtm->rtm_pid == getpid())
		return;

	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		cmm_itf_handle_ifinfo(g, buf, n);
		break;
	case RTM_NEWADDR:
		cmm_itf_handle_newaddr(g, buf, n);
		break;
	case RTM_DELADDR:
		cmm_itf_handle_deladdr(g, buf, n);
		break;
	case RTM_ADD:
	case RTM_DELETE:
	case RTM_CHANGE:
		cmm_route_handle_change(g, rtm, (size_t)n);
		break;
	default:
		cmm_print(CMM_LOG_TRACE, "rtsock: unhandled msg type %d",
		    rtm->rtm_type);
		break;
	}
}
