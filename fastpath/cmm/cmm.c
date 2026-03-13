/*
 * cmm.c — Connection Management Module for FreeBSD
 *
 * Userspace daemon that monitors PF state table and routes,
 * then programs FMan hardware hash tables via FCI/CDX for
 * hardware flow offload on the NXP LS1046A.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <net/pfvar.h>
#include <fcntl.h>
#include <errno.h>
#include <libutil.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_rtsock.h"
#include "cmm_itf.h"
#include "cmm_neigh.h"
#include "cmm_route.h"
#include "cmm_conn.h"
#include "cmm_fe.h"
#include "cmm_lagg.h"
#include "cmm_vlan.h"
#include "cmm_ipsec.h"
#include "cmm_tunnel.h"
#include "cmm_l2tp.h"
#include "cmm_deny.h"
#include "cmm_socket.h"
#include "cmm_bridge.h"
#include "cmm_wifi.h"
#include "cmm_pppoe.h"
#include "cmm_ctrl.h"
#include "pf_notify.h"
#include "libfci.h"

struct cmm_global cmm_g;

/*
 * Top-level FCI async event dispatcher.
 *
 * Routes CDX notifications to the appropriate subsystem handler.
 * Each handler returns FCI_CB_CONTINUE if the event wasn't for it,
 * allowing the next handler to try.
 */
static int
cmm_fci_catch(unsigned short fcode, unsigned short len,
    unsigned short *payload)
{
	int rc;

	rc = cmm_conn_fci_event(fcode, len, payload);
	if (rc <= FCI_CB_STOP)
		return (rc);

	rc = cmm_bridge_fci_event(fcode, len, payload);
	return (rc);
}

static void
sigterm_handler(int sig __unused)
{
	cmm_g.running = 0;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: cmm [-f] [-d level] [-p poll_ms] [-D deny_conf]\n"
	    "  -f          run in foreground\n"
	    "  -d level    debug level (0=err, 1=warn, 2=info, 3=debug, 4=trace)\n"
	    "  -p poll_ms  PF state poll interval in ms (default %d)\n"
	    "  -D path     deny-rule config file (default %s)\n",
	    CMM_DEFAULT_POLL_MS, CMM_DENY_CONF);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct cmm_global *g = &cmm_g;
	struct pidfh *pfh;
	struct kevent kev[16];
	const char *deny_conf = NULL;
	int ch, nev;

	/* Defaults */
	g->debug_level = CMM_LOG_INFO;
	g->poll_ms = CMM_DEFAULT_POLL_MS;
	g->foreground = 0;
	g->running = 1;
	g->pf_fd = -1;
	g->rtsock_fd = -1;
	g->rtsock_query_fd = -1;
	g->kq = -1;
	g->pfkey_fd = -1;
	g->ctrl_listen_fd = -1;
	g->autobridge_fd = -1;
	g->pfnotify_fd = -1;

	while ((ch = getopt(argc, argv, "fd:p:D:")) != -1) {
		switch (ch) {
		case 'f':
			g->foreground = 1;
			break;
		case 'd':
			g->debug_level = atoi(optarg);
			if (g->debug_level < 0)
				g->debug_level = 0;
			if (g->debug_level > CMM_LOG_TRACE)
				g->debug_level = CMM_LOG_TRACE;
			break;
		case 'p':
			g->poll_ms = atoi(optarg);
			if (g->poll_ms < 10)
				g->poll_ms = 10;
			break;
		case 'D':
			deny_conf = optarg;
			break;
		default:
			usage();
		}
	}

	cmm_print(CMM_LOG_INFO, "CMM starting (debug=%d poll=%dms)",
	    g->debug_level, g->poll_ms);

	/* Acquire PID file lock — prevents duplicate instances */
	{
		pid_t otherpid;

		pfh = pidfile_open(CMM_PID_FILE, 0600, &otherpid);
		if (pfh == NULL) {
			if (errno == EEXIST) {
				cmm_print(CMM_LOG_ERR,
				    "already running (pid %jd)",
				    (intmax_t)otherpid);
				exit(1);
			}
			cmm_print(CMM_LOG_ERR, "pidfile_open: %s",
			    strerror(errno));
			exit(1);
		}
	}

	/* Daemonize unless -f */
	if (!g->foreground) {
		if (daemon(0, 1) < 0) {
			cmm_print(CMM_LOG_ERR, "daemon: %s", strerror(errno));
			pidfile_remove(pfh);
			exit(1);
		}
	}
	pidfile_write(pfh);

	/* Install signal handlers */
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sigterm_handler;
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);

		sa.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &sa, NULL);
	}

	/* Open FCI — retry on boot to handle module/device init race */
	{
		int retries;

		for (retries = 0; retries < 10; retries++) {
			g->fci_handle = fci_open(FCILIB_FF_TYPE, 0);
			if (g->fci_handle != NULL)
				break;
			if (retries == 0)
				cmm_print(CMM_LOG_WARN,
				    "fci_open failed, retrying...");
			sleep(1);
		}
		if (g->fci_handle == NULL) {
			cmm_print(CMM_LOG_ERR,
			    "fci_open failed after %d attempts "
			    "— is fci.ko loaded?", retries);
			goto out;
		}
	}
	cmm_print(CMM_LOG_INFO, "FCI opened");

	/* Open FCI event handle */
	g->fci_catch = fci_open(FCILIB_FF_TYPE, NL_FF_GROUP);

	/* Reset CDX tables */
	cmm_fe_reset(g);

	/* Enable CDX per-flow statistics */
	{
		fpp_stat_enable_cmd_t stat_en;

		memset(&stat_en, 0, sizeof(stat_en));
		stat_en.action = FPP_CMM_STAT_ENABLE;
		stat_en.bitmask = FPP_STAT_FLOW_BITMASK;
		if (fci_write(g->fci_handle, FPP_CMD_STAT_ENABLE,
		    sizeof(stat_en), (unsigned short *)&stat_en) == 0)
			cmm_print(CMM_LOG_INFO,
			    "CDX flow statistics enabled");
		else
			cmm_print(CMM_LOG_WARN,
			    "CDX flow statistics enable failed");
	}

	/* Open /dev/pf */
	g->pf_fd = open("/dev/pf", O_RDONLY);
	if (g->pf_fd < 0) {
		cmm_print(CMM_LOG_ERR, "open /dev/pf: %s — is PF enabled?",
		    strerror(errno));
		goto out;
	}
	cmm_print(CMM_LOG_INFO, "/dev/pf opened");

	/* Warn if IP forwarding is not enabled */
	{
		int fwd = 0;
		size_t fwdlen = sizeof(fwd);
		if (sysctlbyname("net.inet.ip.forwarding", &fwd, &fwdlen,
		    NULL, 0) == 0 && fwd == 0)
			cmm_print(CMM_LOG_WARN,
			    "net.inet.ip.forwarding=0 — no traffic to offload");
	}

	/* Open route sockets: one for monitoring, one for RTM_GET queries */
	g->rtsock_fd = cmm_rtsock_open();
	if (g->rtsock_fd < 0) {
		cmm_print(CMM_LOG_ERR, "route socket: %s", strerror(errno));
		goto out;
	}
	g->rtsock_query_fd = cmm_rtsock_open();
	if (g->rtsock_query_fd < 0) {
		cmm_print(CMM_LOG_ERR, "route query socket: %s",
		    strerror(errno));
		goto out;
	}
	cmm_print(CMM_LOG_INFO, "route sockets opened");

	/* Initialize subsystems */
	if (cmm_itf_init() < 0)
		goto out;
	cmm_lagg_init(g);
	cmm_vlan_init(g);
	if (cmm_neigh_init() < 0)
		goto out;
	if (cmm_route_init() < 0)
		goto out;
	if (cmm_conn_init() < 0)
		goto out;

	cmm_tunnel_init(g);
	cmm_l2tp_init(g);
	cmm_socket_init();
	cmm_bridge_init(g);
	cmm_wifi_init(g);
	cmm_pppoe_init(g);

	if (cmm_ipsec_init() < 0)
		goto out;

	/* Load deny rules (optional — missing file means offload everything) */
	if (cmm_deny_init(deny_conf) < 0)
		goto out;

	/* Open PF_KEY socket for IPsec SA events */
	g->pfkey_fd = cmm_pfkey_open();
	if (g->pfkey_fd < 0)
		cmm_print(CMM_LOG_WARN,
		    "PF_KEY unavailable — IPsec offload disabled");

	/* Open /dev/pfnotify for push-based state events */
	{
		int fd;

		fd = open(PFN_DEV_PATH, O_RDWR | O_NONBLOCK);
		if (fd >= 0) {
			g->pfnotify_fd = fd;
			cmm_print(CMM_LOG_INFO,
			    "pfnotify: push mode (fd=%d)", fd);
		} else {
			cmm_print(CMM_LOG_WARN,
			    "pfnotify: %s unavailable (%s) — polling mode",
			    PFN_DEV_PATH, strerror(errno));
		}
	}

	/* Register FCI event dispatcher for CDX async notifications */
	if (g->fci_catch != NULL)
		fci_register_cb(g->fci_catch, cmm_fci_catch);

	cmm_print(CMM_LOG_INFO, "all subsystems initialized");

	/* Create kqueue */
	g->kq = kqueue();
	if (g->kq < 0) {
		cmm_print(CMM_LOG_ERR, "kqueue: %s", strerror(errno));
		goto out;
	}

	/* Register events */
	nev = 0;

	/* Route socket: interface/route/neighbor changes */
	EV_SET(&kev[nev], g->rtsock_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	nev++;

	/* FCI event fd (if available) */
	if (g->fci_catch != NULL) {
		int fci_event_fd = fci_fd(g->fci_catch);
		if (fci_event_fd >= 0) {
			EV_SET(&kev[nev], fci_event_fd, EVFILT_READ,
			    EV_ADD, 0, 0, NULL);
			nev++;
		}
	}

	/* PF_KEY socket: IPsec SA events */
	if (g->pfkey_fd >= 0) {
		EV_SET(&kev[nev], g->pfkey_fd, EVFILT_READ,
		    EV_ADD, 0, 0, NULL);
		nev++;
	}

	/* Control socket: external tool commands (cmmctl) */
	if (cmm_ctrl_init(g) == 0) {
		EV_SET(&kev[nev], g->ctrl_listen_fd, EVFILT_READ,
		    EV_ADD, 0, 0, (void *)(uintptr_t)1);
		nev++;
	}

	/* auto_bridge device: L2 flow events */
	if (g->autobridge_fd >= 0) {
		EV_SET(&kev[nev], g->autobridge_fd, EVFILT_READ,
		    EV_ADD, 0, 0, (void *)(uintptr_t)3);
		nev++;
	}

	/* pf_notify device: PF state change events */
	if (g->pfnotify_fd >= 0) {
		EV_SET(&kev[nev], g->pfnotify_fd, EVFILT_READ,
		    EV_ADD, 0, 0, (void *)(uintptr_t)4);
		nev++;
	}

	/*
	 * PF state polling timer.
	 * In push mode: 30s reconciliation to catch ring overflow drops.
	 * In poll mode: fast polling (default 100ms) as primary path.
	 */
	{
		int timer_ms;

		timer_ms = (g->pfnotify_fd >= 0) ?
		    CMM_RECONCILE_MS : g->poll_ms;
		EV_SET(&kev[nev], 1, EVFILT_TIMER, EV_ADD,
		    NOTE_MSECONDS, timer_ms, NULL);
		nev++;
	}

	/* CDX flow counter sync timer (5s) */
	if (g->pfnotify_fd >= 0) {
		EV_SET(&kev[nev], 5, EVFILT_TIMER, EV_ADD,
		    NOTE_MSECONDS, CMM_STATS_SYNC_MS, NULL);
		nev++;
	}

	if (kevent(g->kq, kev, nev, NULL, 0, NULL) < 0) {
		cmm_print(CMM_LOG_ERR, "kevent register: %s",
		    strerror(errno));
		goto out;
	}

	cmm_print(CMM_LOG_INFO, "event loop started");

	/* Main event loop */
	while (g->running) {
		struct kevent events[16];
		int n, i;

		n = kevent(g->kq, NULL, 0, events, 16, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			cmm_print(CMM_LOG_ERR, "kevent: %s", strerror(errno));
			break;
		}

		for (i = 0; i < n; i++) {
			if (events[i].filter == EVFILT_TIMER) {
				if (events[i].ident == 5)
					cmm_conn_stats_sync(g);
				else
					cmm_conn_poll(g);
			} else if (events[i].udata ==
			    (void *)(uintptr_t)1) {
				/* Control socket: new connection */
				cmm_ctrl_accept(g);
			} else if (events[i].udata ==
			    (void *)(uintptr_t)2) {
				/* Control socket: client command */
				cmm_ctrl_dispatch(g,
				    (int)events[i].ident);
			} else if ((int)events[i].ident ==
			    g->rtsock_fd) {
				cmm_rtsock_dispatch(g);
			} else if (g->pfkey_fd >= 0 &&
			    (int)events[i].ident == g->pfkey_fd) {
				cmm_pfkey_dispatch(g);
			} else if (events[i].udata ==
			    (void *)(uintptr_t)3) {
				/* auto_bridge: L2 flow event */
				cmm_bridge_event(g);
			} else if (events[i].udata ==
			    (void *)(uintptr_t)4) {
				/* pf_notify: state change event */
				cmm_conn_event(g);
			} else if (g->fci_catch != NULL &&
			    (int)events[i].ident ==
			    fci_fd(g->fci_catch)) {
				fci_drain(g->fci_catch);
			}
		}
	}

	cmm_print(CMM_LOG_INFO, "shutting down");

out:
	/* Clean shutdown */
	cmm_ctrl_fini(g);
	cmm_sa_flush_all(g);
	cmm_conn_deregister_all(g);
	cmm_wifi_fini(g);
	cmm_bridge_fini(g);
	cmm_socket_fini(g);
	cmm_l2tp_fini(g);
	cmm_tunnel_fini(g);
	cmm_vlan_fini(g);
	cmm_lagg_fini(g);
	cmm_fe_reset(g);

	cmm_deny_fini();
	cmm_ipsec_fini(g);
	cmm_conn_fini(g);
	cmm_route_fini();
	cmm_neigh_fini();
	cmm_itf_fini();

	if (g->kq >= 0)
		close(g->kq);
	if (g->pfkey_fd >= 0)
		close(g->pfkey_fd);
	if (g->rtsock_fd >= 0)
		close(g->rtsock_fd);
	if (g->rtsock_query_fd >= 0)
		close(g->rtsock_query_fd);
	if (g->pfnotify_fd >= 0)
		close(g->pfnotify_fd);
	if (g->pf_fd >= 0)
		close(g->pf_fd);
	if (g->fci_catch != NULL)
		fci_close(g->fci_catch);
	if (g->fci_handle != NULL)
		fci_close(g->fci_handle);

	pidfile_remove(pfh);
	cmm_print(CMM_LOG_INFO, "exited");

	return (0);
}
