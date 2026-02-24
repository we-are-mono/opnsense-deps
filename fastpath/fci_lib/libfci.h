/*
 * libfci — FCI userspace library header (FreeBSD version)
 *
 * Public API is identical to the Linux version for CMM compatibility.
 * Internal FCI_CLIENT struct uses /dev/fci fd + kqueue instead of netlink.
 *
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef _FCILIB_H
#define _FCILIB_H

/* FCI message definitions */
#define FCI_MAX_PAYLOAD		512

/* Supported client types (same values as Linux for CMM compat) */
#define FCILIB_FF_TYPE		0	/* Fast Forward */
#define FCILIB_KEY_TYPE		2	/* Key (IPSec) — not supported on FreeBSD */

/* Event groups (used in fci_open to enable async events) */
#define NL_FF_GROUP		(1 << 0)
#define NL_KEY_SA_GROUP		(1 << 0)
#define NL_KEY_FLOW_GROUP	(1 << 1)
#define NL_KEY_ALL_GROUP	(NL_KEY_SA_GROUP | NL_KEY_FLOW_GROUP)

/* PIDs for ODP compat (kept for source compat, unused on FreeBSD) */
#ifndef CMM_SOCK_PID_CMD
#define CMM_SOCK_PID_CMD	100
#endif
#ifndef FCI_SOCK_PID_CMD
#define FCI_SOCK_PID_CMD	200
#endif
#ifndef CMM_SOCK_PID_EVENT
#define CMM_SOCK_PID_EVENT	300
#endif
#ifndef FCI_SOCK_PID_EVENT
#define FCI_SOCK_PID_EVENT	400
#endif

/* FCI callback return codes */
enum FCI_CB_ACTION {
	FCI_CB_STOP = 0,	/* stop catching events from FCI */
	FCI_CB_CONTINUE,	/* continue event catching */
};

/*
 * FCI_CLIENT — opaque to library users.
 *
 * On FreeBSD, this holds a /dev/fci file descriptor for ioctl commands,
 * and optionally a kqueue fd for async event notification.
 */
typedef struct t_FCI_CLIENT {
	int fd;			/* /dev/fci file descriptor */
	int kq;			/* kqueue fd for events, -1 if unused */
	int client_type;	/* FCILIB_FF_TYPE or FCILIB_KEY_TYPE */
	int (*event_cb)(unsigned short fcode, unsigned short len,
	    unsigned short *payload);
} FCI_CLIENT;

/*
 * Public API — identical prototypes to the Linux version.
 */
FCI_CLIENT *fci_open(unsigned long socket_type, unsigned long group);
int fci_close(FCI_CLIENT *client);
int fci_cmd(FCI_CLIENT *this_client, unsigned short fcode,
    unsigned short *cmd_buf, unsigned short cmd_len,
    unsigned short *rep_buf, unsigned short *rep_len);
int fci_write(FCI_CLIENT *client, unsigned short fcode,
    unsigned short len, unsigned short *payload);
int fci_query(FCI_CLIENT *this_client, unsigned short fcode,
    unsigned short length, unsigned short *pcmd,
    unsigned short *rsplen, unsigned short *rsp_data);
int fci_catch(FCI_CLIENT *client);
int fci_drain(FCI_CLIENT *client);
int fci_register_cb(FCI_CLIENT *client,
    int (*event_cb)(unsigned short fcode, unsigned short len,
    unsigned short *payload));
int fci_fd(FCI_CLIENT *this_client);

#endif /* _FCILIB_H */
