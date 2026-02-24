/*
 * FCI (Fast Control Interface) — shared kernel/userspace header
 *
 * Defines the ioctl interface for /dev/fci on FreeBSD.
 * Replaces Linux netlink-based FCI IPC.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _FCI_FREEBSD_H_
#define _FCI_FREEBSD_H_

#include <sys/types.h>
#include <sys/ioccom.h>

#define FCI_MSG_MAX_PAYLOAD	512
#define FCI_MSG_HDR_SIZE	4	/* fcode(2) + length(2) */
#define FCI_MAX_EVENTS		64	/* async event ring buffer size */

/*
 * Synchronous command/response ioctl structure.
 *
 * Userspace fills fcode, cmd_len, and payload (command data).
 * Kernel fills status, rep_len, and payload (reply data).
 */
struct fci_ioc_msg {
	uint16_t fcode;				/* function code */
	uint16_t cmd_len;			/* command payload length (bytes) */
	uint16_t rep_len;			/* in: reply buffer size, out: actual reply length */
	uint16_t status;			/* out: 0 = success, else error */
	uint8_t  payload[FCI_MSG_MAX_PAYLOAD];	/* cmd in, reply out */
};

/*
 * Async event structure (delivered via kqueue + read ioctl).
 * CDX pushes events when hardware state changes.
 */
struct fci_event {
	uint16_t fcode;
	uint16_t length;
	uint8_t  payload[FCI_MSG_MAX_PAYLOAD];
};

/* ioctl commands */
#define FCI_IOC_CMD		_IOWR('F', 1, struct fci_ioc_msg)	/* send cmd, get reply */
#define FCI_IOC_READ_EVT	_IOR('F', 2, struct fci_event)		/* dequeue one event */

/*
 * Cross-module interface: CDX ↔ FCI
 *
 * These function pointers are registered at CDX module load time.
 * FCI calls send_command to dispatch to CDX.
 * CDX calls event_cb to push async events to FCI (→ userspace).
 */
typedef int (*fci_send_command_fn)(uint16_t fcode, uint16_t length,
    uint16_t *payload, uint16_t *rlen, uint16_t *rbuf);
typedef int (*fci_event_cb_fn)(uint16_t fcode, uint16_t length,
    uint16_t *payload);

#ifdef _KERNEL

/* Called by CDX at load time to register its command handler */
void fci_register_send_command(fci_send_command_fn fn);

/* Called by CDX at load time to register for async event delivery */
void fci_register_event_cb(fci_event_cb_fn *cb_ptr);

/*
 * Legacy API names for source compatibility with CDX code that
 * calls these directly (cdx_cmdhandler.c, fci.c).
 */
int comcerto_fpp_send_command(uint16_t fcode, uint16_t length,
    uint16_t *payload, uint16_t *rlen, uint16_t *rbuf);
int comcerto_fpp_register_event_cb(void *cb);

#endif /* _KERNEL */

#endif /* _FCI_FREEBSD_H_ */
