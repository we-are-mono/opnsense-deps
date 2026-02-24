/*
 * libfci — FCI userspace library (FreeBSD implementation)
 *
 * Replaces Linux netlink-based libfci.c with /dev/fci ioctl + kqueue.
 * Public API is identical for CMM source compatibility.
 *
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "libfci.h"
#include "fci_freebsd.h"

/* Debug macros (matching Linux version style) */
#define FCILIB_PRINT	0
#define FCILIB_ERR	0
#define FCILIB_INIT	0
#define FCILIB_OPEN	0
#define FCILIB_CLOSE	0
#define FCILIB_WRITE	0
#define FCILIB_READ	0
#define FCILIB_CATCH	0

#ifdef FCILIB_PRINT
#define FCILIB_PRINTF(type, info, args...) \
	do { if (type) fprintf(stderr, info, ## args); } while (0)
#else
#define FCILIB_PRINTF(type, info, args...) do { } while (0)
#endif

/* ----------------------------------------------------------------
 * Internal: send command via ioctl, receive reply
 * ---------------------------------------------------------------- */
static int
__fci_cmd(FCI_CLIENT *client, unsigned short fcode,
    unsigned short *cmd_buf, unsigned short cmd_len,
    unsigned short *rep_buf, unsigned short *rep_len)
{
	struct fci_ioc_msg msg;
	int rc;

	memset(&msg, 0, sizeof(msg));
	msg.fcode = fcode;
	msg.cmd_len = cmd_len;
	msg.rep_len = (rep_len != NULL) ? *rep_len : FCI_MSG_MAX_PAYLOAD;

	/* Copy command payload into ioctl struct */
	if (cmd_buf != NULL && cmd_len > 0) {
		if (cmd_len > FCI_MSG_MAX_PAYLOAD) {
			FCILIB_PRINTF(FCILIB_ERR,
			    "LIBFCI: cmd payload %u exceeds max %u\n",
			    cmd_len, FCI_MSG_MAX_PAYLOAD);
			errno = EOVERFLOW;
			return (-1);
		}
		memcpy(msg.payload, cmd_buf, cmd_len);
	}

	FCILIB_PRINTF(FCILIB_WRITE, "%s: fcode %#x length %d fd %d\n",
	    __func__, fcode, cmd_len, client->fd);

	rc = ioctl(client->fd, FCI_IOC_CMD, &msg);
	if (rc < 0) {
		FCILIB_PRINTF(FCILIB_ERR, "LIBFCI: ioctl(FCI_IOC_CMD) failed: %s\n",
		    strerror(errno));
		return (-1);
	}

	/* Copy reply back to caller */
	if (rep_buf != NULL && msg.rep_len > 0) {
		unsigned short copy_len = msg.rep_len;
		if (copy_len > FCI_MSG_MAX_PAYLOAD) {
			FCILIB_PRINTF(FCILIB_ERR,
			    "LIBFCI: reply %u exceeds max %u, truncating\n",
			    copy_len, FCI_MSG_MAX_PAYLOAD);
			copy_len = FCI_MSG_MAX_PAYLOAD;
		}
		memcpy(rep_buf, msg.payload, copy_len);
	}
	if (rep_len != NULL)
		*rep_len = msg.rep_len;

	return (0);
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

/*
 * fci_open — create an FCI client.
 *
 * client_type: FCILIB_FF_TYPE (Fast Forward)
 * group: if non-zero, enable async event notification via kqueue
 */
FCI_CLIENT *
fci_open(unsigned long client_type, unsigned long group)
{
	FCI_CLIENT *client;
	int fd;

	if (client_type != FCILIB_FF_TYPE) {
		FCILIB_PRINTF(FCILIB_ERR,
		    "LIBFCI: fci_open(): client type %lu not supported\n",
		    client_type);
		return (NULL);
	}

	fd = open("/dev/fci", O_RDWR);
	if (fd < 0) {
		FCILIB_PRINTF(FCILIB_ERR,
		    "LIBFCI: open(/dev/fci) failed: %s\n", strerror(errno));
		return (NULL);
	}

	client = calloc(1, sizeof(FCI_CLIENT));
	if (client == NULL) {
		close(fd);
		return (NULL);
	}

	client->fd = fd;
	client->kq = -1;
	client->client_type = (int)client_type;
	client->event_cb = NULL;

	/*
	 * If group is non-zero, create a kqueue and register EVFILT_READ
	 * on the /dev/fci fd for async event notification.
	 */
	if (group != 0) {
		struct kevent kev;
		int kq;

		kq = kqueue();
		if (kq < 0) {
			FCILIB_PRINTF(FCILIB_ERR,
			    "LIBFCI: kqueue() failed: %s\n", strerror(errno));
			close(fd);
			free(client);
			return (NULL);
		}

		EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
			FCILIB_PRINTF(FCILIB_ERR,
			    "LIBFCI: kevent() register failed: %s\n",
			    strerror(errno));
			close(kq);
			close(fd);
			free(client);
			return (NULL);
		}

		client->kq = kq;

		FCILIB_PRINTF(FCILIB_OPEN,
		    "fci_open: fd=%d kq=%d group=%lu\n", fd, kq, group);
	} else {
		FCILIB_PRINTF(FCILIB_OPEN,
		    "fci_open: fd=%d (no events)\n", fd);
	}

	return (client);
}

/*
 * fci_close — destroy an FCI client.
 */
int
fci_close(FCI_CLIENT *client)
{
	if (client == NULL)
		return (-1);

	FCILIB_PRINTF(FCILIB_CLOSE, "fci_close: fd=%d\n", client->fd);

	if (client->kq >= 0)
		close(client->kq);
	close(client->fd);
	free(client);

	return (0);
}

/*
 * fci_cmd — send command, receive full reply.
 *
 * Returns 0 on success, < 0 on transport error.
 * Reply data is in rep_buf, reply length in *rep_len.
 */
int
fci_cmd(FCI_CLIENT *client, unsigned short fcode,
    unsigned short *cmd_buf, unsigned short cmd_len,
    unsigned short *rep_buf, unsigned short *rep_len)
{
	FCILIB_PRINTF(FCILIB_WRITE, "%s: fcode %#x length %d\n",
	    __func__, fcode, cmd_len);

	return (__fci_cmd(client, fcode, cmd_buf, cmd_len, rep_buf, rep_len));
}

/*
 * fci_write — send command, return FPP result code.
 *
 * Returns: FPP return code (rep_buf[0]), or < 0 on transport error.
 */
int
fci_write(FCI_CLIENT *client, unsigned short fcode,
    unsigned short cmd_len, unsigned short *cmd_buf)
{
	unsigned short rep_buf[FCI_MAX_PAYLOAD / sizeof(unsigned short)]
	    __attribute__((aligned(4)));
	unsigned short rep_len = sizeof(rep_buf);
	int rc;

	FCILIB_PRINTF(FCILIB_WRITE, "%s: fcode %#x length %d\n",
	    __func__, fcode, cmd_len);

	rep_buf[0] = 0;
	rc = __fci_cmd(client, fcode, cmd_buf, cmd_len, rep_buf, &rep_len);
	if (rc < 0)
		return (rc);

	return (rep_buf[0]);
}

/*
 * fci_query — send command, return FPP result code + reply data.
 *
 * Reply data (skipping the first u16 result code) is copied to rep_buf.
 * Returns: FPP return code (first u16), or < 0 on transport error.
 */
int
fci_query(FCI_CLIENT *client, unsigned short fcode,
    unsigned short cmd_len, unsigned short *cmd_buf,
    unsigned short *rep_len, unsigned short *rep_buf)
{
	unsigned short lrep_buf[FCI_MAX_PAYLOAD / sizeof(unsigned short)]
	    __attribute__((aligned(4)));
	unsigned short lrep_len = sizeof(lrep_buf);
	int rc;

	FCILIB_PRINTF(FCILIB_WRITE, "%s: fcode %#x length %d\n",
	    __func__, fcode, cmd_len);

	if (rep_len)
		*rep_len = 0;

	rc = __fci_cmd(client, fcode, cmd_buf, cmd_len, lrep_buf, &lrep_len);
	if (rc < 0)
		return (rc);

	/* Copy reply data (skip first u16 which is the result code) */
	if (lrep_len > 2 && rep_len != NULL && rep_buf != NULL) {
		memcpy(rep_buf, lrep_buf + 1, lrep_len - 2);
		*rep_len = lrep_len - 2;
	}

	return (lrep_buf[0]);
}

/*
 * fci_catch — blocking event loop.
 *
 * Waits for async events from CDX via kqueue, dequeues them via
 * FCI_IOC_READ_EVT ioctl, and dispatches to the registered callback.
 *
 * Returns when callback returns FCI_CB_STOP, or on error.
 */
int
fci_catch(FCI_CLIENT *client)
{
	struct kevent kev;
	struct fci_event evt;
	int rc;

	if (client == NULL)
		return (-1);

	if (client->kq < 0) {
		FCILIB_PRINTF(FCILIB_ERR,
		    "LIBFCI: fci_catch() called but no kqueue (group=0)\n");
		return (-1);
	}

	FCILIB_PRINTF(FCILIB_CATCH, "%s: kq=%d\n", __func__, client->kq);

	while (1) {
		/* Block until an event is available */
		rc = kevent(client->kq, NULL, 0, &kev, 1, NULL);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			FCILIB_PRINTF(FCILIB_ERR,
			    "%s: kevent() failed: %s\n",
			    __func__, strerror(errno));
			break;
		}

		if (rc == 0)
			continue;	/* timeout (shouldn't happen with NULL timeout) */

		/* Dequeue events from kernel ring buffer */
		while (1) {
			rc = ioctl(client->fd, FCI_IOC_READ_EVT, &evt);
			if (rc < 0) {
				if (errno == EAGAIN)
					break;	/* ring empty, go back to kevent */
				FCILIB_PRINTF(FCILIB_ERR,
				    "%s: ioctl(FCI_IOC_READ_EVT) failed: %s\n",
				    __func__, strerror(errno));
				return (-1);
			}

			/* Dispatch to callback */
			if (client->event_cb != NULL) {
				rc = client->event_cb(evt.fcode, evt.length,
				    (unsigned short *)evt.payload);
				if (rc <= FCI_CB_STOP)
					return (rc);
			}
		}
	}

	return (rc);
}

/*
 * fci_register_cb — register async event callback.
 */
int
fci_register_cb(FCI_CLIENT *client,
    int (*cb)(unsigned short fcode, unsigned short len,
    unsigned short *payload))
{
	if (client == NULL)
		return (-1);

	client->event_cb = cb;

	FCILIB_PRINTF(FCILIB_INIT,
	    "fci_register_cb(): event callback registered for fd %d\n",
	    client->fd);

	return (0);
}

/*
 * fci_drain — non-blocking event drain.
 *
 * Dequeues and dispatches all pending events from CDX via
 * FCI_IOC_READ_EVT ioctl.  Unlike fci_catch(), this does NOT block
 * waiting for new events — it returns immediately when the ring is
 * empty.  Designed for use in a caller-managed event loop (e.g.,
 * CMM's main kqueue loop).
 *
 * Returns 0 on success, -1 on error.
 */
int
fci_drain(FCI_CLIENT *client)
{
	struct fci_event evt;
	int rc;

	if (client == NULL)
		return (-1);

	while (1) {
		rc = ioctl(client->fd, FCI_IOC_READ_EVT, &evt);
		if (rc < 0) {
			if (errno == EAGAIN)
				break;	/* ring empty — done */
			FCILIB_PRINTF(FCILIB_ERR,
			    "%s: ioctl(FCI_IOC_READ_EVT) failed: %s\n",
			    __func__, strerror(errno));
			return (-1);
		}

		/* Dispatch to callback */
		if (client->event_cb != NULL) {
			rc = client->event_cb(evt.fcode, evt.length,
			    (unsigned short *)evt.payload);
			if (rc <= FCI_CB_STOP)
				break;
		}
	}

	return (0);
}

/*
 * fci_fd — return a file descriptor suitable for poll/select.
 *
 * If kqueue is active (events enabled), return the kqueue fd.
 * Otherwise return the /dev/fci fd.
 */
int
fci_fd(FCI_CLIENT *client)
{
	if (client->kq >= 0)
		return (client->kq);
	return (client->fd);
}
