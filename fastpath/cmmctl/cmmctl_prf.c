/*
 * cmmctl_prf.c — FPP trace / profiling CLI sub-commands
 *
 * cmmctl prf status                       Query trace state
 * cmmctl prf trace start [pmn0 [pmn1]]    Start tracing
 * cmmctl prf trace stop                   Stop tracing, display buffer
 * cmmctl prf trace switch                 Switch buffers, display current
 * cmmctl prf trace show                   Display current trace
 * cmmctl prf trace setmask <mask>         Set module trace mask
 * cmmctl prf busycpu start [weight]       Start CPU measurement
 * cmmctl prf busycpu stop                 Stop, show busy/idle counts
 * cmmctl prf dmem <addr> [len]            Display CDX memory (hex words)
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "cmmctl.h"
#include "fpp.h"

static const char *
fpp_trc_strerror(int16_t rc)
{

	switch ((uint16_t)rc) {
	case FPP_ERR_UNKNOWN_COMMAND:
		return ("command not supported by CDX (no trace handler)");
	case FPP_ERR_WRONG_COMMAND_SIZE:
		return ("wrong command size");
	case FPP_ERR_WRONG_COMMAND_PARAM:
		return ("wrong command parameter");
	case FPP_ERR_TRC_UNIMPLEMENTED:
		return ("not implemented in CDX microcode");
	default:
		return (NULL);
	}
}

static void
prf_errmsg(const char *cmd, int16_t rc)
{
	const char *msg;

	msg = fpp_trc_strerror(rc);
	if (msg != NULL)
		fprintf(stderr, "%s: %s (0x%04x)\n", cmd, msg,
		    (unsigned)(uint16_t)rc);
	else
		fprintf(stderr, "%s: error 0x%04x\n", cmd,
		    (unsigned)(uint16_t)rc);
}

static void
prf_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl prf <command>\n\n"
	    "Commands:\n"
	    "  status                       Query trace state\n"
	    "  trace start [pmn0 [pmn1]]    Start tracing\n"
	    "  trace stop                   Stop tracing, display buffer\n"
	    "  trace switch                 Switch buffers, display current\n"
	    "  trace show                   Display current trace buffer\n"
	    "  trace setmask <mask>         Set module trace mask\n"
	    "  busycpu start [weight]       Start CPU measurement\n"
	    "  busycpu stop                 Stop, show busy/idle counts\n"
	    "  dmem <addr> [len]            Display CDX memory (hex words)\n");
}

/* ---- dmem: read and display CDX memory --------------------------------- */

/*
 * Read CDX memory via FPP_CMD_TRC_DMEM in 224-byte chunks and display
 * as 32-bit hex words with address prefix.
 */
static int
prf_dmem(int fd, uint32_t addr, uint32_t len)
{
	fpp_dm_cmd_t cmd;
	fpp_dm_cmd_t resp;
	uint16_t resp_len;
	int16_t rc;
	uint32_t off, chunk, i;

	for (off = 0; off < len; ) {
		chunk = len - off;
		if (chunk > sizeof(cmd.mspmem))
			chunk = sizeof(cmd.mspmem);
		/* Round down to multiple of 16 for long reads */
		if (chunk > 16)
			chunk = (chunk / 16) * 16;

		memset(&cmd, 0, sizeof(cmd));
		cmd.msp_addr = addr + off;
		cmd.msp_len = chunk;

		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_TRC_DMEM, &cmd,
		    offsetof(fpp_dm_cmd_t, mspmem),
		    &rc, &resp, &resp_len) < 0)
			return (1);

		if (rc != 0) {
			prf_errmsg("dmem", rc);
			return (1);
		}

		if (resp_len < offsetof(fpp_dm_cmd_t, mspmem)) {
			fprintf(stderr, "dmem: short response (%u bytes)\n",
			    resp_len);
			return (1);
		}

		/* Display as 32-bit hex words, 4 per line */
		for (i = 0; i < resp.msp_len; i += 4) {
			if ((i % 16) == 0)
				printf("0x%08x:", resp.msp_addr + i);
			if (i + 4 <= resp.msp_len) {
				printf(" %02x%02x%02x%02x",
				    resp.mspmem[i],
				    resp.mspmem[i + 1],
				    resp.mspmem[i + 2],
				    resp.mspmem[i + 3]);
			} else {
				/* Trailing bytes */
				uint32_t j;
				for (j = i; j < resp.msp_len; j++)
					printf(" %02x", resp.mspmem[j]);
			}
			if (((i + 4) % 16) == 0 || i + 4 >= resp.msp_len)
				printf("\n");
		}

		off += resp.msp_len;
	}

	return (0);
}

/* Display trace buffer contents using dmem */
static int
prf_trace_display(int fd, fpp_trc_off_cmd_t *res)
{
	uint32_t base, data_off, data_len, offset;

	if (res->trc_length == 0 || res->trc_address == 0) {
		printf("No trace buffer available (tracing not active)\n");
		return (0);
	}

	/*
	 * Trace buffer layout: [counters][masks][4-byte gap][trace data]
	 * The offset field points to the oldest entry (circular).
	 */
	data_off = res->trc_ctr_length + res->trc_mask_length + 4;
	if (data_off >= res->trc_length) {
		printf("No trace data (buffer too small)\n");
		return (0);
	}
	data_len = res->trc_length - data_off;
	base = res->trc_address + data_off;
	offset = res->offset * 16; /* entry index → byte offset */

	printf("Trace at 0x%08x for 0x%x bytes offset 0x%x\n",
	    base, data_len, offset);

	/* Display from oldest entry to end, then wrap to beginning */
	if (offset > 0 && offset < data_len) {
		if (prf_dmem(fd, base + offset, data_len - offset) != 0)
			return (1);
		return (prf_dmem(fd, base, offset));
	}

	return (prf_dmem(fd, base, data_len));
}

/* ---- status ------------------------------------------------------------ */

static int
prf_status(int fd)
{
	fpp_trc_stat_cmd_t resp;
	uint16_t resp_len;
	int16_t rc;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_TRC_STATUS, NULL, 0,
	    &rc, &resp, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		prf_errmsg("status", rc);
		return (1);
	}

	switch (resp.state) {
	case 0:
		printf("Tracing is OFF\n");
		break;
	case 1:
		printf("Tracing is ON\n");
		break;
	case 2:
		printf("CPU measurement is ON\n");
		break;
	default:
		printf("Unknown state %u\n", resp.state);
		break;
	}
	printf("pmn0:0x%02x pmn1:0x%02x mask:0x%04x weight:0x%x\n",
	    resp.pmn0, resp.pmn1, resp.trc_mask, resp.bsycpu_weight);

	return (0);
}

/* ---- trace sub-commands ------------------------------------------------ */

static int
prf_trace_start(int fd, int argc, char **argv)
{
	fpp_trc_on_cmd_t cmd;
	uint16_t payload_len;
	int16_t rc;
	unsigned int tmp;

	memset(&cmd, 0, sizeof(cmd));
	payload_len = 0;

	if (argc > 0) {
		if (sscanf(argv[0], "%i", &tmp) != 1) {
			fprintf(stderr,
			    "usage: cmmctl prf trace start [pmn0 [pmn1]]\n");
			return (1);
		}
		cmd.pmn0_id = (uint16_t)(tmp & 0xff);
		payload_len = offsetof(fpp_trc_on_cmd_t, pmn1_id) +
		    sizeof(cmd.pmn1_id);

		if (argc > 1) {
			if (sscanf(argv[1], "%i", &tmp) != 1) {
				fprintf(stderr,
				    "usage: cmmctl prf trace start"
				    " [pmn0 [pmn1]]\n");
				return (1);
			}
			cmd.pmn1_id = (uint16_t)(tmp & 0xff);
		}
	}

	if (ctrl_command(fd, FPP_CMD_TRC_ON, &cmd, payload_len,
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		prf_errmsg("trace start", rc);
		return (1);
	}

	printf("tracing started\n");
	return (0);
}

static int
prf_trace_stop(int fd)
{
	fpp_trc_off_cmd_t resp;
	uint16_t resp_len;
	int16_t rc;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_TRC_OFF, NULL, 0,
	    &rc, &resp, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		prf_errmsg("trace stop", rc);
		return (1);
	}

	return (prf_trace_display(fd, &resp));
}

static int
prf_trace_switch(int fd)
{
	fpp_trc_off_cmd_t resp;
	uint16_t resp_len;
	int16_t rc;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_TRC_SWITCH, NULL, 0,
	    &rc, &resp, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		prf_errmsg("trace switch", rc);
		return (1);
	}

	return (prf_trace_display(fd, &resp));
}

static int
prf_trace_show(int fd)
{
	fpp_trc_off_cmd_t resp;
	uint16_t resp_len;
	int16_t rc;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_TRC_SHOW, NULL, 0,
	    &rc, &resp, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		prf_errmsg("trace show", rc);
		return (1);
	}

	return (prf_trace_display(fd, &resp));
}

static int
prf_trace_setmask(int fd, int argc, char **argv)
{
	fpp_trc_sm_cmd_t cmd;
	unsigned int tmp;
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl prf trace setmask <mask>\n");
		return (1);
	}

	if (sscanf(argv[0], "%i", &tmp) != 1) {
		fprintf(stderr, "invalid mask: %s\n", argv[0]);
		return (1);
	}

	cmd.mask = (uint16_t)tmp;

	if (ctrl_command(fd, FPP_CMD_TRC_SETMASK, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		prf_errmsg("trace setmask", rc);
		return (1);
	}

	printf("trace mask set to 0x%04x\n", (unsigned)cmd.mask);
	return (0);
}

/* ---- busycpu ----------------------------------------------------------- */

static int
prf_busycpu(int fd, int argc, char **argv)
{
	fpp_trc_cpu_cmd_t cmd, resp;
	uint16_t payload_len, resp_len;
	int16_t rc;
	unsigned int tmp;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl prf busycpu start|stop [weight]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	if (strcmp(argv[0], "start") == 0) {
		cmd.on_off = 1;
		payload_len = 2 * sizeof(uint16_t);

		if (argc > 1) {
			if (sscanf(argv[1], "%i", &tmp) != 1) {
				fprintf(stderr, "invalid weight: %s\n",
				    argv[1]);
				return (1);
			}
			cmd.weight = tmp;
			payload_len += sizeof(uint32_t);
		}

		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_TRC_BSYCPU, &cmd, payload_len,
		    &rc, &resp, &resp_len) < 0)
			return (1);

		if (rc == (int16_t)FPP_ERR_TRC_SOME_OK) {
			printf("weight factor changed\n");
			return (0);
		}
		if (rc != 0) {
			prf_errmsg("busycpu start", rc);
			return (1);
		}

		printf("CPU measurement started\n");
		return (0);

	} else if (strcmp(argv[0], "stop") == 0) {
		cmd.on_off = 0;
		payload_len = 2 * sizeof(uint16_t);

		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_TRC_BSYCPU, &cmd, payload_len,
		    &rc, &resp, &resp_len) < 0)
			return (1);

		if (rc != 0) {
			prf_errmsg("busycpu stop", rc);
			return (1);
		}

		if (resp.busy_count > 0x100 || resp.idle_count > 0x100) {
			uint64_t busy = resp.busy_count >> 8;
			uint64_t idle = resp.idle_count >> 8;
			printf("Busy: 0x%" PRIx64
			    "  Idle: 0x%" PRIx64
			    "  Busy%%: %5.2f\n",
			    resp.busy_count, resp.idle_count,
			    100.0 * (double)busy /
			    (double)(busy + idle));
		} else {
			printf("System is idle\n");
		}
		return (0);
	}

	fprintf(stderr, "unknown busycpu action: %s\n", argv[0]);
	return (1);
}

/* ---- main dispatcher --------------------------------------------------- */

int
cmmctl_prf_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		prf_usage();
		return (1);
	}

	if (strcmp(argv[0], "status") == 0)
		return (prf_status(fd));

	if (strcmp(argv[0], "trace") == 0) {
		if (argc < 2) {
			fprintf(stderr,
			    "usage: cmmctl prf trace"
			    " start|stop|switch|show|setmask\n");
			return (1);
		}
		if (strcmp(argv[1], "start") == 0)
			return (prf_trace_start(fd, argc - 2, argv + 2));
		if (strcmp(argv[1], "stop") == 0)
			return (prf_trace_stop(fd));
		if (strcmp(argv[1], "switch") == 0)
			return (prf_trace_switch(fd));
		if (strcmp(argv[1], "show") == 0)
			return (prf_trace_show(fd));
		if (strcmp(argv[1], "setmask") == 0)
			return (prf_trace_setmask(fd, argc - 2, argv + 2));
		fprintf(stderr, "unknown trace command: %s\n", argv[1]);
		return (1);
	}

	if (strcmp(argv[0], "busycpu") == 0)
		return (prf_busycpu(fd, argc - 1, argv + 1));

	if (strcmp(argv[0], "dmem") == 0) {
		uint32_t addr, len;
		unsigned int tmp;

		if (argc < 2) {
			fprintf(stderr,
			    "usage: cmmctl prf dmem <addr> [len]\n");
			return (1);
		}
		if (sscanf(argv[1], "%i", &tmp) != 1) {
			fprintf(stderr, "invalid address: %s\n", argv[1]);
			return (1);
		}
		addr = tmp;
		len = 64;
		if (argc > 2 && sscanf(argv[2], "%i", &tmp) == 1)
			len = tmp;
		return (prf_dmem(fd, addr, len));
	}

	fprintf(stderr, "unknown prf command: %s\n", argv[0]);
	prf_usage();
	return (1);
}
