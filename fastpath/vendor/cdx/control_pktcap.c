/*
 * control_pktcap.c — Packet capture configuration handler for CDX
 *
 * Stores per-port capture state (enabled, slice size, BPF filter) and
 * responds to FPP_CMD_PKTCAP_* commands.  The actual data-plane capture
 * (FMan frame replication / mirroring) is a separate hardware
 * integration task.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "cdx.h"

/*
 * Per-port packet capture state.
 *
 * The FPP structs use a bare `ifindex` field (0-7) to identify ports.
 * We store configuration for up to PKTCAP_MAX_PORTS ports.
 */
#define PKTCAP_MAX_PORTS	8
#define PKTCAP_MIN_SLICE	40
#define PKTCAP_MAX_SLICE	1518
#define MAX_FLF_INSTRUCTIONS	30
#define PKTCAP_FLF_MAX_INSN	(3 * MAX_FLF_INSTRUCTIONS)	/* 90 */

/* BPF instruction — matches struct bpf_insn layout (8 bytes) */
struct pktcap_bpf_insn {
	U16	code;
	U8	jt;
	U8	jf;
	U32	k;
};

struct pktcap_port {
	int	enabled;		/* 0 or 1 */
	U16	slice;			/* capture size, 0 = not set */
	int	flf_len;		/* total BPF instruction count */
	struct pktcap_bpf_insn flf[PKTCAP_FLF_MAX_INSN];
};

static struct pktcap_port pktcap_ports[PKTCAP_MAX_PORTS];
static int pktcap_global_enabled;

/* ---- FPP struct layouts (must match fpp.h definitions) ---- */

/* FPP action codes */
#define FPP_PKTCAP_STATUS	0x1
#define FPP_PKTCAP_SLICE_ACT	0x2

struct __attribute__((__packed__)) pktcap_status_cmd {
	U16	action;
	U8	ifindex;
	U8	status;
};

struct __attribute__((__packed__)) pktcap_slice_cmd {
	U16	action;
	U8	ifindex;
	U8	rsvd;
	U16	slice;
};

struct __attribute__((__packed__)) pktcap_query_resp {
	U16	slice;
	U16	status;
};

struct __attribute__((__packed__)) pktcap_flf_cmd {
	U16	flen;
	U8	ifindex;
	U8	mfg;		/* bit 3: more fragments; bits 2-0: seqno */
	struct pktcap_bpf_insn filter[MAX_FLF_INSTRUCTIONS];
};

/* ---- Command handlers ---- */

static U16
pktcap_handle_enable(U16 *pcmd, U16 cmd_len)
{
	/* CMD_PKTCAP_ENABLE has no documented payload — toggle global enable */
	if (pktcap_global_enabled)
		return ERR_PKTCAP_ALREADY_ENABLED;

	pktcap_global_enabled = 1;
	return NO_ERR;
}

static U16
pktcap_handle_ifstatus(U16 *pcmd, U16 cmd_len)
{
	struct pktcap_status_cmd *cmd = (struct pktcap_status_cmd *)pcmd;

	if (cmd_len < sizeof(*cmd))
		return ERR_WRONG_COMMAND_SIZE;

	if (cmd->ifindex >= PKTCAP_MAX_PORTS)
		return ERR_WRONG_COMMAND_PARAM;

	if (cmd->status == 0)
		pktcap_ports[cmd->ifindex].enabled = 0;
	else if (cmd->status == 1)
		pktcap_ports[cmd->ifindex].enabled = 1;
	else
		return ERR_WRONG_COMMAND_PARAM;

	return NO_ERR;
}

static U16
pktcap_handle_slice(U16 *pcmd, U16 cmd_len)
{
	struct pktcap_slice_cmd *cmd = (struct pktcap_slice_cmd *)pcmd;

	if (cmd_len < sizeof(*cmd))
		return ERR_WRONG_COMMAND_SIZE;

	if (cmd->ifindex >= PKTCAP_MAX_PORTS)
		return ERR_WRONG_COMMAND_PARAM;

	if (cmd->slice < PKTCAP_MIN_SLICE || cmd->slice > PKTCAP_MAX_SLICE)
		return ERR_WRONG_COMMAND_PARAM;

	pktcap_ports[cmd->ifindex].slice = cmd->slice;
	return NO_ERR;
}

static U16
pktcap_handle_flf(U16 *pcmd, U16 cmd_len)
{
	struct pktcap_flf_cmd *cmd = (struct pktcap_flf_cmd *)pcmd;
	struct pktcap_port *port;
	int seqno, more;
	int offset, count;

	if (cmd_len < 4) /* at least flen + ifindex + mfg */
		return ERR_WRONG_COMMAND_SIZE;

	if (cmd->ifindex >= PKTCAP_MAX_PORTS)
		return ERR_WRONG_COMMAND_PARAM;

	port = &pktcap_ports[cmd->ifindex];

	/* flen == 0 means reset filter */
	if (cmd->flen == 0) {
		port->flf_len = 0;
		memset(port->flf, 0, sizeof(port->flf));
		return ERR_PKTCAP_FLF_RESET;
	}

	if (cmd->flen > MAX_FLF_INSTRUCTIONS)
		return ERR_WRONG_COMMAND_PARAM;

	seqno = cmd->mfg & 0x7;
	more = (cmd->mfg >> 3) & 1;

	/* First fragment clears the buffer */
	if (seqno == 0)
		port->flf_len = 0;

	offset = seqno * MAX_FLF_INSTRUCTIONS;
	count = cmd->flen;

	if (offset + count > PKTCAP_FLF_MAX_INSN)
		return ERR_WRONG_COMMAND_PARAM;

	memcpy(&port->flf[offset], cmd->filter,
	    count * sizeof(struct pktcap_bpf_insn));

	if (!more) {
		/* Last fragment — record total length */
		port->flf_len = offset + count;
	}

	return NO_ERR;
}

static U16
pktcap_handle_query(U16 *pcmd, U16 cmd_len, U16 *retlen)
{
	/*
	 * Write response data at pcmd + 1 (byte offset 2), because
	 * M_pktcap_cmdproc will set *pcmd = error_code after we return.
	 * The CDX response format is: [2-byte error code][data...].
	 */
	struct pktcap_query_resp *resp =
	    (struct pktcap_query_resp *)(pcmd + 1);
	int i;

	for (i = 0; i < PKTCAP_MAX_PORTS; i++) {
		resp[i].slice = pktcap_ports[i].slice;
		resp[i].status = pktcap_ports[i].enabled ? 1 : 0;
	}

	*retlen = 2 + PKTCAP_MAX_PORTS * sizeof(struct pktcap_query_resp);
	return NO_ERR;
}

/* ---- Main command processor ---- */

static U16
M_pktcap_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 retlen = 2;

	switch (cmd_code) {
	case CMD_PKTCAP_ENABLE:
		rc = pktcap_handle_enable(pcmd, cmd_len);
		break;

	case CMD_PKTCAP_IFSTATUS:
		rc = pktcap_handle_ifstatus(pcmd, cmd_len);
		break;

	case CMD_PKTCAP_SLICE:
		rc = pktcap_handle_slice(pcmd, cmd_len);
		break;

	case CMD_PKTCAP_FLF:
		rc = pktcap_handle_flf(pcmd, cmd_len);
		break;

	case CMD_PKTCAP_QUERY:
		rc = pktcap_handle_query(pcmd, cmd_len, &retlen);
		break;

	default:
		rc = ERR_UNKNOWN_COMMAND;
		break;
	}

	*pcmd = rc;
	return retlen;
}

/* ---- Module init/exit ---- */

int
pktcap_init(void)
{
	memset(pktcap_ports, 0, sizeof(pktcap_ports));
	pktcap_global_enabled = 0;
	set_cmd_handler(EVENT_PKTCAP, M_pktcap_cmdproc);
	return 0;
}

void
pktcap_exit(void)
{
	memset(pktcap_ports, 0, sizeof(pktcap_ports));
}
