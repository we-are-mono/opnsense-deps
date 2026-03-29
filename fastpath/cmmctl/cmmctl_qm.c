/*
 * cmmctl_qm.c — QoS / Queue Manager command handlers for cmmctl
 *
 * Ported from Linux module_qm.c (LS1043 path).  All commands are
 * pure FCI passthrough — cmmctl builds the FPP struct and sends
 * it through the CMM control socket; CMM forwards to CDX via FCI.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

/* Rate limit bounds (from Linux module_qm.h) */
#define QM_EXPTRATE_MINVAL	1000
#define QM_EXPTRATE_MAXVAL	5000000
#define QM_EXPTRATE_MIN_BS	1
#define QM_EXPTRATE_MAX_BS	2048
#define QM_FFRATE_MIN_CIR	1
#define QM_FFRATE_MAX_CIR	20971250
#define QM_FFRATE_MIN_PIR	1
#define QM_FFRATE_MAX_PIR	20971250
#define QM_INGRESS_MIN_CIR	1
#define QM_INGRESS_MAX_CIR	20971250
#define QM_INGRESS_MIN_PIR	1
#define QM_INGRESS_MAX_PIR	20971250

#define MAX_PQS		8

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static int
parse_uint32(const char *s, uint32_t max_val, uint32_t *val)
{
	char *endptr;
	unsigned long tmp;

	if (s == NULL)
		return (-1);
	endptr = NULL;
	tmp = strtoul(s, &endptr, 0);
	if (s == endptr || tmp > max_val)
		return (-1);
	*val = (uint32_t)tmp;
	return (0);
}

static int
send_cmd(int fd, uint16_t cmd, const void *payload, uint16_t len,
    const char *cmd_name)
{
	int16_t rc;
	uint16_t resp_len = 0;

	if (ctrl_command(fd, cmd, payload, len, &rc, NULL, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "%s: error %d\n", cmd_name, rc);
		return (1);
	}
	return (0);
}

static int
send_query(int fd, uint16_t cmd, void *payload, uint16_t len,
    void *resp, uint16_t *resp_len, const char *cmd_name)
{
	int16_t rc;

	if (ctrl_command(fd, cmd, payload, len, &rc, resp, resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "%s: error %d\n", cmd_name, rc);
		return (1);
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* enable / disable                                                   */
/* ------------------------------------------------------------------ */

static int
qm_enable(int argc, char **argv, int fd)
{
	fpp_qm_qos_enable_cmd_t cmd;

	if (argc < 2) {
		fprintf(stderr, "usage: cmmctl qm enable|disable <ifname>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[1], sizeof(cmd.interface));

	if (strcasecmp(argv[0], "enable") == 0)
		cmd.enable = 1;
	else
		cmd.enable = 0;

	return (send_cmd(fd, FPP_CMD_QM_QOSENABLE, &cmd, sizeof(cmd),
	    "QM_QOSENABLE"));
}

/* ------------------------------------------------------------------ */
/* reset                                                              */
/* ------------------------------------------------------------------ */

static int
qm_reset(int argc, char **argv, int fd)
{
	fpp_qm_reset_cmd_t cmd;

	if (argc < 2) {
		fprintf(stderr, "usage: cmmctl qm reset <ifname>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[1], sizeof(cmd.interface));

	return (send_cmd(fd, FPP_CMD_QM_RESET, &cmd, sizeof(cmd),
	    "QM_RESET"));
}

/* ------------------------------------------------------------------ */
/* shaper (shared for port and channel)                               */
/* ------------------------------------------------------------------ */

static int
qm_shaper_parse(int argc, char **argv, int start,
    fpp_qm_shaper_cfg_cmd_t *cmd)
{
	uint32_t v;
	int i;

	if (start >= argc) {
		fprintf(stderr, "shaper: expected on|off\n");
		return (-1);
	}

	for (i = start; i < argc; i++) {
		if (strcasecmp(argv[i], "on") == 0) {
			if (cmd->enable) return (-1);
			cmd->enable = SHAPER_ON;
		} else if (strcasecmp(argv[i], "off") == 0) {
			if (cmd->enable) return (-1);
			cmd->enable = SHAPER_OFF;
		} else if (strcasecmp(argv[i], "rate") == 0) {
			if (++i >= argc) return (-1);
			if (parse_uint32(argv[i], UINT_MAX, &v) < 0)
				return (-1);
			cmd->rate = v;
			cmd->cfg_flags |= (RATE_VALID | SHAPER_CFG_VALID);
		} else if (strcasecmp(argv[i], "bucketsize") == 0) {
			if (++i >= argc) return (-1);
			if (parse_uint32(argv[i], UINT_MAX, &v) < 0)
				return (-1);
			cmd->bsize = v;
			cmd->cfg_flags |= (BSIZE_VALID | SHAPER_CFG_VALID);
		} else {
			fprintf(stderr, "shaper: unknown keyword '%s'\n",
			    argv[i]);
			return (-1);
		}
	}

	if ((cmd->cfg_flags & SHAPER_CFG_VALID) &&
	    (cmd->cfg_flags & (RATE_VALID | BSIZE_VALID)) !=
	    (RATE_VALID | BSIZE_VALID)) {
		fprintf(stderr, "shaper: both rate and bucketsize required\n");
		return (-1);
	}

	return (0);
}

/* cmmctl qm shaper <ifname> on|off [rate <N>] [bucketsize <N>] */
static int
qm_port_shaper(int argc, char **argv, int fd)
{
	fpp_qm_shaper_cfg_cmd_t cmd;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl qm shaper <ifname> on|off "
		    "[rate <kbps>] [bucketsize <bytes>]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[0], sizeof(cmd.interface));
	cmd.cfg_flags = PORT_SHAPER_CFG;

	if (qm_shaper_parse(argc, argv, 1, &cmd) < 0)
		return (1);

	return (send_cmd(fd, FPP_CMD_QM_SHAPER_CFG, &cmd, sizeof(cmd),
	    "QM_SHAPER_CFG"));
}

/* ------------------------------------------------------------------ */
/* channel sub-commands                                               */
/* ------------------------------------------------------------------ */

/* cmmctl qm channel <N> assign <ifname> */
static int
qm_channel_assign(int argc, char **argv, int fd, uint32_t chnl)
{
	fpp_qm_chnl_assign_cmd_t cmd;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl qm channel <N> assign <ifname>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[0], sizeof(cmd.interface));
	cmd.channel_num = chnl;

	return (send_cmd(fd, FPP_CMD_QM_CHNL_ASSIGN, &cmd, sizeof(cmd),
	    "QM_CHNL_ASSIGN"));
}

/* cmmctl qm channel <N> shaper on|off [rate <N>] [bucketsize <N>] */
static int
qm_channel_shaper(int argc, char **argv, int fd, uint32_t chnl)
{
	fpp_qm_shaper_cfg_cmd_t cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.channel_num = chnl;
	cmd.cfg_flags = CHANNEL_SHAPER_CFG;

	if (qm_shaper_parse(argc, argv, 0, &cmd) < 0)
		return (1);

	return (send_cmd(fd, FPP_CMD_QM_SHAPER_CFG, &cmd, sizeof(cmd),
	    "QM_SHAPER_CFG"));
}

/* cmmctl qm channel <N> wbfq chshaper on|off [priority <P>] */
static int
qm_channel_wbfq(int argc, char **argv, int fd, uint32_t chnl)
{
	fpp_qm_wbfq_cfg_cmd_t cmd;
	uint32_t v;
	int i;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl qm channel <N> wbfq "
		    "chshaper on|off [priority <P>]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.channel_num = chnl;

	i = 0;
	if (strcasecmp(argv[i], "chshaper") != 0) {
		fprintf(stderr, "wbfq: expected 'chshaper'\n");
		return (1);
	}
	i++;
	if (i >= argc) {
		fprintf(stderr, "wbfq: expected on|off\n");
		return (1);
	}

	if (strcasecmp(argv[i], "on") == 0)
		cmd.wbfq_chshaper = 1;
	else if (strcasecmp(argv[i], "off") == 0)
		cmd.wbfq_chshaper = 0;
	else {
		fprintf(stderr, "wbfq: expected on|off, got '%s'\n", argv[i]);
		return (1);
	}
	cmd.cfg_flags |= WBFQ_SHAPER_VALID;
	i++;

	if (i < argc && strcasecmp(argv[i], "priority") == 0) {
		i++;
		if (i >= argc) {
			fprintf(stderr, "wbfq: expected priority value\n");
			return (1);
		}
		if (parse_uint32(argv[i], MAX_PQS - 2, &v) < 0) {
			fprintf(stderr, "wbfq: invalid priority\n");
			return (1);
		}
		cmd.priority = v;
		cmd.cfg_flags |= WBFQ_PRIORITY_VALID;
	}

	return (send_cmd(fd, FPP_CMD_QM_WBFQ_CFG, &cmd, sizeof(cmd),
	    "QM_WBFQ_CFG"));
}

/*
 * cmmctl qm channel <N> cq <Q> [qdepth <D>] [weight <W>]
 *     [chshaper on|off] [cqshaper on|off [rate <R>]]
 */
static int
qm_channel_cq(int argc, char **argv, int fd, uint32_t chnl)
{
	fpp_qm_cq_cfg_cmd_t cmd;
	uint32_t v;
	int i;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl qm channel <N> cq <Q> "
		    "[qdepth <D>] [weight <W>] "
		    "[chshaper on|off] [cqshaper on|off [rate <R>]]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.channel_num = chnl;

	if (parse_uint32(argv[0], 15, &v) < 0) {
		fprintf(stderr, "cq: invalid queue number\n");
		return (1);
	}
	cmd.quenum = v;

	for (i = 1; i < argc; ) {
		if (strcasecmp(argv[i], "qdepth") == 0) {
			if (++i >= argc) return (1);
			if (parse_uint32(argv[i], UINT_MAX, &v) < 0) {
				fprintf(stderr, "cq: invalid qdepth\n");
				return (1);
			}
			cmd.tdthresh = v;
			cmd.cfg_flags |= CQ_TDINFO_VALID;
			i++;
		} else if (strcasecmp(argv[i], "weight") == 0) {
			if (cmd.quenum < NUM_PRIO_QUEUES) {
				fprintf(stderr,
				    "cq: weight only for WBFQ queues "
				    "(%d-%d)\n", NUM_PRIO_QUEUES,
				    MAX_CLASS_QUEUES - 1);
				return (1);
			}
			if (++i >= argc) return (1);
			if (parse_uint32(argv[i], UINT_MAX, &v) < 0) {
				fprintf(stderr, "cq: invalid weight\n");
				return (1);
			}
			cmd.weight = v;
			cmd.cfg_flags |= CQ_WEIGHT_VALID;
			i++;
		} else if (strcasecmp(argv[i], "chshaper") == 0) {
			if (++i >= argc) return (1);
			if (strcasecmp(argv[i], "on") == 0)
				cmd.ch_shaper_en = 1;
			else if (strcasecmp(argv[i], "off") == 0)
				cmd.ch_shaper_en = 0;
			else {
				fprintf(stderr,
				    "cq chshaper: expected on|off\n");
				return (1);
			}
			cmd.cfg_flags |= CQ_SHAPER_CFG_VALID;
			i++;
		} else if (strcasecmp(argv[i], "cqshaper") == 0) {
			if (++i >= argc) return (1);
			if (strcasecmp(argv[i], "on") == 0)
				cmd.cq_shaper_on = 1;
			else if (strcasecmp(argv[i], "off") == 0)
				cmd.cq_shaper_on = 0;
			else {
				fprintf(stderr,
				    "cq cqshaper: expected on|off\n");
				return (1);
			}
			cmd.cfg_flags |= CQ_SHAPER_CFG_VALID;
			i++;
			if (i < argc &&
			    strcasecmp(argv[i], "rate") == 0) {
				if (++i >= argc) return (1);
				if (parse_uint32(argv[i], UINT_MAX,
				    &v) < 0) {
					fprintf(stderr,
					    "cq: invalid shaper rate\n");
					return (1);
				}
				cmd.shaper_rate = v;
				cmd.cfg_flags |= CQ_RATE_VALID;
				i++;
			}
		} else {
			fprintf(stderr, "cq: unknown keyword '%s'\n",
			    argv[i]);
			return (1);
		}
	}

	if (!(cmd.cfg_flags & (CQ_WEIGHT_VALID | CQ_SHAPER_CFG_VALID |
	    CQ_TDINFO_VALID))) {
		fprintf(stderr, "cq: no parameters specified\n");
		return (1);
	}

	return (send_cmd(fd, FPP_CMD_QM_CQ_CFG, &cmd, sizeof(cmd),
	    "QM_CQ_CFG"));
}

/* cmmctl qm channel <N> assign|shaper|wbfq|cq ... */
static int
qm_channel(int argc, char **argv, int fd)
{
	uint32_t chnl;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl qm channel <1-8> "
		    "assign|shaper|wbfq|cq ...\n");
		return (1);
	}

	if (parse_uint32(argv[0], MAX_CHANNELS, &chnl) < 0 || chnl == 0) {
		fprintf(stderr, "channel: number must be 1-%d\n",
		    MAX_CHANNELS);
		return (1);
	}
	/* Internally channels are 0-based */
	chnl--;

	if (strcasecmp(argv[1], "assign") == 0)
		return (qm_channel_assign(argc - 2, argv + 2, fd, chnl));
	if (strcasecmp(argv[1], "shaper") == 0)
		return (qm_channel_shaper(argc - 2, argv + 2, fd, chnl));
	if (strcasecmp(argv[1], "wbfq") == 0)
		return (qm_channel_wbfq(argc - 2, argv + 2, fd, chnl));
	if (strcasecmp(argv[1], "cq") == 0)
		return (qm_channel_cq(argc - 2, argv + 2, fd, chnl));

	fprintf(stderr, "channel: unknown sub-command '%s'\n", argv[1]);
	return (1);
}

/* ------------------------------------------------------------------ */
/* dscp-fqmap                                                         */
/* ------------------------------------------------------------------ */

/*
 * cmmctl qm dscp-fqmap <ifname> enable|disable
 * cmmctl qm dscp-fqmap <ifname> dscp <D> channel-id <C> classqueue <Q>
 * cmmctl qm dscp-fqmap <ifname> dscp <D> reset
 */
static int
qm_dscp_fqmap(int argc, char **argv, int fd)
{
	fpp_qm_dscp_chnl_clsq_map_t cmd;
	uint16_t fpp_cmd;
	uint32_t val;
	int i;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl qm dscp-fqmap <ifname> "
		    "enable|disable|dscp ...\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[0], sizeof(cmd.interface));
	i = 1;

	if (strcasecmp(argv[i], "enable") == 0) {
		cmd.status = 1;
		fpp_cmd = FPP_CMD_QM_DSCP_FQ_MAP_STATUS;
	} else if (strcasecmp(argv[i], "disable") == 0) {
		cmd.status = 0;
		fpp_cmd = FPP_CMD_QM_DSCP_FQ_MAP_STATUS;
	} else if (strcasecmp(argv[i], "dscp") == 0) {
		/* dscp <D> channel-id <C> classqueue <Q> | reset */
		if (++i >= argc) goto dscp_usage;
		if (parse_uint32(argv[i], FPP_NUM_DSCP - 1, &val) < 0) {
			fprintf(stderr, "dscp-fqmap: invalid dscp value\n");
			return (1);
		}
		cmd.dscp = (uint8_t)val;
		i++;

		if (i >= argc) goto dscp_usage;

		if (strcasecmp(argv[i], "reset") == 0) {
			fpp_cmd = FPP_CMD_QM_DSCP_FQ_MAP_RESET;
		} else if (strcasecmp(argv[i], "channel-id") == 0) {
			if (++i >= argc) goto dscp_usage;
			if (parse_uint32(argv[i], MAX_CHANNELS - 1,
			    &val) < 0) {
				fprintf(stderr,
				    "dscp-fqmap: invalid channel-id\n");
				return (1);
			}
			cmd.channel_num = (uint8_t)val;
			i++;

			if (i >= argc ||
			    strcasecmp(argv[i], "classqueue") != 0)
				goto dscp_usage;
			if (++i >= argc) goto dscp_usage;
			if (parse_uint32(argv[i], MAX_QUEUES - 1, &val) < 0) {
				fprintf(stderr,
				    "dscp-fqmap: invalid classqueue\n");
				return (1);
			}
			cmd.queue_num = (uint8_t)val;
			fpp_cmd = FPP_CMD_QM_DSCP_FQ_MAP_CFG;
		} else {
			goto dscp_usage;
		}
	} else {
		goto dscp_usage;
	}

	return (send_cmd(fd, fpp_cmd, &cmd, sizeof(cmd), "QM_DSCP_FQ_MAP"));

dscp_usage:
	fprintf(stderr,
	    "usage: cmmctl qm dscp-fqmap <ifname> enable|disable\n"
	    "       cmmctl qm dscp-fqmap <ifname> dscp <0-63> "
	    "channel-id <0-7> classqueue <0-15>\n"
	    "       cmmctl qm dscp-fqmap <ifname> dscp <0-63> reset\n");
	return (1);
}

/* ------------------------------------------------------------------ */
/* exptrate                                                           */
/* ------------------------------------------------------------------ */

/* cmmctl qm exptrate eth <pps> <burst> */
static int
qm_exptrate(int argc, char **argv, int fd)
{
	fpp_qm_expt_rate_cmd_t cmd;
	uint32_t v;

	if (argc < 3) {
		fprintf(stderr,
		    "usage: cmmctl qm exptrate eth <pps> <burst>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	if (strcasecmp(argv[0], "eth") != 0) {
		fprintf(stderr, "exptrate: only 'eth' type supported\n");
		return (1);
	}
	cmd.if_type = FPP_EXPT_TYPE_ETH;

	if (parse_uint32(argv[1], UINT_MAX, &v) < 0) {
		fprintf(stderr, "exptrate: invalid pps value\n");
		return (1);
	}
	cmd.pkts_per_sec = v;
	if (cmd.pkts_per_sec != 0 &&
	    (cmd.pkts_per_sec < QM_EXPTRATE_MINVAL ||
	    cmd.pkts_per_sec > QM_EXPTRATE_MAXVAL)) {
		fprintf(stderr,
		    "exptrate: pps must be 0 (disable) or %u-%u\n",
		    QM_EXPTRATE_MINVAL, QM_EXPTRATE_MAXVAL);
		return (1);
	}

	if (parse_uint32(argv[2], UINT_MAX, &v) < 0) {
		fprintf(stderr, "exptrate: invalid burst value\n");
		return (1);
	}
	cmd.burst_size = v;
	if (cmd.burst_size < QM_EXPTRATE_MIN_BS ||
	    cmd.burst_size > QM_EXPTRATE_MAX_BS) {
		fprintf(stderr, "exptrate: burst must be %u-%u\n",
		    QM_EXPTRATE_MIN_BS, QM_EXPTRATE_MAX_BS);
		return (1);
	}

	return (send_cmd(fd, FPP_CMD_QM_EXPT_RATE, &cmd, sizeof(cmd),
	    "QM_EXPT_RATE"));
}

/* ------------------------------------------------------------------ */
/* ffrate                                                             */
/* ------------------------------------------------------------------ */

/* cmmctl qm ffrate <ifname> cir <CIR> pir <PIR> */
static int
qm_ffrate(int argc, char **argv, int fd)
{
	fpp_qm_ff_rate_cmd_t cmd;
	uint32_t v;
	int i;

	if (argc < 5) {
		fprintf(stderr,
		    "usage: cmmctl qm ffrate <ifname> cir <CIR> pir <PIR>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[0], sizeof(cmd.interface));

	i = 1;
	if (strcasecmp(argv[i], "cir") != 0) {
		fprintf(stderr, "ffrate: expected 'cir'\n");
		return (1);
	}
	i++;
	if (parse_uint32(argv[i], UINT_MAX, &v) < 0 ||
	    v < QM_FFRATE_MIN_CIR || v > QM_FFRATE_MAX_CIR) {
		fprintf(stderr, "ffrate: cir must be %u-%u\n",
		    QM_FFRATE_MIN_CIR, QM_FFRATE_MAX_CIR);
		return (1);
	}
	cmd.cir = v;
	i++;

	if (i >= argc || strcasecmp(argv[i], "pir") != 0) {
		fprintf(stderr, "ffrate: expected 'pir'\n");
		return (1);
	}
	i++;
	if (i >= argc) {
		fprintf(stderr, "ffrate: missing pir value\n");
		return (1);
	}
	if (parse_uint32(argv[i], UINT_MAX, &v) < 0 ||
	    v < QM_FFRATE_MIN_PIR || v > QM_FFRATE_MAX_PIR) {
		fprintf(stderr, "ffrate: pir must be %u-%u\n",
		    QM_FFRATE_MIN_PIR, QM_FFRATE_MAX_PIR);
		return (1);
	}
	cmd.pir = v;

	if (cmd.pir < cmd.cir) {
		fprintf(stderr, "ffrate: pir must be >= cir\n");
		return (1);
	}

	return (send_cmd(fd, FPP_CMD_QM_FF_RATE, &cmd, sizeof(cmd),
	    "QM_FF_RATE"));
}

/* ------------------------------------------------------------------ */
/* ingress policer                                                    */
/* ------------------------------------------------------------------ */

/*
 * cmmctl qm ingress queue <0-7> policer on|off
 * cmmctl qm ingress queue <0-7> cir <CIR> pir <PIR>
 * cmmctl qm ingress reset
 */
static int
qm_ingress(int argc, char **argv, int fd)
{
	uint32_t queue_no;

	if (argc < 1) goto ingress_usage;

	if (strcasecmp(argv[0], "reset") == 0) {
		fpp_qm_ingress_policer_reset_cmd_t cmd;
		memset(&cmd, 0, sizeof(cmd));
		return (send_cmd(fd, FPP_CMD_QM_INGRESS_POLICER_RESET,
		    &cmd, sizeof(cmd), "QM_INGRESS_POLICER_RESET"));
	}

	if (strcasecmp(argv[0], "queue") != 0)
		goto ingress_usage;

	if (argc < 4) goto ingress_usage;

	if (parse_uint32(argv[1], FPP_NUM_INGRESS_POLICER_QUEUES - 1,
	    &queue_no) < 0) {
		fprintf(stderr,
		    "ingress: queue must be 0-%d\n",
		    FPP_NUM_INGRESS_POLICER_QUEUES - 1);
		return (1);
	}

	if (strcasecmp(argv[2], "policer") == 0) {
		fpp_qm_ingress_policer_enable_cmd_t cmd;

		if (argc < 4) goto ingress_usage;
		memset(&cmd, 0, sizeof(cmd));
		cmd.queue_no = (uint16_t)queue_no;

		if (strcasecmp(argv[3], "on") == 0)
			cmd.enable_flag = 1;
		else if (strcasecmp(argv[3], "off") == 0)
			cmd.enable_flag = 0;
		else
			goto ingress_usage;

		return (send_cmd(fd, FPP_CMD_QM_INGRESS_POLICER_ENABLE,
		    &cmd, sizeof(cmd), "QM_INGRESS_POLICER_ENABLE"));
	}

	if (strcasecmp(argv[2], "cir") == 0) {
		fpp_qm_ingress_policer_cfg_cmd_t cmd;
		uint32_t v;

		if (argc < 6) goto ingress_usage;
		memset(&cmd, 0, sizeof(cmd));
		cmd.queue_no = (uint16_t)queue_no;

		if (parse_uint32(argv[3], UINT_MAX, &v) < 0 ||
		    v < QM_INGRESS_MIN_CIR ||
		    v > QM_INGRESS_MAX_CIR) {
			fprintf(stderr, "ingress: cir must be %u-%u\n",
			    QM_INGRESS_MIN_CIR, QM_INGRESS_MAX_CIR);
			return (1);
		}
		cmd.cir = v;

		if (strcasecmp(argv[4], "pir") != 0)
			goto ingress_usage;

		if (parse_uint32(argv[5], UINT_MAX, &v) < 0 ||
		    v < QM_INGRESS_MIN_PIR ||
		    v > QM_INGRESS_MAX_PIR) {
			fprintf(stderr, "ingress: pir must be %u-%u\n",
			    QM_INGRESS_MIN_PIR, QM_INGRESS_MAX_PIR);
			return (1);
		}
		cmd.pir = v;

		if (cmd.pir < cmd.cir) {
			fprintf(stderr, "ingress: pir must be >= cir\n");
			return (1);
		}

		return (send_cmd(fd, FPP_CMD_QM_INGRESS_POLICER_CONFIG,
		    &cmd, sizeof(cmd), "QM_INGRESS_POLICER_CONFIG"));
	}

ingress_usage:
	fprintf(stderr,
	    "usage: cmmctl qm ingress queue <0-7> policer on|off\n"
	    "       cmmctl qm ingress queue <0-7> cir <CIR> pir <PIR>\n"
	    "       cmmctl qm ingress reset\n");
	return (1);
}

/* ------------------------------------------------------------------ */
/* show / query commands                                              */
/* ------------------------------------------------------------------ */

static void
print_rate_counters(const uint32_t *cv)
{
	printf("  Red (dropped) packets    %u\n", cv[RED_TOTAL]);
	printf("  Yellow packets           %u\n", cv[YELLOW_TOTAL]);
	printf("  Green packets            %u\n", cv[GREEN_TOTAL]);
	printf("  Recolored red            %u\n", cv[RED_RECOLORED]);
	printf("  Recolored yellow         %u\n", cv[YELLOW_RECOLORED]);
}

/* cmmctl qm show <ifname> [clearstats] */
static int
qm_show_iface(int argc, char **argv, int fd)
{
	fpp_qm_query_cmd_t qcmd;
	uint16_t resp_len;
	uint32_t ii, chnl_map;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl qm show <ifname>\n");
		return (1);
	}

	memset(&qcmd, 0, sizeof(qcmd));
	strlcpy((char *)qcmd.interface, argv[0], sizeof(qcmd.interface));

	resp_len = sizeof(qcmd);
	if (send_query(fd, FPP_CMD_QM_QUERY, &qcmd, sizeof(qcmd),
	    &qcmd, &resp_len, "QM_QUERY") != 0)
		return (1);

	if (resp_len < sizeof(qcmd)) {
		fprintf(stderr, "show: short response (%u bytes)\n", resp_len);
		return (1);
	}

	if (!qcmd.if_qos_enabled) {
		printf("Interface %s: QoS disabled\n", argv[0]);
		return (0);
	}

	printf("Interface %s: QoS enabled\n", argv[0]);

	if (qcmd.shaper_enabled)
		printf("  Port shaper: rate %u kbps, bucketsize %u\n",
		    qcmd.rate, qcmd.bsize);
	else
		printf("  Port shaper: disabled\n");

	chnl_map = 0;
	for (ii = 0; ii < MAX_CHANNELS; ii++) {
		if (!qcmd.chnl_shaper_info[ii].valid)
			continue;
		chnl_map |= (1 << ii);
		if (qcmd.chnl_shaper_info[ii].shaper_enabled)
			printf("  Channel %u: shaper rate %u kbps, "
			    "bucketsize %u\n", ii + 1,
			    qcmd.chnl_shaper_info[ii].rate,
			    qcmd.chnl_shaper_info[ii].bsize);
		else
			printf("  Channel %u: shaper disabled\n", ii + 1);
	}

	if (!chnl_map) {
		printf("  No channels assigned\n");
		return (0);
	}

	/* Query per-channel class queues */
	for (ii = 0; ii < MAX_CHANNELS; ii++) {
		uint32_t jj;
		uint32_t clear_stats = 0;

		if (!(chnl_map & (1 << ii)))
			continue;

		if (argc >= 2 && strcasecmp(argv[1], "clearstats") == 0)
			clear_stats = 1;

		for (jj = 0; jj < MAX_QUEUES; jj++) {
			fpp_qm_cq_query_cmd_t cq;
			uint64_t val;

			memset(&cq, 0, sizeof(cq));
			cq.channel_num = ii;
			cq.queuenum = jj;
			cq.clear_stats = clear_stats;

			resp_len = sizeof(cq);
			if (send_query(fd, FPP_CMD_QM_CQ_STATS, &cq,
			    sizeof(cq), &cq, &resp_len,
			    "QM_CQ_STATS") != 0)
				return (1);

			if (resp_len < sizeof(cq))
				continue;

			printf("  ---\n");
			if (jj < NUM_PQS)
				printf("  Channel %u, priority queue %u:\n",
				    ii + 1, jj);
			else
				printf("  Channel %u, WBFQ queue %u:\n",
				    ii + 1, jj);

			printf("    FQID %u (0x%x), frame count %u, "
			    "qdepth %u\n",
			    cq.fqid, cq.fqid, cq.frm_count, cq.qdepth);

			if (jj < NUM_PQS) {
				printf("    Channel queue shaper: %s\n",
				    cq.cq_ch_shaper ? "enabled" : "disabled");
			} else {
				printf("    WBFQ priority %u, weight %u\n",
				    cq.wbfq_priority, cq.weight);
				printf("    Channel queue shaper: %s\n",
				    cq.wbfq_chshaper ? "enabled" : "disabled");
			}

			val = ((uint64_t)cq.deque_pkts_high << 32) |
			    cq.deque_pkts_lo;
			printf("    Dequeue packets: %llu\n",
			    (unsigned long long)val);
			val = ((uint64_t)cq.deque_bytes_high << 32) |
			    cq.deque_bytes_lo;
			printf("    Dequeue bytes:   %llu\n",
			    (unsigned long long)val);
			val = ((uint64_t)cq.reject_pkts_high << 32) |
			    cq.reject_pkts_lo;
			printf("    Reject packets:  %llu\n",
			    (unsigned long long)val);
			val = ((uint64_t)cq.reject_bytes_high << 32) |
			    cq.reject_bytes_lo;
			printf("    Reject bytes:    %llu\n",
			    (unsigned long long)val);

			if (cq.cq_shaper_on) {
				printf("    CQ shaper: rate %u kbps\n",
				    cq.cir);
				print_rate_counters(cq.counterval);
			}
		}
	}

	return (0);
}

/* cmmctl qm show exptrate eth [clear] */
static int
qm_show_exptrate(int argc, char **argv, int fd)
{
	fpp_qm_expt_rate_cmd_t cmd;
	uint16_t resp_len;

	if (argc < 1 || strcasecmp(argv[0], "eth") != 0) {
		fprintf(stderr,
		    "usage: cmmctl qm show exptrate eth [clear]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.if_type = FPP_EXPT_TYPE_ETH;
	if (argc >= 2 && strcasecmp(argv[1], "clear") == 0)
		cmd.clear = 1;

	resp_len = sizeof(cmd);
	if (send_query(fd, FPP_CMD_QM_QUERY_EXPT_RATE, &cmd, sizeof(cmd),
	    &cmd, &resp_len, "QM_QUERY_EXPT_RATE") != 0)
		return (1);

	if (resp_len < sizeof(cmd)) {
		fprintf(stderr, "show exptrate: short response\n");
		return (1);
	}

	printf("Exception rate:  %u pps\n", cmd.pkts_per_sec);
	printf("Burst size:      %u\n", cmd.burst_size);
	print_rate_counters(cmd.counterval);

	return (0);
}

/* cmmctl qm show ffrate <ifname> [clear] */
static int
qm_show_ffrate(int argc, char **argv, int fd)
{
	fpp_qm_ff_rate_cmd_t cmd;
	uint16_t resp_len;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl qm show ffrate <ifname> [clear]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[0], sizeof(cmd.interface));
	if (argc >= 2 && strcasecmp(argv[1], "clear") == 0)
		cmd.clear = 1;

	resp_len = sizeof(cmd);
	if (send_query(fd, FPP_CMD_QM_QUERY_FF_RATE, &cmd, sizeof(cmd),
	    &cmd, &resp_len, "QM_QUERY_FF_RATE") != 0)
		return (1);

	if (resp_len < sizeof(cmd)) {
		fprintf(stderr, "show ffrate: short response\n");
		return (1);
	}

	printf("FF rate %s: CIR %u, PIR %u\n",
	    cmd.interface, cmd.cir, cmd.pir);
	print_rate_counters(cmd.counterval);

	return (0);
}

/* cmmctl qm show dscp-fqmap <ifname> */
static int
qm_show_dscp_fqmap(int argc, char **argv, int fd)
{
	fpp_qm_iface_dscp_fqid_map_cmd_t cmd;
	uint16_t resp_len;
	int i;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl qm show dscp-fqmap <ifname>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.interface, argv[0], sizeof(cmd.interface));

	resp_len = sizeof(cmd);
	if (send_query(fd, FPP_CMD_QM_QUERY_IFACE_DSCP_FQID_MAP,
	    &cmd, sizeof(cmd), &cmd, &resp_len,
	    "QM_QUERY_IFACE_DSCP_FQID_MAP") != 0)
		return (1);

	if (resp_len < sizeof(cmd)) {
		fprintf(stderr, "show dscp-fqmap: short response\n");
		return (1);
	}

	printf("DSCP-FQ map: %s\n", cmd.enable ? "enabled" : "disabled");
	if (cmd.enable) {
		for (i = 0; i < FPP_NUM_DSCP; i++) {
			if (cmd.fqid[i] == 0)
				continue;
			printf("  DSCP %2d: FQID 0x%x (profile 0x%x)\n",
			    i, (cmd.fqid[i] << 8) >> 8,
			    cmd.fqid[i] >> 24);
		}
	}

	return (0);
}

/* cmmctl qm show cq <channel> <queue> [clear] */
static int
qm_show_cq(int argc, char **argv, int fd)
{
	fpp_qm_cq_query_cmd_t cq;
	uint16_t resp_len;
	uint32_t chnl, que;
	uint64_t val;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl qm show cq <channel> <queue> [clear]\n");
		return (1);
	}

	if (parse_uint32(argv[0], MAX_CHANNELS, &chnl) < 0 || chnl == 0) {
		fprintf(stderr, "show cq: channel must be 1-%d\n",
		    MAX_CHANNELS);
		return (1);
	}
	if (parse_uint32(argv[1], MAX_QUEUES - 1, &que) < 0) {
		fprintf(stderr, "show cq: queue must be 0-%d\n",
		    MAX_QUEUES - 1);
		return (1);
	}

	memset(&cq, 0, sizeof(cq));
	cq.channel_num = chnl - 1;
	cq.queuenum = que;
	if (argc >= 3 && strcasecmp(argv[2], "clear") == 0)
		cq.clear_stats = 1;

	resp_len = sizeof(cq);
	if (send_query(fd, FPP_CMD_QM_CQ_STATS, &cq, sizeof(cq),
	    &cq, &resp_len, "QM_CQ_STATS") != 0)
		return (1);

	if (resp_len < sizeof(cq)) {
		fprintf(stderr, "show cq: short response\n");
		return (1);
	}

	printf("Channel %u, queue %u:\n", chnl, que);
	printf("  FQID %u (0x%x), frame count %u, qdepth %u\n",
	    cq.fqid, cq.fqid, cq.frm_count, cq.qdepth);

	val = ((uint64_t)cq.deque_pkts_high << 32) | cq.deque_pkts_lo;
	printf("  Dequeue packets: %llu\n", (unsigned long long)val);
	val = ((uint64_t)cq.deque_bytes_high << 32) | cq.deque_bytes_lo;
	printf("  Dequeue bytes:   %llu\n", (unsigned long long)val);
	val = ((uint64_t)cq.reject_pkts_high << 32) | cq.reject_pkts_lo;
	printf("  Reject packets:  %llu\n", (unsigned long long)val);
	val = ((uint64_t)cq.reject_bytes_high << 32) | cq.reject_bytes_lo;
	printf("  Reject bytes:    %llu\n", (unsigned long long)val);

	if (cq.cq_shaper_on) {
		printf("  CQ shaper: rate %u kbps\n", cq.cir);
		print_rate_counters(cq.counterval);
	}

	return (0);
}

/* cmmctl qm show ingress [clear] */
static int
qm_show_ingress(int argc, char **argv, int fd)
{
	fpp_qm_ingress_plcr_query_stats_cmd_t cmd;
	uint16_t resp_len;
	uint32_t ii;

	memset(&cmd, 0, sizeof(cmd));
	if (argc >= 1 && strcasecmp(argv[0], "clear") == 0)
		cmd.clear = 1;

	resp_len = sizeof(cmd);
	if (send_query(fd, FPP_CMD_QM_INGRESS_POLICER_QUERY_STATS,
	    &cmd, sizeof(cmd), &cmd, &resp_len,
	    "QM_INGRESS_POLICER_QUERY_STATS") != 0)
		return (1);

	if (resp_len < sizeof(cmd)) {
		fprintf(stderr, "show ingress: short response\n");
		return (1);
	}

	for (ii = 0; ii < FPP_NUM_INGRESS_POLICER_QUEUES; ii++) {
		struct fpp_qm_ingress_policer_info *p =
		    &cmd.policer_stats[ii];

		printf("Queue %u: policer %s\n", ii,
		    p->policer_on ? "enabled" : "disabled");
		printf("  CIR %u, PIR %u\n", p->cir, p->pir);
		if (p->policer_on)
			print_rate_counters(p->counterval);
		printf("\n");
	}

	return (0);
}

/* cmmctl qm show <sub> ... */
static int
qm_show(int argc, char **argv, int fd)
{
	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl qm show <ifname>\n"
		    "       cmmctl qm show exptrate eth [clear]\n"
		    "       cmmctl qm show ffrate <ifname> [clear]\n"
		    "       cmmctl qm show dscp-fqmap <ifname>\n"
		    "       cmmctl qm show cq <channel> <queue> [clear]\n"
		    "       cmmctl qm show ingress [clear]\n");
		return (1);
	}

	if (strcasecmp(argv[0], "exptrate") == 0)
		return (qm_show_exptrate(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "ffrate") == 0)
		return (qm_show_ffrate(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "dscp-fqmap") == 0)
		return (qm_show_dscp_fqmap(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "cq") == 0)
		return (qm_show_cq(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "ingress") == 0)
		return (qm_show_ingress(argc - 1, argv + 1, fd));

	/* Default: treat as interface name */
	return (qm_show_iface(argc, argv, fd));
}

/* ------------------------------------------------------------------ */
/* Top-level QM dispatcher                                            */
/* ------------------------------------------------------------------ */

static void
qm_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl qm <command> [args...]\n\n"
	    "Configuration:\n"
	    "  enable <ifname>              Enable QoS on interface\n"
	    "  disable <ifname>             Disable QoS on interface\n"
	    "  reset <ifname>               Reset QoS config\n"
	    "  shaper <ifname> on|off ...   Port shaper\n"
	    "  channel <N> assign|shaper|wbfq|cq ...\n"
	    "  dscp-fqmap <ifname> ...      DSCP-to-FQ mapping\n"
	    "  exptrate eth <pps> <burst>   Exception rate limit\n"
	    "  ffrate <ifname> cir <C> pir <P>  Fast-forward rate\n"
	    "  ingress queue|reset ...      Ingress policer\n\n"
	    "Query:\n"
	    "  show <ifname> [clearstats]   QoS status + queue stats\n"
	    "  show exptrate eth [clear]    Exception rate stats\n"
	    "  show ffrate <ifname> [clear] FF rate stats\n"
	    "  show dscp-fqmap <ifname>     DSCP-FQ map\n"
	    "  show cq <ch> <q> [clear]     Class queue stats\n"
	    "  show ingress [clear]         Ingress policer stats\n");
}

int
cmmctl_qm_main(int argc, char **argv, int fd)
{
	if (argc < 1) {
		qm_usage();
		return (1);
	}

	if (strcasecmp(argv[0], "enable") == 0 ||
	    strcasecmp(argv[0], "disable") == 0)
		return (qm_enable(argc, argv, fd));
	if (strcasecmp(argv[0], "reset") == 0)
		return (qm_reset(argc, argv, fd));
	if (strcasecmp(argv[0], "shaper") == 0)
		return (qm_port_shaper(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "channel") == 0)
		return (qm_channel(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "dscp-fqmap") == 0)
		return (qm_dscp_fqmap(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "exptrate") == 0)
		return (qm_exptrate(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "ffrate") == 0)
		return (qm_ffrate(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "ingress") == 0)
		return (qm_ingress(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "show") == 0)
		return (qm_show(argc - 1, argv + 1, fd));

	fprintf(stderr, "cmmctl qm: unknown command '%s'\n", argv[0]);
	qm_usage();
	return (1);
}
