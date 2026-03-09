/*
 * CDX command handler — FreeBSD port
 *
 * Minimal changes from cdx_cmdhandler.c. The compat headers handle:
 * - container_of, list_head, list_entry, list_del, list_empty
 * - spin_lock_irqsave / spin_unlock_irqrestore
 * - struct work_struct / schedule_work
 * - EXPORT_SYMBOL (no-op)
 * - __init / __exit (no-op)
 *
 * The main functional change: comcerto_fpp_send_command is now the
 * local dispatch function (CDX is not an EXPORT_SYMBOL provider for
 * FCI; instead CDX registers with FCI via fci_register_send_command).
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "cdx.h"

/* FCI registration API (from fci_freebsd.h) */
extern void fci_register_send_command(
    int (*fn)(uint16_t, uint16_t, uint16_t *, uint16_t *, uint16_t *));

/* Forward declarations for exported functions */
static int cdx_send_command(uint16_t fcode, uint16_t length,
    uint16_t *payload, uint16_t *rlen, uint16_t *rbuf);
int comcerto_fpp_send_command(u16 fcode, u16 length, u16 *payload,
    u16 *rlen, u16 *rbuf);
int comcerto_fpp_send_command_simple(u16 fcode, u16 length, u16 *payload);
int comcerto_fpp_send_command_atomic(u16 fcode, u16 length, u16 *payload,
    void (*callback)(unsigned long, int, u16, u16 *), unsigned long data);
int comcerto_fpp_register_event_cb(int (*event_cb)(u16, u16, u16 *));
int cdx_ctrl_send_command_simple(u16 fcode, u16 length, u16 *payload);

CmdProc gCmdProcTable[EVENT_MAX];

int
FCODE_TO_EVENT(U32 fcode)
{
	int eventid;

	switch ((fcode & 0xFF00) >> 8) {
	case FC_RX:
		if (fcode >= L2BRIDGE_FIRST_COMMAND &&
		    fcode <= L2BRIDGE_LAST_COMMAND)
			eventid = EVENT_BRIDGE;
		else
			eventid = EVENT_PKT_RX;
		break;
	case FC_IPV4: eventid = EVENT_IPV4; break;
	case FC_IPV6: eventid = EVENT_IPV6; break;
	case FC_QM: eventid = EVENT_QM; break;
	case FC_TX: eventid = EVENT_PKT_TX; break;
	case FC_PPPOE: eventid = EVENT_PPPOE; break;
	case FC_MC:
		if (fcode <= CMD_MC4_RESET)
			eventid = EVENT_MC4;
		else
			eventid = EVENT_MC6;
		break;
	case FC_RTP: eventid = EVENT_RTP_RELAY; break;
	case FC_VLAN: eventid = EVENT_VLAN; break;
	case FC_IPSEC: eventid = EVENT_IPS_IN; break;
	case FC_TRC: eventid = EVENT_IPS_OUT; break;
	case FC_TNL: eventid = EVENT_TNL_IN; break;
	case FC_MACVLAN: eventid = EVENT_MACVLAN; break;
	case FC_STAT: eventid = EVENT_STAT; break;
	case FC_ALTCONF: eventid = EVENT_IPV4; break;
	case FC_WIFI_RX: eventid = EVENT_PKT_WIFIRX; break;
	case FC_NATPT: eventid = EVENT_NATPT; break;
	case FC_PKTCAP: eventid = EVENT_PKTCAP; break;
	case FC_FPPDIAG: eventid = EVENT_IPV4; break;
	case FC_ICC: eventid = EVENT_ICC; break;
	case FC_L2TP: eventid = EVENT_L2TP; break;
	case FC_LAGG: eventid = EVENT_LAGG; break;
	default: eventid = -1; break;
	}

	return (eventid);
}

void
cdx_cmd_handler(U16 fcode, U16 length, U16 *payload, U16 *rlen, U16 *rbuf)
{
	CmdProc cmdproc;
	int eventid;

	if (length > FPP_MAX_MSG_LENGTH) {
		rbuf[0] = ERR_WRONG_COMMAND_SIZE;
		*rlen = 2;
		return;
	}

	eventid = FCODE_TO_EVENT(fcode);

	if (fcode == CMD_VOICE_BUFFER_RESET) {
		rbuf[0] = NO_ERR;
		*rlen = 2;
	} else if (eventid >= 0 && eventid < EVENT_MAX &&
	    (cmdproc = gCmdProcTable[eventid]) != NULL) {
		memcpy(rbuf, payload, length);
		*rlen = (*cmdproc)(fcode, length, rbuf);
		if (*rlen > FPP_MAX_MSG_LENGTH) {
			DPA_ERROR("%s: handler fcode 0x%x returned rlen %u, "
			    "clamped to %u\n", __func__, fcode,
			    *rlen, FPP_MAX_MSG_LENGTH);
			*rlen = FPP_MAX_MSG_LENGTH;
		}
		if (*rlen == 0) {
			rbuf[0] = NO_ERR;
			*rlen = 2;
		}
	} else {
		rbuf[0] = ERR_UNKNOWN_COMMAND;
		*rlen = 2;
	}

	if (rbuf[0] != NO_ERR)
		DPRINT("rbuf[0]=0x%04x, *rlen=%d\n", rbuf[0], *rlen);
}

#define CMD_DECLARE(xx)		\
static int xx##_init_flag = 0;	\
int xx##_init(void);		\
void xx##_exit(void);

#define CMD_INIT(xx) do {	\
	rc = xx##_init();	\
	if (rc < 0)		\
		goto exit;	\
	xx##_init_flag = 1;	\
} while (0)

#define CMD_EXIT(xx) do {	\
	if (xx##_init_flag)	\
		xx##_exit();	\
	xx##_init_flag = 0;	\
} while (0)

CMD_DECLARE(tx)
CMD_DECLARE(rx)
CMD_DECLARE(pppoe)
CMD_DECLARE(vlan)
CMD_DECLARE(ipv4)
CMD_DECLARE(ipv6)
CMD_DECLARE(socket)
CMD_DECLARE(tunnel)
CMD_DECLARE(natpt)
CMD_DECLARE(bridge)
CMD_DECLARE(qm)
CMD_DECLARE(statistics)
#ifdef DPA_IPSEC_OFFLOAD
CMD_DECLARE(ipsec)
#endif
#ifdef WIFI_ENABLE
CMD_DECLARE(wifi)
#endif
CMD_DECLARE(mc4)
CMD_DECLARE(mc6)
CMD_DECLARE(rtp_relay)
CMD_DECLARE(pktcap)
CMD_DECLARE(lagg)

int
cdx_cmdhandler_init(void)
{
	int rc = 0;

	CMD_INIT(tx);
	CMD_INIT(rx);
	CMD_INIT(pppoe);
	CMD_INIT(vlan);
	CMD_INIT(lagg);
	CMD_INIT(ipv4);
	CMD_INIT(ipv6);
	CMD_INIT(socket);
	CMD_INIT(tunnel);
	CMD_INIT(natpt);
	CMD_INIT(bridge);
	CMD_INIT(qm);
	CMD_INIT(statistics);
#ifdef DPA_IPSEC_OFFLOAD
	CMD_INIT(ipsec);
#endif
#ifdef WIFI_ENABLE
	CMD_INIT(wifi);
#endif
	CMD_INIT(mc4);
	CMD_INIT(mc6);
	CMD_INIT(rtp_relay);
	CMD_INIT(pktcap);

	/* Register CDX command handler with FCI module */
	fci_register_send_command(cdx_send_command);

exit:
	return (rc);
}

void
cdx_cmdhandler_exit(void)
{
	CMD_EXIT(pktcap);
	CMD_EXIT(rtp_relay);
	CMD_EXIT(mc6);
	CMD_EXIT(mc4);
#ifdef DPA_IPSEC_OFFLOAD
	CMD_EXIT(ipsec);
#endif
#ifdef WIFI_ENABLE
	CMD_EXIT(wifi);
#endif
	CMD_EXIT(statistics);
	CMD_EXIT(qm);
	CMD_EXIT(bridge);
	CMD_EXIT(natpt);
	CMD_EXIT(tunnel);
	CMD_EXIT(socket);
	CMD_EXIT(ipv6);
	CMD_EXIT(ipv4);
	CMD_EXIT(lagg);
	CMD_EXIT(vlan);
	CMD_EXIT(pppoe);
	CMD_EXIT(rx);
	CMD_EXIT(tx);
}

/*
 * comcerto_fpp_send_command — synchronous command dispatch.
 *
 * On FreeBSD, this is called both internally by CDX and by FCI
 * (via the registered function pointer). It takes the ctrl mutex,
 * dispatches the command, and returns.
 */
static int
cdx_send_command(uint16_t fcode, uint16_t length,
    uint16_t *payload, uint16_t *rlen, uint16_t *rbuf)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	mutex_lock(&ctrl->mutex);
	cdx_cmd_handler(fcode, length, payload, rlen, rbuf);
	mutex_unlock(&ctrl->mutex);

	return (0);
}

/*
 * Legacy name for internal callers.
 */
int
comcerto_fpp_send_command(u16 fcode, u16 length, u16 *payload,
    u16 *rlen, u16 *rbuf)
{
	return (cdx_send_command(fcode, length, payload, rlen, rbuf));
}

int
comcerto_fpp_send_command_simple(u16 fcode, u16 length, u16 *payload)
{
	u16 rbuf[128];
	u16 rlen;
	int rc;

	rc = comcerto_fpp_send_command(fcode, length, payload, &rlen, rbuf);
	if (rc < 0)
		return (rc);
	return (rbuf[0]);
}

void
comcerto_fpp_workqueue(struct work_struct *work)
{
	struct _cdx_ctrl *ctrl = container_of(work, struct _cdx_ctrl, work);
	struct fpp_msg *msg;
	unsigned long flags;
	u16 rbuf[128];
	u16 rlen;
	int rc;

	spin_lock_irqsave(&ctrl->lock, flags);

	while (!list_empty(&ctrl->msg_list)) {
		msg = list_entry(ctrl->msg_list.next, struct fpp_msg, list);
		list_del(&msg->list);
		spin_unlock_irqrestore(&ctrl->lock, flags);

		rc = comcerto_fpp_send_command(msg->fcode, msg->length,
		    msg->payload, &rlen, rbuf);

		if (msg->callback != NULL)
			msg->callback(msg->data, rc, rlen, rbuf);

		kfree(msg);

		spin_lock_irqsave(&ctrl->lock, flags);
	}

	spin_unlock_irqrestore(&ctrl->lock, flags);
}

int
comcerto_fpp_send_command_atomic(u16 fcode, u16 length, u16 *payload,
    void (*callback)(unsigned long, int, u16, u16 *), unsigned long data)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	struct fpp_msg *msg;
	unsigned long flags;

	if (length > FPP_MAX_MSG_LENGTH)
		return (-EINVAL);

	msg = kmalloc(sizeof(struct fpp_msg) + length, GFP_ATOMIC);
	if (!msg)
		return (-ENOMEM);

	msg->callback = callback;
	msg->data = data;
	msg->payload = (u16 *)(msg + 1);
	msg->fcode = fcode;
	msg->length = length;
	memcpy(msg->payload, payload, length);

	spin_lock_irqsave(&ctrl->lock, flags);
	list_add(&msg->list, &ctrl->msg_list);
	spin_unlock_irqrestore(&ctrl->lock, flags);

	schedule_work(&ctrl->work);

	return (0);
}

/*
 * Register CDX's command handler with FCI.
 *
 * Called from cdx_cmdhandler_init or cdx_main_freebsd.c at module load.
 */
int
comcerto_fpp_register_event_cb(int (*event_cb)(u16, u16, u16 *))
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	ctrl->event_cb = event_cb;
	return (0);
}

int
cdx_ctrl_send_command_simple(u16 fcode, u16 length, u16 *payload)
{
	u16 rbuf[128];
	u16 rlen;

	comcerto_fpp_send_command(fcode, length, payload, &rlen, rbuf);
	return (rbuf[0]);
}
