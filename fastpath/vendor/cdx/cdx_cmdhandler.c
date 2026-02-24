/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include "cdx.h"

CmdProc gCmdProcTable[EVENT_MAX];

int FCODE_TO_EVENT(U32 fcode)
{
	int eventid;
	switch((fcode & 0xFF00) >> 8)
	{
		case FC_RX:
			if (fcode >= L2BRIDGE_FIRST_COMMAND && fcode <= L2BRIDGE_LAST_COMMAND)
				eventid = EVENT_BRIDGE;
			else
				eventid = EVENT_PKT_RX;
			break;

		case FC_IPV4: eventid = EVENT_IPV4; break;

		case FC_IPV6: eventid = EVENT_IPV6; break;

		case FC_QM: eventid = EVENT_QM; break;

		case FC_TX: eventid = EVENT_PKT_TX; break;

		case FC_PPPOE: eventid = EVENT_PPPOE; break;

		case FC_MC: if(fcode <= CMD_MC4_RESET)
									eventid = EVENT_MC4;
								else 
									eventid = EVENT_MC6;             
								break;

		case FC_RTP: eventid = EVENT_RTP_RELAY; break;

		case FC_VLAN: eventid = EVENT_VLAN; break;

		case FC_IPSEC: eventid = EVENT_IPS_IN; break;

		case FC_TRC: eventid = EVENT_IPS_OUT; break;

		case FC_TNL:eventid = EVENT_TNL_IN; break;

		case FC_MACVLAN: eventid = EVENT_MACVLAN; break;

		case FC_STAT: eventid = EVENT_STAT; break;

		case FC_ALTCONF: eventid = EVENT_IPV4; break;

		case FC_WIFI_RX: eventid = EVENT_PKT_WIFIRX; break;

		case FC_NATPT: eventid = EVENT_NATPT; break;

		case FC_PKTCAP: eventid = EVENT_PKTCAP; break;

		case FC_FPPDIAG: eventid = EVENT_IPV4; break;

		case FC_ICC: eventid = EVENT_ICC; break;

		case FC_L2TP: eventid = EVENT_L2TP; break;

		default: eventid = -1; break;
	}

	return eventid;
}

void cdx_cmd_handler(U16 fcode, U16 length, U16 *payload, U16 *rlen, U16 *rbuf)
{
	CmdProc cmdproc;
	int eventid;

	eventid = FCODE_TO_EVENT(fcode);
#ifdef CDX_DEBUG_ENABLE
	DPRINT("fcode=0x%04x, length=%d\n", fcode, length);
	print_hex_dump(KERN_DEBUG, "cmd: ", DUMP_PREFIX_NONE, 16, 1, payload, length, 1);
#endif
/////////////////////////////////////////////////////////////////////////////
	// TEMP code to satisfy CMM
	if (fcode == CMD_VOICE_BUFFER_RESET)
	{
		rbuf[0] = NO_ERR;
		*rlen = 2;
	}
	else
/////////////////////////////////////////////////////////////////////////////
	if (eventid >= 0 && (cmdproc = gCmdProcTable[eventid]) != NULL)
	{
		memcpy(rbuf, payload, length);
		*rlen = (*cmdproc)(fcode, length, rbuf);
		if (*rlen == 0)
		{
			rbuf[0] = NO_ERR;
			*rlen = 2;
		}
	}
	else
	{
		rbuf[0] = ERR_UNKNOWN_COMMAND;
		*rlen = 2;
	}
	if (rbuf[0] != NO_ERR)
		DPRINT("rbuf[0]=0x%04x, *rlen=%d\n", rbuf[0], *rlen);
}

#define CMD_DECLARE(xx)		\
static BOOL xx##_init_flag = 0;	\
int xx##_init(void);		\
void xx##_exit(void);		\

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
#ifdef CDX_TODO
CMD_DECLARE(pktcap)
CMD_DECLARE(l2tp)
#endif

int __init cdx_cmdhandler_init(void)
{
	int rc = 0;

	CMD_INIT(tx);
	CMD_INIT(rx);
	CMD_INIT(pppoe);
	CMD_INIT(vlan);
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
#ifdef CDX_TODO
	CMD_INIT(pktcap);
#ifdef WIFI_ENABLE
	CMD_INIT(wifi);
#endif
	CMD_INIT(l2tp);
#endif

exit:
	return rc;
}

void __exit cdx_cmdhandler_exit(void)
{
	DPRINT("\n");

	// EXIT routines must be in reverse order from the INIT routines

#ifdef CDX_TODO
	CMD_EXIT(pktcap);
	CMD_EXIT(l2tp);
#endif
	CMD_EXIT(rtp_relay);
	CMD_EXIT(mc6);
	CMD_EXIT(mc4);
#ifdef WIFI_ENABLE
	CMD_EXIT(wifi);
#endif
#ifdef DPA_IPSEC_OFFLOAD 
	CMD_EXIT(ipsec);
#endif
	CMD_EXIT(statistics);
	CMD_EXIT(qm);
	CMD_EXIT(bridge);
	CMD_EXIT(natpt);
	CMD_EXIT(tunnel);
	CMD_EXIT(socket);
	CMD_EXIT(ipv6);
	CMD_EXIT(ipv4);
	CMD_EXIT(vlan);
	CMD_EXIT(pppoe);
	CMD_EXIT(rx);
	CMD_EXIT(tx);
}

int comcerto_fpp_send_command(u16 fcode, u16 length, u16 *payload, u16 *rlen, u16 *rbuf)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	mutex_lock(&ctrl->mutex);

	cdx_cmd_handler(fcode, length, payload, rlen, rbuf);

	mutex_unlock(&ctrl->mutex);

	return 0;
}
EXPORT_SYMBOL(comcerto_fpp_send_command);

/**
 * comcerto_fpp_send_command_simple - 
 *
 *	This function is used to send command to FPP in a synchronous way. Calls to the function blocks until a response
 *	from FPP is received. This API can not be used to query data from FPP
 *	
 * Parameters
 *	fcode:		Function code. FPP function code associated to the specified command payload
 *	length:		Command length. Length in bytes of the command payload
 *	payload:	Command payload. Payload of the command sent to the FPP. 16bits buffer allocated by the client's code and sized up to 256 bytes
 *
 * Return values
 *	0:	Success
 *	<0:	Linux system failure (check errno for detailed error condition)
 *	>0:	FPP returned code
 */
int comcerto_fpp_send_command_simple(u16 fcode, u16 length, u16 *payload)
{
	u16 rbuf[128];
	u16 rlen;
	int rc;

	rc = comcerto_fpp_send_command(fcode, length, payload, &rlen, rbuf);

	/* if a command delivery error is detected, do not check command returned code */
	if (rc < 0)
		return rc;

	/* retrieve FPP command returned code. Could be error or acknowledgment */
	rc = rbuf[0];

	return rc;
}
EXPORT_SYMBOL(comcerto_fpp_send_command_simple);


void comcerto_fpp_workqueue(struct work_struct *work)
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

		rc = comcerto_fpp_send_command(msg->fcode, msg->length, msg->payload, &rlen, rbuf);

		/* send command response to caller's callback */
		if (msg->callback != NULL)
			msg->callback(msg->data, rc, rlen, rbuf);

		kfree(msg);

		spin_lock_irqsave(&ctrl->lock, flags);
	}

	spin_unlock_irqrestore(&ctrl->lock, flags);
}

/**
 * comcerto_fpp_send_command_atomic -
 *
 *	This function is used to send command to FPP in an asynchronous way. The Caller specifies a function pointer
 *	that is called by the FPP Comcerto driver when command reponse from FPP engine is received. This API can be also
 *	used to query data from FPP. Queried data are returned through the specified client's callback function
 *
 * Parameters
 *	fcode:		Function code. FPP function code associated to the specified command payload
 *	length:		Command length. Length in bytes of the command payload
 *	payload:	Command payload. Payload of the command sent to the FPP. 16bits buffer allocated by the client's code and sized up to 256 bytes
 *	callback:	Client's callback handler for FPP response processing
 *	data:		Client's private data. Not interpreted by the FPP driver and sent back to the Client as a reference (client's code own usage)
 *
 * Return values
 *	0:	Success
 *	<0:	Linux system failure (check errno for detailed error condition)
 **/
int comcerto_fpp_send_command_atomic(u16 fcode, u16 length, u16 *payload, void (*callback)(unsigned long, int, u16, u16 *), unsigned long data)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	struct fpp_msg *msg;
	unsigned long flags;
	int rc;

	if (length > FPP_MAX_MSG_LENGTH) {
		rc = -EINVAL;
		goto err0;
	}

	msg = kmalloc(sizeof(struct fpp_msg) + length, GFP_ATOMIC);
	if (!msg) {
		rc = -ENOMEM;
		goto err0;
	}

	/* set caller's callback function */
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

	return 0;

err0:
	return rc;
}

EXPORT_SYMBOL(comcerto_fpp_send_command_atomic);


int cdx_ctrl_send_command_simple(u16 fcode, u16 length, u16 *payload)
{
	u16 rbuf[128];
	u16 rlen;
	int rc;

	/* send command to FE */
	comcerto_fpp_send_command(fcode, length, payload, &rlen, rbuf);

	/* retrieve FE command returned code. Could be error or acknowledgment */
	rc = rbuf[0];

	return rc;
}


/**
 * comcerto_fpp_register_event_cb -
 *
 */
int comcerto_fpp_register_event_cb(int (*event_cb)(u16, u16, u16*))
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	/* register FCI callback used for asynchrounous event */
	ctrl->event_cb = event_cb;

	return 0;
}
EXPORT_SYMBOL(comcerto_fpp_register_event_cb);



