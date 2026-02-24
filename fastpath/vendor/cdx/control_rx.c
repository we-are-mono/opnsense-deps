/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "cdx.h"
#include "control_rx.h"

static U16 M_rx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U32  portid;
	U16 acklen;
	U16 ackstatus;
	U8 enable;

	acklen = 2;
	ackstatus = CMD_OK;

	switch (cmd_code)
	{
	case CMD_RX_ENABLE:
		portid = (U8)*pcmd;
		if (portid >= GEM_PORTS) {
			ackstatus = CMD_ERR;
			break;
		}
		break;

	case CMD_RX_DISABLE:
		portid = (U8)*pcmd;
		if (portid >= GEM_PORTS) {
			ackstatus = CMD_ERR;
			break;
		}
		break;

	case CMD_RX_LRO:
		enable = (U8)*pcmd;
		if (enable > 0)
			ackstatus = CMD_ERR;

		break;

	default:
		ackstatus = CMD_ERR;
		break;
	}

	*pcmd = ackstatus;
	return acklen;
}


int rx_init(void)
{
	set_cmd_handler(EVENT_PKT_RX, M_rx_cmdproc);

	ff_enable = 1;

	return 0;
}

void rx_exit(void)
{
}
