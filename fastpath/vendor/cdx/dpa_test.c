/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                dpa_test.c     
 * @description         test code to add connections
 */

#include <linux/device.h>
#include "linux/ioctl.h"
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fdtable.h>

#include "portdefs.h"
#include "misc.h"
#include "lnxwrp_fm.h"
#include "layer2.h"
#include "cdx.h"
#include "control_ipv4.h"
#include "dpa_control_mc.h"

//#define DPA_TEST_DEBUG 1

#define EGRESS_PORTNAME_LEN	32
enum flow_id
{
	FWD_FLOW_IDENTIFIER,
	REV_FLOW_IDENTIFIER,
	MAX_IDENTIFIERS
};


int mcast_grpd;

int cdx_ioc_create_mc_group(unsigned long args)
{
	printk("%s::not implemented\n", __FUNCTION__);
	return -1;
}


int cdx_ioc_add_member_to_group(unsigned long args)
{
	printk("%s::not implemented\n", __FUNCTION__);
	return -1;
}

int cdx_ioc_add_mcast_table_entry(unsigned long args)
{
	return -1;
}

int cdx_ioc_dpa_connadd(unsigned long args)
{
	struct add_conn_info add_conn;
	int retval;
	uint32_t ii;
	struct test_conn_info *conn_info;
	struct _tCtEntry *ct;
	RouteEntry *rt;
	struct _tCtEntry *ct_entry;
	RouteEntry *rt_entry;

	if (copy_from_user(&add_conn, (void *)args,
				sizeof(struct add_conn_info))) {
		DPA_ERROR("%s::Read uspace args failed\n", __FUNCTION__);
		return -EBUSY;
	}
	retval = 0;
	ct = NULL;
	rt = NULL;
	conn_info = (struct test_conn_info *) 
		kzalloc ((sizeof(struct test_conn_info) * add_conn.num_conn),
				0);
	if (!conn_info) {
		DPA_ERROR("%s::mem alloc for conn info failed\n", 
				__FUNCTION__);
		retval = -ENOMEM;	
		goto err_ret;

	}
	if (copy_from_user(conn_info, add_conn.conn_info,
				(sizeof(struct test_conn_info) * add_conn.num_conn))) {
		DPA_ERROR("%s::Read uspace args failed\n",
				__FUNCTION__);
		retval = -EIO;
		goto err_ret;
	}
	ct = kzalloc((sizeof(struct _tCtEntry) * 2), 0);
	if (!ct) {
		retval = -ENOMEM;	
		goto err_ret;
	}
	rt = kzalloc((sizeof(RouteEntry) * 2), 0);
	if (!rt) {
		retval = -ENOMEM;	
		goto err_ret;
	}
#ifdef DPA_TEST_DEBUG
	DPA_INFO("%s::adding %d connections\n", __FUNCTION__, add_conn.num_conn);
#endif
	for (ii = 0; ii < add_conn.num_conn; ii++) {
		char port_name[EGRESS_PORTNAME_LEN];
		POnifDesc onif_desc;
		uint32_t nat_op;

		if ((conn_info->fwd_flow.sport != conn_info->rev_flow.dport) ||
				(conn_info->fwd_flow.dport != conn_info->rev_flow.sport) ||
				(conn_info->fwd_flow.ipv4_saddr != 
				 conn_info->rev_flow.ipv4_daddr) ||
				(conn_info->fwd_flow.ipv4_daddr != 
				 conn_info->rev_flow.ipv4_saddr))
			nat_op = CONNTRACK_NAT;
		else
			nat_op = 0;

		ct_entry = ct;
		rt_entry = rt;

		//fill fwd flow entry
		ct_entry->status = 
			(conn_info->flags | CONNTRACK_ORIG);

		ct_entry->proto = conn_info->proto;
		ct_entry->Sport = htons(conn_info->fwd_flow.sport);
		ct_entry->Dport = htons(conn_info->fwd_flow.dport);
		ct_entry->Saddr_v4 = htonl(conn_info->fwd_flow.ipv4_saddr);
		ct_entry->Daddr_v4 = htonl(conn_info->fwd_flow.ipv4_daddr);
		ct_entry->twin = (ct_entry + 1);
		ct_entry->twin_Sport = htons(conn_info->rev_flow.sport);
		ct_entry->twin_Dport = htons(conn_info->rev_flow.dport);
		ct_entry->twin_Saddr = htonl(conn_info->rev_flow.ipv4_saddr);
		ct_entry[FWD_FLOW_IDENTIFIER].twin_Daddr = 						htonl(conn_info->rev_flow.ipv4_daddr);
		ct_entry->pRtEntry = rt_entry;
		memcpy(&rt_entry->dstmac[0], conn_info->fwd_flow.dest_mac, 
				ETHER_ADDR_LEN);
		rt_entry->mtu = conn_info->fwd_flow.mtu;
		retval = strncpy_from_user(&port_name[0],
				conn_info->fwd_flow.egress_port, EGRESS_PORTNAME_LEN);
		if (retval == -EFAULT) {
			DPA_ERROR("%s::unable to read fwd flow egress port\n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}
		onif_desc = get_onif_by_name(&port_name[0]); 
		if (!onif_desc) {
			DPA_ERROR("%s::unable to get onif for iface %s\n",
					__FUNCTION__, &port_name[0]);
			retval = -EIO;
			goto err_ret;
		}
		rt_entry->itf = onif_desc->itf;
		retval = strncpy_from_user(&port_name[0],
				conn_info->fwd_flow.ingress_port, EGRESS_PORTNAME_LEN);
		if (retval == -EFAULT) {
			DPA_ERROR("%s::unable to read fwd flow ingress port\n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}
		if(!rt_entry->input_itf)
		{
			DPA_ERROR("%s::NULL input interface \n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}

		ct_entry->inPhyPortNum = rt_entry->input_itf->index;
		ct_entry->status |= nat_op;

		//fill rev flow entra
		rt_entry++;
		ct_entry++;
		rt_entry->mtu = conn_info->fwd_flow.mtu;
		ct_entry->proto = conn_info->proto;
		ct_entry->status = conn_info->flags;
		ct_entry->Sport = htons(conn_info->rev_flow.sport);
		ct_entry->Dport = htons(conn_info->rev_flow.dport);
		ct_entry->Saddr_v4 = htonl(conn_info->rev_flow.ipv4_saddr);
		ct_entry->Daddr_v4 = htonl(conn_info->rev_flow.ipv4_daddr);
		ct_entry->twin = (ct_entry - 1);
		ct_entry->twin_Sport = 
			htons(conn_info->fwd_flow.sport);
		ct_entry->twin_Dport = 
			htons(conn_info->fwd_flow.dport);
		ct_entry->twin_Saddr = 
			htonl(conn_info->fwd_flow.ipv4_saddr);
		ct_entry->twin_Daddr = 
			htonl(conn_info->fwd_flow.ipv4_daddr);

		ct_entry->pRtEntry = rt_entry;
		memcpy(&rt_entry->dstmac[0], conn_info->rev_flow.dest_mac, 
				ETHER_ADDR_LEN);
		rt_entry->mtu = conn_info->rev_flow.mtu;

		retval = strncpy_from_user(&port_name[0],
				conn_info->rev_flow.egress_port, EGRESS_PORTNAME_LEN);
		if (retval == -EFAULT) {
			DPA_ERROR("%s::unable to read rev flow egress port\n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}
		onif_desc = get_onif_by_name(&port_name[0]); 
		if (!onif_desc) {
			DPA_ERROR("%s::unable to get onif for iface %s\n",
					__FUNCTION__, &port_name[0]);
			retval = -EIO;
			goto err_ret;
		}
		rt_entry->itf = onif_desc->itf;
		retval = strncpy_from_user(&port_name[0],
				conn_info->rev_flow.ingress_port, EGRESS_PORTNAME_LEN);
		if (retval == -EFAULT) {
			DPA_ERROR("%s::unable to read rev flow ingress port\n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}
		if(!rt_entry->input_itf)
		{
			DPA_ERROR("%s::NULL input interface \n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}

		ct_entry->inPhyPortNum = rt_entry->input_itf->index;
		ct_entry->status |= nat_op;
		//insert forward entry
		if (insert_entry_in_classif_table((ct_entry - 1))) {
			DPA_ERROR("%s::failed to insert forward entry\n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}
#ifdef DPA_TEST_DEBUG
		DPA_INFO("%s::inserted forward entry\n", __FUNCTION__);
#endif
		//insert reply/reverse entry
		if (insert_entry_in_classif_table(ct_entry)) {
			DPA_ERROR("%s::unable to repl entry\n",
					__FUNCTION__);
			retval = -EIO;
			goto err_ret;
		}
#ifdef DPA_TEST_DEBUG
		DPA_INFO("%s::inserted reverse entry\n", __FUNCTION__);
#endif
	}
err_ret:
	if (ct)
		kfree(ct);
	if (rt)
		kfree(rt);
	if (conn_info)
		kfree(conn_info);
	return retval;

}
