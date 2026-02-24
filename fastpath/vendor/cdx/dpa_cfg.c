/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/**
 * @file                dpa_cfg.c
 * @description         dpa configuration routines.
 */
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
//#include <linux/fsl_dpa_classifier.h>
#include "dpaa_eth.h"

#include "cdx.h"
#include "portdefs.h"
#include "misc.h"
#include "lnxwrp_fm.h"
#include "cdx_ceetm_gdef.h"

//#define DPA_CFG_DEBUG 	1

//number of Frame managers used
static uint32_t num_fmans;
//pointer to Frame manager info array
struct cdx_fman_info *fman_info;
//frame queue list created
static struct dpa_fq *dpa_pcd_fq;
//ipr info received via ioctl
struct cdx_ipr_info ipr_info;

#ifdef DPA_CFG_DEBUG
//show port related info
static void display_port_info(struct cdx_port_info *pinfo)
{
	uint32_t ii;

	printk("------------------------------------\n");
	printk("port		\t%s\n", pinfo->name);
	printk("fmindex		\t%d\n", pinfo->fm_index);
	printk("pindex		\t%d\n", pinfo->index);
	printk("portid		\t%d\n", pinfo->portid);
	printk("type		\t%dG\n", pinfo->type);
	printk("max_dist	\t%d\n", pinfo->max_dist);
	if (pinfo->max_dist) {
		struct cdx_dist_info *dist_info;
		dist_info = pinfo->dist_info;
		printk("distributions\n");
		for (ii = 0; ii < pinfo->max_dist; ii++) {
			printk("handle		\t%p\n", dist_info->handle);
			printk("type		\t%d\n", dist_info->type);
			printk("fq_base		\t%x(%d)\n", dist_info->base_fqid,
					dist_info->base_fqid);
			printk("fq_count	\t%d\n", dist_info->count);
			printk("dist_type	\t%d\n", dist_info->type);
			dist_info++;
		}
	}
}

//display classif table info
static void display_tbl_info(struct table_info *tinfo)
{
	printk("===================================\n");
	printk("table		\t%s\n", tinfo->name);
	printk("dpa_type	\t%d\n", tinfo->dpa_type);
	printk("type		\t%d\n", tinfo->type);
#if 0
	switch (tinfo->dpa_type) {
		case DPA_CLS_TBL_EXACT_MATCH:
			printk("num keys	\t%d\n", tinfo->num_keys);
			break;
		case DPA_CLS_TBL_EXTERNAL_HASH:
		case DPA_CLS_TBL_INTERNAL_HASH:
			printk("num sets 	\t%d\n", tinfo->num_sets);
			printk("num ways 	\t%d\n", tinfo->num_ways);
			break;
	}
#endif
	printk("port idx 	\t%x\n", tinfo->port_idx);
	printk("key size	\t%d\n", tinfo->key_size);
	printk("handle		\t%p\n", tinfo->id);
	//printk("table desc	\t%d\n", tinfo->td);
}

//display entire dpa configuration, ports, tables, dist etc
static void display_dpa_cfg(void)
{	
	uint32_t ii;
	uint32_t jj;
	struct cdx_fman_info *finfo;

	finfo = fman_info;	
	printk("num fm		\t%d\n", num_fmans);
	for (ii = 0; ii < num_fmans; ii++)  {
		struct cdx_port_info *pinfo;
		struct table_info *tinfo;

		printk(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		printk("fm index	\t%d\n", finfo->index);
		printk("max ports	\t%d\n", finfo->max_ports);
		printk("num tables	\t%d\n", finfo->num_tables);
		printk("fm handle 	\t%p\n", finfo->fm_handle);
		printk("pcd handle 	\t%p\n", finfo->pcd_handle);
		pinfo = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			display_port_info(pinfo);
			pinfo++;
		}
		tinfo = finfo->tbl_info;
		for (jj = 0; jj < finfo->num_tables; jj++) {
			display_tbl_info(tinfo);
			tinfo++;
		}
		finfo++;
	}
}
#else
#define display_dpa_cfg()
#endif

int  get_tableInfo_by_portid( int fm_index, int portid,  void **td,  int * flags) 
{
	uint32_t jj;
	struct cdx_fman_info *finfo;
	struct table_info *tinfo;

	finfo = &fman_info[fm_index];	
	tinfo = finfo->tbl_info;
	for (jj = 0; jj < finfo->num_tables; jj++) {
		if(tinfo->port_idx  == (1<< portid))
		{
			td[tinfo->type] = tinfo->id ;
			*flags |= (1 << tinfo->type);
		}
		tinfo++;
	}
	return 0;
}

//release all configuration releated resources
static void release_cfg_info(void)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;
	uint32_t jj;

	if (!fman_info)
		return;
	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		//free port information for this fman
		if (finfo->portinfo) {
			struct cdx_port_info *port_info;
			port_info = finfo->portinfo;
			for (jj = 0; jj < finfo->max_ports; jj++) {
				if (port_info->dist_info)
					kfree(port_info->dist_info);
				port_info++;
			}
			kfree(finfo->portinfo);
		}
		//free cc table information for this fman
		if (finfo->tbl_info) {
			kfree(finfo->tbl_info);
		}
		finfo++;
	}
	kfree(fman_info);
	fman_info = NULL;
	num_fmans = 0;
}

//allocate and copy distribution info from uspace 
static int get_dist_info(struct cdx_port_info *port_info)
{
	uint32_t mem_size;
	struct cdx_dist_info *dist_info;
	void *uspace_info;

#ifdef DPA_CFG_DEBUG
	DPA_INFO("%s::port %s dist %d\n", __FUNCTION__, 
			port_info->name, port_info->max_dist);
#endif
	mem_size = (sizeof(struct cdx_dist_info) * port_info->max_dist);
	dist_info = kzalloc(mem_size, 0);
	if (!dist_info) {
		DPA_ERROR("%s::memalloc for dist_info failed\n",
				__FUNCTION__);
		return -ENOMEM;
	}
	memset(dist_info, 0, mem_size);
	uspace_info = port_info->dist_info;
	port_info->dist_info = dist_info;
	if (copy_from_user(dist_info, uspace_info, 
				mem_size)) {
		DPA_ERROR("%s::Read dist_info failed port %s\n",
				__FUNCTION__, port_info->name);
		return -EIO;
	}
	return 0;
}

#ifndef CDX_RTP_RELAY // In RTP relay support , need distribution handles for 3tuple tables also
void *get_ethdist_info_by_fman_params(struct cdx_fman_info *finfo)
{
	struct cdx_port_info *port_info;
	struct cdx_dist_info *dist;
	uint32_t ii;
	uint32_t jj;

	port_info = finfo->portinfo;
	for (ii = 0; ii < finfo->max_ports; ii++) {
		dist = port_info->dist_info;
		for (jj = 0; jj < port_info->max_dist; jj++) {
			if (dist->type == ETHERNET_DIST) {   // dist ++  is  missing in this for loop
				return (dist->handle);
			}
		}
		port_info++; 
	}
	return NULL;
}
#else
void *get_dist_info_by_fman_params(struct cdx_fman_info *finfo, uint32_t table_type)
{
	struct cdx_port_info *port_info;
	struct cdx_dist_info *dist;
	uint32_t ii, table_distrb_type = 0;
	uint32_t jj;

	DPA_INFO("%s(%d) table type %d \n", __FUNCTION__,__LINE__, table_type);
	switch (table_type)
	{
		case ETHERNET_TABLE:
			table_distrb_type = ETHERNET_DIST;
			break;
		case IPV4_3TUPLE_UDP_TABLE:
			table_distrb_type =  IPV4_3TUPLE_UDP_DIST;
			break;
		case IPV4_3TUPLE_TCP_TABLE:
			table_distrb_type =  IPV4_3TUPLE_TCP_DIST;
			break;
		case IPV6_3TUPLE_UDP_TABLE:
			table_distrb_type =  IPV6_3TUPLE_UDP_DIST;
			break;
		case IPV6_3TUPLE_TCP_TABLE:
			table_distrb_type =  IPV6_3TUPLE_TCP_DIST;
			break;
		case IPV6_MULTICAST_TABLE:
			table_distrb_type =  IPV6_MULTICAST_DIST;
			break;
		case IPV4_MULTICAST_TABLE:
			table_distrb_type =  IPV4_MULTICAST_DIST;
			break;
	}	
	port_info = finfo->portinfo;
	for (ii = 0; ii < finfo->max_ports; ii++) {
		dist = port_info->dist_info;
		for (jj = 0; jj < port_info->max_dist; jj++) {
			if (dist->type == table_distrb_type) {
				DPA_INFO("%s(%d) dist type %d , handle found \n",
						__FUNCTION__,__LINE__, dist->type);
				return (dist->handle);
			}
			dist++;
		}
		port_info++; 
	}
	return NULL;
}
#endif //CDX_RTP_RELAY

//allocate and copy port releated info from uspace 
static int get_port_info(struct cdx_fman_info *finfo) 
{	
	struct cdx_port_info *port_info;
	void *uspace_info;
	uint32_t mem_size;
	uint32_t ii;

	//allocate port information area
	mem_size = (sizeof(struct cdx_port_info) * finfo->max_ports);
#ifdef DPA_CFG_DEBUG
	DPA_INFO("%s::fm %d num ports %d\n", __FUNCTION__, 
			finfo->index, finfo->max_ports);
#endif
	port_info = kzalloc(mem_size, 0); 
	if (!port_info) {
		DPA_ERROR("%s::memalloc for port_info failed\n",
				__FUNCTION__);
		return -ENOMEM;
	}
	memset(port_info, 0, mem_size);
	uspace_info = finfo->portinfo;
	finfo->portinfo = port_info;
	if (copy_from_user(port_info, uspace_info, mem_size)) {
		DPA_ERROR("%s::Read port_info failed\n",
				__FUNCTION__);
		return -EIO;
	}
	//put the linux name for the port
	for (ii = 0; ii < finfo->max_ports; ii++) {
		struct net_device *dev;

		if (port_info->type) {
			dev = find_osdev_by_fman_params(port_info->fm_index,
					port_info->index, port_info->type);
			if (!dev) {
				DPA_ERROR("%s::could not map port %s\n",
						__FUNCTION__, port_info->name);
				return -EIO;
			} else {
				strcpy(port_info->name, dev->name);
			}
		}
#ifdef DPA_CFG_DEBUG
		DPA_INFO("%s::port %s, fmindex %d, port index %d, port id %d\n",
				__FUNCTION__, port_info->name,
				port_info->fm_index,
				port_info->index,
				port_info->portid);
#endif
		port_info++;
	}
	port_info = finfo->portinfo;
	for (ii = 0; ii < finfo->max_ports; ii++) {
		int retval;
		//get dist info for this port
		retval = get_dist_info(port_info);
		if (retval)
			return retval;
		port_info++;
	}
	return 0;
}	

//allocate and copy cc table infor from uspace
static int get_cctbl_info(struct cdx_fman_info *finfo) 
{	
	struct table_info *tbl_info;
	uint32_t mem_size;
	void *uspace_info;

	//allocate table information area
	mem_size = (sizeof(struct table_info) * finfo->num_tables);
	tbl_info = kzalloc(mem_size, 0); 
	if (!tbl_info) {
		DPA_ERROR("%s::memalloc for table_info failed\n",
				__FUNCTION__);
		return -ENOMEM;
	}
	memset(tbl_info, 0, mem_size);
	uspace_info = finfo->tbl_info;
	finfo->tbl_info = tbl_info;
	//copy table related info from user space	
	if (copy_from_user(tbl_info, (void *)uspace_info, mem_size)) {
		DPA_ERROR("%s::Read tbl_info failed\n",
				__FUNCTION__);
		return -EIO;
	}
	return 0;
}

int cdx_set_expt_rate(uint32_t fm_index, uint32_t type, uint32_t limit, uint32_t burst_size)
{
	struct cdx_fman_info *finfo;
	uint32_t old_limit;

	if (fm_index > num_fmans)
		return -1;
	if (type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return -1;
	finfo = (fman_info + fm_index);
	if (!finfo->expt_rate_limit_info[type].handle)
		return -1;
	old_limit = finfo->expt_rate_limit_info[type].limit;
	finfo->expt_rate_limit_info[type].limit = limit;
	finfo->expt_ratelim_burst_size = burst_size;
	if (cdxdrv_modify_missaction_policer_profile(finfo, type)) {
		finfo->expt_rate_limit_info[type].limit = old_limit;
		return -1;
	}
	return 0;
}


static int cdxdrv_set_miss_action(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;
	struct table_info *tbl_info;
	uint32_t ii;

	finfo = (fman_info + fm_index);
	tbl_info = finfo->tbl_info;
	//based on gathered table info, set miss action for all tables
#ifdef DPA_CFG_DEBUG
	DPA_INFO("%s::tables %d\n", __FUNCTION__, finfo->num_tables);
#endif
	for (ii = 0; ii < finfo->num_tables; ii++) {
		t_FmPcdCcNextEngineParams miss_engine_params;
		memset(&miss_engine_params, 0, sizeof(t_FmPcdCcNextEngineParams));
#ifdef DPA_CFG_DEBUG
		DPA_INFO("%s::tbl %s %p changing miss action\n", __FUNCTION__,
				tbl_info->name, tbl_info->id);
#endif
#ifndef CDX_RTP_RELAY // if no RTP relay setting of miss-action is same for all tables
#ifdef DPA_CFG_DEBUG
		DPA_INFO("%s::RTP relay disabled,  changing miss action\n", __FUNCTION__);
#endif
		if((tbl_info->type != ETHERNET_TABLE) &&
				(tbl_info->type != PPPOE_RELAY_TABLE) &&
#ifdef CDX_IP_REASSEMBLY
				(tbl_info->type != IPV4_REASSM_TABLE) &&
				(tbl_info->type != IPV6_REASSM_TABLE)
#endif // CDX_IP_REASSEMBLY
			) {
			//adding miss action as KG
			miss_engine_params.nextEngine = e_FM_PCD_KG;
			//get ethernet distribution scheme handle
			miss_engine_params.params.kgParams.h_DirectScheme = 
				get_ethdist_info_by_fman_params(finfo);
#if 1//def DPA_CFG_DEBUG
			DPA_INFO("%s::changing miss action for table %s as KG scheme %p\n",
					__FUNCTION__, tbl_info->name, 
					miss_engine_params.params.kgParams.h_DirectScheme);
#endif
			if (miss_engine_params.params.kgParams.h_DirectScheme == NULL) {
				DPA_ERROR("%s::error finding direct dist for table %s\n",
						__FUNCTION__, tbl_info->name);
				return -1;
			}
			printk("%s::found direct dist for %s\n", __FUNCTION__,
					tbl_info->name);
		} else {
			//adding miss action as policer
			miss_engine_params.nextEngine = e_FM_PCD_PLCR;
			//shared profile
			miss_engine_params.params.plcrParams.sharedProfile = 1;
			//get policer profile id for CP Ethernet traffic
			miss_engine_params.params.plcrParams.newRelativeProfileId =
				CDX_EXPT_ETH_RATELIMIT;
#if 1//def DPA_CFG_DEBUG
			DPA_INFO("%s::changing miss action for table %s as policer profile %d\n",
					__FUNCTION__, tbl_info->name, 
					miss_engine_params.params.plcrParams.newRelativeProfileId);
#endif
		}
		if (FM_PCD_HashTableModifyMissNextEngine(tbl_info->id,	
					&miss_engine_params) != E_OK) {
			DPA_ERROR("%s::error changing miss action table %s\n",
					__FUNCTION__, tbl_info->name);
			return -1;
		}
#else
		// RTP relay enabled
#ifdef DPA_CFG_DEBUG
		DPA_INFO("%s::RTP relay enabled,  changing miss action\n", __FUNCTION__);
#endif
		switch (tbl_info->type)
		{
			case IPV4_UDP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme = 
					get_dist_info_by_fman_params(finfo, IPV4_3TUPLE_UDP_TABLE);
				break;
#ifdef TCP_3TUPLE_TABLE
			case IPV4_TCP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, IPV4_3TUPLE_TCP_TABLE);
				break;
#endif // TCP_3TUPLE_TABLE
			case IPV6_UDP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme = 
					get_dist_info_by_fman_params(finfo, IPV6_3TUPLE_UDP_TABLE);
				break;
#ifdef TCP_3TUPLE_TABLE
			case IPV6_TCP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, IPV6_3TUPLE_TCP_TABLE);
				break;
#endif // TCP_3TUPLE_TABLE
			case ESP_IPV4_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, IPV4_MULTICAST_TABLE);
				break;
			case ESP_IPV6_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, IPV6_MULTICAST_TABLE);
				break;
			case IPV4_MULTICAST_TABLE:
			case IPV6_MULTICAST_TABLE:
			case IPV4_3TUPLE_UDP_TABLE:
#ifdef TCP_3TUPLE_TABLE
			case IPV4_3TUPLE_TCP_TABLE:
			case IPV6_3TUPLE_TCP_TABLE:
#else
			case IPV6_TCP_TABLE:
			case IPV4_TCP_TABLE:
#endif // TCP_3TUPLE_TABLE
			case IPV6_3TUPLE_UDP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme = 
					get_dist_info_by_fman_params(finfo, ETHERNET_TABLE);
				break;

		}
		//adding miss action 
		//get ethernet distribution scheme handle
		if((tbl_info->type != ETHERNET_TABLE) && (tbl_info->type != PPPOE_RELAY_TABLE) 
#ifdef CDX_IP_REASSEMBLY
				&& (tbl_info->type != IPV4_REASSM_TABLE) && (tbl_info->type != IPV6_REASSM_TABLE)
#endif
			) {
			if (miss_engine_params.params.kgParams.h_DirectScheme == NULL) {
				DPA_ERROR("%s::error finding direct dist for table %s\n",
						__FUNCTION__, tbl_info->name);
				return -1;
			}
			miss_engine_params.nextEngine = e_FM_PCD_KG;
#if 1//def DPA_CFG_DEBUG
			//DPA_INFO("%s::changing miss action table %s as KG scheme %p\n",
			printk("%s::changing miss action table %s as KG scheme %p\n",
					__FUNCTION__, tbl_info->name,
					miss_engine_params.params.kgParams.h_DirectScheme);
#endif
		} else {
			//adding miss action as policer
			miss_engine_params.nextEngine = e_FM_PCD_PLCR;
			//shared profile
			miss_engine_params.params.plcrParams.sharedProfile = 1;
			//get policer profile id for CP traffic
			miss_engine_params.params.plcrParams.newRelativeProfileId =
				CDX_EXPT_ETH_RATELIMIT;
#if 1//def DPA_CFG_DEBUG
			//DPA_INFO("%s::changing miss action table %s as policer, profile %d\n",
			printk("%s::changing miss action table %s as policer, profile %d\n",
					__FUNCTION__, tbl_info->name,
					miss_engine_params.params.plcrParams.newRelativeProfileId);
#endif
		}
		if (FM_PCD_HashTableModifyMissNextEngine(tbl_info->id,
					&miss_engine_params) != E_OK)
		{
			DPA_ERROR("%s::error changing miss action table %s\n",
					__FUNCTION__, tbl_info->name);
			return -1;
		}
#endif //CDX_RTP_RELAY 
		tbl_info++;
	}
	return 0;
}

//initialize fman handles and init iface stats
static int cdxdrv_get_fman_handles(struct cdx_fman_info *finfo)
{
	//translate pcd handle from uspace
	struct file *fm_pcd_file;
	t_LnxWrpFmDev *fm_wrapper_dev;

	//get handle	
	fm_pcd_file = fcheck((unsigned long)finfo->pcd_handle);
	if (!fm_pcd_file) {
		DPA_ERROR("%s::PCD handle 0x%p trans failed.\n",
				__FUNCTION__, finfo->pcd_handle);
		return -1;
	}
	//map it to wrapper dev
	fm_wrapper_dev = (t_LnxWrpFmDev *)fm_pcd_file->private_data;
	if (!fm_wrapper_dev) {
		DPA_ERROR("%s::null wrap dev for pcd 0x%p\n",
				__FUNCTION__, finfo->pcd_handle);
		return -1;
	}
	if (!fm_wrapper_dev->h_PcdDev) {
		DPA_ERROR("%s::null pcd dev for pcd 0x%p\n",
				__FUNCTION__, finfo->pcd_handle);
		return -1;
	}
	//get handle from dev
	finfo->pcd_handle = fm_wrapper_dev->h_PcdDev;
	finfo->fm_handle = fm_wrapper_dev->h_Dev;
	finfo->muram_handle = fm_wrapper_dev->h_MuramDev; 
	finfo->physicalMuramBase = fm_wrapper_dev->fmMuramPhysBaseAddr; 
	finfo->fmMuramMemSize = fm_wrapper_dev->fmMuramMemSize; 	
	return 0;
}


//ioctl handler for set dpa configuration
int cdx_ioc_set_dpa_params(unsigned long args)
{
	struct cdx_ctrl_set_dpa_params params;
	struct cdx_fman_info *finfo;
	uint32_t ii;	
	uint32_t mem_size;
	int retval;

	if (copy_from_user(&params, (void *)args, 
				sizeof(struct cdx_ctrl_set_dpa_params))) {
		DPA_ERROR("%s::Read uspace args failed\n", 
				__FUNCTION__);
		return -EBUSY;
	}
	mem_size = (sizeof(struct cdx_fman_info) * params.num_fmans);
	fman_info = kzalloc(mem_size, 0);
	if (!fman_info) {
		DPA_ERROR("%s::unable to allocate mem for fman_info\n",
				__FUNCTION__);
		return -ENOMEM;
	}
	num_fmans = params.num_fmans;
#ifdef DPA_CFG_DEBUG
	DPA_INFO("%s::num fmans %d\n", __FUNCTION__, num_fmans);
#endif
	memset(fman_info, 0, mem_size);
	//get fman info
	if (copy_from_user(fman_info, (void *)params.fman_info, 
				(sizeof(struct cdx_fman_info) * num_fmans))) {
		DPA_ERROR("%s::Read fman_info failed\n", 
				__FUNCTION__);
		retval = -EIO;
		goto err_ret;
	}
	if (copy_from_user(&ipr_info, (void *)params.ipr_info,
				sizeof(struct cdx_ipr_info))) {
		DPA_ERROR("%s::Read iprv_info failed\n", 
				__FUNCTION__);
		retval = -EIO;
		goto err_ret;
	}
	//init the fman handles 
	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		if (cdxdrv_get_fman_handles(finfo))
			return -1;
		finfo++;
	}
	finfo = fman_info;
	//init interface stats module
	if (cdxdrv_init_stats(finfo->muram_handle))
		return -1;

	for (ii = 0; ii < num_fmans; ii++) {
		//get port info
		retval = get_port_info(finfo);
		if (retval)
			goto err_ret;
		//get cc table info
		retval = get_cctbl_info(finfo);
		if (retval)
			goto err_ret;
		finfo++;
	}
	finfo = fman_info;
	//loop thru all fmans
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;

		port_info = finfo->portinfo;
		//add all oh ports on this fman
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (!port_info->type)  {
#ifdef DPA_CFG_DEBUG
				DPA_INFO("%s::oh port %s found\n", __FUNCTION__, port_info->name);
#endif
				if (cdx_add_oh_iface(port_info->name)) {
					DPA_ERROR("%s::port %s add failed\n",
							__FUNCTION__, port_info->name);
					retval = -EIO;
					goto err_ret;
				}
			}
			port_info++;
		}

		//add all eth ports on this fman
		port_info = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (port_info->type)  {
#ifdef DPA_CFG_DEBUG
				DPA_INFO("%s::adding port %s\n", __FUNCTION__, port_info->name);
#endif
				if (cdx_add_eth_onif(port_info->name)) {
					DPA_ERROR("%s::port %s add failed\n", 
							__FUNCTION__, port_info->name);
					retval = -EIO;
					goto err_ret;
				}
			}
			port_info++;
		}
		finfo++;
	}

	if (cdx_create_port_fqs())
		return -1;
	//create cp rate limit policier profiles
	if (cdxdrv_create_missaction_policer_profiles(fman_info)) {
		goto err_ret;
	}
#ifdef ENABLE_INGRESS_QOS
	if (cdxdrv_create_ingress_qos_policer_profiles(fman_info)) {
		goto err_ret;
	}
#endif
#ifdef ENABLE_EGRESS_QOS
	if(ceetm_init_cq_plcr())
		goto err_ret;
#endif
	//init the fman and its ports
	for (ii = 0; ii < num_fmans; ii++) {
		if (cdxdrv_set_miss_action(ii))
			goto err_ret;
	}
	display_dpa_cfg();
	return 0;
err_ret:
	release_cfg_info();
	return retval;
}

//get pcd fq info from fqid
int find_pcd_fq_info(uint32_t fqid)
{
	struct dpa_fq *fqinfo;
	fqinfo = dpa_pcd_fq;
	while(1) {
		if (!fqinfo)
			break;
		if (fqinfo->fqid == fqid)	
			return 0;
		fqinfo = (struct dpa_fq *)fqinfo->list.next;
	}
	return -1;
}

void add_pcd_fq_info(struct dpa_fq *fq_info)
{
	//add to tail of resource list
	fq_info->list.next = (struct list_head *)dpa_pcd_fq;
	dpa_pcd_fq = fq_info;
}

//get ether iface info by name
int get_dpa_eth_iface_info(struct eth_iface_info *iface_info, char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		//seach for port in fman structures
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				iface_info->fman_idx = port_info->fm_index;
				iface_info->port_idx = port_info->index;
				iface_info->portid = port_info->portid;
				iface_info->max_dist = port_info->max_dist;
				iface_info->dist_info = port_info->dist_info;
				return 0;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find info for port %s\n", 
			__FUNCTION__, name);
	return -1;
}

//get oh iface info by name
int get_dpa_oh_iface_info(struct oh_iface_info *iface_info, char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		//seach for port in fman structures
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				iface_info->max_dist = port_info->max_dist;
				iface_info->dist_info = port_info->dist_info;
				iface_info->portid = port_info->portid;
				return 0;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find info for port %s\n",
			__FUNCTION__, name);
	return -1;
}

/* get port information by name */
struct cdx_port_info *get_dpa_port_info(char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		//seach for port in fman structures
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				return port_info;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find info for port %s\n", 
			__FUNCTION__, name);
	return NULL;
}

/* get port name by port id */
char *get_dpa_port_name(uint32_t portid)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		/* seach for port in fman structures*/
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (port_info->portid == portid) {
				return port_info->name;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find port name for port %u\n", __func__, portid);
	return NULL;
}

//get kernel pcd dev handle by fman index
void *dpa_get_pcdhandle(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	finfo =  fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		if (finfo->index == fm_index) {
			return finfo->pcd_handle;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(dpa_get_pcdhandle); 

//get channel and workque id infor given a fqid
int dpa_get_tx_chnl_info(uint32_t fqid, uint32_t *ch_id, uint32_t *wq_id)
{
	struct qman_fq fq;
	struct qm_fqd fqd;

	memset(&fq, 0, sizeof(struct qman_fq));
	fq.fqid = fqid;
	//query for fq info
	if (qman_query_fq(&fq, &fqd)) {
		DPA_ERROR("%s::query fq failed on fqid %d\n",
				__FUNCTION__, fq.fqid);
		return FAILURE; 
	}
	//read tnd return he wq and channel info
	*wq_id = fqd.dest.wq;
	*ch_id = fqd.dest.channel;
	return SUCCESS;
}

//get table descriptor given a table type and port index
void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type)
{
	struct cdx_fman_info *finfo;
	struct table_info *tinfo;
	uint32_t ii;

	finfo =  fman_info;
	//loop thru al fmans
	for (ii = 0; ii < num_fmans; ii++) {
		if (finfo->index == fm_index) {
			tinfo = finfo->tbl_info;
			//scan all tables with this instance
			for (ii = 0; ii < finfo->num_tables; ii++) {
				//return if type and port index match
				if ((tinfo->type == type) && 
						(tinfo->port_idx & (1 << port_idx))) {
					return (tinfo->id);
				}
				tinfo++;
			}
			DPA_ERROR("%s::no matching type %d at index %d\n", 
					__FUNCTION__, type, fm_index);
			return NULL;
		}
	}
	DPA_ERROR("%s::invalid index %d\n", __FUNCTION__, fm_index);	
	return NULL;
}
#define DPA_PORT_TYPE_10G 10

/* it is assumed only one port will be the wan port and  it is  10G port*/
int dpa_get_wan_port(uint32_t fm_index, uint32_t *port_idx)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	finfo =  fman_info;
	//loop thru al fmans
	for (ii = 0; ii < num_fmans; ii++) {
		if (finfo->index == fm_index) {
			struct cdx_port_info *port_info;
			uint32_t jj;
			port_info = finfo->portinfo;
			//seach for port in fman structures
			for (jj = 0; jj < finfo->max_ports; jj++) {
				if (port_info->type  == DPA_PORT_TYPE_10G) {
					*port_idx  = (uint32_t)( port_info->portid);
					return SUCCESS;
				}
				port_info++;
			}
		}
		finfo++;
	}
	DPA_ERROR("%s::no wan port found fm_index %d\n",
			__FUNCTION__, fm_index);
	return FAILURE;
}

uint32_t dpa_get_fm_timestamp(void *fm_ctx)
{
	return JIFFIES32;
}

void *dpa_get_fm_ctx(uint32_t fm_idx)
{
	if (fm_idx < num_fmans)
		return (fman_info + fm_idx);
	else
		return NULL;
}


void *dpa_get_fm_MURAM_handle(uint32_t fm_idx, uint64_t *phyBaseAddr,
		uint32_t *MuramSize)
{
	struct cdx_fman_info *finfo;

	if (fm_idx < num_fmans)
		finfo = fman_info + fm_idx;
	else
		return NULL;
	*phyBaseAddr = finfo->physicalMuramBase;
	*MuramSize = finfo->fmMuramMemSize;
	return finfo->muram_handle;

}
EXPORT_SYMBOL(dpa_get_fm_MURAM_handle);

#ifdef ENABLE_INGRESS_QOS
/*get policer handle given fman index and queue_no */
int cdx_get_policer_profile_id(uint32_t fm_index, uint32_t queue_no)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	finfo =  fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		if (finfo->index == fm_index) {
			if(finfo->ingress_policer_info[queue_no].policer_on == ENABLE_INGRESS_POLICER)
				return finfo->ingress_policer_info[queue_no].profile_id;
			else
				break;
		}
	}
	return 0;
}
int cdx_ingress_enable_or_disable_qos(uint32_t fm_index,uint32_t queue_no,uint32_t oper)
{
	struct cdx_fman_info *finfo;

	if (fm_index > num_fmans)
		return -1;

	finfo = (fman_info + fm_index);

	if (!finfo->ingress_policer_info[queue_no].handle)
		return ERR_QM_INGRESS_POLICER_HANDLE_NULL;

	return cdxdrv_enable_or_disable_ingress_policer(finfo,queue_no,oper);

}
int cdx_ingress_policer_modify_config(uint32_t fm_index,uint32_t queue_no,uint32_t cir,uint32_t pir, uint32_t cbs, uint32_t pbs)
{
	struct cdx_fman_info *finfo;

	if (fm_index > num_fmans)
		return -1;

	finfo = (fman_info + fm_index);

	if (!finfo->ingress_policer_info[queue_no].handle)
		return ERR_QM_INGRESS_POLICER_HANDLE_NULL;

	return cdxdrv_modify_ingress_qos_policer_profile(finfo,queue_no,cir,pir,cbs,pbs);
}
int cdx_ingress_policer_reset(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;

	if (fm_index > num_fmans)
		return -1;

	finfo = (fman_info + fm_index);
	cdxdrv_ingress_policer_reset(finfo);
	return 0;
}

#ifdef SEC_PROFILE_SUPPORT
int cdx_sec_policer_reset(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;

	if (fm_index > num_fmans)
		return -1;

	finfo = (fman_info + fm_index);
	cdxdrv_sec_policer_reset(finfo);
	return 0;
}
#endif /* endif for SEC_PROFILE_SUPPORT */

int cdx_ingress_policer_stats(uint32_t fm_index,uint32_t queue_no,void *stats,uint32_t clear)
{
	struct cdx_fman_info *finfo;

	if (fm_index > num_fmans)
		return -1;

	finfo = (fman_info + fm_index);

	if (!finfo->ingress_policer_info[queue_no].handle)
	{
		printk("%s::policer handle is NULL\n", __FUNCTION__);
		return -1;
	}

	cdxdrv_ingress_policer_stats(finfo,queue_no,stats,clear);

	return 0;
}
#endif
