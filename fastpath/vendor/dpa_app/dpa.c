/*
 *  Copyright (c) 2011, 2014 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/**
 * @file                dpa.c
 * @description         dpaa offload uspace initialization 
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "fmc.h"
#include "cdx_ioctl.h"

//uncomment to enable debug messages from this app
//#define DPA_C_DEBUG 	1
#define MAX_FMAN_PORTS 	16
#define MAX_TABLES 	64
#define SP_OFFSET 	0x20

//default configuration, pcd and pdl files 
#define DEFAULT_CFG_FILE	(char *)"/etc/cdx_cfg.xml"
#define DEFAULT_PCD_FILE	(char *)"/etc/cdx_pcd.xml"
#define DEFAULT_SP_FILE		(char *)"/etc/cdx_sp.xml"
#define DEFAULT_PDL_FILE	(char *)"/etc/fmc/config/hxs_pdl_v3.xml"

//IP reassembly default configuration
#define IPR_TIMEOUT             2000 //milli seconds
#define IPR_MAX_FRAGS           2
#define IPR_MIN_FRAG_SIZE       128
#define IPR_MAX_SESSIONS        128
#define IPR_CTX_BSIZE           1700
#define IPR_FRAG_BSIZE          1700

enum dpa_cls_tbl_type {
	DPA_CLS_TBL_INTERNAL_HASH = 0,	/* HASH table in MURAM */
	DPA_CLS_TBL_EXTERNAL_HASH,	/* HASH table in DDR */
	DPA_CLS_TBL_INDEXED,		/* Indexed table */
	DPA_CLS_TBL_EXACT_MATCH		/* Exact match table */
};


//structure holding table config parameters for tables defined in pcd_file 
struct ccnode_table_params 
{
	char *name;		//table name as in the pcd file
	uint32_t type;		//internal table type
};

//structure holding name for distributions and types 
struct model_dist_params 
{
	char *name;		//dist name as in the pcd file
	uint32_t type;		//internal table type
};

//cctable infor associated with a fman instance
struct ccnode_tbl_info {
        char name[64];          //table name
        uint32_t port_map;      //port sharing info
        uint32_t key_size;      //size of key
        uint32_t dpa_type;      //table type
        uint32_t max_keys;      //max keys allowed for table
	struct {
		uint32_t num_sets; //max bucktets for int/ext table
		uint32_t max_ways; //max collisions for int table
	};
        void *handle;           //driver handle
};


extern void * FM_PCD_Open(t_FmPcdParams *p_FmPcdParams);     
void *FM_PCD_Get_Sch_handle(t_Handle pDev);

char *cfg_file = DEFAULT_CFG_FILE;
char *pcd_file = DEFAULT_PCD_FILE;
char *pdl_file = DEFAULT_PDL_FILE;
char *sp_file = DEFAULT_SP_FILE;

//fmc model from xml files
static struct fmc_model_t cmodel;

//handle to cdx device
int cdx_dev_handle;

//mapping CC tables names to types
static struct ccnode_table_params table_params[] = {
	{(char *)"cdx_udp4", 	IPV4_UDP_TABLE},
	{(char *)"cdx_tcp4", 	IPV4_TCP_TABLE},
	{(char *)"cdx_multicast4", IPV4_MULTICAST_TABLE},
	{(char *)"cdx_multicast6", IPV6_MULTICAST_TABLE},
	{(char *)"cdx_udp6",	IPV6_UDP_TABLE},
	{(char *)"cdx_tcp6", 	IPV6_TCP_TABLE},
	{(char *)"cdx_pppoe", PPPOE_RELAY_TABLE},  
	{(char *)"cdx_ethernet", ETHERNET_TABLE},
	{(char *)"cdx_esp4", 	ESP_IPV4_TABLE},
	{(char *)"cdx_esp6", 	ESP_IPV6_TABLE},
	{(char *)"cdx_tuple3udp4",	IPV4_3TUPLE_UDP_TABLE},
	{(char *)"cdx_tuple3tcp4",	IPV4_3TUPLE_TCP_TABLE},
	{(char *)"cdx_tuple3udp6", IPV6_3TUPLE_UDP_TABLE},
	{(char *)"cdx_tuple3tcp6", IPV6_3TUPLE_TCP_TABLE},
	{(char *)"cdx_frag4",   IPV4_REASSM_TABLE},
    {(char *)"cdx_frag6",   IPV6_REASSM_TABLE}
};
#define MAX_TABLE_PARAMS\
		(sizeof(table_params) / sizeof(struct ccnode_table_params))


static struct model_dist_params dist_name[] = {
	{(char *)"cdx_udp4_dist", 	IPV4_UDP_DIST},
	{(char *)"cdx_tcp4_dist", 	IPV4_TCP_DIST},
	{(char *)"cdx_udp6_dist", 	IPV6_UDP_DIST},
	{(char *)"cdx_tcp6_dist", 	IPV6_TCP_DIST},
	{(char *)"cdx_ipv4multicast_dist", 	IPV4_MULTICAST_DIST},
	{(char *)"cdx_ipv6multicast_dist", 	IPV6_MULTICAST_DIST},
	{(char *)"cdx_esp4_dist", 	IPV4_ESP_DIST},
	{(char *)"cdx_esp6_dist", 	IPV6_ESP_DIST},
	{(char *)"cdx_pppoe_dist",      PPPOE_DIST},
	{(char *)"cdx_ethernet_dist", 	ETHERNET_DIST},
#ifdef CDX_RTP_RELAY // RTP relay support
	{(char *)"cdx_tup3udp4_dist", 	IPV4_3TUPLE_UDP_DIST},
	{(char *)"cdx_tup3tcp4_dist", 	IPV4_3TUPLE_TCP_DIST},
	{(char *)"cdx_tup3udp6_dist", 	IPV6_3TUPLE_UDP_DIST},
	{(char *)"cdx_tup3tcp6_dist", 	IPV6_3TUPLE_TCP_DIST},
#endif //CDX_RTP_RELAY
	{(char *)"cdx_ipv4frag_dist",   IPV4_FRAG_DIST},
    {(char *)"cdx_ipv6frag_dist",   IPV6_FRAG_DIST},
};
#define MAX_DIST_PARAMS\
		(sizeof(dist_name) / sizeof(struct model_dist_params))

//rate limiter policier defaults
#define CDX_EXPT_ETH_DEFA_LIMIT         195312  //100 mbps
#define CDX_EXPT_WIFI_DEFA_LIMIT        DISABLE_EXPT_PROFILE
#define CDX_EXPT_ARPND_DEFA_LIMIT       DISABLE_EXPT_PROFILE
#define CDX_EXPT_PCAP_DEFA_LIMIT        DISABLE_EXPT_PROFILE
#define CDX_EXPT_RATELIM_MODE           EXPT_PKT_LIM_PLCR_MODE_PKT
#define CDX_EXPT_BURST_SIZE             64


//display the contents of the model as read from the xml config files
#ifdef DPA_C_DEBUG
static void display_model(struct fmc_model_t *model)
{
	uint32_t ii;
	uint32_t jj;

	printf("==================model====================\n");
	if (model->sp_enable)
		printf("sp_enabled\n");
	printf("------------------fman_info----------------\n");
	for ( ii = 0; ii < model->fman_count; ii++) {
		printf("number	\t%d\n", model->fman[ii].number);
		printf("name	\t%s\n", model->fman[ii].name);
		printf("number	\t%p\n", model->fman[ii].handle);
		printf("pcdname	\t%s\n", model->fman[ii].pcd_name);
		printf("pcd handle\t%p\n", model->fman[ii].pcd_handle);
		printf("portcount\t%d\n", model->fman[ii].port_count);
		printf("ports::	\t");
		for (jj = 0; jj < model->fman[ii].port_count; jj++)
			printf("%d ", model->fman[ii].ports[jj]);
		printf("\n");
	}
	printf("------------------schemes----------------\n");
	printf("scheme count\t%d\n", model->scheme_count);
	for (ii = 0; ii < model->scheme_count; ii++) { 
		t_FmPcdKgSchemeParams *scheme;
		printf("name	\t%s\n", &model->scheme_name[ii][0]);
		printf("handle	\t%p\n", FM_PCD_Get_Sch_handle(model->scheme_handle[ii]));
		scheme = &model->scheme[ii];
		printf("relid	\t%d\n", scheme->id.relativeSchemeId);
		printf("direct	\t%d\n", scheme->alwaysDirect);
	}
	printf("------------------ccnodes----------------\n");
	printf("ccnode count\t%d\n", model->ccnode_count);
	for (ii = 0; ii < model->ccnode_count; ii++) {
		printf("name	\t%s\n", model->ccnode_name[ii]);
		printf("handle	\t%p\n", model->ccnode_handle[ii]);
	}
	printf("------------------htnodes----------------\n");
	printf("htnode count\t%d\n", model->htnode_count);
	for (ii = 0; ii < model->htnode_count; ii++) {
		printf("name	\t%s\n", model->htnode_name[ii]);
		printf("handle	\t%p\n", model->htnode_handle[ii]);
	}
	printf("------------------ports------------------\n");
	printf("port count\t%d\n", model->port_count);
	for (ii = 0; ii < model->port_count; ii++) {
	printf("----------------port num %d---------------\n",  model->port[ii].number);
		printf("type	\t%d\n", model->port[ii].type);
		printf("name	\t%s\n", model->port[ii].name);
		printf("handle	\t%p\n", model->port[ii].handle);
		printf("cctreename\t%s\n", model->port[ii].cctree_name);
		if (model->port[ii].schemes_count) {
			printf("schemes\t%d\n", model->port[ii].schemes_count);
			printf("scheme nodes indices\n");
			for (jj = 0; jj < model->port[ii].schemes_count; jj++) {
				printf("%d ", model->port[ii].schemes[jj]);
			}
			printf("\n");
		} else
			printf("no schemes\n");
		if (model->port[ii].ccnodes_count) {
			printf("ccnodes_count\t%d\n", model->port[ii].ccnodes_count);
			printf("ccnode nodes indices\n");
			for (jj = 0; jj < model->port[ii].ccnodes_count; jj++) {
				printf("%d ", model->port[ii].ccnodes[jj]);
			}
			printf("\n");
		} else
			printf("no ccnodes\n");
		if (model->port[ii].htnodes_count) {
			printf("htnodes_count\t%d\n", model->port[ii].htnodes_count);
			printf("htnode nodes indices\n");
			for (jj = 0; jj < model->port[ii].htnodes_count; jj++) {
				printf("%d ", model->port[ii].htnodes[jj]);
			}
			printf("\n");
		} else
			printf("no htnodes\n");
	}
	printf("===========================================\n");
}
#endif

/* advance features like HMs are not enabled by default, 
   enable them before executing fmc */
static int set_fm_adv_options(struct cdx_fman_info *finfo)
{
	void *handle;
	void *fdev;
	t_FmPcdParams fm_pcd_params;
	
	//open FM device and PCD
	fdev = FM_Open(finfo->index);
	if (!fdev) {
		printf("%s::could not opem fm device\n",
			__FUNCTION__);
		return -1;
	}
	memset(&fm_pcd_params, 0, sizeof(t_FmPcdParams));
	fm_pcd_params.h_Fm = fdev;
	handle = FM_PCD_Open(&fm_pcd_params);
	//Disable PCD before we set advanced features
	if (FM_PCD_Disable(handle) != E_OK) {
 		printf("%s::could not disable pcd fm %d\n",
                        __FUNCTION__, finfo->index);
                return -1;
        }
	//enable Advanced pcd function before fmc_execute enables PCD
	if (FM_PCD_SetAdvancedOffloadSupport(handle) != E_OK) {
		printf("%s::could not enbl adv offload fm %d\n",
			__FUNCTION__, finfo->index); 
		return -1; 
	}
	finfo->fm_handle = handle;
	return 0;
}


/* fill FM-PCD device handle into finfo, required for all pcd 
  operations */
static int get_fm_pcd_handle(struct cdx_fman_info *finfo)
{
	struct t_Device *dev;
	
	//exract and pass device handles to kernel
	dev = (struct t_Device *)finfo->fm_handle;
	finfo->pcd_handle = (void *)((uint64_t)dev->fd);
	return 0;
}

static int get_dist_type(char *name) 
{
	uint32_t ii;
	for (ii = 0; ii < MAX_TABLE_PARAMS; ii++) {
		if (strstr(name, dist_name[ii].name) == 0)
			continue;
		return dist_name[ii].type; 
	}
	return -1;
}

/* scan port list in the fmc model, distributions associated with it, allocate
and fill port info structure and add it to the fman info structure */
static int get_port_info(struct cdx_fman_info *finfo)
{
	struct cdx_port_info *port_info;
	struct cdx_port_info *pinfo;
	struct cdx_dist_info *dist_info;
	char name[256];
	uint32_t size;
	uint32_t ports;
	uint32_t ii;
	uint32_t jj;

	if (!cmodel.port_count) {
		printf("%s::fm %d, no port info\n", __FUNCTION__, 
				finfo->index);
		return 0;
	}
	size = 0;
	ports = 0;
	for (ii = 0; ii < cmodel.port_count ; ii++) {
#ifdef DPA_C_DEBUG
		printf("%s::port %s\n", __FUNCTION__,
				cmodel.port[ii].name);
#endif
		//FM  name would be fm0, fm1 etc
		sprintf(name, "fm%d", finfo->index);
		//look for fm name in the port name
		if (strstr(cmodel.port[ii].name, name) == 0)
			continue;
		//found port on this fman instance
		size += sizeof(struct cdx_port_info);
		ports++;
		//add memory for dist for this port
		size += (cmodel.port[ii].schemes_count * sizeof(struct cdx_dist_info));
	}
	if (!ports) {
		printf("%s::no ports with fm%d\n", __FUNCTION__,
			finfo->index);
		return 0;
	}
	pinfo = (struct cdx_port_info *) calloc(1, size);
	if (!pinfo) {
		printf("%s::unable to allocate mem for port info\n",
				__FUNCTION__);
		goto err_ret;
	}
	port_info = pinfo;
	dist_info = (struct cdx_dist_info *)(port_info + cmodel.port_count);
	//scan all ports associated with this fman
	for (ii = 0; ii < cmodel.port_count; ii++) {
		sprintf(name, "fm%d", finfo->index);
		if (strstr(cmodel.port[ii].name, name) == 0)
                        continue;
		//fill all port related infor from model into cdx structures
		port_info->fm_index = finfo->index;
		port_info->index = cmodel.port[ii].number;
		port_info->portid = cmodel.port[ii].portid;
		port_info->max_dist = cmodel.port[ii].schemes_count;
		port_info->dist_info = dist_info;
		//encode the type, speed, fm index and port index in device name
		switch (cmodel.port[ii].type) {
			case 0:
				sprintf(port_info->name, "dpa-fman%d-oh@%d", 
					port_info->fm_index, (port_info->index + 1));
				port_info->type = 0;
				break;
			case 1:
				sprintf(port_info->name, "dpa-fm%d-1G-eth%d", 
					port_info->fm_index, port_info->index);
				port_info->type = 1;
				break;
			case 2:
				sprintf(port_info->name, "dpa-fm%d-10G-eth%d", 
					port_info->fm_index, port_info->index);
				port_info->type = 10;
				break;
			default:
				printf("%s::unhandled type %d\n", __FUNCTION__,
					cmodel.port[ii].type);
				break;
		}
		//scan all distributions associated with this port 
		for (jj = 0; jj < port_info->max_dist; jj++) {
			uint32_t handle;

			handle = cmodel.port[ii].schemes[jj];
			dist_info->base_fqid = cmodel.scheme[handle].baseFqid;
			dist_info->type = get_dist_type(&cmodel.scheme_name[handle][0]);
			if (dist_info->type == -1) {
				printf("%s::unable to get type for dist %s\n", 
					__FUNCTION__, &cmodel.scheme_name[handle][0]);
			}
			dist_info->count = 
				cmodel.scheme[handle].keyExtractAndHashParams.hashDistributionNumOfFqids;
#ifdef DPA_C_DEBUG
			printf("%s:: port %d, iter %d scheme %s handle %d basefqid %x(%d), count %d type %d\n",  __FUNCTION__,
				ii, jj, &cmodel.scheme_name[handle][0], handle, dist_info->base_fqid, 
				dist_info->base_fqid, dist_info->count, dist_info->type);
#endif
			dist_info++;
		}
		port_info++;
	}
	finfo->portinfo = pinfo;
	return 0;
err_ret:
	return -1;
}

/* scan port list in the fmc model, update distribution handles associated with it */
static int update_port_dist_info(struct cdx_fman_info *finfo)
{
	struct cdx_port_info *port_info;
	struct cdx_dist_info *dist_info;
	uint32_t ii;
	uint32_t jj;

	port_info = finfo->portinfo;
	//update all ports associated with this fman
	for (ii = 0; ii < cmodel.port_count; ii++) {
		dist_info = port_info->dist_info;
		for (jj = 0; jj < port_info->max_dist; jj++) {
			uint32_t handle;
			
			handle = cmodel.port[ii].schemes[jj];
			dist_info->handle = FM_PCD_Get_Sch_handle(cmodel.scheme_handle[handle]);
			dist_info++;
		}
		port_info++;
	}	
	return 0;
}

//get cc table configuration info from user
static int get_tbl_params(struct table_info *info)
{
	uint32_t ii;
	for (ii = 0; ii < MAX_TABLE_PARAMS; ii++) {
		if (strstr(info->name, table_params[ii].name) == 0)
			continue;
		info->type = table_params[ii].type;
		return 0; 
	}
	return -1;
}


static void create_tbl_portmap(struct table_info *tbl_info, uint32_t tbl_index)
{
	uint32_t ii;
	uint32_t jj;
	fmc_port *port;
	uint32_t count;
	uint32_t *tblref;

	port = &cmodel.port[0]; 

	for (ii = 0; ii < cmodel.port_count; ii++) {
		if (tbl_info->dpa_type == DPA_CLS_TBL_EXACT_MATCH) {
			count = port->ccnodes_count;
			tblref = &port->ccnodes[0];
		} else {
			count = port->htnodes_count;
			tblref = &port->htnodes[0];
		}
		for (jj = 0; jj < count; jj++) {
			if (*tblref == tbl_index) {
				tbl_info->port_idx |= (1 << port->portid);
				break;
			}
			tblref++;
		} 
		port++;
	}
#ifdef DPA_C_DEBUG
	printf("%s::tbl %s portmap %08x\n", __FUNCTION__,
			tbl_info->name, tbl_info->port_idx);
#endif
}

static int get_table_info(struct cdx_fman_info *fman_info)
{
	struct table_info *info;
	uint32_t num_tables;
	uint32_t ii;
	uint32_t jj;
	uint32_t count;
	int retval;

	//get count of number of hash tables and exact match tables
	count = (cmodel.ccnode_count + cmodel.htnode_count);
	if (!count) {
		printf("%s::no tables defined\n", __FUNCTION__);
		return 0;
	}
	//allocate memory for as many tables for this fman instance 
	info = (struct table_info *)
		calloc(1, (count * sizeof(struct table_info)));
	if (!info) {
		printf("%s::unable to alloc table info\n", __FUNCTION__); 
		retval = -1;
		goto func_ret;
	}
	fman_info->num_tables = count;
	fman_info->tbl_info = info;
	num_tables = 0;
	retval = 0;
	//first pass is nonhash, second for hash tables
	for (jj = 0; jj < 2; jj++) {
		if (!jj) {
			//find all non-hash tables
			count = (cmodel.ccnode_count);
		} else {
			//find all hash tables
			count = (cmodel.htnode_count);
		}
		for (ii = 0; ii < count; ii++) {
			t_Handle handle;
			char *tblname;
			uint32_t fm_idx;
			uint32_t port_id;
			uint32_t speed;
			if (!jj) 
				tblname = cmodel.ccnode_name[ii];
			else
				tblname = cmodel.htnode_name[ii];
			/* parse table name assuming it is for a physical port
			get fman instance, port speed and index & name */
			if (sscanf(tblname, "fm%d/port/%dG/%d/ccnode/%s",
                        	&fm_idx, &speed, &port_id,
                                &info->name[0]) != 4) {
				/* parse table name assuming it is for an offline port
				get fman instance, index & name */
                        	if (sscanf(tblname,
                                	"fm%d/port/OFFLINE/%d/ccnode/%s",
                                       	&fm_idx, &port_id,
                                       	&info->name[0]) != 3) {
					//neither of the two....	
                                	printf("%s::unable to parse "
                                        	"node name %s\n",
                                        	__FUNCTION__, tblname);
                               		retval = -1;
                               		goto func_ret;
				}
			}
			//table for this instance?, if not skip
			if (fm_idx != fman_info->index)
				continue;
			if (!jj) {
				info->dpa_type = DPA_CLS_TBL_EXACT_MATCH;
				info->num_keys = 
					cmodel.ccnode[ii].keysParams.maxNumOfKeys;
				info->key_size = cmodel.ccnode[ii].keysParams.keySize;
				handle = cmodel.ccnode_handle[ii];
#ifdef DPA_C_DEBUG
				printf("%s::found non-hash tbl %s\n", 
					__FUNCTION__, 
					info->name);
#endif
			} else {
				info->dpa_type = DPA_CLS_TBL_EXTERNAL_HASH;
				info->num_keys =
					cmodel.htnode[ii].maxNumOfKeys;
				info->num_sets = 
					(cmodel.htnode[ii].hashResMask + 1);
				info->num_ways = 
					(info->num_keys / info->num_sets);
				info->key_size = cmodel.htnode[ii].matchKeySize;
				handle = cmodel.htnode_handle[ii];
#ifdef DPA_C_DEBUG
				printf("%s::found hash tbl %s table mask %x\n", 
					__FUNCTION__,
					info->name, info->num_sets);
#endif
			}
			//get and fill fd ref to table 
			info->id = (void *)((struct t_Device *)handle)->id;
			//create port map for this table
			create_tbl_portmap(info, ii);
			//fill app table type
			if (get_tbl_params(info)) {
				printf("%s::unable to get params for table %s\n", 
					__FUNCTION__, info->name); 
				return -1;
			}
			info++;
			num_tables++;
		}
	}
	if (!num_tables) {
		printf("%s::fm %d, no tables defined\n", __FUNCTION__, 
			fman_info->index);	
		goto func_ret;
	}	
#ifdef DPA_C_DEBUG
	printf("%s::fm %d, num tables %d\n", __FUNCTION__, 
			fman_info->index, num_tables);
#endif
func_ret:
	return retval;
}

static int set_reassembly_params(struct fmc_model_t *model)
{
	uint32_t index;
	uint32_t reassm_table_type;
	
	for (index = 0; index < model->htnode_count; index++) {
		reassm_table_type = 0;
		do {
			if (strstr(model->htnode_name[index], "cdx_frag4")) {
				model->htnode[index].table_type = IPV4_REASSM_TABLE;
				reassm_table_type = 1;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_udp4")) {
				model->htnode[index].table_type = IPV4_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tcp4")) {
				model->htnode[index].table_type = IPV4_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_esp4")) {
				model->htnode[index].table_type = ESP_IPV4_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_multicast4")) {
				model->htnode[index].table_type = IPV4_MULTICAST_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_frag6")) {
				model->htnode[index].table_type = IPV6_REASSM_TABLE;
				reassm_table_type = 1;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_udp6")) {
				model->htnode[index].table_type = IPV6_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tcp6")) {
				model->htnode[index].table_type = IPV6_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_esp6")) {
				model->htnode[index].table_type = ESP_IPV6_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_multicast6")) {
				model->htnode[index].table_type = IPV6_MULTICAST_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_pppoe")) {
				model->htnode[index].table_type = PPPOE_RELAY_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tuple3udp4")) {
				model->htnode[index].table_type = IPV4_3TUPLE_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tuple3tcp4")) {
				model->htnode[index].table_type = IPV4_3TUPLE_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tuple3udp6")) {
				model->htnode[index].table_type = IPV6_3TUPLE_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tuple3tcp6")) {
				model->htnode[index].table_type = IPV6_3TUPLE_TCP_TABLE;
				break;
			}
			model->htnode[index].table_type = ETHERNET_TABLE;
			break;
		} while(1);
		if (reassm_table_type) {
		        model->htnode[index].timeout_val = 
				IPR_TIMEOUT;
        		model->htnode[index].timeout_fqid = 
				0;
        		model->htnode[index].max_frags = 
				IPR_MAX_FRAGS;
        		model->htnode[index].min_frag_size = 									IPR_MIN_FRAG_SIZE;
        		model->htnode[index].max_sessions = 
				IPR_MAX_SESSIONS;

#ifdef DPA_C_DEBUG
			{
			      uint32_t ii;
			      uint8_t *ptr;

			        ptr = (uint8_t *)&model->htnode[index];
				printf("%s::node %s:: %p\n", __FUNCTION__, model->htnode_name[index],
					ptr);
			        for (ii = 0; ii < sizeof(t_FmPcdHashTableParams); ii++) {
			                if ((ii % 16) == 0)
                        			printf("\n %02x ", *(ptr + ii));
                		else
                        		printf("%02x ", *(ptr + ii));
        			}
    			}
#endif
		}
	}
	return 0;
}


void set_exptrate_policer_defaults(struct cdx_fman_info *fman_info)
{
        uint32_t ii;

        fman_info->expt_ratelim_mode = CDX_EXPT_RATELIM_MODE;
        fman_info->expt_ratelim_burst_size = CDX_EXPT_BURST_SIZE;

        for (ii = 0; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {
                switch (ii) {
                        case CDX_EXPT_ETH_RATELIMIT:
                                fman_info->expt_rate_limit_info[ii].limit = CDX_EXPT_ETH_DEFA_LIMIT;
                                break;
                        case CDX_EXPT_WIFI_RATELIMIT:
                                fman_info->expt_rate_limit_info[ii].limit = CDX_EXPT_WIFI_DEFA_LIMIT;
                                break;
                        case CDX_EXPT_ARPND_RATELIMIT:
                        case CDX_EXPT_PCAP_RATELIMIT:
                                fman_info->expt_rate_limit_info[ii].limit = DISABLE_EXPT_PROFILE;
                                break;
                }
                fman_info->expt_rate_limit_info[ii].handle = 0;
        }
}

/* dpa offload initialization.
	opens cdx device for ioctl
	compiles fmc model
	executes model (loads fman)
	for each fman in the xml configuration, gets port, table and other info
	performs ioctl call to pass this info to kernel module.
 should be called once from uspace application.
*/

void show_muram_temp(void);
int dpa_init(void)
{
	uint32_t ii;
	struct cdx_fman_info *fman_info;
	struct cdx_ctrl_set_dpa_params params;
	char devname[64];
	int retval;

	//open cdx control device
        sprintf(devname, "/dev/%s", CDX_CTRL_CDEVNAME);
        cdx_dev_handle = open(devname, O_RDWR);
        if (cdx_dev_handle < 0) {
                printf("%s:unable to open dev %s\n", __FUNCTION__,
                        devname);
                return -1;
        }
	//compile the FMC PCD model	
   	retval = fmc_compile(&cmodel, cfg_file, pcd_file, pdl_file, sp_file,  SP_OFFSET, 0, 
			NULL);
	if (retval) {
		printf("%s::unable to compile fmc input files, err %d\n",
			__FUNCTION__, retval);
                return -1;
	}
	retval = -1;
	//fill dpaa config info for ioctl
	memset(&params, 0, sizeof(struct cdx_ctrl_set_dpa_params));
	params.num_fmans = cmodel.fman_count;
	if (!cmodel.fman_count) {
		printf("%s::no cfg info in model\n", __FUNCTION__);
		return -1;
	}
	fman_info = (struct cdx_fman_info *)
		calloc (1, (sizeof(struct cdx_fman_info) * params.num_fmans));
	if (!fman_info) {
		printf("%s::unable to allocate mem for fman info\n",
			__FUNCTION__);
		goto err_ret;
	}
	params.fman_info = fman_info;
	//pass ip reassembly limits to cdx
	params.ipr_info = (struct cdx_ipr_info *)
                calloc (1, (sizeof(struct cdx_ipr_info) * params.num_fmans));
        if (!params.ipr_info) {
                printf("%s::unable to allocate mem for ipr info\n",
                        __FUNCTION__);
                goto err_ret;
        }
        params.ipr_info->timeout = IPR_TIMEOUT;
        params.ipr_info->max_frags = IPR_MAX_FRAGS;
        params.ipr_info->min_frag_size = IPR_MIN_FRAG_SIZE;
        params.ipr_info->max_contexts = IPR_MAX_SESSIONS;
        params.ipr_info->ipr_ctx_bsize = IPR_CTX_BSIZE;
        params.ipr_info->ipr_frag_bsize = IPR_FRAG_BSIZE;
#ifdef DPA_C_DEBUG
	printf("%s::fman count %d\n", __FUNCTION__,
			cmodel.fman_count);
#endif
	for (ii = 0; ii < cmodel.fman_count; ii++) {	
		fman_info->index = cmodel.fman[ii].number ;
#ifdef DPA_C_DEBUG
		printf("%s::fman index %d\n", __FUNCTION__,
			cmodel.fman[ii].number);
#endif
		fman_info->max_ports = cmodel.fman[ii].port_count;
		if (get_port_info(fman_info))
			goto err_ret;
		if (set_fm_adv_options(fman_info))
			goto err_ret;
		fman_info++;
	}
#ifdef DPA_C_DEBUG
	printf("%s::executing fman model\n", __FUNCTION__);
#endif
	 //set reassembly parameters for those tables
        if (set_reassembly_params(&cmodel)) {
                printf("%s::unable to set reassembly params in FMC Model\n", __FUNCTION__);
                return -1;
        }
	//load compiled cfg it into the FMAN
	if (fmc_execute(&cmodel)) {
                printf("%s::unable to execute the FMC Model\n", __FUNCTION__);
                return -1;
        }
	fman_info = params.fman_info;
	for (ii = 0; ii < cmodel.fman_count; ii++) {	
		if (update_port_dist_info(fman_info)) {
#ifdef DPA_C_DEBUG
			printf("%s::cmodel.fman_count failed fman index %d\n", __FUNCTION__,
				cmodel.fman[ii].number);
#endif
			goto err_ret;
		}
		fman_info++;
	}
#ifdef DPA_C_DEBUG
	printf("%s::fmc_execute complete\n", __FUNCTION__);
	display_model(&cmodel);
	sleep(3);
#endif
	fman_info = params.fman_info;
	for (ii = 0; ii < cmodel.fman_count; ii++) {	
		//fill fm pcd handle needed by kernel
		if (get_fm_pcd_handle(fman_info))
			goto err_ret;	
		//get cctable infor
		if (get_table_info(fman_info))
			goto err_ret;
		fman_info++;
	}
	//set default for exception packet rate limiting
        fman_info = params.fman_info;
        for (ii = 0; ii < cmodel.fman_count; ii++) {
                set_exptrate_policer_defaults(fman_info);
                fman_info++;
        }
#ifdef DPA_C_DEBUG
	sleep(3);
#endif
	//pass config infor to kernel module
        retval = ioctl(cdx_dev_handle, CDX_CTRL_DPA_SET_PARAMS,
                        &params);
	if (retval) 
        	printf("%s:set params ioctl failed\n", __FUNCTION__);
err_ret:
	//release resources allocated
	fman_info = params.fman_info;
	if (fman_info) {
		for (ii = 0; ii < cmodel.fman_count; ii++) {
			if (fman_info->tbl_info)
				free(fman_info->tbl_info);
			if (fman_info->portinfo)
				free(fman_info->portinfo);
			fman_info++;
		}
		free(params.fman_info);
	}
	if (params.ipr_info)
    		free(params.ipr_info);
	//close device in case of any failure.
	if (retval) {
	        printf("%s::retval %d\n", __FUNCTION__, retval);
		close(cdx_dev_handle);
	}
	return retval;
}
