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
#include "list.h"
#include "cdx_common.h"
#include "misc.h"
#include "control_ipv4.h"
#include "dpa_control_mc.h"
#include "control_ipv6.h"
#include "linux/netdevice.h"

typedef union ucode_phyaddr_u {
	struct {
		uint16_t rsvd;
		uint16_t addr_hi;
		uint32_t addr_lo;
	};
	uint64_t addr;
}ucode_phyaddr_t;

struct list_head mc4_grp_list[MC4_NUM_HASH_ENTRIES];
struct list_head mc6_grp_list[MC6_NUM_HASH_ENTRIES];

extern uint64_t XX_VirtToPhys(void * addr);

uint8_t *mc4grp_ids=NULL, *mc6grp_ids=NULL;
spinlock_t *mc4_spinlocks =  NULL, *mc6_spinlocks = NULL;
uint16_t  max_mc4grp_ids, max_mc6grp_ids;


void AddToMcastGrpList(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int uiHash;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_add(&(pMcastGrpInfo->list),&mc4_grp_list[uiHash]);
		spin_unlock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		DPA_INFO("%s(%d) hash %d , ptr %p\n",__FUNCTION__,__LINE__, uiHash, &pMcastGrpInfo->list);
		spin_lock(&mc6_spinlocks[uiHash]);
		list_add(&(pMcastGrpInfo->list),&mc6_grp_list[uiHash]);
		spin_unlock(&mc6_spinlocks[uiHash]);
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__FUNCTION__,__LINE__, pMcastGrpInfo->uiListenerCnt, pMcastGrpInfo->ipv6_saddr[0], pMcastGrpInfo->ipv6_saddr[1],
				pMcastGrpInfo->ipv6_saddr[2],pMcastGrpInfo->ipv6_saddr[3], 
				pMcastGrpInfo->ipv6_daddr[0], pMcastGrpInfo->ipv6_daddr[1],pMcastGrpInfo->ipv6_daddr[2],
				pMcastGrpInfo->ipv6_daddr[3]);
	}

	return;
}

int GetMcastGrpId( struct mcast_group_info *pMcastGrpInfo,
		uint8_t *ingress_iface)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	unsigned int uiHash;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);

		spin_lock(&mc4_spinlocks[uiHash]);
		list_for_each(ptr, &mc4_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);

			DPA_INFO("%s(%d) tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s dst-addr 0x%x, s-addr %x\n",
					__FUNCTION__,__LINE__, tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface, tmp->ipv4_daddr,
					tmp->ipv4_saddr);
			if((tmp->ipv4_daddr == pMcastGrpInfo->ipv4_daddr)
					&& (tmp->ipv4_saddr == pMcastGrpInfo->ipv4_saddr))
			{
				if (ingress_iface)
					strncpy(ingress_iface,tmp->ucIngressIface, IF_NAME_SIZE);
				spin_unlock(&mc4_spinlocks[uiHash]);
				return tmp->grpid;
			}
		}
		spin_unlock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
		list_for_each(ptr, &mc6_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);
			DPA_INFO("%s(%d) ptr %p tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s\n",
					__FUNCTION__,__LINE__, tmp,  tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface);
			DPA_INFO("%s(%d) tmp ipv6daddr: 0x%x:%x:%x:%x src-addr: 0x%x:%x:%x:%x \n",
					__FUNCTION__,__LINE__, tmp->ipv6_daddr[0], tmp->ipv6_daddr[1],
					tmp->ipv6_daddr[2], tmp->ipv6_daddr[3], tmp->ipv6_saddr[0],
					tmp->ipv6_saddr[1], tmp->ipv6_saddr[2], tmp->ipv6_saddr[3]);

			if(!IPV6_CMP(tmp->ipv6_daddr, pMcastGrpInfo->ipv6_daddr) 
					&& !IPV6_CMP(tmp->ipv6_saddr, pMcastGrpInfo->ipv6_saddr))   
			{
				if (ingress_iface)
					strncpy(ingress_iface,tmp->ucIngressIface, IF_NAME_SIZE);
				spin_unlock(&mc6_spinlocks[uiHash]);
				return tmp->grpid;
			}
		}
		spin_unlock(&mc6_spinlocks[uiHash]);
	}
	return -1;
}

int GetNewMcastGrpId(uint8_t mctype)
{
	unsigned int ii;

	if(mctype == 0)
	{
		for (ii=0; ii<max_mc4grp_ids; ii++)
		{
			if (!mc4grp_ids[ii])
			{
				mc4grp_ids[ii] = 1;
				return ii+1;
			}
		}
	}
	else
	{
		for (ii=0; ii<max_mc6grp_ids; ii++)
		{
			if (!mc6grp_ids[ii])
			{
				mc6grp_ids[ii] = 1;
				return ii+1;
			}
		}
	}
	return -1;
}

void FreeMcastGrpID(uint8_t mctype, int grp_id)
{
	if (mctype == 0)
	{
		if ((grp_id > 0) && (grp_id <= max_mc4grp_ids))
		{
			mc4grp_ids[grp_id -1] = 0;
		}
	}
	else
	{
		if ((grp_id > 0) && (grp_id <= max_mc6grp_ids))
		{
			mc6grp_ids[grp_id -1] = 0;
		}
	}
}

struct mcast_group_info* GetMcastGrp( struct mcast_group_info *pMcastGrpInfo)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	unsigned int uiHash;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_for_each(ptr, &mc4_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);

			DPA_INFO("%s(%d) tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s dst-addr 0x%x, s-addr %x\n",
					__FUNCTION__,__LINE__, tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface, tmp->ipv4_daddr,
					tmp->ipv4_saddr);
			if((tmp->ipv4_daddr == pMcastGrpInfo->ipv4_daddr)
					&& (!strncmp(pMcastGrpInfo->ucIngressIface, tmp->ucIngressIface, IF_NAME_SIZE))
					&& (tmp->ipv4_saddr == pMcastGrpInfo->ipv4_saddr))
			{
				spin_unlock(&mc4_spinlocks[uiHash]);
				return tmp;
			}
		}
		spin_unlock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
		list_for_each(ptr, &mc6_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);

			DPA_INFO("%s(%d) ptr %p, tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s\n",
					__FUNCTION__,__LINE__,tmp, tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface);
			DPA_INFO("%s(%d) tmp ipv6daddr: 0x%x:%x:%x:%x src-addr: 0x%x:%x:%x:%x \n",
					__FUNCTION__,__LINE__, tmp->ipv6_daddr[0], tmp->ipv6_daddr[1],
					tmp->ipv6_daddr[2], tmp->ipv6_daddr[3], tmp->ipv6_saddr[0],
					tmp->ipv6_saddr[1], tmp->ipv6_saddr[2], tmp->ipv6_saddr[3]);
			if(!strncmp(pMcastGrpInfo->ucIngressIface, tmp->ucIngressIface, IF_NAME_SIZE))
			{
				if(!IPV6_CMP(tmp->ipv6_daddr, pMcastGrpInfo->ipv6_daddr) 
						&& !IPV6_CMP(tmp->ipv6_saddr, pMcastGrpInfo->ipv6_saddr))   
				{
					spin_unlock(&mc6_spinlocks[uiHash]);
					return tmp;
				}
			}
		}
		spin_unlock(&mc6_spinlocks[uiHash]);
	}
	return NULL;
}

int Cdx_GetMcastMemberId(char *pIn_Info, struct mcast_group_info *pMcastGrpInfo)
{
	int ii;
	struct mcast_group_member *pMember;
	unsigned int uiHash;

	if(!pMcastGrpInfo)
		return -1;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
	}
	for(ii=0; ii < MC4_MAX_LISTENERS_PER_GROUP; ii++)
	{
		pMember = &(pMcastGrpInfo->members[ii]);
		if(pMember->bIsValidEntry == 1)
		{
			if(strcmp(pIn_Info,pMember->if_info )== 0)
			{
				if(pMcastGrpInfo->mctype == 0)
					spin_unlock(&mc4_spinlocks[uiHash]);
				else
					spin_unlock(&mc6_spinlocks[uiHash]);
				return pMember->member_id;
			}
		}
	}  
	if(pMcastGrpInfo->mctype == 0)
		spin_unlock(&mc4_spinlocks[uiHash]);
	else
		spin_unlock(&mc6_spinlocks[uiHash]);
	return -1;
}


int Cdx_GetMcastMemberFreeIndex(struct mcast_group_info *pMcastGrpInfo)
{
	int ii;
	struct mcast_group_member *pMember;
	unsigned int uiHash;

	if(!pMcastGrpInfo)
		return -1;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
	}

	for(ii=0; ii < MC4_MAX_LISTENERS_PER_GROUP; ii++)
	{
		pMember = &(pMcastGrpInfo->members[ii]);
		if (pMember->bIsValidEntry == 0)
		{
			if(pMcastGrpInfo->mctype == 0)
				spin_unlock(&mc4_spinlocks[uiHash]);
			else
				spin_unlock(&mc6_spinlocks[uiHash]);
			return ii;
		}
	}  
	if(pMcastGrpInfo->mctype == 0)
		spin_unlock(&mc4_spinlocks[uiHash]);
	else
		spin_unlock(&mc6_spinlocks[uiHash]);
	return -1;
}


int cdx_free_exthash_mcast_members(struct mcast_group_info *pMcastGrpInfo);
int cdx_add_mcast_table_entry(void *mcast_cmd,
		struct mcast_group_info *pMcastGrpInfo)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	RouteEntry *pRtEntry;
	POnifDesc onif_desc;
	struct _tCtEntry *pCtEntry;
	int retval,ii;
	uint64_t phyaddr=0;
	char ucInterface[IF_NAME_SIZE];

	pRtEntry = NULL;
	pCtEntry = NULL;
	mcast4_group = NULL;
	mcast6_group = NULL;

	if (mcast_cmd == NULL)
		return FAILURE;

	if(pMcastGrpInfo->mctype == 0)
	{
		mcast4_group = (PMC4Command)(mcast_cmd);
		strncpy(ucInterface,mcast4_group->input_device_str,IF_NAME_SIZE-1);
	}
	else
	{
		mcast6_group = (PMC6Command)(mcast_cmd);
		strncpy(ucInterface,mcast6_group->input_device_str,IF_NAME_SIZE-1);
	}

	pRtEntry = kzalloc((sizeof(RouteEntry)), 0);
	if (!pRtEntry)
	{
		return -ENOMEM;	
	}

	pCtEntry = kzalloc((sizeof(struct _tCtEntry)), 0);
	if (!pCtEntry)
	{
		retval = -ENOMEM;	
		goto err_ret;
	}

	pCtEntry->proto = IPPROTOCOL_UDP;
	/** proto is UDP for any mutlicast packet **/

	pCtEntry->Sport = 0;
	pCtEntry->Dport = 0;
	/** port fields should be masked in match key**/

	if(pMcastGrpInfo->mctype == 0)
	{
		pCtEntry->Saddr_v4 = (mcast4_group->src_addr);
		pCtEntry->Daddr_v4 = (mcast4_group->dst_addr);
		pCtEntry->twin_Daddr = pCtEntry->Saddr_v4;
		pCtEntry->twin_Saddr = pCtEntry->Daddr_v4;
		pCtEntry->fftype = FFTYPE_IPV4;
	}
	else
	{
		memcpy(pCtEntry->Saddr_v6,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pCtEntry->Daddr_v6,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		pCtEntry->fftype = FFTYPE_IPV6;
	}

	onif_desc = get_onif_by_name(ucInterface); 
	if (!onif_desc)
	{
		DPA_ERROR("%s::unable to get onif for iface %s\n",__FUNCTION__, ucInterface);
		retval = -EIO;
		goto err_ret;
	}

	pRtEntry->itf = onif_desc->itf;
	pRtEntry->input_itf = onif_desc->itf;
	pRtEntry->underlying_input_itf = pRtEntry->input_itf;
	pCtEntry->pRtEntry = pRtEntry;
	for (ii=0; ii<pMcastGrpInfo->uiListenerCnt; ii++)
	{
		if(pMcastGrpInfo->members[ii].bIsValidEntry)
		{
			phyaddr = XX_VirtToPhys(pMcastGrpInfo->members[ii].tbl_entry);
			DPA_INFO("%s(%d) phyaddr %llx, addr %p\n",
					__FUNCTION__,__LINE__,phyaddr, pMcastGrpInfo->members[ii].tbl_entry);
			break;
		}
	}
	retval = insert_mcast_entry_in_classif_table(pCtEntry, pMcastGrpInfo->uiListenerCnt, phyaddr, 
			pMcastGrpInfo->members[ii].tbl_entry);
	if(retval)
	{
		DPA_ERROR("%s::Insert Mcast entry failed \r\n",__FUNCTION__);
		goto err_ret;
	}

	pMcastGrpInfo->pCtEntry  = pCtEntry;

	return retval;

err_ret:
	if (pRtEntry)
	{
		kfree(pRtEntry);
	}
	if (pCtEntry)
	{
		kfree(pCtEntry);
	}
	return retval;
}


int cdx_create_mcast_group(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	MC4Output	*pListener;
	RouteEntry *pRtEntry, RtEntry;
	int iRet = 0;
	struct ins_entry_info *pInsEntryInfo, InsEntryInfo;
	struct mcast_group_info *pMcastGrpInfo;
	int ii, member_id = 0;
	unsigned int uiNoOfListeners;
	char *pInIface;
	uint8_t IngressIface[IF_NAME_SIZE];
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	uint32_t tbl_type;

	// memory allocation for multicast group
	pMcastGrpInfo = (struct mcast_group_info *)kzalloc((sizeof(struct mcast_group_info)), 0);
	if(!pMcastGrpInfo)
	{
		DPA_ERROR("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
		return ERR_NOT_ENOUGH_MEMORY;
	}

	INIT_LIST_HEAD(&pMcastGrpInfo->list); 
	DPA_INFO("%s(%d) : IP type %s\n", __FUNCTION__,__LINE__,
			(bIsIPv6) ? "IPv6" : "IPv4");
	memset(&mcast4_group, 0, sizeof(mcast4_group));
	memset(&mcast6_group, 0, sizeof(mcast6_group));
	pMcastGrpInfo->mctype = bIsIPv6;
	if(pMcastGrpInfo->mctype == 0)
	{
		mcast4_group = (PMC4Command)mcast_cmd;
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		uiNoOfListeners = mcast4_group->num_output;
		pInIface = mcast4_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IP addr 0x%x,Dst IP addr 0x%x\n",
				__FUNCTION__,__LINE__, uiNoOfListeners, mcast4_group->src_addr,
				mcast4_group->dst_addr);
	}
	else
	{
		mcast6_group = (PMC6Command)mcast_cmd;
		memcpy(pMcastGrpInfo->ipv6_saddr,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		uiNoOfListeners = mcast6_group->num_output;
		pInIface = mcast6_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__FUNCTION__,__LINE__, uiNoOfListeners, mcast6_group->src_addr[0], mcast6_group->src_addr[1],
				mcast6_group->src_addr[2],mcast6_group->src_addr[3], 
				mcast6_group->dst_addr[0], mcast6_group->dst_addr[1],mcast6_group->dst_addr[2],
				mcast6_group->dst_addr[3]);
	}

	pMcastGrpInfo->grpid = -1; 
	strncpy(pMcastGrpInfo->ucIngressIface, pInIface, IF_NAME_SIZE-1);

	if((uiNoOfListeners) > MC_MAX_LISTENERS_PER_GROUP)
	{
		DPA_ERROR("%s::%d Exceeding max members(%d) in the group \r\n",
				__FUNCTION__, __LINE__,MC_MAX_LISTENERS_PER_GROUP);
		iRet	= ERR_MC_MAX_LISTENERS_PER_GROUP;
		goto err_ret;
	}

	if((iRet = GetMcastGrpId(pMcastGrpInfo, IngressIface))!= -1)
	{
		if (strncmp(pMcastGrpInfo->ucIngressIface, 
					IngressIface, IF_NAME_SIZE))
		{
			DPA_ERROR("%s::%d multiple ingress interfaces(%s, existing %s) are not allowed \n"
					"for the same set of source IP and dest.IP pair \r\n",
					__FUNCTION__, __LINE__,pMcastGrpInfo->ucIngressIface,
					IngressIface);
			iRet	= -1;
			goto err_ret;
		}
		kfree(pMcastGrpInfo);
		DPA_INFO("%s(%d) GetMcastGrpId returned %d, calling update_mcast_grp\n",
				__FUNCTION__,__LINE__,iRet);
		return (cdx_update_mcast_group(mcast_cmd, bIsIPv6));
	}

	if ((pMcastGrpInfo->grpid = GetNewMcastGrpId(pMcastGrpInfo->mctype)) == -1)
	{
		DPA_ERROR("Exceeding max number of multicast entries\n");
		goto err_ret;
	}
	memset(&InsEntryInfo, 0, sizeof(struct ins_entry_info));
	pInsEntryInfo = &InsEntryInfo;
	memset(&RtEntry,0, sizeof(RouteEntry));
	pRtEntry = &RtEntry; 

	if(pMcastGrpInfo->mctype == 0)
	{
		pRtEntry->dstmac[0] = 0x01;
		pRtEntry->dstmac[1] = 0x00;
		pRtEntry->dstmac[2] = 0x5E;
		pRtEntry->dstmac[3] = (mcast4_group->dst_addr >> 8)&0x7f;
		pRtEntry->dstmac[4] = (mcast4_group->dst_addr >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast4_group->dst_addr >> 24) & 0xff;
		tbl_type = IPV4_MULTICAST_TABLE;
	}
	else
	{
		pRtEntry->dstmac[0] = 0x33;
		pRtEntry->dstmac[1] = 0x33;
		pRtEntry->dstmac[2] = (mcast6_group->dst_addr[3]) &  0xff;
		pRtEntry->dstmac[3] = (mcast6_group->dst_addr[3] >> 8) & 0xff;
		pRtEntry->dstmac[4] = (mcast6_group->dst_addr[3] >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast6_group->dst_addr[3] >> 24) & 0xff;
		tbl_type = IPV6_MULTICAST_TABLE;
	}


	pMcastGrpInfo->uiListenerCnt = 0;

	for (ii=0; ii< uiNoOfListeners; ii++)
	{
		if(pMcastGrpInfo->mctype == 0)
			pListener = &mcast4_group->output_list[ii];
		else
			pListener = &mcast6_group->output_list[ii];

		DPA_INFO("%s(%d) creating table entry of mcast member %s\n",
				__FUNCTION__,__LINE__, pListener->output_device_str);
		tbl_entry = create_exthash_entry4mcast_member(pRtEntry, pInsEntryInfo, pListener, tbl_entry, tbl_type);
		if (!tbl_entry)
		{
			DPA_ERROR("%s(%d) : create_exthash_entry4mcast_member failed\n",
					__FUNCTION__, __LINE__);
			goto err_ret;
		}
		pMcastGrpInfo->members[member_id].bIsValidEntry = 1;
		strncpy(pMcastGrpInfo->members[member_id].if_info, pListener->output_device_str,IF_NAME_SIZE-1);
		pMcastGrpInfo->members[member_id].member_id = member_id;
		pMcastGrpInfo->members[member_id].tbl_entry= tbl_entry;
		pMcastGrpInfo->uiListenerCnt++; 
		member_id++;
	}

	if(pMcastGrpInfo->mctype == 0)
		iRet = cdx_add_mcast_table_entry(mcast4_group, pMcastGrpInfo);
	else
		iRet = cdx_add_mcast_table_entry(mcast6_group, pMcastGrpInfo);

	if(iRet != 0)
	{
		DPA_ERROR(" %s::%d Adding mcast table entry failed \r\n", __FUNCTION__, __LINE__);
		goto err_ret;
	}
	AddToMcastGrpList(pMcastGrpInfo);
	return 0;

err_ret:
	if(pMcastGrpInfo)
	{
		//Mcast group record is created, delete the group
		if((iRet = cdx_free_exthash_mcast_members(pMcastGrpInfo)))
		{
			DPA_ERROR("%s::%d mcast group deletion failed \r\n", __FUNCTION__, __LINE__);
		}
		kfree(pMcastGrpInfo);
	}
	return iRet;
}

int cdx_free_exthash_mcast_members(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int ii;
	FreeMcastGrpID(pMcastGrpInfo->mctype, pMcastGrpInfo->grpid);
	for (ii=0; ii<pMcastGrpInfo->uiListenerCnt; ii++)
	{
		if (pMcastGrpInfo->members[ii].tbl_entry)
			ExternalHashTableEntryFree(pMcastGrpInfo->members[ii].tbl_entry);
	}
	return 0;
}

void cdx_exthash_update_first_mcast_member_addr(struct en_exthash_tbl_entry *temp_entry,
		uint64_t listener_phyaddri,
		struct en_exthash_tbl_entry *listener);

int cdx_update_mcast_group(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	RouteEntry *pRtEntry, RtEntry;
	struct ins_entry_info *pInsEntryInfo, InsEntryInfo;
	struct mcast_group_info *pMcastGrpInfo, McastGrpInfo;
	struct mcast_group_info *pTempGrpInfo;
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	unsigned int uiNoOfListeners, uiHash;
	int iRet, ii;
	int member_id;
	MC4Output   *pListener;
	char *pInIface;
	uint32_t tbl_type;
	uint64_t phyaddr;


	memset(&InsEntryInfo, 0, sizeof(struct ins_entry_info));
	pInsEntryInfo = &InsEntryInfo;
	pRtEntry = &RtEntry;
	mcast4_group = NULL;
	mcast6_group = NULL;
	iRet = 0;

	if(bIsIPv6)
		mcast6_group = (PMC6Command)mcast_cmd;
	else
		mcast4_group = (PMC4Command)mcast_cmd;

	pMcastGrpInfo = &McastGrpInfo;
	memset(pMcastGrpInfo, 0,sizeof(struct mcast_group_info));

	pMcastGrpInfo->mctype = bIsIPv6;
	if(pMcastGrpInfo->mctype == 0)
	{
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		pMcastGrpInfo->mctype  = 0;
		uiNoOfListeners = mcast4_group->num_output;
		pInIface = mcast4_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IP addr 0x%x,Dst IP addr 0x%x\n",
				__FUNCTION__,__LINE__, uiNoOfListeners, mcast4_group->src_addr,
				mcast4_group->dst_addr);
	}
	else
	{
		memcpy(pMcastGrpInfo->ipv6_saddr,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		pMcastGrpInfo->mctype  = 1;
		uiNoOfListeners = mcast6_group->num_output;
		pInIface = mcast6_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__FUNCTION__,__LINE__, uiNoOfListeners, mcast6_group->src_addr[0], mcast6_group->src_addr[1],
				mcast6_group->src_addr[2],mcast6_group->src_addr[3], 
				mcast6_group->dst_addr[0], mcast6_group->dst_addr[1],mcast6_group->dst_addr[2],
				mcast6_group->dst_addr[3]);
	}
	strncpy(pMcastGrpInfo->ucIngressIface, pInIface, IF_NAME_SIZE-1);

	if((pTempGrpInfo = GetMcastGrp(pMcastGrpInfo)) == NULL)
	{
		DPA_ERROR("%s::%d multicast group does not exist \r\n", __FUNCTION__, __LINE__);
		iRet = -1;
		goto err_ret;
	}

	pMcastGrpInfo = pTempGrpInfo;

	if((uiNoOfListeners +  pMcastGrpInfo->uiListenerCnt) > MC_MAX_LISTENERS_PER_GROUP)
	{
		DPA_ERROR("%s::%d Exceeding max members(%d) in the group \r\n",
				__FUNCTION__, __LINE__,MC_MAX_LISTENERS_PER_GROUP);
		iRet = ERR_MC_MAX_LISTENERS_PER_GROUP;
		goto err_ret;
	}

	if(!bIsIPv6)
	{
		pRtEntry->dstmac[0] = 0x01;
		pRtEntry->dstmac[1] = 0x00;
		pRtEntry->dstmac[2] = 0x5E;
		pRtEntry->dstmac[3] = (mcast4_group->dst_addr >> 8)&0x7f;
		pRtEntry->dstmac[4] = (mcast4_group->dst_addr >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast4_group->dst_addr >> 24) & 0xff;
		tbl_type = IPV4_MULTICAST_TABLE;
	}
	else
	{
		pRtEntry->dstmac[0] = 0x33;
		pRtEntry->dstmac[1] = 0x33;
		pRtEntry->dstmac[2] = (mcast6_group->dst_addr[3]) &  0xff;
		pRtEntry->dstmac[3] = (mcast6_group->dst_addr[3] >> 8) & 0xff;
		pRtEntry->dstmac[4] = (mcast6_group->dst_addr[3] >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast6_group->dst_addr[3] >> 24) & 0xff;
		tbl_type = IPV6_MULTICAST_TABLE;
	}

	for(ii=0 ; ii < uiNoOfListeners; ii++)
	{
		if(bIsIPv6)
		{
			pListener = &(mcast6_group->output_list[ii]);
		}
		else
		{
			pListener = &(mcast4_group->output_list[ii]);
		}

		if((member_id = Cdx_GetMcastMemberId(pListener->output_device_str ,pMcastGrpInfo)) != -1)
		{
			DPA_ERROR("%s::%d member:%s already exists in the mcgroup \r\n",
					__FUNCTION__, __LINE__, pListener->output_device_str );
			iRet = -1;
			goto err_ret;    
		}

		DPA_INFO("%s(%d) creating table entry of mcast member %s\n",
				__FUNCTION__,__LINE__, pListener->output_device_str);

		if( (member_id = Cdx_GetMcastMemberFreeIndex(pMcastGrpInfo)) == -1)
		{
			DPA_ERROR("%s::%d Exceeding max members(%d) in the group \r\n",
					__FUNCTION__, __LINE__,MC_MAX_LISTENERS_PER_GROUP);
			iRet = -1;
			goto err_ret;
		}

		tbl_entry = create_exthash_entry4mcast_member(pRtEntry, pInsEntryInfo, pListener, NULL, tbl_type);
		if (!tbl_entry)
		{
			DPA_ERROR("%s(%d) : create_exthash_entry4mcast_member failed\n",
					__FUNCTION__, __LINE__);
			goto err_ret;
		}
		phyaddr = XX_VirtToPhys(tbl_entry);
		DPA_INFO("%s(%d) member_id %d, tbl_entry %p, phy_tbl_entry %p\n",
				__FUNCTION__,__LINE__, member_id, tbl_entry, (uint64_t *)phyaddr);
		if(pMcastGrpInfo->mctype == 0)
		{
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
		}
		else
		{
			uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
			spin_lock(&mc6_spinlocks[uiHash]);
		}
		pMcastGrpInfo->members[member_id].bIsValidEntry = 1;
		strncpy(pMcastGrpInfo->members[member_id].if_info, pListener->output_device_str,IF_NAME_SIZE-1);
		pMcastGrpInfo->members[member_id].member_id = member_id;
		pMcastGrpInfo->members[member_id].tbl_entry= tbl_entry;
		pMcastGrpInfo->uiListenerCnt++; 
		//fill next pointer info and link into chain
		//adjust the prev pointer in the old entry
		//fill next pointer physaddr for uCode

		cdx_exthash_update_first_mcast_member_addr((struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle, phyaddr,
				tbl_entry);
		if(pMcastGrpInfo->mctype == 0)
			spin_unlock(&mc4_spinlocks[uiHash]);
		else
			spin_unlock(&mc6_spinlocks[uiHash]);

	}

	tbl_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle;
#ifdef CDX_DPA_DEBUG
	{
		if (pMcastGrpInfo->mctype == 0)
			display_ehash_tbl_entry(&tbl_entry->hashentry, 10);
		else
			display_ehash_tbl_entry(&tbl_entry->hashentry, 34);
	}
#endif // CDX_DPA_DEBUG
err_ret:
	return iRet;
}

int cdx_delete_mcast_group_member( void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	int mcast_grpd, member_id;
	struct mcast_group_info  McastGrpInfo, *pMcastGrpInfo;
	int iRet = 0;
	MC4Output *pListener;
	int ii;
	unsigned int uiNoOfListeners, uiHash;
	struct mcast_group_info *pTempGrpInfo;
	struct en_exthash_tbl_entry *tbl_entry, *temp_entry;
	uint64_t phyaddr;
	struct en_ehash_replicate_param *replicate_params; 
	ucode_phyaddr_t tmp_val;

	mcast4_group = NULL;
	mcast6_group = NULL;

	if(bIsIPv6 == 0)
		mcast4_group =  (PMC4Command)mcast_cmd;
	else 
		mcast6_group =  (PMC6Command)mcast_cmd;

	pMcastGrpInfo = &McastGrpInfo;

	INIT_LIST_HEAD(&pMcastGrpInfo->list); 
	pMcastGrpInfo->mctype = bIsIPv6;
	if(pMcastGrpInfo->mctype == 0)
	{
		DPA_INFO("%s(%d) IPv4 \n",__FUNCTION__,__LINE__);
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		pMcastGrpInfo->mctype  = 0;
		uiNoOfListeners = mcast4_group->num_output;
		strncpy(pMcastGrpInfo->ucIngressIface,
				mcast4_group->input_device_str, IF_NAME_SIZE-1);
		DPA_INFO("%s(%d) listeners %d, Src IP addr 0x%x,Dst IP addr 0x%x\n",
				__FUNCTION__,__LINE__, uiNoOfListeners, mcast4_group->src_addr,
				mcast4_group->dst_addr);
	}
	else
	{
		DPA_INFO("%s(%d) IPv6 \n",__FUNCTION__,__LINE__);
		memcpy(pMcastGrpInfo->ipv6_saddr,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		pMcastGrpInfo->mctype  = 1;
		uiNoOfListeners = mcast6_group->num_output;
		strncpy(pMcastGrpInfo->ucIngressIface,
				mcast6_group->input_device_str, IF_NAME_SIZE-1);
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__FUNCTION__,__LINE__, uiNoOfListeners, mcast6_group->src_addr[0], mcast6_group->src_addr[1],
				mcast6_group->src_addr[2],mcast6_group->src_addr[3], 
				mcast6_group->dst_addr[0], mcast6_group->dst_addr[1],mcast6_group->dst_addr[2],
				mcast6_group->dst_addr[3]);
	}

	if((pTempGrpInfo = GetMcastGrp(pMcastGrpInfo)) == NULL)
	{
		DPA_ERROR("%s::%d multicast group does not exist \r\n", __FUNCTION__, __LINE__);
		iRet = -1;
		goto err_ret;
	}

	pMcastGrpInfo = pTempGrpInfo;

	mcast_grpd = pMcastGrpInfo->grpid;

	if(pMcastGrpInfo->uiListenerCnt == uiNoOfListeners)
	{
		//Delete entry in ct table;
		delete_entry_from_classif_table(pMcastGrpInfo->pCtEntry);
		cdx_free_exthash_mcast_members(pMcastGrpInfo);
		if(pMcastGrpInfo->pCtEntry)
		{
			if(pMcastGrpInfo->pCtEntry->pRtEntry)
				kfree(pMcastGrpInfo->pCtEntry->pRtEntry);
			kfree(pMcastGrpInfo->pCtEntry);
		}
		list_del(&(pMcastGrpInfo->list));
		kfree(pMcastGrpInfo);
		return 0;
	}


	for(ii=0 ; ii < uiNoOfListeners; ii++)
	{
		if(bIsIPv6)
			pListener = &(mcast6_group->output_list[ii]);
		else
			pListener = &(mcast4_group->output_list[ii]);

		if((member_id = Cdx_GetMcastMemberId(pListener->output_device_str ,pMcastGrpInfo)) == -1)
		{
			DPA_ERROR("%s::%d member:%s does not exist in the mcgroup \r\n",
					__FUNCTION__, __LINE__, pListener->output_device_str );
			iRet = -1;
			goto err_ret;    
		}

		if(pMcastGrpInfo->mctype == 0)
		{
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
		}
		else
		{
			uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
			spin_lock(&mc6_spinlocks[uiHash]);
		}
		tbl_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->members[member_id].tbl_entry;

		temp_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle;
		replicate_params = (struct en_ehash_replicate_param *)temp_entry->replicate_params;

		if (tbl_entry)
		{
			SET_INVALID_ENTRY(tbl_entry->hashentry.flags); // setting invalid flag
			if (tbl_entry == replicate_params->first_listener_entry)  // first listener
			{
				phyaddr = XX_VirtToPhys(tbl_entry->next);
				tmp_val.rsvd = 0;
				tmp_val.addr_hi = cpu_to_be16((phyaddr >> 32) & 0xffff);
				tmp_val.addr_lo = cpu_to_be32(phyaddr  & 0xffffffff);
				replicate_params->first_member_flow_addr =  tmp_val.addr;
				replicate_params->first_listener_entry = tbl_entry->next;
				if (tbl_entry->next)
					tbl_entry->next->prev = NULL;
			} 
			else 
			{
				temp_entry =  tbl_entry->prev;
				if (tbl_entry->next)
					(tbl_entry->next)->prev = temp_entry;
				temp_entry->next = tbl_entry->next;
				tmp_val.rsvd = temp_entry->hashentry.flags;
				tmp_val.addr_hi = tbl_entry->hashentry.next_entry_hi;
				tmp_val.addr_lo = tbl_entry->hashentry.next_entry_lo;
				temp_entry->hashentry.next_entry = tmp_val.addr;
			}
		}

		pMcastGrpInfo->members[member_id].bIsValidEntry = 0;
		pMcastGrpInfo->uiListenerCnt -= 1;
		pMcastGrpInfo->members[member_id].tbl_entry = NULL;
		if(pMcastGrpInfo->mctype == 0)
			spin_unlock(&mc4_spinlocks[uiHash]);
		else
			spin_unlock(&mc6_spinlocks[uiHash]);
		if (ExternalHashTableFmPcdHcSync(pMcastGrpInfo->pCtEntry->ct->td)) {
			DPA_ERROR("%s::FmPcdHcSync failed\n", __FUNCTION__);
			return -1;
		}
		ExternalHashTableEntryFree(tbl_entry);
	}

	tbl_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle;
#ifdef CDX_DPA_DEBUG
	if (pMcastGrpInfo->mctype == 0)
		display_ehash_tbl_entry(&tbl_entry->hashentry, 10);
	else
		display_ehash_tbl_entry(&tbl_entry->hashentry, 34);
#endif // CDX_DPA_DEBUG
err_ret:
	return iRet;
}


void cdx_exthash_update_first_mcast_member_addr(struct en_exthash_tbl_entry *temp_entry,
		uint64_t listener_phyaddr, 
		struct en_exthash_tbl_entry *listener)
{
	struct en_ehash_replicate_param *param = 
		(struct en_ehash_replicate_param *)temp_entry->replicate_params;
	struct en_exthash_tbl_entry *entry;
	ucode_phyaddr_t tmp_val;

	if (temp_entry->replicate_params)
	{
		listener->hashentry.next_entry_hi = param->first_member_flow_addr_hi;
		listener->hashentry.next_entry_lo = param->first_member_flow_addr_lo;
		tmp_val.rsvd = 0;
		tmp_val.addr_hi = cpu_to_be16((listener_phyaddr >> 32) & 0xffff);
		tmp_val.addr_lo = cpu_to_be32(listener_phyaddr  & 0xffffffff);
		param->first_member_flow_addr = tmp_val.addr;
		entry = (struct en_exthash_tbl_entry *)param->first_listener_entry;
		DPA_INFO("%s(%d) updated first_member_flow_addr %p, next_entry addr %p \n",
				__FUNCTION__,__LINE__,(uint64_t*)param->first_member_flow_addr,
				(uint64_t *)listener->hashentry.next_entry);
		if (entry)
		{
			entry->prev = listener;
		}
		listener->next = param->first_listener_entry;
		param->first_listener_entry = listener;
		return;

	}
}


static int MC6_Command_Handler(PMC6Command cmd)
{
	int rc = NO_ERR;
	int reset_action = 0;

	if(cmd->action != ACTION_QUERY && cmd->action != ACTION_QUERY_CONT)
	{
		if(cmd->num_output > MC6_MAX_LISTENERS_IN_QUERY) {
			*((unsigned short *)cmd)= ERR_MC_MAX_LISTENERS;
			return sizeof(unsigned short);
		}
	}

	switch(cmd->action)
	{
		case CDX_MC_ACTION_ADD:
			rc = cdx_create_mcast_group((void *)cmd,1);
			break;
		case CDX_MC_ACTION_REMOVE:
			rc = cdx_delete_mcast_group_member((void *)cmd, 1);
			break;
		case CDX_MC_ACTION_UPDATE:
			rc = cdx_update_mcast_group((void *)cmd, 1);
			break;
		case ACTION_QUERY:
			reset_action = 1;
			/* fall through */
		case ACTION_QUERY_CONT:
			rc = MC6_Get_Next_Hash_Entry(cmd, reset_action);
			if(rc == NO_ERR)
			{
				rc = sizeof(MC6Command);
			}
			else
			{
				*((unsigned short *)cmd)= rc;
				rc = sizeof(unsigned short);
			}
			goto out;
		default:
			DPA_ERROR("%s::%d Command:%d not yet handled in cdx \r\n", __FUNCTION__, __LINE__,cmd->action);
			rc = 0;
	}

	if ( rc == -1 )
		*((unsigned short *)cmd)= ERR_MC_CONFIG;
	else
		*((unsigned short *)cmd)= rc;

	rc = sizeof(unsigned short);

out:
	return rc;
}

static int MC4_Command_Handler(PMC4Command cmd)
{
	int rc = NO_ERR;
	int reset_action=0;

	/* some errors parsing on the command*/
	if(cmd->action != ACTION_QUERY && cmd->action != ACTION_QUERY_CONT)
	{
		if(cmd->num_output > MC4_MAX_LISTENERS_IN_QUERY) {
			*((unsigned short *)cmd) = ERR_MC_MAX_LISTENERS;
			return sizeof(unsigned short);
		}

		// IPv4 MC addresses must be 224.x.x.x through 239.x.x.x (i.e., high byte => 0xE0-0xEF)
		if ((ntohl(cmd->dst_addr) & 0xF0000000) != 0xE0000000)
		{
			DPA_ERROR("%s::%d \r\n", __FUNCTION__, __LINE__);
			*((unsigned short *)cmd) = ERR_MC_INVALID_ADDR;
			return sizeof(unsigned short);
		}
	}

	switch(cmd->action)
	{
		case CDX_MC_ACTION_ADD:
			rc = cdx_create_mcast_group((void*)cmd, 0);
			break;
		case CDX_MC_ACTION_REMOVE:
			rc = cdx_delete_mcast_group_member((void *)cmd, 0);
			break;
		case CDX_MC_ACTION_UPDATE:
			rc = cdx_update_mcast_group((void *)cmd, 0);
			break;
		case ACTION_QUERY:
			reset_action = 1;
			/* fall through */
		case ACTION_QUERY_CONT:
			rc = MC4_Get_Next_Hash_Entry(cmd, reset_action);
			if(rc == NO_ERR)
			{
				rc = sizeof(MC4Command);
			}
			else
			{
				*((unsigned short *)cmd)= rc;
				rc = sizeof(unsigned short);
			}
			goto out;
		default:
			DPA_ERROR("%s::%d Command:%d not yet handled in cdx \r\n", __FUNCTION__, __LINE__,cmd->action);
			rc = 0;
	}

	if ( rc == -1 )
		*((unsigned short *)cmd)= ERR_MC_CONFIG;
	else
		*((unsigned short *)cmd)= rc;

	rc = sizeof(unsigned short);

out:
	return rc;
}

U16 M_mc6_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc = NO_ERR;

	/* Check length */
	if ((cmd_len > sizeof(MC6Command)) || (cmd_len < MC6_MIN_COMMAND_SIZE)) {
		*pcmd = ERR_WRONG_COMMAND_SIZE;
		return sizeof(unsigned short);
	}

	switch(cmd_code)
	{
		case CMD_MC6_MULTICAST:
			rc = MC6_Command_Handler((MC6Command *)pcmd);
			break;

		default:
			DPA_ERROR("%s::%d invalid command code received \r\n", __FUNCTION__, __LINE__); 
	}
	return rc;
}

U16 M_mc4_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc = NO_ERR;

	/* Check length */
	if ((cmd_len > sizeof(MC4Command)) || (cmd_len < MC4_MIN_COMMAND_SIZE)) {
		*pcmd = ERR_WRONG_COMMAND_SIZE;
		return sizeof(unsigned short);
	}

	switch(cmd_code)
	{
		case CMD_MC4_MULTICAST:
			rc = MC4_Command_Handler((MC4Command  *)pcmd);
			break;

		default:
			DPA_ERROR("%s::%d invalid command code received \r\n", __FUNCTION__, __LINE__); 
	}
	return rc;
}

#define MAX_MC4_ENTRIES 512
#define MAX_MC6_ENTRIES 512
int mc4_init(void)
{
	int ii;

	set_cmd_handler(EVENT_MC4, M_mc4_cmdproc);
	mc4grp_ids = kzalloc((sizeof(uint8_t)*MAX_MC4_ENTRIES), 0);
	if (!mc4grp_ids)
	{
		return -ENOMEM;	
	}
	max_mc4grp_ids = MAX_MC4_ENTRIES;
	mc4_spinlocks = kzalloc((sizeof(spinlock_t) * MC4_NUM_HASH_ENTRIES), 0);
	if (!mc4_spinlocks)
	{
		kfree(mc4grp_ids);
		mc4grp_ids =  NULL;
		return -ENOMEM;
	}
	for (ii = 0; ii < MC4_NUM_HASH_ENTRIES; ii++)
	{
		INIT_LIST_HEAD(&mc4_grp_list[ii]);
		spin_lock_init(&mc4_spinlocks[ii]);
	}

	return 0;
}

int mc6_init(void)
{
	int ii;

	set_cmd_handler(EVENT_MC6, M_mc6_cmdproc);
	mc6grp_ids = kzalloc((sizeof(uint8_t)*MAX_MC6_ENTRIES), 0);
	if (!mc6grp_ids)
	{
		return -ENOMEM;	
	}
	max_mc6grp_ids = MAX_MC6_ENTRIES;
	mc6_spinlocks = kzalloc((sizeof(spinlock_t) * MC6_NUM_HASH_ENTRIES), 0);
	if (!mc6_spinlocks)
	{
		kfree(mc6grp_ids);
		mc6grp_ids =  NULL;
		return -ENOMEM;
	}
	for (ii = 0; ii < MC6_NUM_HASH_ENTRIES; ii++)
	{
		INIT_LIST_HEAD(&mc6_grp_list[ii]);
		spin_lock_init(&mc6_spinlocks[ii]);
	}

	return 0;
}

void mc4_exit(void)
{
	if (mc4_spinlocks)
	{
		kfree(mc4_spinlocks);
		mc4_spinlocks = NULL;
	} 
	if (mc4grp_ids)
	{
		kfree(mc4grp_ids);
		mc4grp_ids = NULL;
	}
	return; 
}

void mc6_exit(void)
{
	if (mc6_spinlocks)
	{
		kfree(mc6_spinlocks);
		mc6_spinlocks = NULL;
	}
	if (mc6grp_ids)
	{
		kfree(mc6grp_ids);
		mc6grp_ids = NULL;
	}

	return;
}
