/*
 * cdx_mc_freebsd.c — Multicast group management for FreeBSD
 *
 * Port of cdx-5.03.1/dpa_control_mc.c + cdx_mc_query.c.
 * Manages IPv4/IPv6 multicast group replication in FMan hardware.
 * CMM sends FCI commands (via cdx_cmdhandler) to create multicast
 * groups, add/remove listener members, and query group state.
 * Each listener gets an EHASH table entry linked in a chain;
 * FMan microcode walks the chain to replicate packets to all
 * listeners.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "portdefs.h"
#include "cdx.h"
#include "list.h"
#include "cdx_common.h"
#include "misc.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "dpa_control_mc.h"
#include "fm_ehash.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* ================================================================
 * Module-scope state
 * ================================================================ */

typedef union ucode_phyaddr_u {
	struct {
		uint16_t rsvd;
		uint16_t addr_hi;
		uint32_t addr_lo;
	};
	uint64_t addr;
} ucode_phyaddr_t;

struct list_head mc4_grp_list[MC4_NUM_HASH_ENTRIES];
struct list_head mc6_grp_list[MC6_NUM_HASH_ENTRIES];

extern uint64_t XX_VirtToPhys(void *addr);

static uint8_t *mc4grp_ids, *mc6grp_ids;
static spinlock_t *mc4_spinlocks, *mc6_spinlocks;
static uint16_t max_mc4grp_ids, max_mc6grp_ids;

#define MAX_MC4_ENTRIES	512
#define MAX_MC6_ENTRIES	512

/* Forward declarations */
static int cdx_free_exthash_mcast_members(
    struct mcast_group_info *pMcastGrpInfo);
int cdx_update_mcast_group(void *mcast_cmd, int bIsIPv6);

/* ================================================================
 * Group list management
 * ================================================================ */

void
AddToMcastGrpList(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int uiHash;

	if (pMcastGrpInfo->mctype == 0) {
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_add(&pMcastGrpInfo->list, &mc4_grp_list[uiHash]);
		spin_unlock(&mc4_spinlocks[uiHash]);
	} else {
		uiHash = HASH_MC6((void *)pMcastGrpInfo->ipv6_daddr);
		spin_lock(&mc6_spinlocks[uiHash]);
		list_add(&pMcastGrpInfo->list, &mc6_grp_list[uiHash]);
		spin_unlock(&mc6_spinlocks[uiHash]);
	}
}

int
GetMcastGrpId(struct mcast_group_info *pMcastGrpInfo,
    uint8_t *ingress_iface)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	unsigned int uiHash;

	if (pMcastGrpInfo->mctype == 0) {
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_for_each(ptr, &mc4_grp_list[uiHash]) {
			tmp = list_entry(ptr, struct mcast_group_info, list);
			if (tmp->ipv4_daddr == pMcastGrpInfo->ipv4_daddr &&
			    tmp->ipv4_saddr == pMcastGrpInfo->ipv4_saddr) {
				if (ingress_iface)
					strncpy((char *)ingress_iface,
					    tmp->ucIngressIface, IF_NAME_SIZE);
				spin_unlock(&mc4_spinlocks[uiHash]);
				return (tmp->grpid);
			}
		}
		spin_unlock(&mc4_spinlocks[uiHash]);
	} else {
		uiHash = HASH_MC6((void *)pMcastGrpInfo->ipv6_daddr);
		spin_lock(&mc6_spinlocks[uiHash]);
		list_for_each(ptr, &mc6_grp_list[uiHash]) {
			tmp = list_entry(ptr, struct mcast_group_info, list);
			if (!IPV6_CMP(tmp->ipv6_daddr,
			    pMcastGrpInfo->ipv6_daddr) &&
			    !IPV6_CMP(tmp->ipv6_saddr,
			    pMcastGrpInfo->ipv6_saddr)) {
				if (ingress_iface)
					strncpy((char *)ingress_iface,
					    tmp->ucIngressIface, IF_NAME_SIZE);
				spin_unlock(&mc6_spinlocks[uiHash]);
				return (tmp->grpid);
			}
		}
		spin_unlock(&mc6_spinlocks[uiHash]);
	}

	return (-1);
}

static int
GetNewMcastGrpId(uint8_t mctype)
{
	unsigned int ii;

	if (mctype == 0) {
		for (ii = 0; ii < max_mc4grp_ids; ii++) {
			if (!mc4grp_ids[ii]) {
				mc4grp_ids[ii] = 1;
				return (ii + 1);
			}
		}
	} else {
		for (ii = 0; ii < max_mc6grp_ids; ii++) {
			if (!mc6grp_ids[ii]) {
				mc6grp_ids[ii] = 1;
				return (ii + 1);
			}
		}
	}

	return (-1);
}

static void
FreeMcastGrpID(uint8_t mctype, int grp_id)
{

	if (mctype == 0) {
		if (grp_id > 0 && grp_id <= max_mc4grp_ids)
			mc4grp_ids[grp_id - 1] = 0;
	} else {
		if (grp_id > 0 && grp_id <= max_mc6grp_ids)
			mc6grp_ids[grp_id - 1] = 0;
	}
}

struct mcast_group_info *
GetMcastGrp(struct mcast_group_info *pMcastGrpInfo)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	unsigned int uiHash;

	if (pMcastGrpInfo->mctype == 0) {
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_for_each(ptr, &mc4_grp_list[uiHash]) {
			tmp = list_entry(ptr, struct mcast_group_info, list);
			if (tmp->ipv4_daddr == pMcastGrpInfo->ipv4_daddr &&
			    !strncmp(pMcastGrpInfo->ucIngressIface,
			    tmp->ucIngressIface, IF_NAME_SIZE) &&
			    tmp->ipv4_saddr == pMcastGrpInfo->ipv4_saddr) {
				spin_unlock(&mc4_spinlocks[uiHash]);
				return (tmp);
			}
		}
		spin_unlock(&mc4_spinlocks[uiHash]);
	} else {
		uiHash = HASH_MC6((void *)pMcastGrpInfo->ipv6_daddr);
		spin_lock(&mc6_spinlocks[uiHash]);
		list_for_each(ptr, &mc6_grp_list[uiHash]) {
			tmp = list_entry(ptr, struct mcast_group_info, list);
			if (!strncmp(pMcastGrpInfo->ucIngressIface,
			    tmp->ucIngressIface, IF_NAME_SIZE) &&
			    !IPV6_CMP(tmp->ipv6_daddr,
			    pMcastGrpInfo->ipv6_daddr) &&
			    !IPV6_CMP(tmp->ipv6_saddr,
			    pMcastGrpInfo->ipv6_saddr)) {
				spin_unlock(&mc6_spinlocks[uiHash]);
				return (tmp);
			}
		}
		spin_unlock(&mc6_spinlocks[uiHash]);
	}

	return (NULL);
}

static int
Cdx_GetMcastMemberId(char *pIn_Info,
    struct mcast_group_info *pMcastGrpInfo)
{
	int ii;
	struct mcast_group_member *pMember;
	unsigned int uiHash;

	if (pMcastGrpInfo == NULL)
		return (-1);

	if (pMcastGrpInfo->mctype == 0) {
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
	} else {
		uiHash = HASH_MC6((void *)pMcastGrpInfo->ipv6_daddr);
		spin_lock(&mc6_spinlocks[uiHash]);
	}

	for (ii = 0; ii < MC4_MAX_LISTENERS_PER_GROUP; ii++) {
		pMember = &pMcastGrpInfo->members[ii];
		if (pMember->bIsValidEntry == 1 &&
		    strcmp(pIn_Info, pMember->if_info) == 0) {
			if (pMcastGrpInfo->mctype == 0)
				spin_unlock(&mc4_spinlocks[uiHash]);
			else
				spin_unlock(&mc6_spinlocks[uiHash]);
			return (pMember->member_id);
		}
	}

	if (pMcastGrpInfo->mctype == 0)
		spin_unlock(&mc4_spinlocks[uiHash]);
	else
		spin_unlock(&mc6_spinlocks[uiHash]);

	return (-1);
}

static int
Cdx_GetMcastMemberFreeIndex(struct mcast_group_info *pMcastGrpInfo)
{
	int ii;
	struct mcast_group_member *pMember;
	unsigned int uiHash;

	if (pMcastGrpInfo == NULL)
		return (-1);

	if (pMcastGrpInfo->mctype == 0) {
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
	} else {
		uiHash = HASH_MC6((void *)pMcastGrpInfo->ipv6_daddr);
		spin_lock(&mc6_spinlocks[uiHash]);
	}

	for (ii = 0; ii < MC4_MAX_LISTENERS_PER_GROUP; ii++) {
		pMember = &pMcastGrpInfo->members[ii];
		if (pMember->bIsValidEntry == 0) {
			if (pMcastGrpInfo->mctype == 0)
				spin_unlock(&mc4_spinlocks[uiHash]);
			else
				spin_unlock(&mc6_spinlocks[uiHash]);
			return (ii);
		}
	}

	if (pMcastGrpInfo->mctype == 0)
		spin_unlock(&mc4_spinlocks[uiHash]);
	else
		spin_unlock(&mc6_spinlocks[uiHash]);

	return (-1);
}

/* ================================================================
 * EHASH table entry insertion for multicast
 * ================================================================ */

static int
cdx_add_mcast_table_entry(void *mcast_cmd,
    struct mcast_group_info *pMcastGrpInfo)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	RouteEntry *pRtEntry;
	POnifDesc onif_desc;
	struct _tCtEntry *pCtEntry;
	int retval, ii;
	uint64_t phyaddr;
	char ucInterface[IF_NAME_SIZE];

	pRtEntry = NULL;
	pCtEntry = NULL;
	mcast4_group = NULL;
	mcast6_group = NULL;

	if (mcast_cmd == NULL)
		return (FAILURE);

	if (pMcastGrpInfo->mctype == 0) {
		mcast4_group = (PMC4Command)mcast_cmd;
		strncpy(ucInterface, (char *)mcast4_group->input_device_str,
		    IF_NAME_SIZE - 1);
		ucInterface[IF_NAME_SIZE - 1] = '\0';
	} else {
		mcast6_group = (PMC6Command)mcast_cmd;
		strncpy(ucInterface, (char *)mcast6_group->input_device_str,
		    IF_NAME_SIZE - 1);
		ucInterface[IF_NAME_SIZE - 1] = '\0';
	}

	pRtEntry = kzalloc(sizeof(RouteEntry), 0);
	if (pRtEntry == NULL)
		return (-ENOMEM);

	pCtEntry = kzalloc(sizeof(struct _tCtEntry), 0);
	if (pCtEntry == NULL) {
		retval = -ENOMEM;
		goto err_ret;
	}

	pCtEntry->proto = IPPROTOCOL_UDP;
	pCtEntry->Sport = 0;
	pCtEntry->Dport = 0;

	if (pMcastGrpInfo->mctype == 0) {
		pCtEntry->Saddr_v4 = mcast4_group->src_addr;
		pCtEntry->Daddr_v4 = mcast4_group->dst_addr;
		pCtEntry->twin_Daddr = pCtEntry->Saddr_v4;
		pCtEntry->twin_Saddr = pCtEntry->Daddr_v4;
		pCtEntry->fftype = FFTYPE_IPV4;
	} else {
		memcpy(pCtEntry->Saddr_v6, mcast6_group->src_addr,
		    IPV6_ADDRESS_LENGTH);
		memcpy(pCtEntry->Daddr_v6, mcast6_group->dst_addr,
		    IPV6_ADDRESS_LENGTH);
		pCtEntry->fftype = FFTYPE_IPV6;
	}

	onif_desc = get_onif_by_name(ucInterface);
	if (onif_desc == NULL) {
		DPA_ERROR("%s: unable to get onif for iface %s\n",
		    __func__, ucInterface);
		retval = -EIO;
		goto err_ret;
	}

	pRtEntry->itf = onif_desc->itf;
	pRtEntry->input_itf = onif_desc->itf;
	pRtEntry->underlying_input_itf = pRtEntry->input_itf;
	pCtEntry->pRtEntry = pRtEntry;

	phyaddr = 0;
	for (ii = 0; ii < (int)pMcastGrpInfo->uiListenerCnt; ii++) {
		if (pMcastGrpInfo->members[ii].bIsValidEntry) {
			phyaddr = XX_VirtToPhys(
			    pMcastGrpInfo->members[ii].tbl_entry);
			break;
		}
	}

	retval = insert_mcast_entry_in_classif_table(pCtEntry,
	    pMcastGrpInfo->uiListenerCnt, phyaddr,
	    pMcastGrpInfo->members[ii].tbl_entry);
	if (retval != 0) {
		DPA_ERROR("%s: insert mcast entry failed\n", __func__);
		goto err_ret;
	}

	pMcastGrpInfo->pCtEntry = pCtEntry;
	return (retval);

err_ret:
	if (pRtEntry != NULL)
		kfree(pRtEntry);
	if (pCtEntry != NULL)
		kfree(pCtEntry);
	return (retval);
}

/* ================================================================
 * Group create / update / delete
 * ================================================================ */

int
cdx_create_mcast_group(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	MC4Output *pListener;
	RouteEntry RtEntry, *pRtEntry;
	int iRet, ii, member_id;
	struct ins_entry_info InsEntryInfo, *pInsEntryInfo;
	struct mcast_group_info *pMcastGrpInfo;
	unsigned int uiNoOfListeners;
	char *pInIface;
	uint8_t IngressIface[IF_NAME_SIZE];
	struct en_exthash_tbl_entry *tbl_entry;
	uint32_t tbl_type;

	iRet = 0;
	tbl_entry = NULL;

	pMcastGrpInfo = kzalloc(sizeof(struct mcast_group_info), 0);
	if (pMcastGrpInfo == NULL) {
		DPA_ERROR("%s: failed to allocate memory\n", __func__);
		return (ERR_NOT_ENOUGH_MEMORY);
	}

	INIT_LIST_HEAD(&pMcastGrpInfo->list);
	pMcastGrpInfo->mctype = bIsIPv6;

	if (pMcastGrpInfo->mctype == 0) {
		mcast4_group = (PMC4Command)mcast_cmd;
		mcast6_group = NULL;
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		uiNoOfListeners = mcast4_group->num_output;
		pInIface = (char *)mcast4_group->input_device_str;
		DPA_INFO("cdx: mc: create v4 group — listeners=%u "
		    "src=0x%x dst=0x%x\n",
		    uiNoOfListeners, mcast4_group->src_addr,
		    mcast4_group->dst_addr);
	} else {
		mcast4_group = NULL;
		mcast6_group = (PMC6Command)mcast_cmd;
		memcpy(pMcastGrpInfo->ipv6_saddr, mcast6_group->src_addr,
		    IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr, mcast6_group->dst_addr,
		    IPV6_ADDRESS_LENGTH);
		uiNoOfListeners = mcast6_group->num_output;
		pInIface = (char *)mcast6_group->input_device_str;
		DPA_INFO("cdx: mc: create v6 group — listeners=%u\n",
		    uiNoOfListeners);
	}

	pMcastGrpInfo->grpid = -1;
	strncpy(pMcastGrpInfo->ucIngressIface, pInIface, IF_NAME_SIZE - 1);
	pMcastGrpInfo->ucIngressIface[IF_NAME_SIZE - 1] = '\0';

	if (uiNoOfListeners > MC_MAX_LISTENERS_PER_GROUP) {
		DPA_ERROR("%s: exceeding max members (%d) in group\n",
		    __func__, MC_MAX_LISTENERS_PER_GROUP);
		iRet = ERR_MC_MAX_LISTENERS_PER_GROUP;
		goto err_ret;
	}

	iRet = GetMcastGrpId(pMcastGrpInfo, IngressIface);
	if (iRet != -1) {
		if (strncmp(pMcastGrpInfo->ucIngressIface,
		    (char *)IngressIface, IF_NAME_SIZE)) {
			DPA_ERROR("%s: multiple ingress interfaces "
			    "(%s, existing %s) not allowed for same "
			    "src/dst IP pair\n", __func__,
			    pMcastGrpInfo->ucIngressIface, IngressIface);
			iRet = -1;
			goto err_ret;
		}
		kfree(pMcastGrpInfo);
		return (cdx_update_mcast_group(mcast_cmd, bIsIPv6));
	}

	pMcastGrpInfo->grpid = GetNewMcastGrpId(pMcastGrpInfo->mctype);
	if (pMcastGrpInfo->grpid == -1) {
		DPA_ERROR("%s: exceeding max number of multicast entries\n",
		    __func__);
		goto err_ret;
	}

	memset(&InsEntryInfo, 0, sizeof(struct ins_entry_info));
	pInsEntryInfo = &InsEntryInfo;
	memset(&RtEntry, 0, sizeof(RouteEntry));
	pRtEntry = &RtEntry;

	if (pMcastGrpInfo->mctype == 0) {
		pRtEntry->dstmac[0] = 0x01;
		pRtEntry->dstmac[1] = 0x00;
		pRtEntry->dstmac[2] = 0x5E;
		pRtEntry->dstmac[3] = (mcast4_group->dst_addr >> 8) & 0x7f;
		pRtEntry->dstmac[4] = (mcast4_group->dst_addr >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast4_group->dst_addr >> 24) & 0xff;
		tbl_type = IPV4_MULTICAST_TABLE;
	} else {
		pRtEntry->dstmac[0] = 0x33;
		pRtEntry->dstmac[1] = 0x33;
		pRtEntry->dstmac[2] = mcast6_group->dst_addr[3] & 0xff;
		pRtEntry->dstmac[3] = (mcast6_group->dst_addr[3] >> 8) & 0xff;
		pRtEntry->dstmac[4] = (mcast6_group->dst_addr[3] >> 16) &
		    0xff;
		pRtEntry->dstmac[5] = (mcast6_group->dst_addr[3] >> 24) &
		    0xff;
		tbl_type = IPV6_MULTICAST_TABLE;
	}

	pMcastGrpInfo->uiListenerCnt = 0;
	member_id = 0;

	for (ii = 0; ii < (int)uiNoOfListeners; ii++) {
		if (pMcastGrpInfo->mctype == 0)
			pListener = &mcast4_group->output_list[ii];
		else
			pListener = &mcast6_group->output_list[ii];

		DPA_INFO("cdx: mc: creating table entry for member %s\n",
		    pListener->output_device_str);

		tbl_entry = create_exthash_entry4mcast_member(pRtEntry,
		    pInsEntryInfo, pListener, tbl_entry, tbl_type);
		if (tbl_entry == NULL) {
			DPA_ERROR("%s: create_exthash_entry4mcast_member "
			    "failed\n", __func__);
			goto err_ret;
		}

		pMcastGrpInfo->members[member_id].bIsValidEntry = 1;
		strncpy(pMcastGrpInfo->members[member_id].if_info,
		    (char *)pListener->output_device_str, IF_NAME_SIZE - 1);
		pMcastGrpInfo->members[member_id].if_info[IF_NAME_SIZE - 1] =
		    '\0';
		pMcastGrpInfo->members[member_id].member_id = member_id;
		pMcastGrpInfo->members[member_id].tbl_entry = tbl_entry;
		pMcastGrpInfo->uiListenerCnt++;
		member_id++;
	}

	if (pMcastGrpInfo->mctype == 0)
		iRet = cdx_add_mcast_table_entry(mcast4_group, pMcastGrpInfo);
	else
		iRet = cdx_add_mcast_table_entry(mcast6_group, pMcastGrpInfo);

	if (iRet != 0) {
		DPA_ERROR("%s: adding mcast table entry failed\n", __func__);
		goto err_ret;
	}

	AddToMcastGrpList(pMcastGrpInfo);
	return (0);

err_ret:
	if (pMcastGrpInfo != NULL) {
		cdx_free_exthash_mcast_members(pMcastGrpInfo);
		kfree(pMcastGrpInfo);
	}
	return (iRet);
}

static int
cdx_free_exthash_mcast_members(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int ii;

	FreeMcastGrpID(pMcastGrpInfo->mctype, pMcastGrpInfo->grpid);
	for (ii = 0; ii < pMcastGrpInfo->uiListenerCnt; ii++) {
		if (pMcastGrpInfo->members[ii].tbl_entry != NULL)
			ExternalHashTableEntryFree(
			    pMcastGrpInfo->members[ii].tbl_entry);
	}

	return (0);
}

static void
cdx_exthash_update_first_mcast_member_addr(
    struct en_exthash_tbl_entry *temp_entry,
    uint64_t listener_phyaddr,
    struct en_exthash_tbl_entry *listener)
{
	struct en_ehash_replicate_param *param;
	struct en_exthash_tbl_entry *entry;
	ucode_phyaddr_t tmp_val;

	param = (struct en_ehash_replicate_param *)temp_entry->replicate_params;
	if (param == NULL)
		return;

	listener->hashentry.next_entry_hi = param->first_member_flow_addr_hi;
	listener->hashentry.next_entry_lo = param->first_member_flow_addr_lo;

	tmp_val.rsvd = 0;
	tmp_val.addr_hi = cpu_to_be16((listener_phyaddr >> 32) & 0xffff);
	tmp_val.addr_lo = cpu_to_be32(listener_phyaddr & 0xffffffff);
	param->first_member_flow_addr = tmp_val.addr;

	entry = (struct en_exthash_tbl_entry *)param->first_listener_entry;
	if (entry != NULL)
		entry->prev = listener;

	listener->next = param->first_listener_entry;
	param->first_listener_entry = listener;
}

int
cdx_update_mcast_group(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	RouteEntry RtEntry, *pRtEntry;
	struct ins_entry_info InsEntryInfo, *pInsEntryInfo;
	struct mcast_group_info McastGrpInfo, *pMcastGrpInfo;
	struct mcast_group_info *pTempGrpInfo;
	struct en_exthash_tbl_entry *tbl_entry;
	unsigned int uiNoOfListeners, uiHash;
	int iRet, ii, member_id;
	MC4Output *pListener;
	char *pInIface;
	uint32_t tbl_type;
	uint64_t phyaddr;

	memset(&InsEntryInfo, 0, sizeof(struct ins_entry_info));
	pInsEntryInfo = &InsEntryInfo;
	pRtEntry = &RtEntry;
	mcast4_group = NULL;
	mcast6_group = NULL;
	iRet = 0;
	tbl_entry = NULL;

	if (bIsIPv6)
		mcast6_group = (PMC6Command)mcast_cmd;
	else
		mcast4_group = (PMC4Command)mcast_cmd;

	pMcastGrpInfo = &McastGrpInfo;
	memset(pMcastGrpInfo, 0, sizeof(struct mcast_group_info));

	pMcastGrpInfo->mctype = bIsIPv6;
	if (pMcastGrpInfo->mctype == 0) {
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		uiNoOfListeners = mcast4_group->num_output;
		pInIface = (char *)mcast4_group->input_device_str;
	} else {
		memcpy(pMcastGrpInfo->ipv6_saddr, mcast6_group->src_addr,
		    IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr, mcast6_group->dst_addr,
		    IPV6_ADDRESS_LENGTH);
		uiNoOfListeners = mcast6_group->num_output;
		pInIface = (char *)mcast6_group->input_device_str;
	}
	strncpy(pMcastGrpInfo->ucIngressIface, pInIface, IF_NAME_SIZE - 1);
	pMcastGrpInfo->ucIngressIface[IF_NAME_SIZE - 1] = '\0';

	pTempGrpInfo = GetMcastGrp(pMcastGrpInfo);
	if (pTempGrpInfo == NULL) {
		DPA_ERROR("%s: multicast group does not exist\n", __func__);
		return (-1);
	}

	pMcastGrpInfo = pTempGrpInfo;

	if (uiNoOfListeners + pMcastGrpInfo->uiListenerCnt >
	    MC_MAX_LISTENERS_PER_GROUP) {
		DPA_ERROR("%s: exceeding max members (%d) in group\n",
		    __func__, MC_MAX_LISTENERS_PER_GROUP);
		return (ERR_MC_MAX_LISTENERS_PER_GROUP);
	}

	if (!bIsIPv6) {
		pRtEntry->dstmac[0] = 0x01;
		pRtEntry->dstmac[1] = 0x00;
		pRtEntry->dstmac[2] = 0x5E;
		pRtEntry->dstmac[3] = (mcast4_group->dst_addr >> 8) & 0x7f;
		pRtEntry->dstmac[4] = (mcast4_group->dst_addr >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast4_group->dst_addr >> 24) & 0xff;
		tbl_type = IPV4_MULTICAST_TABLE;
	} else {
		pRtEntry->dstmac[0] = 0x33;
		pRtEntry->dstmac[1] = 0x33;
		pRtEntry->dstmac[2] = mcast6_group->dst_addr[3] & 0xff;
		pRtEntry->dstmac[3] = (mcast6_group->dst_addr[3] >> 8) & 0xff;
		pRtEntry->dstmac[4] = (mcast6_group->dst_addr[3] >> 16) &
		    0xff;
		pRtEntry->dstmac[5] = (mcast6_group->dst_addr[3] >> 24) &
		    0xff;
		tbl_type = IPV6_MULTICAST_TABLE;
	}

	for (ii = 0; ii < (int)uiNoOfListeners; ii++) {
		if (bIsIPv6)
			pListener = &mcast6_group->output_list[ii];
		else
			pListener = &mcast4_group->output_list[ii];

		member_id = Cdx_GetMcastMemberId(
		    (char *)pListener->output_device_str, pMcastGrpInfo);
		if (member_id != -1) {
			DPA_ERROR("%s: member %s already exists in group\n",
			    __func__, pListener->output_device_str);
			iRet = -1;
			goto err_ret;
		}

		member_id = Cdx_GetMcastMemberFreeIndex(pMcastGrpInfo);
		if (member_id == -1) {
			DPA_ERROR("%s: exceeding max members (%d) in group\n",
			    __func__, MC_MAX_LISTENERS_PER_GROUP);
			iRet = -1;
			goto err_ret;
		}

		tbl_entry = create_exthash_entry4mcast_member(pRtEntry,
		    pInsEntryInfo, pListener, NULL, tbl_type);
		if (tbl_entry == NULL) {
			DPA_ERROR("%s: create_exthash_entry4mcast_member "
			    "failed\n", __func__);
			goto err_ret;
		}

		phyaddr = XX_VirtToPhys(tbl_entry);

		if (pMcastGrpInfo->mctype == 0) {
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
		} else {
			uiHash = HASH_MC6(
			    (void *)pMcastGrpInfo->ipv6_daddr);
			spin_lock(&mc6_spinlocks[uiHash]);
		}

		pMcastGrpInfo->members[member_id].bIsValidEntry = 1;
		strncpy(pMcastGrpInfo->members[member_id].if_info,
		    (char *)pListener->output_device_str, IF_NAME_SIZE - 1);
		pMcastGrpInfo->members[member_id].if_info[IF_NAME_SIZE - 1] =
		    '\0';
		pMcastGrpInfo->members[member_id].member_id = member_id;
		pMcastGrpInfo->members[member_id].tbl_entry = tbl_entry;
		pMcastGrpInfo->uiListenerCnt++;

		cdx_exthash_update_first_mcast_member_addr(
		    (struct en_exthash_tbl_entry *)
		    pMcastGrpInfo->pCtEntry->ct->handle,
		    phyaddr, tbl_entry);

		if (pMcastGrpInfo->mctype == 0)
			spin_unlock(&mc4_spinlocks[uiHash]);
		else
			spin_unlock(&mc6_spinlocks[uiHash]);
	}

err_ret:
	return (iRet);
}

int
cdx_delete_mcast_group_member(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	int member_id;
	struct mcast_group_info McastGrpInfo, *pMcastGrpInfo;
	struct mcast_group_info *pTempGrpInfo;
	int iRet, ii;
	MC4Output *pListener;
	unsigned int uiNoOfListeners, uiHash;
	struct en_exthash_tbl_entry *tbl_entry, *temp_entry;
	uint64_t phyaddr;
	struct en_ehash_replicate_param *replicate_params;
	ucode_phyaddr_t tmp_val;

	mcast4_group = NULL;
	mcast6_group = NULL;
	iRet = 0;

	if (bIsIPv6 == 0)
		mcast4_group = (PMC4Command)mcast_cmd;
	else
		mcast6_group = (PMC6Command)mcast_cmd;

	pMcastGrpInfo = &McastGrpInfo;
	INIT_LIST_HEAD(&pMcastGrpInfo->list);
	pMcastGrpInfo->mctype = bIsIPv6;

	if (pMcastGrpInfo->mctype == 0) {
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		uiNoOfListeners = mcast4_group->num_output;
		strncpy(pMcastGrpInfo->ucIngressIface,
		    (char *)mcast4_group->input_device_str, IF_NAME_SIZE - 1);
		pMcastGrpInfo->ucIngressIface[IF_NAME_SIZE - 1] = '\0';
	} else {
		memcpy(pMcastGrpInfo->ipv6_saddr, mcast6_group->src_addr,
		    IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr, mcast6_group->dst_addr,
		    IPV6_ADDRESS_LENGTH);
		uiNoOfListeners = mcast6_group->num_output;
		strncpy(pMcastGrpInfo->ucIngressIface,
		    (char *)mcast6_group->input_device_str, IF_NAME_SIZE - 1);
		pMcastGrpInfo->ucIngressIface[IF_NAME_SIZE - 1] = '\0';
	}

	pTempGrpInfo = GetMcastGrp(pMcastGrpInfo);
	if (pTempGrpInfo == NULL) {
		DPA_ERROR("%s: multicast group does not exist\n", __func__);
		return (-1);
	}

	pMcastGrpInfo = pTempGrpInfo;

	/* If removing all listeners, delete the entire group */
	if (pMcastGrpInfo->uiListenerCnt == uiNoOfListeners) {
		delete_entry_from_classif_table(pMcastGrpInfo->pCtEntry);
		cdx_free_exthash_mcast_members(pMcastGrpInfo);
		if (pMcastGrpInfo->pCtEntry != NULL) {
			if (pMcastGrpInfo->pCtEntry->pRtEntry != NULL)
				kfree(pMcastGrpInfo->pCtEntry->pRtEntry);
			kfree(pMcastGrpInfo->pCtEntry);
		}
		list_del(&pMcastGrpInfo->list);
		kfree(pMcastGrpInfo);
		return (0);
	}

	/* Remove individual listeners */
	for (ii = 0; ii < (int)uiNoOfListeners; ii++) {
		if (bIsIPv6)
			pListener = &mcast6_group->output_list[ii];
		else
			pListener = &mcast4_group->output_list[ii];

		member_id = Cdx_GetMcastMemberId(
		    (char *)pListener->output_device_str, pMcastGrpInfo);
		if (member_id == -1) {
			DPA_ERROR("%s: member %s does not exist in group\n",
			    __func__, pListener->output_device_str);
			iRet = -1;
			goto err_ret;
		}

		if (pMcastGrpInfo->mctype == 0) {
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
		} else {
			uiHash = HASH_MC6(
			    (void *)pMcastGrpInfo->ipv6_daddr);
			spin_lock(&mc6_spinlocks[uiHash]);
		}

		tbl_entry = (struct en_exthash_tbl_entry *)
		    pMcastGrpInfo->members[member_id].tbl_entry;
		temp_entry = (struct en_exthash_tbl_entry *)
		    pMcastGrpInfo->pCtEntry->ct->handle;
		replicate_params = (struct en_ehash_replicate_param *)
		    temp_entry->replicate_params;

		if (tbl_entry != NULL) {
			SET_INVALID_ENTRY(tbl_entry->hashentry.flags);

			if (tbl_entry ==
			    replicate_params->first_listener_entry) {
				/* Removing first listener */
				phyaddr = XX_VirtToPhys(tbl_entry->next);
				tmp_val.rsvd = 0;
				tmp_val.addr_hi = cpu_to_be16(
				    (phyaddr >> 32) & 0xffff);
				tmp_val.addr_lo = cpu_to_be32(
				    phyaddr & 0xffffffff);
				replicate_params->first_member_flow_addr =
				    tmp_val.addr;
				replicate_params->first_listener_entry =
				    tbl_entry->next;
				if (tbl_entry->next != NULL)
					tbl_entry->next->prev = NULL;
			} else {
				/* Removing non-first listener */
				temp_entry = tbl_entry->prev;
				if (tbl_entry->next != NULL)
					tbl_entry->next->prev = temp_entry;
				temp_entry->next = tbl_entry->next;
				tmp_val.rsvd = temp_entry->hashentry.flags;
				tmp_val.addr_hi =
				    tbl_entry->hashentry.next_entry_hi;
				tmp_val.addr_lo =
				    tbl_entry->hashentry.next_entry_lo;
				temp_entry->hashentry.next_entry = tmp_val.addr;
			}
		}

		pMcastGrpInfo->members[member_id].bIsValidEntry = 0;
		pMcastGrpInfo->uiListenerCnt -= 1;
		pMcastGrpInfo->members[member_id].tbl_entry = NULL;

		if (pMcastGrpInfo->mctype == 0)
			spin_unlock(&mc4_spinlocks[uiHash]);
		else
			spin_unlock(&mc6_spinlocks[uiHash]);

		if (ExternalHashTableFmPcdHcSync(
		    pMcastGrpInfo->pCtEntry->ct->td)) {
			DPA_ERROR("%s: FmPcdHcSync failed\n", __func__);
			return (-1);
		}

		ExternalHashTableEntryFree(tbl_entry);
	}

err_ret:
	return (iRet);
}

/* ================================================================
 * Command handlers — dispatched by cdx_cmdhandler_freebsd.c
 * ================================================================ */

static int
MC4_Command_Handler(PMC4Command cmd)
{
	int rc, reset_action;

	rc = NO_ERR;
	reset_action = 0;

	if (cmd->action != ACTION_QUERY && cmd->action != ACTION_QUERY_CONT) {
		if (cmd->num_output > MC4_MAX_LISTENERS_IN_QUERY) {
			*((unsigned short *)cmd) = ERR_MC_MAX_LISTENERS;
			return (sizeof(unsigned short));
		}

		/* IPv4 MC addresses must be 224.x.x.x - 239.x.x.x */
		if ((ntohl(cmd->dst_addr) & 0xF0000000) != 0xE0000000) {
			*((unsigned short *)cmd) = ERR_MC_INVALID_ADDR;
			return (sizeof(unsigned short));
		}
	}

	switch (cmd->action) {
	case CDX_MC_ACTION_ADD:
		rc = cdx_create_mcast_group((void *)cmd, 0);
		break;
	case CDX_MC_ACTION_REMOVE:
		rc = cdx_delete_mcast_group_member((void *)cmd, 0);
		break;
	case CDX_MC_ACTION_UPDATE:
		rc = cdx_update_mcast_group((void *)cmd, 0);
		break;
	case ACTION_QUERY:
		reset_action = 1;
		/* FALLTHROUGH */
	case ACTION_QUERY_CONT:
		rc = MC4_Get_Next_Hash_Entry(cmd, reset_action);
		if (rc == NO_ERR)
			rc = sizeof(MC4Command);
		else {
			*((unsigned short *)cmd) = rc;
			rc = sizeof(unsigned short);
		}
		return (rc);
	default:
		DPA_ERROR("%s: command %d not handled\n", __func__,
		    cmd->action);
		rc = 0;
	}

	if (rc == -1)
		*((unsigned short *)cmd) = ERR_MC_CONFIG;
	else
		*((unsigned short *)cmd) = rc;

	return (sizeof(unsigned short));
}

static int
MC6_Command_Handler(PMC6Command cmd)
{
	int rc, reset_action;

	rc = NO_ERR;
	reset_action = 0;

	if (cmd->action != ACTION_QUERY && cmd->action != ACTION_QUERY_CONT) {
		if (cmd->num_output > MC6_MAX_LISTENERS_IN_QUERY) {
			*((unsigned short *)cmd) = ERR_MC_MAX_LISTENERS;
			return (sizeof(unsigned short));
		}
	}

	switch (cmd->action) {
	case CDX_MC_ACTION_ADD:
		rc = cdx_create_mcast_group((void *)cmd, 1);
		break;
	case CDX_MC_ACTION_REMOVE:
		rc = cdx_delete_mcast_group_member((void *)cmd, 1);
		break;
	case CDX_MC_ACTION_UPDATE:
		rc = cdx_update_mcast_group((void *)cmd, 1);
		break;
	case ACTION_QUERY:
		reset_action = 1;
		/* FALLTHROUGH */
	case ACTION_QUERY_CONT:
		rc = MC6_Get_Next_Hash_Entry(cmd, reset_action);
		if (rc == NO_ERR)
			rc = sizeof(MC6Command);
		else {
			*((unsigned short *)cmd) = rc;
			rc = sizeof(unsigned short);
		}
		return (rc);
	default:
		DPA_ERROR("%s: command %d not handled\n", __func__,
		    cmd->action);
		rc = 0;
	}

	if (rc == -1)
		*((unsigned short *)cmd) = ERR_MC_CONFIG;
	else
		*((unsigned short *)cmd) = rc;

	return (sizeof(unsigned short));
}

U16
M_mc4_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{

	if (cmd_len > sizeof(MC4Command) || cmd_len < MC4_MIN_COMMAND_SIZE) {
		*pcmd = ERR_WRONG_COMMAND_SIZE;
		return (sizeof(unsigned short));
	}

	switch (cmd_code) {
	case CMD_MC4_MULTICAST:
		return (MC4_Command_Handler((MC4Command *)pcmd));
	default:
		DPA_ERROR("%s: invalid command code 0x%x\n", __func__,
		    cmd_code);
		return (0);
	}
}

U16
M_mc6_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{

	if (cmd_len > sizeof(MC6Command) || cmd_len < MC6_MIN_COMMAND_SIZE) {
		*pcmd = ERR_WRONG_COMMAND_SIZE;
		return (sizeof(unsigned short));
	}

	switch (cmd_code) {
	case CMD_MC6_MULTICAST:
		return (MC6_Command_Handler((MC6Command *)pcmd));
	default:
		DPA_ERROR("%s: invalid command code 0x%x\n", __func__,
		    cmd_code);
		return (0);
	}
}

/* ================================================================
 * Query snapshot functions (from cdx_mc_query.c)
 * ================================================================ */

static int
MC4_Get_Hash_Entries(int mc4_hash_index)
{
	int tot_entries;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	tot_entries = 0;
	list_for_each(ptr, &mc4_grp_list[mc4_hash_index]) {
		pMcastGrpInfo = list_entry(ptr, struct mcast_group_info, list);
		tot_entries++;
		if (pMcastGrpInfo->uiListenerCnt > MC4_MAX_LISTENERS_IN_QUERY)
			tot_entries++;
	}

	return (tot_entries);
}

static int
MC4_Get_Hash_Snapshot(int mc4_hash_index, int mc4_tot_entries,
    PMC4Command pMC4Snapshot)
{
	int tot_entries, i, j;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	tot_entries = 0;
	list_for_each(ptr, &mc4_grp_list[mc4_hash_index]) {
		pMcastGrpInfo = list_entry(ptr, struct mcast_group_info, list);

		memset(pMC4Snapshot, 0, sizeof(MC4Command));
		pMC4Snapshot->src_addr = pMcastGrpInfo->ipv4_saddr;
		pMC4Snapshot->dst_addr = pMcastGrpInfo->ipv4_daddr;
		strncpy((char *)pMC4Snapshot->input_device_str,
		    pMcastGrpInfo->ucIngressIface, IF_NAME_SIZE - 1);

		for (i = 0, j = 0; j < MC_MAX_LISTENERS_PER_GROUP; j++) {
			if (!pMcastGrpInfo->members[j].bIsValidEntry)
				continue;
			strncpy(
			    (char *)pMC4Snapshot->output_list[i].
			    output_device_str,
			    pMcastGrpInfo->members[j].if_info,
			    IF_NAME_SIZE - 1);
			if (++i >= MC4_MAX_LISTENERS_IN_QUERY &&
			    pMcastGrpInfo->uiListenerCnt - i > 0) {
				pMC4Snapshot->num_output =
				    MC4_MAX_LISTENERS_IN_QUERY;
				pMC4Snapshot++;
				tot_entries++;
				mc4_tot_entries--;
				i = 0;
				memset(pMC4Snapshot, 0, sizeof(MC4Command));
			}
		}
		pMC4Snapshot->num_output = i;
		pMC4Snapshot++;
		tot_entries++;
		mc4_tot_entries--;
		if (mc4_tot_entries == 0)
			break;
	}

	return (tot_entries);
}

int
MC4_Get_Next_Hash_Entry(PMC4Command pMC4Cmd, int reset_action)
{
	int mc4_hash_entries;
	PMC4Command pMC4;
	static PMC4Command pMC4Snapshot;
	static int mc4_hash_index, mc4_snapshot_entries;
	static int mc4_snapshot_index, mc4_snapshot_buf_entries;

	if (reset_action) {
		mc4_hash_index = 0;
		mc4_snapshot_entries = 0;
		mc4_snapshot_index = 0;
		if (pMC4Snapshot != NULL) {
			Heap_Free(pMC4Snapshot);
			pMC4Snapshot = NULL;
		}
		mc4_snapshot_buf_entries = 0;
	}

	if (mc4_snapshot_index == 0) {
		while (mc4_hash_index < MC4_NUM_HASH_ENTRIES) {
			mc4_hash_entries =
			    MC4_Get_Hash_Entries(mc4_hash_index);
			if (mc4_hash_entries == 0) {
				mc4_hash_index++;
				continue;
			}

			if (mc4_hash_entries > mc4_snapshot_buf_entries) {
				if (pMC4Snapshot != NULL)
					Heap_Free(pMC4Snapshot);
				pMC4Snapshot = Heap_Alloc(mc4_hash_entries *
				    sizeof(MC4Command));
				if (pMC4Snapshot == NULL) {
					mc4_hash_index = 0;
					mc4_snapshot_buf_entries = 0;
					return (ERR_NOT_ENOUGH_MEMORY);
				}
				mc4_snapshot_buf_entries = mc4_hash_entries;
			}

			mc4_snapshot_entries = MC4_Get_Hash_Snapshot(
			    mc4_hash_index, mc4_hash_entries, pMC4Snapshot);
			break;
		}

		if (mc4_hash_index >= MC4_NUM_HASH_ENTRIES) {
			mc4_hash_index = 0;
			if (pMC4Snapshot != NULL) {
				Heap_Free(pMC4Snapshot);
				pMC4Snapshot = NULL;
			}
			mc4_snapshot_buf_entries = 0;
			return (ERR_MC_ENTRY_NOT_FOUND);
		}
	}

	pMC4 = &pMC4Snapshot[mc4_snapshot_index++];
	memcpy(pMC4Cmd, pMC4, sizeof(MC4Command));
	if (mc4_snapshot_index == mc4_snapshot_entries) {
		mc4_snapshot_index = 0;
		mc4_hash_index++;
	}

	return (NO_ERR);
}

static int
MC6_Get_Hash_Entries(int mc6_hash_index)
{
	int tot_entries;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	tot_entries = 0;
	list_for_each(ptr, &mc6_grp_list[mc6_hash_index]) {
		pMcastGrpInfo = list_entry(ptr, struct mcast_group_info, list);
		tot_entries++;
		if (pMcastGrpInfo->uiListenerCnt > MC4_MAX_LISTENERS_IN_QUERY)
			tot_entries++;
	}

	return (tot_entries);
}

static int
MC6_Get_Hash_Snapshot(int mc6_hash_index, int mc6_tot_entries,
    PMC6Command pMC6Snapshot)
{
	int tot_entries, i, j;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	tot_entries = 0;
	list_for_each(ptr, &mc6_grp_list[mc6_hash_index]) {
		pMcastGrpInfo = list_entry(ptr, struct mcast_group_info, list);

		memset(pMC6Snapshot, 0, sizeof(MC6Command));
		memcpy(pMC6Snapshot->src_addr, pMcastGrpInfo->ipv6_saddr,
		    IPV6_ADDRESS_LENGTH);
		memcpy(pMC6Snapshot->dst_addr, pMcastGrpInfo->ipv6_daddr,
		    IPV6_ADDRESS_LENGTH);
		strncpy((char *)pMC6Snapshot->input_device_str,
		    pMcastGrpInfo->ucIngressIface, IF_NAME_SIZE - 1);

		for (i = 0, j = 0; j < MC_MAX_LISTENERS_PER_GROUP; j++) {
			if (!pMcastGrpInfo->members[j].bIsValidEntry)
				continue;
			strncpy(
			    (char *)pMC6Snapshot->output_list[i].
			    output_device_str,
			    pMcastGrpInfo->members[j].if_info,
			    IF_NAME_SIZE - 1);
			if (++i >= MC4_MAX_LISTENERS_IN_QUERY &&
			    pMcastGrpInfo->uiListenerCnt - i > 0) {
				pMC6Snapshot->num_output =
				    MC6_MAX_LISTENERS_IN_QUERY;
				pMC6Snapshot++;
				tot_entries++;
				mc6_tot_entries--;
				i = 0;
				memset(pMC6Snapshot, 0, sizeof(MC6Command));
			}
		}
		pMC6Snapshot->num_output = i;
		pMC6Snapshot++;
		tot_entries++;
		mc6_tot_entries--;
		if (mc6_tot_entries == 0)
			break;
	}

	return (tot_entries);
}

int
MC6_Get_Next_Hash_Entry(PMC6Command pMC6Cmd, int reset_action)
{
	int mc6_hash_entries;
	PMC6Command pMC6;
	static PMC6Command pMC6Snapshot;
	static int mc6_hash_index, mc6_snapshot_entries;
	static int mc6_snapshot_index, mc6_snapshot_buf_entries;

	if (reset_action) {
		mc6_hash_index = 0;
		mc6_snapshot_entries = 0;
		mc6_snapshot_index = 0;
		if (pMC6Snapshot != NULL) {
			Heap_Free(pMC6Snapshot);
			pMC6Snapshot = NULL;
		}
		mc6_snapshot_buf_entries = 0;
	}

	if (mc6_snapshot_index == 0) {
		while (mc6_hash_index < MC6_NUM_HASH_ENTRIES) {
			mc6_hash_entries =
			    MC6_Get_Hash_Entries(mc6_hash_index);
			if (mc6_hash_entries == 0) {
				mc6_hash_index++;
				continue;
			}

			if (mc6_hash_entries > mc6_snapshot_buf_entries) {
				if (pMC6Snapshot != NULL)
					Heap_Free(pMC6Snapshot);
				pMC6Snapshot = Heap_Alloc(mc6_hash_entries *
				    sizeof(MC6Command));
				if (pMC6Snapshot == NULL) {
					mc6_hash_index = 0;
					mc6_snapshot_buf_entries = 0;
					return (ERR_NOT_ENOUGH_MEMORY);
				}
				mc6_snapshot_buf_entries = mc6_hash_entries;
			}

			mc6_snapshot_entries = MC6_Get_Hash_Snapshot(
			    mc6_hash_index, mc6_hash_entries, pMC6Snapshot);
			break;
		}

		if (mc6_hash_index >= MC6_NUM_HASH_ENTRIES) {
			mc6_hash_index = 0;
			if (pMC6Snapshot != NULL) {
				Heap_Free(pMC6Snapshot);
				pMC6Snapshot = NULL;
			}
			mc6_snapshot_buf_entries = 0;
			return (ERR_MC_ENTRY_NOT_FOUND);
		}
	}

	pMC6 = &pMC6Snapshot[mc6_snapshot_index++];
	memcpy(pMC6Cmd, pMC6, sizeof(MC6Command));
	if (mc6_snapshot_index == mc6_snapshot_entries) {
		mc6_snapshot_index = 0;
		mc6_hash_index++;
	}

	return (NO_ERR);
}

/* ================================================================
 * Init / Exit
 * ================================================================ */

int
mc4_init(void)
{
	int ii;

	set_cmd_handler(EVENT_MC4, M_mc4_cmdproc);

	mc4grp_ids = kzalloc(sizeof(uint8_t) * MAX_MC4_ENTRIES, 0);
	if (mc4grp_ids == NULL)
		return (-ENOMEM);

	max_mc4grp_ids = MAX_MC4_ENTRIES;

	mc4_spinlocks = kzalloc(sizeof(spinlock_t) * MC4_NUM_HASH_ENTRIES, 0);
	if (mc4_spinlocks == NULL) {
		kfree(mc4grp_ids);
		mc4grp_ids = NULL;
		return (-ENOMEM);
	}

	for (ii = 0; ii < MC4_NUM_HASH_ENTRIES; ii++) {
		INIT_LIST_HEAD(&mc4_grp_list[ii]);
		spin_lock_init(&mc4_spinlocks[ii]);
	}

	DPA_INFO("cdx: mc4_init: registered %d hash buckets, "
	    "%d max groups\n", MC4_NUM_HASH_ENTRIES, MAX_MC4_ENTRIES);
	return (0);
}

int
mc6_init(void)
{
	int ii;

	set_cmd_handler(EVENT_MC6, M_mc6_cmdproc);

	mc6grp_ids = kzalloc(sizeof(uint8_t) * MAX_MC6_ENTRIES, 0);
	if (mc6grp_ids == NULL)
		return (-ENOMEM);

	max_mc6grp_ids = MAX_MC6_ENTRIES;

	mc6_spinlocks = kzalloc(sizeof(spinlock_t) * MC6_NUM_HASH_ENTRIES, 0);
	if (mc6_spinlocks == NULL) {
		kfree(mc6grp_ids);
		mc6grp_ids = NULL;
		return (-ENOMEM);
	}

	for (ii = 0; ii < MC6_NUM_HASH_ENTRIES; ii++) {
		INIT_LIST_HEAD(&mc6_grp_list[ii]);
		spin_lock_init(&mc6_spinlocks[ii]);
	}

	DPA_INFO("cdx: mc6_init: registered %d hash buckets, "
	    "%d max groups\n", MC6_NUM_HASH_ENTRIES, MAX_MC6_ENTRIES);
	return (0);
}

void
mc4_exit(void)
{

	if (mc4_spinlocks != NULL) {
		kfree(mc4_spinlocks);
		mc4_spinlocks = NULL;
	}
	if (mc4grp_ids != NULL) {
		kfree(mc4grp_ids);
		mc4grp_ids = NULL;
	}
}

void
mc6_exit(void)
{

	if (mc6_spinlocks != NULL) {
		kfree(mc6_spinlocks);
		mc6_spinlocks = NULL;
	}
	if (mc6grp_ids != NULL) {
		kfree(mc6grp_ids);
		mc6grp_ids = NULL;
	}
}
