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
#include "control_ipv4.h"

/**
 * get_onif_by_name()
 *
 *
 */
POnifDesc get_onif_by_name(U8 *itf_name)
{
	POnifDesc onif_desc = NULL;
	int i;

	if (itf_name) {
		/* return pointer on entry of the global ouput nif information database */
		for (i = 0; i < L2_MAX_ONIF; i++)
		{
			onif_desc = &gOnif_DB[i];
			if ((onif_desc->flags & ENTRY_VALID) && !strcmp((const char*)itf_name, (char*)onif_desc->name))
				return onif_desc;
		}
	}
	return NULL;
}

/**
 * add_onif()
 *
 *
 */
POnifDesc add_onif(U8 *input_itf_name, struct _itf *itf, struct _itf *phys_itf, U8 type)
{
	U32 i;

	/* find free entry (valid = 0) in the table */
	for (i = 0; i < L2_MAX_ONIF; i++)
	{
		if ((gOnif_DB[i].flags & ENTRY_VALID) == 0)
		{
			gOnif_DB[i].itf = itf;
			strncpy((char*)gOnif_DB[i].name, (char*)input_itf_name, IF_NAME_SIZE);
			gOnif_DB[i].name[IF_NAME_SIZE - 1] = '\0';

			itf->phys = phys_itf;
			itf->index = i;
			itf->type = type;
			if (type & IF_TYPE_ETHERNET) {
				if (dpa_add_eth_if(input_itf_name, itf, 
							phys_itf) != 0) {
					printk("%s::dpa_add_eth_if failed\n", 
							__FUNCTION__);
					return NULL;
				}
			} 
			gOnif_DB[i].flags = ENTRY_VALID;
			return &gOnif_DB[i];
		}
	}
	return NULL;
}

/**
 * remove_onif_by_name()
 *
 *
 */
void remove_onif_by_name(U8 *itf_name)
{
	int i;

	for (i = 0; i < L2_MAX_ONIF; i++)
	{
		if(!strcmp((char*)itf_name, (char*)gOnif_DB[i].name))
		{
			remove_onif_by_index(i);
			return; 
		}
	}
}


/**
 * remove_onif_by_index()
 *
 *
 */
void remove_onif_by_index(U32 if_index)
{
	int i;

	IP_deleteCt_from_onif_index(if_index);

	// disable route entries bound to this interface
	for (i = 0 ; i < NUM_ROUTE_ENTRIES ; i++)
	{
		PRouteEntry pRtentry;
		struct slist_entry *entry;

		// find and delete any routes that still use the interface (use counts should be zero)
		slist_for_each_safe(pRtentry, entry, &rt_cache[i], list)
		{
			if (pRtentry->itf->index == if_index)
				L2_route_remove(pRtentry->id);
		}
	}

#ifdef CDX_TODO_MC
	// Remove any multicast listener entries that reference this interface
	MC6_interface_purge(if_index);
	MC4_interface_purge(if_index);

	// Remove any Bridge entry references
	Bridge_output_interface_reset(if_index);
#endif

	memset(&gOnif_DB[if_index], 0, sizeof(OnifDesc));
	dpa_release_interface(if_index);
}


/**
 * remove_onif()
 *
 *
 */
void remove_onif(POnifDesc onif_desc)
{
	remove_onif_by_index(get_onif_index(onif_desc));
}


PRouteEntry L2_route_find(U32 id)
{
	U32 hash;
	PRouteEntry pRtEntry;
	struct slist_entry *entry;

	hash = HASH_RT(id);
	slist_for_each(pRtEntry, entry, &rt_cache[hash], list)
	{
		if (pRtEntry->id == id)
			return pRtEntry;
	}

	return NULL;
}

U16 itf_get_phys_port(struct _itf *itf)
{
	while (itf->phys)
		itf = itf->phys;

	return ((struct physical_port *)itf)->id;
}

struct _itf *itf_get_phys_itf(struct _itf *itf)
{
	while (itf->phys)
		itf = itf->phys;

	return itf;
}

/**
 * __L2_route_remove()
 *
 *          This function removes an L2 route entry
 *
 */
int __L2_route_remove(PRouteEntry pRtEntry)
{
	U32 hash;

	hash = HASH_RT(pRtEntry->id);

	slist_remove(&rt_cache[hash], &pRtEntry->list);

	Heap_Free((PVOID)pRtEntry);

	return NO_ERR;
}

/**
 * L2_route_remove()
 *
 *          This function removes an L2 route entry
 *
 */
int L2_route_remove(U32 id)
{
	PRouteEntry pRtEntry;

	pRtEntry = L2_route_find(id);
	if (pRtEntry == NULL)
		return ERR_RT_ENTRY_NOT_FOUND;

	if (pRtEntry->nbref)
		return ERR_RT_ENTRY_LINKED;

	return __L2_route_remove(pRtEntry);
}


/**
 * L2_route_get()
 *
 *
 */
PRouteEntry L2_route_get(U32 id)
{
	PRouteEntry pRtEntry;

	pRtEntry = L2_route_find(id);
	if (pRtEntry == NULL)
	{
		return NULL;
	}

	if (pRtEntry->nbref == 0xFFFF)
	{
		return NULL;
	}

	if (pRtEntry->itf == NULL)
	{
		return NULL;
	}

	pRtEntry->nbref++;

	return pRtEntry;
}

/**
 * L2_route_put()
 *
 *
 */
void L2_route_put(PRouteEntry pRtEntry)
{
	if (pRtEntry == NULL)
		return;

	pRtEntry->nbref--;
}

/**
 * L2_route_add()
 *
 *          This function removes an L2 route entry
 *
 */
PRouteEntry L2_route_add(U32 id, int info_size)
{
	PRouteEntry pRtEntry;
	int size;
	U32 hash;

	size = ROUND_UP32(sizeof (RouteEntry)) + info_size;

	pRtEntry = (PRouteEntry)__Heap_Alloc(hGlobalHeap, size);
	if (!pRtEntry)
		return NULL;

	memset(pRtEntry, 0, size);

	hash = HASH_RT(id);

	pRtEntry->id = id;

	if (info_size)
		pRtEntry->flags |= RT_F_EXTRA_INFO;

	pRtEntry->nbref = 0;

	slist_add(&rt_cache[hash], &pRtEntry->list);

	return pRtEntry;
}

