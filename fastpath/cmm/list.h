/*
 *
 *  Copyright (C) 2009 Mindspeed Technologies, Inc.
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 *
 */

#ifndef __LIST_H
#define __LIST_H

#include <assert.h>

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

static inline void list_head_init(struct list_head *head)
{
	head->prev = head;
	head->next = head;
}

static inline void list_add(struct list_head *head, struct list_head *entry)
{
	assert((!entry->next) && (!entry->prev));

	entry->next = head->next;
	entry->next->prev = entry;

	head->next = entry;
	entry->prev = head;
}

static inline void list_del(struct list_head *entry)
{
	if((!entry->next) && (!entry->prev))
		return;
	assert((entry->next) && (entry->prev));

	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = NULL;
	entry->next = NULL;
}

#define list_empty(head)	((head)->next == (head))

#define offset_of(type, member) ((unsigned long)&(((type *)0)->member))
#define container_of(entry, type, member) ((type *)((unsigned char *)(entry) - offset_of(type, member)))

#define list_first(head)	((head)->next)
#define list_last(head)		((head)->prev)
#define list_next(entry)	((entry)->next)

#endif
