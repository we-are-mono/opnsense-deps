/*
 * Linux-to-FreeBSD kernel compatibility shim — list_head / hlist
 *
 * CDX uses TWO different list implementations:
 * 1. CDX's own list.h (slist_head/slist_entry/dlist_head) — OS-independent, untouched
 * 2. Linux kernel lists (list_head, hlist_head, hlist_node) — provided here
 *
 * Used by: cdx_ctrl.h (msg_list), cdx_timer.c/h (timer nodes),
 *          cdx_cmdhandler.c (workqueue msg processing),
 *          dpa_control_mc.c (multicast group lists)
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_LIST_COMPAT_H_
#define _LINUX_LIST_COMPAT_H_

/* ----------------------------------------------------------------
 * Linux list_head (circular doubly-linked list)
 * ---------------------------------------------------------------- */
struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name)	{ &(name), &(name) }
/* Note: We do NOT redefine LIST_HEAD here. FreeBSD sys/queue.h defines
 * LIST_HEAD(name, type) which must coexist. CDX code only uses
 * INIT_LIST_HEAD() to initialize list_head structs, not the Linux
 * LIST_HEAD() declaration macro. */

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
    struct list_head *prev, struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

#define list_entry(ptr, type, member)	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_for_each(pos, head) \
	for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

#define list_for_each_safe(pos, n, head) \
	for ((pos) = (head)->next, (n) = (pos)->next; \
	     (pos) != (head); \
	     (pos) = (n), (n) = (pos)->next)

#define list_for_each_entry(pos, head, member) \
	for ((pos) = list_entry((head)->next, typeof(*(pos)), member); \
	     &(pos)->member != (head); \
	     (pos) = list_entry((pos)->member.next, typeof(*(pos)), member))

#define list_for_each_entry_safe(pos, n, head, member) \
	for ((pos) = list_entry((head)->next, typeof(*(pos)), member), \
	     (n) = list_entry((pos)->member.next, typeof(*(pos)), member); \
	     &(pos)->member != (head); \
	     (pos) = (n), (n) = list_entry((n)->member.next, typeof(*(n)), member))

/* ----------------------------------------------------------------
 * Linux hlist (hash list — singly-linked head for space efficiency)
 *
 * Used for timer wheel buckets (inner + outer wheel) and hash tables.
 * ---------------------------------------------------------------- */
struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};

#define HLIST_HEAD_INIT		{ .first = NULL }
#define HLIST_HEAD(name)	struct hlist_head name = HLIST_HEAD_INIT

static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline void INIT_HLIST_HEAD(struct hlist_head *h)
{
	h->first = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static inline void hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	*pprev = next;
	if (next)
		next->pprev = pprev;
	n->next = NULL;
	n->pprev = NULL;
}

static inline void hlist_del_init(struct hlist_node *n)
{
	if (n->pprev) {
		hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

/*
 * hlist_for_each_entry_safe — iterate over hlist, safe against removal
 *
 * Linux 3.x signature: hlist_for_each_entry_safe(pos, tmp, head, member)
 * where tmp is struct hlist_node *.
 *
 * CDX uses this signature in cdx_timer.c.
 */
#define hlist_for_each_entry_safe(pos, tmp, head, member)		\
	for ((tmp) = (head)->first;					\
	     (tmp) && ({ (pos) = container_of((tmp),			\
			typeof(*(pos)), member);			\
			(tmp) = (tmp)->next; 1; }); )

#define hlist_for_each_entry(pos, head, member)				\
	for ((pos) = (head)->first ?					\
		container_of((head)->first, typeof(*(pos)), member) :	\
		NULL;							\
	     (pos);							\
	     (pos) = (pos)->member.next ?				\
		container_of((pos)->member.next, typeof(*(pos)), member) : \
		NULL)

#endif /* _LINUX_LIST_COMPAT_H_ */
