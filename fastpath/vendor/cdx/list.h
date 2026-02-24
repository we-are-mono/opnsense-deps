/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/** @file
 *  Generic implementation for linked lists
 */

#ifndef _LIST_H_
#define _LIST_H_

/** @name Null terminated simple linked lists */
/**@{*/


/** Simple linked list entry.
* To keep a generic data structure in a simple linked list add a slist_entry member to the structure.
* If the generic data structure may be part of several lists at a time, then one slist_entry member is needed for each list.
*
*/
struct slist_entry
{
	struct slist_entry *next;
};


/** Simple linked list head.
* One slist_head structure exists for each list. Each list should contain a
* single type of data structures (so that the loop functions work correctly).
*
*/
struct slist_head
{
	struct slist_entry *next;
};


/** Returns the next element of a simple linked list.
*
* @param entry	pointer to a list entry
*
* @return	pointer to next list element, may be NULL
*
*/
static inline struct slist_entry *slist_next(struct slist_entry *entry)
{
	return entry->next;
}


/** Sets the next pointer on a list entry
*
* @param entry	pointer to a list entry
* @param next	next pointer value to set
*
*/
static inline void slist_set_next(struct slist_entry *entry, struct slist_entry *next)
{
	entry->next = next;
}


/** Returns the first element of a simple linked list.
*
* @param list	pointer to the list head
*
* @return	pointer to the first list element, may be NULL
*/
static inline struct slist_entry *slist_first(struct slist_head *list)
{
	return list->next;
}


/** Loops over all container data structures in a list.
*
* @param container	pointer to the container data structure type, this is the loop variable
* @param entry		pointer to a temporary list entry
* @param list		pointer to the list head
* @param member		name of the list entry member in the container data structure
*/
#define slist_for_each(container, entry, list, member)	\
	for ((entry) = slist_first(list); \
		((entry) != NULL) && ({(container) = container_of(entry, typeof(*container), member); 1;}); \
		(entry) = slist_next(&((container)->member)))


/** Loops over all container data structures in a list.
* The safe version should be used when the list entry may be removed inside the loop
*
* @param container	pointer to the container data structure type, this is the loop variable
* @param entry		pointer to a temporary list entry
* @param list		pointer to the list head
* @param member		name of the list entry member in the container data structure
*/
#define slist_for_each_safe(container, entry, list, member)	\
	for ((entry) = slist_first(list); \
		((entry) != NULL) && ({(container) = container_of(entry, typeof(*container), member); (entry) = slist_next(entry); 1;}); )


/** Loops over all entries in a list.
*
* @param entry	pointer to a list entry, this is the loop variable
* @param list	pointer to the list head
*
*/

#define slist_for_each_entry(entry, list)	\
	for ((entry) = slist_first(list); \
		(entry) != NULL; \
		(entry) = slist_next(entry))


/** Initializes the head of a simple linked list.
* Must be called once for all slist_head structures.
*
* @param list	pointer to the list head to be initialized
*
*/
static inline void slist_head_init(struct slist_head *list)
{
	list->next = NULL;
}


/** Adds one entry at the head of a simple linked list.
*
* @param list	pointer to the list head, where the entry is to be added
* @param entry	pointer to the list entry to be added to the list, must not be part of another list already
*
*/
static inline void slist_add(struct slist_head *list, struct slist_entry *entry)
{
	entry->next = list->next;
	list->next = entry;
}


/** Returns the previous entry in a simple linked list.
*
* @param list	pointer to the list head
* @param entry	pointer to the list entry
*
* @return	pointer to the previous list entry (may point to list head), if the entry is not in the list returns NULL
*/
static inline struct slist_entry *slist_prev(struct slist_head *list, struct slist_entry *entry)
{
	struct slist_entry *cur = slist_first(list);
	struct slist_entry *prev = (struct slist_entry *)list;

	while (1)
	{
		/* Entry not on the list */
		if (!cur)
			return NULL;
	
		if (cur == entry)
			break;

		prev = cur;
		cur = slist_next(cur);
	}

	return prev;
}


/** Removes the next entry in a simple linked list.
* If prev is not NULL the caller needs to make sure the next is not NULL either
*
* @param prev	pointer to the previous list entry
*
*/
static inline void slist_remove_after(struct slist_entry *prev)
{
	if (prev)
		prev->next = prev->next->next;
}

/** Removes one entry from a simple linked list.
* If the entry is not part of the list, nothing is done.
*
* @param list	pointer to the list head, from where the entry is to be removed
* @param entry	pointer to the list entry to be removed from the list
*
*/
static inline void slist_remove(struct slist_head *list, struct slist_entry *entry)
{
	struct slist_entry *prev = slist_prev(list, entry);

	slist_remove_after(prev);
}


/**@}*/


/** @name Circular double linked lists */
/**@{*/


/** Double linked list element.
* To keep a generic data structure in a double linked list add a dlist_head member to the structure.
* If the generic data structure may be part of several lists at a time, then one dlist_head member is needed for each list.
*
*/
struct dlist_head
{
	struct dlist_head *next;
	struct dlist_head *prev;
};


/** Returns the previous element of a double linked list.
*
* @param entry	pointer to a list element
*
* @return	pointer to previous list element, may be the head
*
*/
static inline struct dlist_head *dlist_prev(struct dlist_head *entry)
{
	return entry->prev;
}


/** Returns the next element of a double linked list.
*
* @param entry	pointer to a list element
*
* @return	pointer to next list element, may be the head
*
*/
static inline struct dlist_head *dlist_next(struct dlist_head *entry)
{
	return entry->next;
}


/** Returns the first element of a double linked list.
*
* @param list	pointer to the list head
*
* @return	pointer to the first list element, may be the head
*
*/
static inline struct dlist_head *dlist_first(struct dlist_head *list)
{
	return list->next;
}


/** Returns the last element of a double linked list.
*
* @param list	pointer to the list head
*
* @return	pointer to the last list element, may be the head
*
*/
static inline struct dlist_head *dlist_last(struct dlist_head *list)
{
	return list->prev;
}


/** Loops over all container data structures in a list.
*
* @param container	pointer to the container data structure type, this is the loop variable
* @param entry		pointer to a temporary list entry
* @param list		pointer to the list head
* @param member		name of the list entry member in the container data structure
*/
#define dlist_for_each(container, entry, list, member)	\
	for ((entry) = dlist_first(list); \
		((entry) != (list)) && ({(container) = container_of(entry, typeof(*container), member); 1;}); \
		(entry) = dlist_next(entry))


/** Loops over all container data structures in a list.
* The safe version should be used when the list entry may be removed inside the loop
*
* @param container	pointer to the container data structure type, this is the loop variable
* @param entry		pointer to a temporary list entry
* @param list		pointer to the list head
* @param member		name of the list entry member in the container data structure
*/
#define dlist_for_each_safe(container, entry, list, member)	\
	for ((entry) = dlist_first(list); \
		((entry) != (list)) && ({(container) = container_of(entry, typeof(*container), member); (entry) = dlist_next(entry); 1;}); )


/** Loops over all entries in a list.
*
* @param entry	pointer to a list entry, this is the loop variable
* @param list	pointer to the list head
*
*/

#define dlist_for_each_entry(entry, list)	\
	for ((entry) = dlist_first(list); \
		(entry) != (list); \
		(entry) = dlist_next(entry))

/** Initializes the head of a double linked list.
* Must be called once for all list head structures.
*
* @param list	pointer to the list head to be initialized
*
*/
static inline void dlist_head_init(struct dlist_head *list)
{
	list->next = list;
	list->prev = list;
}


/** Adds one entry at the head of a double linked list.
*
* @param list	pointer to the list head, where the entry is to be added
* @param entry	pointer to the list entry to be added to the list, must not be part of another list already
*
*/
static inline void dlist_add(struct dlist_head *list, struct dlist_head *entry)
{
	struct dlist_head *list_next = list->next;
	entry->next = list_next;
	entry->prev = list;
	list_next->prev = entry;
	list->next = entry;

}


/** Removes one entry from a double linked list.
*
* @param list	pointer to the list head, from where the entry is to be removed
* @param entry	pointer to the list entry to be removed from the list
*
*/
static inline void dlist_remove(struct dlist_head *entry)
{
	struct dlist_head *prev = entry->prev;
	struct dlist_head *next = entry->next;
	next->prev = prev;
	prev->next = next;
}

/** Checks if a double linked list is empty.
*
* @param list	pointer to the list head
*
* @return	1 if list is empty, 0 otherwise
*
*/
static inline int dlist_empty(struct dlist_head *list)
{
	return list->next == list;
}

/**@}*/
#endif /* _LIST_H_ */
