/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright (c) 2009, 2010, Freescale Semiconductor, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *  Author    : Hendricks Vince
 *
 * ===================================================================*/

/****************************************************************************
 *   File Name : dll.c
 *
 *   This file contains the implementation of the Doubly-Linked List
 *   (DLL) module.
 *  
 *   What follows is a brief description of the internal link list
 *   structure used in the DLL module. 
 *
 *   An empty list: 
 *   - both the head_p and tail_p pointers point to list. 
 *
 *   +-----------------+
 *   | dll_list_t      |
 *   |   head_p *------+----\
 *   |   tail_p *------+--\ |
 *   |                 |<-/ |
 *   |                 |<---/
 *   +-----------------+
 *
 *
 *   A list with nodes in it:
 *   - head_p points to the first node.  
 *   - tail_p points to the last node.
 *   - prev_p in the first node in the list points to the list, 
 *     prev_p in the other nodes in the list point to their previous node.
 *   - next_p in the last node points to list, next_p in the other
 *     nodes in the list point to their next node.
 *
 *   +-----------------+
 *   | dll_list_t      |<---------------------------------------------------\
 *   |   head_p *------+---\                                                |
 *   |   tail_p *------+---+-------------------------------\                |
 *   |                 |   |                               |                |
 *   |                 |   |                               |                |
 *   +-----------------+   |                               |                |
 *    ^                    |                               |                |
 *    |                    V                               V                |
 *    |   +-----------------+    +-----------------+    +-----------------+ |
 *    |   | dll_node_t      |    | dll_node_t      |    | dll_node_t      | |
 *    |   |   next_p *------+--->|   next_p *------+--->|   next_p *------+-/
 *    \---+-* prev_p        |<---+-* prev_p        |<---+-* prev_p        |
 *        |                 |    |                 |    |                 |
 *        +-----------------+    +-----------------+    +-----------------+
 *
 *
 *   Note:  The list and node structures are designed this way to
 *   allow fast manipulations.  For example, in the dll_insert_after()
 *   function there is no check if the node is the last node in the
 *   list because the list structure itself can be treated as a node
 *   in terms of the pointer manipulations.  Note that because of this
 *   the order of the head_p and tail_p inside the dll_list_t must
 *   match the order of the next_p and prev_p inside dll_node_t.
 *
 ****************************************************************************/



/*--------------------- Include Files -----------------------------*/

#include "dll.h"








/*--------------------- Macro Definitions--------------------------*/







/*--------------------- Type Definitions---------------------------*/








/*--------------------- Global Data Definitions -------------------*/








/*--------------------- Static Function Definitions ---------------*/









/*--------------------- Public Function Definitions ---------------*/

/*
 * Count the number of nodes in the specified DLL list.
 * 
 * param list_p  The DLL list to use.
 * retval        The number of nodes in the list.
 */
int
dll_count(
  dll_list_t *list_p)
{   
  dll_node_t *temp_p = NULL;
  int         count  = 0;


#ifdef DLL_DEBUG_ENABLED
  /* This check is too stupid to pay it's price all the time. */
  if (list_p == NULL) {
    printf(
               "The double linked list ptr is null!");
    return 0;
  }
#endif

  if (dll_is_list_empty(list_p)) {
    return 0;
  }
  
  temp_p = list_p->head_p;
  count++;
  while (!dll_is_node_at_back(list_p, temp_p)) {
    count++;
    temp_p = temp_p->next_p;
  }
  return count;
}


/*
 * Displays the nodes in the specified DLL list.
 * 
 * param list_p  The DLL list to use.
 */
void 
dll_show_list(
  dll_list_t *list_p)
{   
  dll_node_t *node_p = NULL;
  
  
  if (list_p == NULL) {
    printf(
               "The double linked list ptr is null!");
  }
  else {
    node_p = dll_get_first(list_p);
    
    printf(
               "\t\tlist_p = %-10p  head_p = %-10p  tail_p = %-10p\n",
               list_p, list_p->head_p, list_p->tail_p);
    
    if (NULL != node_p) { 
      printf(
                 "\t\tnode_p = %-10p  next_p = %-10p  prev_p = %-10p\n", 
                 node_p, node_p->next_p, node_p->prev_p);
      while (NULL != (node_p = dll_get_next_node(list_p, node_p))) {
        printf(
                   "\t\tnode_p = %-10p  next_p = %-10p  prev_p = %-10p\n", 
                   node_p, node_p->next_p, node_p->prev_p);
      }
    }
  }
}


#ifdef DLL_DEBUG_ENABLED
/*! @brief Checks the integrity of a Double Linked List
 *
 *  This is a shallow test.  It does not walk the entire list.
 * 
 *  @param  list_p  List to initialize.
 *  @retval false   Failure
 *  @retval true    Success
 */
bool 
dll_integrity_check(
  dll_list_t *list_p)
{
  /* This check is too stupid to pay it's price all the time. */
  if (list_p == NULL) {
    printf(
               "The double linked list ptr is null!");
    return false;
  }
  if (list_p->head_p == NULL) {
    printf(
               "The double linked list is corrupted.");
    return false;
  }
  if (list_p->tail_p == NULL) {
    printf(
               "The double linked list is corrupted.");
    return false;
  }

  return true;
}
#endif


/* 
 * Initialize a DLL list structure.
 * 
 * param list_p  DLL list to be initialized.
 */
void 
dll_list_init(
  dll_list_t *list_p)
{
#ifdef DLL_DEBUG_ENABLED
  /* This check is too stupid to pay it's price all the time. */
  if (list_p == NULL) {
    printf(
               "The double linked list ptr is null!");
    return;
  }
#endif

  list_p->head_p = (dll_node_t *)list_p;
  list_p->tail_p = (dll_node_t *)list_p;
}


/* 
 * Check if the passed in DLL list is empty.
 * 
 * param list_p  List to be checked.
 * retval        true if the list is empty; false otherwise.
 */
bool 
dll_is_list_empty(
  dll_list_t *list_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return true; /* Try to get the caller to stop using the list. */
  }
#endif

  return (list_p->head_p == (dll_node_t*)list_p);
}


/*
 * Check if the passed in DLL node is at the front of the DLL list.
 * 
 * param list_p   List to check against.
 * param node_p   Node to check.
 * retval         true if the node is at the front of the list; false
 *                otherwise.
 */
bool 
dll_is_node_at_front(
  dll_list_t *list_p, 
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return false;
  }
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return false;
  }
#endif

  return (list_p->head_p == node_p);
}


/*
 * Check if the passed in DLL node is at the back of the DLL list.
 * 
 * param list_p   List to check against.
 * param node_p   Node to check.
 * retval         true if the node is at the back of the list; false
 *                otherwise.
 */
bool 
dll_is_node_at_back(
  dll_list_t *list_p, 
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return false;
  }
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return false;
  }
#endif
  
  return (list_p->tail_p == node_p);
}


/* Get the first node from the specified DLL list.
 * 
 * This function can be used to start "walking" a DLL list.  The
 * subsequent calls should use the dll_get_next_node() function.
 *
 * param list_p  The DLL list to use.
 * retval        NULL if the list is empty; the pointer to the first
 *               node in the list otherwise.
 */
dll_node_t *
dll_get_first(
  dll_list_t *list_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return NULL;
  }
#endif

  if (dll_is_list_empty(list_p)) {
    return NULL;
  }
  return list_p->head_p;
}


/*
 * Get the node following the specified node in the specified DLL list.
 * 
 * param list_p  The DLL list to used.
 * param node_p  The DLL node to use.
 * retval        NULL if there are more nodes in the list after the
 *               specified node.  The pointer to the node
 *               immediately after the specified node, i.e., the 
 *               next node, otherwise. 
 */
dll_node_t * 
dll_get_next_node(
  dll_list_t *list_p, 
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return NULL;
  }
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return NULL;
  }
#endif
  
  if (dll_is_node_at_back(list_p,node_p)){
    return NULL;
  }
  return node_p->next_p;
}


/*
 * Get the node preceding the specified node in the specified DLL list.
 * 
 * param list_p  The DLL list to used.
 * param node_p  The DLL node to use.
 * retval        NULL if the specified node is the first node in the
 *               list.  The pointer to the node immediately before the
 *               specified node, i.e., the previous node, otherwise. 
 */
dll_node_t * 
dll_get_prev_node(
  dll_list_t *list_p, 
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) { 
    return NULL;
  }
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return NULL;
  }
#endif
  
  if (dll_is_node_at_front(list_p,node_p)) {
    return NULL;
  }
  return node_p->prev_p;
}


/*
 * Append the source DLL list to the destination DLL list.
 * 
 * This function appends the source double linked list to the end of
 * the destination double linked list but only if the source list is
 * not empty.  The source list is returned empty.
 *
 * param destList_p  List to append to.
 * param srcList_p   List to be appended.
 */
void
dll_append_list(
  dll_list_t *destList_p, 
  dll_list_t *srcList_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(srcList_p)) {
    return;
  }
  if (!dll_integrity_check(destList_p)) {
    return;
  }
#endif
  
  if (!dll_is_list_empty(srcList_p)) {
    destList_p->tail_p->next_p = srcList_p->head_p;
    srcList_p->head_p->prev_p  = destList_p->tail_p;
    destList_p->tail_p         = srcList_p->tail_p;
    destList_p->tail_p->next_p = (dll_node_t*)destList_p;
    dll_list_init(srcList_p);
  }

}


/*
 * Move the nodes of one DLL list to another DLL list.
 * 
 * This function moves the nodes of one DLL list to another DLL list.
 * If the source list is empty the destination list is initialized to
 * empty.  The source list is returned empty.
 *
 * WARNING:  If the destination list is not empty, the nodes in the
 *           destination list are lost.  This may cause a memory leak.
 *
 * param destList_p  List to move to.
 * param srcList_p   List to be moved.
 */
void 
dll_move_list(
  dll_list_t *destList_p, 
  dll_list_t *srcList_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(srcList_p)) {
    return;
  }
  /* This check is too stupid to pay it's price all the time. */
  if (destList_p == NULL) {
    printf(
               "The destination double linked list ptr is null!");
    return;
  }
#endif
  
  if (!dll_is_list_empty(srcList_p)) {
    destList_p->head_p         = srcList_p->head_p;
    destList_p->tail_p         = srcList_p->tail_p;
    destList_p->head_p->prev_p = (dll_node_t*)destList_p;
    destList_p->tail_p->next_p = (dll_node_t*)destList_p;
  }
  else {
    dll_list_init(destList_p);
  }
  dll_list_init(srcList_p);
}


/* 
 * Add a node to the front of a list.
 * 
 * param lista_p  List to add to.
 * param node_p   Node to add.
 */
void 
dll_add_to_front(
  dll_list_t *list_p, 
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return;
  }
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return;
  }
#endif
  
  list_p->head_p->prev_p = node_p;
  node_p->prev_p         = (dll_node_t*)list_p;
  node_p->next_p         = list_p->head_p;
  list_p->head_p         = node_p;
}


/* 
 * Add a node at the back of a list.
 * 
 * param lista_p  List to add to.
 * param node_p   Node to add.
 */
void 
dll_add_to_back(
  dll_list_t *list_p, 
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return;
  }
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return;
  }
#endif

  list_p->tail_p->next_p = node_p;
  node_p->next_p         = (dll_node_t*)list_p;
  node_p->prev_p         = list_p->tail_p;
  list_p->tail_p         = node_p;
}


/* 
 * Insert a node in a list after the specified node.
 * 
 * param pos_p   Node in list to insert after.
 * param node_p  Node to insert.
 */
void 
dll_insert_after(
  dll_node_t *pos_p,
  dll_node_t *node_p)
{
  printf(
             "Entering function: %s(pos_p=%p, node_p=%p).", __FUNCTION__, 
             pos_p, node_p);

#ifdef DLL_DEBUG_ENABLED
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return;
  }
  if (pos_p == NULL) {
    printf(
               "The double linked list position node ptr is null!");
    return;
  }
  if (pos_p->next_p == NULL) {
    /* The double linked list is corrupted or the position node is no
     * longer in the list. */
    printf(
               "The double linked list "
               "position node ptr is not in the list!");
    return;
  }
#endif
  
  node_p->prev_p        = pos_p;
  node_p->next_p        = pos_p->next_p;
  pos_p->next_p->prev_p = node_p;
  pos_p->next_p         = node_p;
}


/* 
 * Insert a node in a list before the specified node.
 * 
 * param pos_p   Node in list to insert before.
 * param node_p  Node to insert.
 */
void 
dll_insert_before(
  dll_node_t *pos_p,
  dll_node_t *node_p)
{
  printf(
             "Entering function: %s(pos_p=%p, node_p=%p).", __FUNCTION__, 
             pos_p, node_p);

#ifdef DLL_DEBUG_ENABLED
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return;
  }
  if (pos_p == NULL) {
    printf(
               "The double linked list position node ptr is null!");
    return;
  }
  if (pos_p->prev_p == NULL) {
    /* The double linked list is corrupted or the position node is no
     * longer in the list. */
    printf(
               "The double linked list position node ptr is not in the list!");
    return;
  }
#endif

  node_p->next_p        = pos_p;
  node_p->prev_p        = pos_p->prev_p;
  pos_p->prev_p->next_p = node_p;
  pos_p->prev_p         = node_p;
}


/*
 * Remove a node from a DLL list.
 *
 * param node_p  Node to be reomved.
 */
void 
dll_remove_node(
  dll_node_t *node_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (node_p == NULL) {
    printf(
               "The double linked list node ptr is null!");
    return;
  }
  if (node_p->next_p == NULL || node_p->prev_p == NULL) {
    /* The double linked list is corrupted or the node is no longer in
     * a list. */
    printf(
               "The double linked list node ptr is not in the list!");
    return;
  }
#endif

  node_p->prev_p->next_p = node_p->next_p;
  node_p->next_p->prev_p = node_p->prev_p;

  node_p->next_p = NULL;
  node_p->prev_p = NULL;
}


/*
 * Remove a node from the front of a DLL list.
 * 
 * param list_p  The DLL list to use.
 * retval        NULL if the list is empty; the pointer to the removed
 *               node otherwise.
 */
dll_node_t * 
dll_remove_from_front(
  dll_list_t *list_p)
{
  dll_node_t* removedNode_p;
  
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return NULL;
  }
#endif
  
  if (!dll_is_list_empty(list_p)) {
    removedNode_p = list_p->head_p;
    dll_remove_node(removedNode_p);
  }
  else {
    return NULL;
  }
  
  return removedNode_p;
}


/*
 * Remove a node from the back of a DLL list.
 * 
 * param list_p  The DLL list to use.
 * retval        NULL if the list is empty; the pointer to the removed
 *               node otherwise.
 */
dll_node_t * 
dll_remove_from_back(
  dll_list_t *list_p)
{
  dll_node_t* removedNode_p;
  
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return NULL;
  }
#endif
  
  if (!dll_is_list_empty(list_p)) {
    removedNode_p = list_p->tail_p;
    dll_remove_node(removedNode_p);
  }
  else {
    return NULL;
  }
  
  return removedNode_p;
}


/*
 * Remove a node located after the specified node in a list.
 * 
 * param list_p  The DLL list to use.
 * param pos_p   The node in list to remove after.
 * retval        NULL if the specified node is the last node in the
 *               list; the pointer to the removed node otherwise.
 */
dll_node_t * 
dll_remove_after(
  dll_list_t *list_p, 
  dll_node_t *pos_p)
{
  dll_node_t *removedNode_p;
  
#ifdef DLL_DEBUG_ENABLED
  /* Other safety checks are performed in dll_is_node_at_front(). */
  if (pos_p->next_p == NULL) {
    /* There is no node after the position node, or the position node
     * is not in the list.  Either way the function shouldn't be
     * called. */
    printf(
               "No node after the position node to remove.");
    return NULL;
  }
#endif
  
  /* Safe so long as there is a node after the position node. */
  if (!dll_is_node_at_back(list_p, pos_p)) {
    removedNode_p = pos_p->next_p;
    dll_remove_node(removedNode_p);
  }
  else {
    return NULL;
  }
  
  return removedNode_p;
}


/*
 * Remove a node located before the specified node in a list.
 * 
 * param list_p  The DLL list to use.
 * param pos_p   The node in list to remove before.
 * retval        NULL if the specified node is the first node in the
 *               list; the pointer to the removed node otherwise.
 */
dll_node_t * 
dll_remove_before(
  dll_list_t *list_p, 
  dll_node_t *pos_p)
{
  dll_node_t *removedNode_p;
  
#ifdef DLL_DEBUG_ENABLED
  /* Other safety checks are performed in dll_is_node_at_front(). */
  if (pos_p->prev_p == NULL) {
    /* There is no node before the position node, or the position node
     * is not in the list.  Either way the function shouldn't be
     * called. */
    printf(
               "No node before the position node to remove.");
    return NULL;
  }
#endif

  /* Safe so long as there is a node before the position node. */
  if (!dll_is_node_at_front(list_p, pos_p)) {
    removedNode_p = pos_p->prev_p;
    dll_remove_node(removedNode_p);
    return removedNode_p;
  }
  else {
    return NULL;
  }
}


/*
 * Get the last node of a list.
 *
 * param list_p   The DLL list to use.
 * retval         NULL if the list is empty; the pointer to the last
 *                node in the list otherwise.
 */
dll_node_t *
dll_get_last(
  dll_list_t *list_p)
{
#ifdef DLL_DEBUG_ENABLED
  if (!dll_integrity_check(list_p)) {
    return NULL;
  }
#endif

  if (dll_is_list_empty(list_p)) {
    return NULL;
  }

  return list_p->tail_p;
}



