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

/************************************************************************
 *   File Name : dll.h
 *
 *   This file defines the public interface to the Doubly-Linked List
 *   (DLL) module.
 *
 *   In order to use the DLL module the user needs to allocate a DLL
 *   list structure and then initialize the list with a call to the
 *   dll_list_init() function.  Once the list has been initialized the
 *   user can add and/or remove nodes to/from the list at a different
 *   locations in the list.  Some basic list operations, e.g.,
 *   appending a list or moving of a list, are also available.
 *
 *   A dll_node_t structure is expected to be included in the user data
 *   structure that is to be represented by the DLL node structure.
 *   The DLL_STRUCT_FROM_NODE_GET() macro can be used to extract the
 *   pointer to the user data structure given the pointer to the DLL
 *   node structure within the user data structure. 
 *
 *   NOTE:  The implementation of the DLL module is optimized for
 *          performance.  This means that checks for NULL pointers,
 *          etc., are not normally performed.  To enable these kind of
 *          checks the user must define the DLL_DEBUG_ENABLED macro
 *          and recompile the module.  The intention behind this
 *          approach is that the user will have the DLL_DEBUG_ENABLED
 *          macro defined and therefore the extra checks enabled
 *          during the development phase but he/she would remove the
 *          macro and disable the checks in the production code. 
 *
 ************************************************************************/
#ifndef DLL_H_INCLUDE
#define DLL_H_INCLUDE



/*--------------------- Include Files ----------------------------------*/

#ifndef _MSC_VER
#include <inttypes.h>  /* For standard int types and print format macros */
#include <stdbool.h>   /* For the bool type */
#else
#if !defined(__cplusplus)
typedef int bool;
static const bool true = 1;
static const bool false = 0;
#endif
#define uint64_t unsigned long long
#define uint32_t unsigned int
#define int32_t  signed   int
#define uint16_t unsigned short
#define uint8_t  unsigned char
#endif

#include <stdio.h>





/*--------------------- Macro Definitions-------------------------------*/

/* This macro defines the abbreviated name for this module. */
#define DLL_MODULE_NAME                       "DLL"


/* This macro can be used to extract a pointer to the structure that
 * contains the specified type. */
#define DLL_STRUCT_FROM_NODE_GET(                           \
  dllNode_p, /* pointer to the DLL node */                  \
  type,      /* name of the type containing the DLL node */ \
  fieldName  /* name of the DLL node field in the "type" */ \
  )                                                         \
  ((type *)((uint8_t *)dllNode_p -                          \
            (uint8_t *)(&(((type *)0)->fieldName))))






/*--------------------- Type Definitions--------------------------------*/

/* This structure defines the DLL node.  The order of next and prev
 * must match the order of head and tail, respectively in the list
 * structure. */
typedef struct dll_node dll_node_t;
struct dll_node {
  dll_node_t *next_p;
  dll_node_t *prev_p;
};


/* This structure defines the DLL list.  The order of head and tail
 * must match the order of next and prev, respectively in the node
 * structure. */
typedef struct {
  dll_node_t *head_p;
  dll_node_t *tail_p;
} dll_list_t;





/*--------------------- Private Global Data Definitions ----------------*/









/*--------------------- Function Declarations --------------------------*/

/* 
 * Initialize a DLL list structure.
 * 
 * param list_p  DLL list to be initialized.
 */
void 
dll_list_init(
  dll_list_t *list_p);


/* 
 * Check if the passed in DLL list is empty.
 * 
 * param list_p  List to be checked.
 * retval        true if the list is empty; false otherwise.
 */
bool 
dll_is_list_empty(
  dll_list_t *list_p);


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
  dll_node_t *node_p);


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
  dll_node_t *node_p);


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
  dll_list_t *list_p);


/*
 * Get the last node of a list.
 *
 * param list_p   The DLL list to use.
 * retval         NULL if the list is empty; the pointer to the last
 *                node in the list otherwise.
 */
dll_node_t *
dll_get_last(
  dll_list_t *list_p);


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
  dll_node_t *node_p);


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
  dll_node_t *node_p);


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
  dll_list_t *srcList_p);


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
 * param destList_p:  List to move to.
 * param srcList_p:   List to be moved.
 */
void 
dll_move_list(
  dll_list_t *destList_p, 
  dll_list_t *srcList_p);


/* 
 * Add a node to the front of a list.
 * 
 * param lista_p  List to add to.
 * param node_p   Node to add.
 */
void 
dll_add_to_front(
  dll_list_t *list_p, 
  dll_node_t *node_p);


/* 
 * Add a node at the back of a list.
 * 
 * param lista_p  List to add to.
 * param node_p   Node to add.
 */
void 
dll_add_to_back(
  dll_list_t *list_p,
  dll_node_t *node_p);


/* 
 * Insert a node in a list after the specified node.
 * 
 * param pos_p   Node in list to insert after.
 * param node_p  Node to insert.
 */
void 
dll_insert_after(
  dll_node_t *pos_p,
  dll_node_t *node_p);


/* 
 * Insert a node in a list before the specified node.
 * 
 * param pos_p   Node in list to insert before.
 * param node_p  Node to insert.
 */
void 
dll_insert_before(
  dll_node_t *pos_p,
  dll_node_t *node_p);


/*
 * Remove a node from a DLL list.
 *
 * param node_p  Node to be reomved.
 */
void 
dll_remove_node(
  dll_node_t *node_p);


/*
 * Remove a node from the front of a DLL list.
 * 
 * param list_p  The DLL list to use.
 * retval        NULL if the list is empty; the pointer to the removed
 *               node otherwise.
 */
dll_node_t * 
dll_remove_from_front(
  dll_list_t *list_p);


/*
 * Remove a node from the back of a DLL list.
 * 
 * param list_p  The DLL list to use.
 * retval        NULL if the list is empty; the pointer to the removed
 *               node otherwise.
 */
dll_node_t * 
dll_remove_from_back(
  dll_list_t *list_p);


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
  dll_node_t *pos_p);


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
  dll_node_t *pos_p);


/*
 * Count the number of nodes in the specified DLL list.
 * 
 * param list_p  The DLL list to use.
 * retval        The number of nodes in the list.
 */
int 
dll_count(
  dll_list_t *list_p);


/*
 * Displays the nodes in the specified DLL list.
 * 
 * param list_p  The DLL list to use.
 */
void 
dll_show_list(
  dll_list_t *list_p);








/*--------------------- Function Definitions ---------------------------*/





#endif /* DLL_H_INCLUDE */
