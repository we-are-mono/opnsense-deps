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

/* --------------------------------------------------------------------------
 * Hash table module.
 *
 * This module provides a simple hash table for quickly finding an entry.
 * To use the module:
 *
 * - Create a hash table via htbl_create()
 *
 * - Add the htbl_entry_t object into your object which you would like
 *   to access via a hash table.
 *
 * - Use one of the following features (see each function for more detail):
 *   - htbl_clear()
 *   - htbl_insert()
 *   - htbl_delete()
 *   - htbl_exists()
 *   - htbl_get()
 *
 * --------------------------------------------------------------------------*/

#include "dll.h"

/* --------------------------------------------------------------------------
 * This macro can be used to extract a pointer to the object that
 * contains the hash table entry.
 *
 * Example:
 *
 * typedef struct foo
 * {
 *    uint32_t      size;
 *    htbl_entry_t  hash_entry;
 *    char         *name_p;
 * } foo_t;
 *
 * foo_t *my_object_p;
 * ...
 * ...
 * my_object_p = HTBL_GET_ENTRY_OBJECT(entry_p, foo_t, hash_entry);
 *
 * --------------------------------------------------------------------------*/
#define HTBL_GET_ENTRY_OBJECT(                                      \
  entry_p,   /* pointer to the hash table entry */                  \
  type,      /* name of the type containing the hash table entry */ \
  field_name /* name of the hash table entry field in the "type" */ \
  )                                                                 \
  ((type *)((uint8_t *)entry_p -                                    \
            (uint8_t *)(&(((type *)0)->field_name))))

/* --------------------------------------------------------------------------
 * Hash entry type
 * --------------------------------------------------------------------------*/
typedef struct htbl_entry htbl_entry_t;
struct htbl_entry
{
   char         *key_p;         /* Hash key */
   htbl_entry_t *next_p;        /* Next entry in this bucket */
};

/* --------------------------------------------------------------------------
 * Hash key type. This type is used for retrieving a linked list of keys
 * from the hash table
 * --------------------------------------------------------------------------*/
typedef struct htbl_key
{
   char       *string_p;        /* Hash key string*/
   dll_node_t  dll_node;        /* Doubly linked list node */
} htbl_key_t;

/* --------------------------------------------------------------------------
 * Hash table type
 * --------------------------------------------------------------------------*/
typedef struct htbl_table
{
   htbl_entry_t **entries;
   uint32_t       size;
} htbl_table_t;

/* --------------------------------------------------------------------------
 * Create a hash table.
 *
 * Parameters:
 *    size - Number of "buckets" in the hash table.
 *
 * Returns:
 *   A pointer to the hash table (NULL on failure).
 * --------------------------------------------------------------------------*/
htbl_table_t *htbl_create(uint32_t size);

/* --------------------------------------------------------------------------
 * Destroy a hash table.
 *
 * NOTE: This does not destroy the objects within the hash table, just the
 *       table itself. You must clean up the objects in the table yourself.
 *
 * Parameters:
 *    object_p - The hash table object to destroy.
 *
 * Returns:
 *   Nothing.
 * --------------------------------------------------------------------------*/
void htbl_destroy(htbl_table_t *object_p);

/* --------------------------------------------------------------------------
 * Insert an entry into a hash table.
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    entry_p - A pointer to the hash entry object to be inserted.
 *
 *    NOTE: The key which will be hashed must be set in the entry object.
 *
 * Returns:
 *   A bool - Successful (true) or not (false)
 * --------------------------------------------------------------------------*/
bool htbl_insert(htbl_table_t *table_p,
                 htbl_entry_t *entry_p);

/* --------------------------------------------------------------------------
 * Delete an entry from a hash table by entry pointer.
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    entry_p - A pointer to the hash entry object to be deleted.
 *
 * Returns:
 *   A bool - Successful (true) or not (false)
 * --------------------------------------------------------------------------*/
bool htbl_delete_by_entry(htbl_table_t *table_p,
                          htbl_entry_t *entry_p);

/* --------------------------------------------------------------------------
 * Delete an entry from a hash table by key.
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    key_p   - A pointer to the a key string.
 *
 * Returns:
 *   A bool - Successful (true) or not (false)
 * --------------------------------------------------------------------------*/
bool htbl_delete_by_key(htbl_table_t *table_p,
                        char         *key_p);

/* --------------------------------------------------------------------------
 * Exists in hash table?
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    key_p   - A pointer to the key string to search for.
 *
 * Returns:
 *    A boolean. True -> entry exists. False -> entry does NOT exist.
 * --------------------------------------------------------------------------*/
bool htbl_exists(htbl_table_t *table_p,
                 char         *key_p);

/* --------------------------------------------------------------------------
 * Get entry associated with key in hash table.
 * (Use the macro HTBL_GET_ENTRY_OBJECT to retrieve the associated object)
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    key_p   - A pointer to the key string to search for.
 *
 * Returns:
 *    Pointer to the entry object.
 * --------------------------------------------------------------------------*/
htbl_entry_t *htbl_get_entry(htbl_table_t *table_p,
                             char         *key_p);

/* --------------------------------------------------------------------------
 * Get linked list of keys in hash table.
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *
 * Returns:
 *    Doubly linked list of all keys in the hash table.
 * --------------------------------------------------------------------------*/
dll_list_t *htbl_get_key_list(htbl_table_t *table_p);

/* --------------------------------------------------------------------------
 * Destroy a previously retrieved linked list of keys.
 *
 * Parameters:
 *    list_p - A pointer to the list of keys.
 *
 * Returns:
 *    Nothing.
 * --------------------------------------------------------------------------*/
void htbl_destroy_key_list(dll_list_t *list_p);
