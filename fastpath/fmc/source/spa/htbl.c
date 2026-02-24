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

#include <string.h>
#include <stdlib.h>

#include "htbl.h"
#include "dll.h"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

/* ==========================================================================
 * PRIVATE FUNCTIONS
 * ==========================================================================*/

/* --------------------------------------------------------------------------
 * Hash function.
 *
 * Parameters:
 *    name_p - A pointer to the name string to hashed.
 *             This string MUST be NULL terminated!
 *
 * Returns:
 *    A hash index of type uint32_t.
 * --------------------------------------------------------------------------*/
static uint32_t htbl_hash (htbl_table_t *table_p,
                           char         *key_p)
{
   uint32_t hash_value;
   uint32_t hash_index;

   /* Accumulate a value based on the ascii value of each character */
   for (hash_value = 0; *key_p != '\0'; key_p++)
   {
      hash_value = *key_p + 31 * hash_value;
   }

   /* Find an index within the hash table size */
   hash_index = hash_value % table_p->size;

   return(hash_index);
}

/* --------------------------------------------------------------------------
 * New key object
 *
 * Parameters:
 *    string_p - A pointer to the key string.
 *               This string MUST be NULL terminated!
 *
 * Returns:
 *    A new key object of type htbl_key_t.
 * --------------------------------------------------------------------------*/
static htbl_key_t *htbl_new_key (char *string_p)
{
   htbl_key_t *object_p;

   object_p = (htbl_key_t *)calloc(1, sizeof(htbl_key_t));

   if (object_p == NULL)
   {
      return (NULL);
   }

   object_p->string_p = (char *)calloc(1, strlen(string_p) + 1);

   if (object_p->string_p == NULL)
   {
      free(object_p);
      return (NULL);
   }

   strcpy(object_p->string_p, string_p);

   return (object_p);
}

/* --------------------------------------------------------------------------
 * Destroy key object
 *
 * Parameters:
 *    object_p - A pointer to the key object.
 *
 * Returns:
 *    Nothing.
 * --------------------------------------------------------------------------*/
static void htbl_destroy_key (htbl_key_t *object_p)
{
   if (object_p != NULL)
   {
      if (object_p->string_p != NULL)
      {
         free(object_p->string_p);
      }

      free(object_p);
   }
}

/* ==========================================================================
 * PUBLIC FUNCTIONS
 * ==========================================================================*/

/* --------------------------------------------------------------------------
 * Create a hash table.
 *
 * Parameters:
 *    size - Number of "buckets" in the hash table.
 *
 * Returns:
 *   A pointer to the hash table (NULL on failure).
 * --------------------------------------------------------------------------*/
htbl_table_t *htbl_create(uint32_t size)
{
   htbl_table_t *table_p;

   table_p = (htbl_table_t *)calloc(1, sizeof(htbl_table_t));

   if (table_p == NULL)
   {
      return (NULL);
   }

   table_p->entries = (htbl_entry_t **)calloc(size, 
                                                  sizeof(htbl_entry_t *));

   if (table_p->entries == NULL)
   {
      free (table_p);
      return (NULL);
   }

   table_p->size = size;

   return (table_p);
}

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
void htbl_destroy(htbl_table_t *object_p)
{
   free(object_p->entries);
   free(object_p);
}

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
                 htbl_entry_t *entry_p)
{
   uint32_t hash_index;

   /* Check for NULL table or entry */
   if (table_p == NULL ||
       entry_p == NULL)
   {
      return (false);
   }

   /* Check for NULL key */
   if (entry_p->key_p == NULL)
   {
      return (false);
   }

   /* Check if this key already exists */
   if (htbl_exists(table_p,
                   entry_p->key_p))
   {
      return (false);
   }

   /*
    * Insert the entry at the beginning of the appropriate bucket's list.
    */

   /* Hash the key. */
   hash_index = htbl_hash(table_p,
                          entry_p->key_p);

   /* Entry points to current bucket list. */
   entry_p->next_p = *(table_p->entries + hash_index);

   /* Bucket points to entry. */
   *(table_p->entries + hash_index) = entry_p;

   return (true);
}

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
                          htbl_entry_t *entry_p)
{
   htbl_entry_t *cur_entry_p;
   uint32_t      hash_index;

   /* Check for NULL table or entry */
   if (table_p == NULL ||
       entry_p == NULL)
   {
      return (false);
   }

   /* Check for NULL key */
   if (entry_p->key_p == NULL)
   {
      return (false);
   }

   /* Check if this key is in the table */
   if (htbl_exists(table_p,
                   entry_p->key_p))
   {
      /* Get the hash index */
      hash_index = htbl_hash(table_p,
                             entry_p->key_p);

      /* Remove the entry */
      if (*(table_p->entries + hash_index) == entry_p)
      {
         /* First entry in bucket */
         *(table_p->entries + hash_index) = entry_p->next_p;

         entry_p->next_p = NULL; /* Clear entry we are removing */

         return (true);
      }
      else
      {
         cur_entry_p = *(table_p->entries + hash_index);

         while (cur_entry_p->next_p != NULL)
         {
            if (cur_entry_p->next_p == entry_p)
            {
               cur_entry_p->next_p = entry_p->next_p;
 
               entry_p->next_p = NULL; /* Clear entry we are removing */

               return (true);
            }
            cur_entry_p = cur_entry_p->next_p;
         }
      }
   }
   else
   {
      /* Not in table to begin with, but this is a delete so return true */
      return (true);
   }

   return (false);
}

/* --------------------------------------------------------------------------
 * Delete an entry from a hash table by key.
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    key_p   - A pointer to a key string.
 *
 * Returns:
 *   A bool - Successful (true) or not (false)
 * --------------------------------------------------------------------------*/
bool htbl_delete_by_key(htbl_table_t *table_p,
                        char         *key_p)
{
   htbl_entry_t *entry_p;

   entry_p = htbl_get_entry(table_p, key_p);

   if (entry_p != NULL)
   {
      return (htbl_delete_by_entry(table_p, entry_p));
   }
   else
   {
      return (false);
   }
}

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
                 char         *key_p)
{
   htbl_entry_t *cur_entry_p;

   for (cur_entry_p = *(table_p->entries + htbl_hash(table_p, key_p));
        cur_entry_p != NULL;
        cur_entry_p = cur_entry_p->next_p)
   { 
      if (strcmp(key_p, cur_entry_p->key_p) == 0)
      {
         return(true);
      }
   }
   return(false);
}

/* --------------------------------------------------------------------------
 * Get entry associated with key in hash table.
 * (Use the macro HTBL_GET_ENTRY_OBJECT to retrieve the associated object).
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *    key_p   - A pointer to the key string to search for.
 *
 * Returns:
 *    Pointer to the entry object.
 * --------------------------------------------------------------------------*/
htbl_entry_t *htbl_get_entry(htbl_table_t *table_p,
                             char         *key_p)
{
   htbl_entry_t *cur_entry_p;

   for (cur_entry_p = *(table_p->entries + htbl_hash(table_p, key_p));
        cur_entry_p != NULL;
        cur_entry_p = cur_entry_p->next_p)
   { 
      if (strcmp(key_p, cur_entry_p->key_p) == 0)
      {
         return(cur_entry_p);
      }
   }
   return(NULL);
}

/* --------------------------------------------------------------------------
 * Get linked list of keys in hash table.
 *
 * Parameters:
 *    table_p - A pointer to the hash table.
 *
 * Returns:
 *    Doubly linked list of all keys in the hash table.
 * --------------------------------------------------------------------------*/
dll_list_t *htbl_get_key_list(htbl_table_t *table_p)
{
   dll_list_t    *list_p;
   htbl_entry_t **bucket_p;
   htbl_entry_t  *cur_entry_p;
   htbl_key_t    *new_key_p;
   uint32_t       bucket_idx;

   list_p = (dll_list_t *)calloc(1, sizeof(dll_list_t));

   if (list_p == NULL)
   {
      return (NULL);
   }

   dll_list_init(list_p);

   for (bucket_idx = 0; bucket_idx < table_p->size; bucket_idx++)
   {
      bucket_p = table_p->entries + bucket_idx;

      cur_entry_p = *bucket_p;

      while (cur_entry_p != NULL)
      {
         /* Insert key object into linked list */
         new_key_p = htbl_new_key(cur_entry_p->key_p);

         dll_add_to_back(list_p, &(new_key_p->dll_node));

         cur_entry_p = cur_entry_p->next_p;
      }
   }

   return (list_p);
}

/* --------------------------------------------------------------------------
 * Destroy a previously retrieved linked list of keys.
 *
 * Parameters:
 *    list_p - A pointer to the list of keys.
 *
 * Returns:
 *    Nothing.
 * --------------------------------------------------------------------------*/
void htbl_destroy_key_list(dll_list_t *list_p)
{
   htbl_key_t *cur_key_p;
   dll_node_t *cur_node_p;
   dll_node_t *next_node_p;
   uint32_t    num_keys;
   uint32_t    count;

   num_keys = dll_count(list_p);

   cur_node_p = dll_get_first(list_p);

   for (count = 0; count < num_keys; count++)
   {
      cur_key_p = DLL_STRUCT_FROM_NODE_GET(cur_node_p,
                                           htbl_key_t,
                                           dll_node);

      next_node_p = dll_get_next_node(list_p,
                                      cur_node_p);

      dll_remove_node(cur_node_p);

      htbl_destroy_key(cur_key_p);

      cur_node_p = next_node_p;
   }

   free(list_p);
}
