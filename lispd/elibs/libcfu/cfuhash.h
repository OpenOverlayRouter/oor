/* Creation date: 2005-06-24 21:22:09
 * Authors: Don
 * Change log:
 */

/* Copyright (c) 2005 Don Owens
   Copyright (C) 2015 Cisco Systems, Inc.
   Copyright (C) 2015 CBA research group, Technical University of Catalonia.
   All rights reserved.

   This code is released under the BSD license:

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

     * Redistributions in binary form must reproduce the above
       copyright notice, this list of conditions and the following
       disclaimer in the documentation and/or other materials provided
       with the distribution.

     * Neither the name of the author nor the names of its
       contributors may be used to endorse or promote products derived
       from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
   COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
   OF THE POSSIBILITY OF SUCH DAMAGE.

   Original code by the Open vSwitch project. Modified by the LISPmob project.
*/

#ifndef _CFU_HASH_H_
#define _CFU_HASH_H_

#include "cfu.h"
#include "../../lib/generic_list.h"

#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* The hash table itself. */
    struct hash_table;
    typedef struct hash_table hash_table_t;

    /* Prototype for a pointer to a hashing function. */
    typedef u_int32_t (*hash_function_t)(const void *key);
    
    /* Prototype for a pointer to a hashing function. */
    typedef int (*hash_cmp_key_fn_t)(const void *key1, const void *key2);

    /* Prototype for a pointer to a free key function. */
    typedef void (*hash_free_key_fn_t)(const void *key);

    /* Prototype for a pointer to a clone key function. */
    typedef void *(*hash_clone_key_fn_t)(const void *key);

    /* Prototype for a pointer to a free function. */
    typedef void (*hash_free_fn_t)(void *data);

    /* Prototype for a pointer to a function that determines whether
     * or not to remove an entry from the hash.
    */
    typedef int (*hash_remove_fn_t)(void *key, void *data,void *arg);

    /* Prototype for a pointer to a function to be called foreach
     * key/value pair in the hash by hash_foreach().  Iteration
     * stops if a non-zero value is returned.
	 */
    typedef int (*hash_foreach_fn_t)(void *key, void *data,void *arg);
    
    /* Creates a new hash table. */
    extern hash_table_t *hash_new(hash_function_t hash_fn, hash_cmp_key_fn_t key_equal_fn,
            hash_free_key_fn_t free_key_fn, hash_free_fn_t free_val_fn,
            hash_clone_key_fn_t clone_key_fn,u_int32_t flags);


    /* Sets the hashing function to use when computing which bucket to add
     * entries to.  It should return a 32-bit unsigned integer.  By
     * default, Perl's hashing algorithm is used.
     */
    extern int hash_set_hash_function(hash_table_t *ht, hash_function_t hf);

    /* Sets the thresholds for when to rehash.  The ratio
     * num_entries/buckets is compared against low and high.  If it is
     * below 'low' or above 'high', the hash will shrink or grow,
     * respectively, unless the flags say to do otherwise.
     */
    extern int hash_set_thresholds(hash_table_t *ht, float low, float high);

    /* Sets the function to use when removing an entry from the hash,
     * i.e., when replacing an existing entry, deleting an entry, or
     * clearing the hash.  It is passed the value of the entry as a
     * void *.
     */
    extern int hash_set_free_function(hash_table_t * ht, hash_free_fn_t ff);

    /* Sets the function to use when removing a key from the hash,
     * i.e., when replacing an existing entry, deleting an entry, or
     * clearing the hash.  It is passed the value of the key as a
     * void *.
     */
    extern int hash_set_free_key_function(hash_table_t * ht, hash_free_key_fn_t ff);

    /* Sets the function to use when duplicating the key */
    extern int hash_set_clone_key_function(hash_table_t * ht, hash_clone_key_fn_t ckfn);

    /* Sets the function to use when comparing key */
    extern int hash_set_cmp_key_function(hash_table_t * ht, hash_cmp_key_fn_t cmp_f);

    /* Returns the hash's flags. See below for flag definitions. */
    extern u_int32_t hash_get_flags(hash_table_t *ht);

    /* Sets a flag. */
    extern u_int32_t hash_set_flag(hash_table_t *ht, u_int32_t flag);

    /* Clears a flag. */
    extern u_int32_t hash_clear_flag(hash_table_t *ht, u_int32_t new_flag);

    /* Returns the value for the entry with given key.
     */
    extern int hash_get_data(hash_table_t *ht, const void *key, void **data);

    /* Returns 1 if an entry with the given key exists in the hash, 0 otherwise. */
    extern int hash_exists_data(hash_table_t *ht, const void *key);

    /* Inserts the given data value into the hash and associates it with
     *  key.
     */
    extern int hash_put_data(hash_table_t *ht, const void *key, void *data,
        void **r);

    /* Clears the hash table (deletes all entries). */
    extern void hash_clear(hash_table_t *ht);

    /* Deletes the entry in the hash associated with key. If the entry
     * existed and no delete value function is defined, it's value will
     * be returned.
     */
    extern void * hash_delete_data(hash_table_t *ht, const void *key);

    /* Initializes a loop over all the key/value pairs in the hash.  It
     * returns the first key/value pair (see hash_next_data()).  1 is
     * returned if there are any entries in the hash.  0 is returned
     * otherwise.
     */
    extern int hash_each_data(hash_table_t *ht, void **key,  void **data);

    /* Gets the next key/value pair from the hash.  You must initialize
     * the loop using hash_each_data() before calling this function.
     * If a entry is left to return, 1 is returned from the function.  0
     * is returned if there are no more entries in the hash.
     */
    extern int hash_next_data(hash_table_t *ht, void **key, void **data);

    /* Iterates over the key/value pairs in the hash, passing each one
     * to r_fn, and removes all entries for which r_fn returns true.
     * If ff is not NULL, it is the passed the data to be freed.  arg
     * is passed to r_fn.
     */
    extern int hash_foreach_remove(hash_table_t *ht, hash_remove_fn_t r_fn, void *arg);


    /* Iterates over the key/value pairs in the hash, passing each one
     * to fe_fn, along with arg. This locks the hash, so do not call
     * any operations on the hash from within fe_fn unless you really
     * know what you're doing.  A non-zero return value from fe_fn()
     * stops the iteration.
     */
    extern size_t hash_foreach(hash_table_t *ht, hash_foreach_fn_t fe_fn, void *arg);

    /* Frees all resources allocated by the hash.  If ff is not NULL, it
     * is called for each hash entry with the value of the entry passed as
     * its only argument.  If ff is not NULL, it overrides any function
     * set previously with hash_set_free_function().
     */
    extern void hash_destroy(hash_table_t *ht);

    /* Rebuild the hash to better accomodate the number of entries. See
     * hash_set_thresholds().
     */
    extern int hash_rehash(hash_table_t *ht);

    /* Returns the number entries in the hash. */
    extern size_t hash_num_entries(hash_table_t *ht);

    /* Returns the number of buckets allocated for the hash. */
    extern size_t hash_num_buckets(hash_table_t *ht);

    /* Returns the number of buckets actually used out of the total number
     * allocated for the hash.
     */
    extern size_t hash_num_buckets_used(hash_table_t *ht);

    /* Locks the hash.  Use this with the each and next functions for
     * concurrency control.  Note that the hash is locked automatically
     * when doing inserts and deletes, so if you lock the hash and then
     * try to insert something into it, you may get into a deadlock,
     * depending on your system defaults for how mutexes work.
     */
    extern int hash_lock(hash_table_t *ht);

    /* Unlocks the hash.  Use this with the each an next functions for
     * concurrency control.  The caveat for hash_lcok() also applies to
     * this function.
     */
    extern int hash_unlock(hash_table_t *ht);

    /* Pretty print the hash's key/value pairs to the stream fp.  It is
     * assumed that all the keys and values are null-terminated strings.
     */
    extern int hash_pretty_print(hash_table_t *ht, FILE *fp);

    /* These are like the _data versions of these functions, with the
     * following exceptions:
     *   1) They assume that the key provided is a null-terminated string.
     *   2) They don't worry about the size of the data.
     *   3) Returned keys or values are the return value of the function.
     */
    extern void * hash_get(hash_table_t *ht, const void *key);
    extern int hash_exists(hash_table_t *ht, const void *key);
    extern void * hash_put(hash_table_t *ht, const void *key, void *data);
    extern void * hash_delete(hash_table_t *ht, const void *key);
    extern glist_t *hash_keys(hash_table_t *ht, int fast);
    extern glist_t *hash_values(hash_table_t *ht);


/* hash table flags */
#define HASH_NOCOPY_KEYS 1        /* do not copy the key when inserting a hash entry */
#define HASH_NO_LOCKING (1 << 1)  /* do not make the hash thread-safe */
#define HASH_FROZEN (1 << 2)      /* do not rehash when the size thresholds are reached */
#define HASH_FROZEN_UNTIL_GROWS (1 << 3) /* do not shrink the hash until it has grown */
#define HASH_FREE_DATA (1 << 4)   /* call free() on each value when the hash is destroyed */
#define HASH_IGNORE_CASE (1 << 5) /* treat keys case-insensitively */


#ifdef __cplusplus
}
#endif

#endif
