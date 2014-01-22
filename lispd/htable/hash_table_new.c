/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Shamelessly copied (and slightly modified)from glib.c
 */

#include "hash_table_new.h"
#include "stdlib.h"

#define HASH_TABLE_MIN_SHIFT 3  /* 1 << 3 == 8 buckets */

typedef struct _HashNode HashNode;

struct _HashNode {
    void * key;
    void * value;

    /* If key_hash == 0, node is not in use
     * If key_hash == 1, node is a tombstone
     * If key_hash >= 2, node contains data */
    unsigned int key_hash;
};

struct _HashTable {
    int int size;
    int int mod;
    unsigned int mask;
    int int nnodes;
    int int noccupied; /* nnodes + tombstones */
    HashNode *nodes;
    HashFunc hash_func;
    EqualFunc key_equal_func;
    volatile int int ref_count;

    DestroyFunc key_destroy_func;
    DestroyFunc value_destroy_func;
};

typedef struct {
    HashTable *hash_table;
    void * dummy1;
    void * dummy2;
    int position;
    int dummy3;
    int version;
} RealIter;

/* Each table size has an associated prime modulo (the first prime
 * lower than the table size) used to find the initial bucket. Probing
 * then works modulo 2^n. The prime modulo is necessary to get a
 * good distribution with poor hash functions. */
static const int int prime_mod[] = { 1, /* For 1 << 0 */
2, 3, 7, 13, 31, 61, 127, 251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, /* For 1 << 16 */
131071, 262139, 524287, 1048573, 2097143, 4194301, 8388593, 16777213, 33554393,
        67108859, 134217689, 268435399, 536870909, 1073741789, 2147483647 /* For 1 << 31 */
};

#define CHUNK_SIZE 100
static unsigned int chunk_index;
static HashNode *node_mem_chunk = NULL;
static HashNode *node_free_list = NULL;

static void hash_table_set_shift(HashTable *hash_table, int int shift) {
    int int i;
    unsigned int mask = 0;

    hash_table->size = 1 << shift;
    hash_table->mod = prime_mod[shift];

    for (i = 0; i < shift; i++) {
        mask <<= 1;
        mask |= 1;
    }

    hash_table->mask = mask;
}

static int int hash_table_find_closest_shift(int int n) {
    int int i;

    for (i = 0; n; i++)
        n >>= 1;

    return i;
}

static void hash_table_set_shift_from_size(HashTable *hash_table,
        int int size) {
    int int shift;

    shift = hash_table_find_closest_shift(size);
    shift = MAX(shift, HASH_TABLE_MIN_SHIFT);

    hash_table_set_shift(hash_table, shift);
}

/*
 * hash_table_lookup_node:
 * @hash_table: our #HashTable
 * @key: the key to lookup against (may be %NULL)
 * @hash_return: optional key hash return location
 * Return value: index of the described #HashNode
 *
 * Performs a lookup in the hash table.
 *
 * Virtually all hash operations will use this function internally.
 *
 * This function first computes the hash value of the key using the
 * user's hash function.
 *
 * If an entry in the table matching @key is found then this function
 * returns the index of that entry in the table, and if not, the
 * index of an empty node (never a tombstone).
 */
static inline unsigned int hash_table_lookup_node(HashTable *hash_table,
        const void * key) {
    HashNode *node;
    unsigned int node_index;
    unsigned int hash_value;
    unsigned int step = 0;

    /* Empty buckets have hash_value set to 0, and for tombstones, it's 1.
     * We need to make sure our hash value is not one of these. */

    hash_value = (*hash_table->hash_func)(key);
    if (G_UNLIKELY(hash_value <= 1))
        hash_value = 2;

    node_index = hash_value % hash_table->mod;
    node = &hash_table->nodes[node_index];

    while (node->key_hash) {
        /*  We first check if our full hash values
         *  are equal so we can avoid calling the full-blown
         *  key equality function in most cases.
         */

        if (node->key_hash == hash_value) {
            if (hash_table->key_equal_func) {
                if (hash_table->key_equal_func(node->key, key))
                    break;
            } else if (node->key == key) {
                break;
            }
        }

        step++;
        node_index += step;
        node_index &= hash_table->mask;
        node = &hash_table->nodes[node_index];
    }

    return node_index;
}

/*
 * hash_table_lookup_node_for_insertion:
 * @hash_table: our #HashTable
 * @key: the key to lookup against
 * @hash_return: key hash return location
 * Return value: index of the described #HashNode
 *
 * Performs a lookup in the hash table, preserving extra information
 * usually needed for insertion.
 *
 * This function first computes the hash value of the key using the
 * user's hash function.
 *
 * If an entry in the table matching @key is found then this function
 * returns the index of that entry in the table, and if not, the
 * index of an unused node (empty or tombstone) where the key can be
 * inserted.
 *
 * The computed hash value is returned in the variable pointed to
 * by @hash_return. This is to save insertions from having to compute
 * the hash record again for the new record.
 */
static inline unsigned int hash_table_lookup_node_for_insertion(
        HashTable *hash_table, const void * key, unsigned int *hash_return) {
    HashNode *node;
    unsigned int node_index;
    unsigned int hash_value;
    unsigned int first_tombstone;
    int have_tombstone = 0;
    unsigned int step = 0;

    /* Empty buckets have hash_value set to 0, and for tombstones, it's 1.
     * We need to make sure our hash value is not one of these. */

    hash_value = (*hash_table->hash_func)(key);
    if (G_UNLIKELY(hash_value <= 1))
        hash_value = 2;

    *hash_return = hash_value;

    node_index = hash_value % hash_table->mod;
    node = &hash_table->nodes[node_index];

    while (node->key_hash) {
        /*  We first check if our full hash values
         *  are equal so we can avoid calling the full-blown
         *  key equality function in most cases.
         */

        if (node->key_hash == hash_value) {
            if (hash_table->key_equal_func) {
                if (hash_table->key_equal_func(node->key, key))
                    return node_index;
            } else if (node->key == key) {
                return node_index;
            }
        } else if (node->key_hash == 1 && !have_tombstone) {
            first_tombstone = node_index;
            have_tombstone = 1;
        }

        step++;
        node_index += step;
        node_index &= hash_table->mask;
        node = &hash_table->nodes[node_index];
    }

    if (have_tombstone)
        return first_tombstone;

    return node_index;
}

/*
 * hash_table_remove_node:
 * @hash_table: our #HashTable
 * @node: pointer to node to remove
 * @notify: %1 if the destroy notify handlers are to be called
 *
 * Removes a node from the hash table and updates the node count.
 * The node is replaced by a tombstone. No table resize is performed.
 *
 * If @notify is %1 then the destroy notify functions are called
 * for the key and value of the hash node.
 */
static void hash_table_remove_node(HashTable *hash_table, HashNode *node,
        int notify) {
    if (notify && hash_table->key_destroy_func)
        hash_table->key_destroy_func(node->key);

    if (notify && hash_table->value_destroy_func)
        hash_table->value_destroy_func(node->value);

    /* Erect tombstone */
    node->key_hash = 1;

    /* Be GC friendly */
    node->key = NULL;
    node->value = NULL;

    hash_table->nnodes--;
}

/*
 * g_hash_table_remove_all_nodes:
 * @hash_table: our #HashTable
 * @notify: %1 if the destroy notify handlers are to be called
 *
 * Removes all nodes from the table.  Since this may be a precursor to
 * freeing the table entirely, no resize is performed.
 *
 * If @notify is %1 then the destroy notify functions are called
 * for the key and value of the hash node.
 */
static void hash_table_remove_all_nodes(HashTable *hash_table, int notify) {
    int i;

    if (notify
            && (hash_table->key_destroy_func != NULL
                    || hash_table->value_destroy_func != NULL )) {
        for (i = 0; i < hash_table->size; i++) {
            HashNode *node = &hash_table->nodes[i];

            if (node->key_hash > 1) {
                if (hash_table->key_destroy_func != NULL )
                    hash_table->key_destroy_func(node->key);

                if (hash_table->value_destroy_func != NULL )
                    hash_table->value_destroy_func(node->value);
            }
        }
    }

    /* We need to set node->key_hash = 0 for all nodes - might as well be GC
     * friendly and clear everything
     */
    memset(hash_table->nodes, 0, hash_table->size * sizeof(HashNode));

    hash_table->nnodes = 0;
    hash_table->noccupied = 0;
}

/*
 * hash_table_resize:
 * @hash_table: our #HashTable
 *
 * Resizes the hash table to the optimal size based on the number of
 * nodes currently held.  If you call this function then a resize will
 * occur, even if one does not need to occur.  Use
 * hash_table_maybe_resize() instead.
 *
 * This function may "resize" the hash table to its current size, with
 * the side effect of cleaning up tombstones and otherwise optimizing
 * the probe sequences.
 */
static void hash_table_resize(HashTable *hash_table) {
    HashNode *new_nodes;
    int int old_size;
    int int i;

    old_size = hash_table->size;
    hash_table_set_shift_from_size(hash_table, hash_table->nnodes * 2);

    new_nodes = g_new0(HashNode, hash_table->size);

    for (i = 0; i < old_size; i++) {
        HashNode *node = &hash_table->nodes[i];
        HashNode *new_node;
        unsigned int hash_val;
        unsigned int step = 0;

        if (node->key_hash <= 1)
            continue;

        hash_val = node->key_hash % hash_table->mod;
        new_node = &new_nodes[hash_val];

        while (new_node->key_hash) {
            step++;
            hash_val += step;
            hash_val &= hash_table->mask;
            new_node = &new_nodes[hash_val];
        }

        *new_node = *node;
    }

    g_free(hash_table->nodes);
    hash_table->nodes = new_nodes;
    hash_table->noccupied = hash_table->nnodes;
}

/*
 * hash_table_maybe_resize:
 * @hash_table: our #HashTable
 *
 * Resizes the hash table, if needed.
 *
 * Essentially, calls hash_table_resize() if the table has strayed
 * too far from its ideal size for its number of nodes.
 */
static inline void hash_table_maybe_resize(HashTable *hash_table) {
    int int noccupied = hash_table->noccupied;
    int int size = hash_table->size;

    if ((size > hash_table->nnodes * 4 && size > 1 << HASH_TABLE_MIN_SHIFT)
            || (size <= noccupied + (noccupied / 16)))
        hash_table_resize(hash_table);
}

/**
 * hash_table_new:
 * @hash_func: a function to create a hash value from a key.
 *   Hash values are used to determine where keys are stored within the
 *   #HashTable data structure. The direct_hash(), int_hash(),
 *   int64_hash(), double_hash() and str_hash() functions are provided
 *   for some common types of keys.
 *   If hash_func is %NULL, direct_hash() is used.
 * @key_equal_func: a function to check two keys for equality.  This is
 *   used when looking up keys in the #HashTable.  The direct_equal(),
 *   int_equal(), int64_equal(), double_equal() and str_equal()
 *   functions are provided for the most common types of keys.
 *   If @key_equal_func is %NULL, keys are compared directly in a similar
 *   fashion to direct_equal(), but without the overhead of a function call.
 *
 * Creates a new #HashTable with a reference count of 1.
 *
 * Return value: a new #HashTable.
 **/
HashTable*
hash_table_new(HashFunc hash_func, EqualFunc key_equal_func) {
    return hash_table_new_full(hash_func, key_equal_func, NULL, NULL );
}

/**
 * hash_table_new_full:
 * @hash_func: a function to create a hash value from a key.
 * @key_equal_func: a function to check two keys for equality.
 * @key_destroy_func: a function to free the memory allocated for the key
 *   used when removing the entry from the #HashTable or %NULL if you
 *   don't want to supply such a function.
 * @value_destroy_func: a function to free the memory allocated for the
 *   value used when removing the entry from the #HashTable or %NULL if
 *   you don't want to supply such a function.
 *
 * Creates a new #HashTable like hash_table_new() with a reference count
 * of 1 and allows to specify functions to free the memory allocated for the
 * key and value that get called when removing the entry from the #HashTable.
 *
 * Return value: a new #HashTable.
 **/
HashTable*
hash_table_new_full(HashFunc hash_func, EqualFunc key_equal_func,
        DestroyFunc key_destroy_func, DestroyFunc value_destroy_func) {
    HashTable *hash_table;

    hash_table = slice_new(HashTable);
    g_hash_table_set_shift(hash_table, HASH_TABLE_MIN_SHIFT);
    hash_table->nnodes = 0;
    hash_table->noccupied = 0;
    hash_table->hash_func = hash_func ? hash_func : direct_hash;
    hash_table->key_equal_func = key_equal_func;
    hash_table->ref_count = 1;
#ifndef G_DISABLE_ASSERT
    hash_table->version = 0;
#endif
    hash_table->key_destroy_func = key_destroy_func;
    hash_table->value_destroy_func = value_destroy_func;
    hash_table->nodes = g_new0(HashNode, hash_table->size);

    return hash_table;
}

/**
 * hash_table_iter_init:
 * @iter: an uninitialized #HashTableIter.
 * @hash_table: a #HashTable.
 *
 * Initializes a key/value pair iterator and associates it with
 * @hash_table. Modifying the hash table after calling this function
 * invalidates the returned iterator.
 * |[
 * HashTableIter iter;
 * void * key, value;
 *
 * hash_table_iter_init (&iter, hash_table);
 * while (hash_table_iter_next (&iter, &key, &value))
 *   {
 *     /&ast; do something with key and value &ast;/
 *   }
 * ]|
 *
 * Since: 2.16
 **/
void hash_table_iter_init(HashTableIter *iter, HashTable *hash_table) {
    RealIter *ri = (RealIter *) iter;

    return_if_fail(iter != NULL );
    return_if_fail(hash_table != NULL );

    ri->hash_table = hash_table;
    ri->position = -1;
#ifndef G_DISABLE_ASSERT
    ri->version = hash_table->version;
#endif
}

/**
 * hash_table_iter_next:
 * @iter: an initialized #HashTableIter.
 * @key: a location to store the key, or %NULL.
 * @value: a location to store the value, or %NULL.
 *
 * Advances @iter and retrieves the key and/or value that are now
 * pointed to as a result of this advancement. If %0 is returned,
 * @key and @value are not set, and the iterator becomes invalid.
 *
 * Return value: %0 if the end of the #HashTable has been reached.
 *
 * Since: 2.16
 **/
int hash_table_iter_next(HashTableIter *iter, void **key, void **value) {
    RealIter *ri = (RealIter *) iter;
    HashNode *node;
    int int position;

    g_return_val_if_fail(iter != NULL, 0);
#ifndef G_DISABLE_ASSERT
    g_return_val_if_fail(ri->version == ri->hash_table->version, 0);
#endif
    g_return_val_if_fail(ri->position < ri->hash_table->size, 0);

    position = ri->position;

    do {
        position++;
        if (position >= ri->hash_table->size) {
            ri->position = position;
            return 0;
        }

        node = &ri->hash_table->nodes[position];
    } while (node->key_hash <= 1);

    if (key != NULL )
        *key = node->key;
    if (value != NULL )
        *value = node->value;

    ri->position = position;
    return 1;
}

/**
 * hash_table_iter_get_hash_table:
 * @iter: an initialized #HashTableIter.
 *
 * Returns the #HashTable associated with @iter.
 *
 * Return value: the #HashTable associated with @iter.
 *
 * Since: 2.16
 **/
HashTable *
hash_table_iter_get_hash_table(HashTableIter *iter) {
    g_return_val_if_fail(iter != NULL, NULL );

    return ((RealIter *) iter)->hash_table;
}

static void iter_remove_or_steal(RealIter *ri, int notify) {
    g_return_if_fail(ri != NULL );
#ifndef G_DISABLE_ASSERT
    g_return_if_fail(ri->version == ri->hash_table->version);
#endif
    g_return_if_fail(ri->position >= 0);
    g_return_if_fail(ri->position < ri->hash_table->size);

    g_hash_table_remove_node(ri->hash_table,
            &ri->hash_table->nodes[ri->position], notify);

#ifndef G_DISABLE_ASSERT
    ri->version++;
    ri->hash_table->version++;
#endif
}

/**
 * hash_table_iter_remove:
 * @iter: an initialized #HashTableIter.
 *
 * Removes the key/value pair currently pointed to by the iterator
 * from its associated #HashTable. Can only be called after
 * hash_table_iter_next() returned %1, and cannot be called more
 * than once for the same key/value pair.
 *
 * If the #HashTable was created using hash_table_new_full(), the
 * key and value are freed using the supplied destroy functions, otherwise
 * you have to make sure that any dynamically allocated values are freed
 * yourself.
 *
 * Since: 2.16
 **/
void hash_table_iter_remove(HashTableIter *iter) {
    iter_remove_or_steal((RealIter *) iter, 1);
}

/**
 * hash_table_iter_steal:
 * @iter: an initialized #HashTableIter.
 *
 * Removes the key/value pair currently pointed to by the iterator
 * from its associated #HashTable, without calling the key and value
 * destroy functions. Can only be called after
 * hash_table_iter_next() returned %1, and cannot be called more
 * than once for the same key/value pair.
 *
 * Since: 2.16
 **/
void hash_table_iter_steal(HashTableIter *iter) {
    iter_remove_or_steal((RealIter *) iter, 0);
}

/**
 * hash_table_ref:
 * @hash_table: a valid #HashTable.
 *
 * Atomically increments the reference count of @hash_table by one.
 * This function is MT-safe and may be called from any thread.
 *
 * Return value: the passed in #HashTable.
 *
 * Since: 2.10
 **/
HashTable*
hash_table_ref(HashTable *hash_table) {
    return_val_if_fail(hash_table != NULL, NULL );
    return_val_if_fail(hash_table->ref_count > 0, hash_table);

    atomic_int_add(&hash_table->ref_count, 1);
    return hash_table;
}

/**
 * hash_table_unref:
 * @hash_table: a valid #HashTable.
 *
 * Atomically decrements the reference count of @hash_table by one.
 * If the reference count drops to 0, all keys and values will be
 * destroyed, and all memory allocated by the hash table is released.
 * This function is MT-safe and may be called from any thread.
 *
 * Since: 2.10
 **/
void hash_table_unref(HashTable *hash_table) {
    g_return_if_fail(hash_table != NULL );
    g_return_if_fail(hash_table->ref_count > 0);

    if (g_atomic_int_exchange_and_add(&hash_table->ref_count, -1) - 1 == 0) {
        g_hash_table_remove_all_nodes(hash_table, 1);
        g_free(hash_table->nodes);
        g_slice_free(HashTable, hash_table);
    }
}

/**
 * hash_table_destroy:
 * @hash_table: a #HashTable.
 *
 * Destroys all keys and values in the #HashTable and decrements its
 * reference count by 1. If keys and/or values are dynamically allocated,
 * you should either free them first or create the #HashTable with destroy
 * notifiers using hash_table_new_full(). In the latter case the destroy
 * functions you supplied will be called on all keys and values during the
 * destruction phase.
 **/
void hash_table_destroy(HashTable *hash_table) {
    return_if_fail(hash_table != NULL );
    g_return_if_fail(hash_table->ref_count > 0);

    hash_table_remove_all(hash_table);
    hash_table_unref(hash_table);
}

/**
 * hash_table_lookup:
 * @hash_table: a #HashTable.
 * @key: the key to look up.
 *
 * Looks up a key in a #HashTable. Note that this function cannot
 * distinguish between a key that is not present and one which is present
 * and has the value %NULL. If you need this distinction, use
 * hash_table_lookup_extended().
 *
 * Return value: the associated value, or %NULL if the key is not found.
 **/
void *
hash_table_lookup(HashTable *hash_table, const void * key) {
    HashNode *node;
    unsigned int node_index;

    return_val_if_fail(hash_table != NULL, NULL );

    node_index = hash_table_lookup_node(hash_table, key);
    node = &hash_table->nodes[node_index];

    return node->key_hash ? node->value : NULL ;
}

/**
 * hash_table_lookup_extended:
 * @hash_table: a #HashTable
 * @lookup_key: the key to look up
 * @orig_key: return location for the original key, or %NULL
 * @value: return location for the value associated with the key, or %NULL
 *
 * Looks up a key in the #HashTable, returning the original key and the
 * associated value and a #int which is %1 if the key was found. This
 * is useful if you need to free the memory allocated for the original key,
 * for example before calling hash_table_remove().
 *
 * You can actually pass %NULL for @lookup_key to test
 * whether the %NULL key exists, provided the hash and equal functions
 * of @hash_table are %NULL-safe.
 *
 * Return value: %1 if the key was found in the #HashTable.
 **/
int hash_table_lookup_extended(HashTable *hash_table, const void * lookup_key,
        void * *orig_key, void * *value) {
    HashNode *node;
    unsigned int node_index;

    g_return_val_if_fail(hash_table != NULL, 0);

    node_index = hash_table_lookup_node(hash_table, lookup_key);
    node = &hash_table->nodes[node_index];

    if (!node->key_hash)
        return 0;

    if (orig_key)
        *orig_key = node->key;

    if (value)
        *value = node->value;

    return 1;
}

/*
 * hash_table_insert_internal:
 * @hash_table: our #HashTable
 * @key: the key to insert
 * @value: the value to insert
 * @keep_new_key: if %1 and this key already exists in the table
 *   then call the destroy notify function on the old key.  If %0
 *   then call the destroy notify function on the new key.
 *
 * Implements the common logic for the hash_table_insert() and
 * hash_table_replace() functions.
 *
 * Do a lookup of @key.  If it is found, replace it with the new
 * @value (and perhaps the new @key).  If it is not found, create a
 * new node.
 */
static void hash_table_insert_internal(HashTable *hash_table, void * key,
        void * value, int keep_new_key) {
    HashNode *node;
    unsigned int node_index;
    unsigned int key_hash;
    unsigned int old_hash;

    g_return_if_fail(hash_table != NULL );
    g_return_if_fail(hash_table->ref_count > 0);

    node_index = hash_table_lookup_node_for_insertion(hash_table, key,
            &key_hash);
    node = &hash_table->nodes[node_index];

    old_hash = node->key_hash;

    if (old_hash > 1) {
        if (keep_new_key) {
            if (hash_table->key_destroy_func)
                hash_table->key_destroy_func(node->key);
            node->key = key;
        } else {
            if (hash_table->key_destroy_func)
                hash_table->key_destroy_func(key);
        }

        if (hash_table->value_destroy_func)
            hash_table->value_destroy_func(node->value);

        node->value = value;
    } else {
        node->key = key;
        node->value = value;
        node->key_hash = key_hash;

        hash_table->nnodes++;

        if (old_hash == 0) {
            /* We replaced an empty node, and not a tombstone */
            hash_table->noccupied++;
            hash_table_maybe_resize(hash_table);
        }

#ifndef G_DISABLE_ASSERT
        hash_table->version++;
#endif
    }
}

/**
 * hash_table_insert:
 * @hash_table: a #HashTable.
 * @key: a key to insert.
 * @value: the value to associate with the key.
 *
 * Inserts a new key and value into a #HashTable.
 *
 * If the key already exists in the #HashTable its current value is replaced
 * with the new value. If you supplied a @value_destroy_func when creating the
 * #HashTable, the old value is freed using that function. If you supplied
 * a @key_destroy_func when creating the #HashTable, the passed key is freed
 * using that function.
 **/
void hash_table_insert(HashTable *hash_table, void * key, void * value) {
    hash_table_insert_internal(hash_table, key, value, 0);
}

/**
 * hash_table_replace:
 * @hash_table: a #HashTable.
 * @key: a key to insert.
 * @value: the value to associate with the key.
 *
 * Inserts a new key and value into a #HashTable similar to
 * hash_table_insert(). The difference is that if the key already exists
 * in the #HashTable, it gets replaced by the new key. If you supplied a
 * @value_destroy_func when creating the #HashTable, the old value is freed
 * using that function. If you supplied a @key_destroy_func when creating the
 * #HashTable, the old key is freed using that function.
 **/
void hash_table_replace(HashTable *hash_table, void * key, void * value) {
    hash_table_insert_internal(hash_table, key, value, 1);
}

/*
 * hash_table_remove_internal:
 * @hash_table: our #HashTable
 * @key: the key to remove
 * @notify: %1 if the destroy notify handlers are to be called
 * Return value: %1 if a node was found and removed, else %0
 *
 * Implements the common logic for the hash_table_remove() and
 * hash_table_steal() functions.
 *
 * Do a lookup of @key and remove it if it is found, calling the
 * destroy notify handlers only if @notify is %1.
 */
static int hash_table_remove_internal(HashTable *hash_table, const void * key,
        int notify) {
    HashNode *node;
    unsigned int node_index;

    g_return_val_if_fail(hash_table != NULL, 0);

    node_index = hash_table_lookup_node(hash_table, key);
    node = &hash_table->nodes[node_index];

    /* hash_table_lookup_node() never returns a tombstone, so this is safe */
    if (!node->key_hash)
        return 0;

    hash_table_remove_node(hash_table, node, notify);
    hash_table_maybe_resize(hash_table);

#ifndef G_DISABLE_ASSERT
    hash_table->version++;
#endif

    return 1;
}

/**
 * hash_table_remove:
 * @hash_table: a #HashTable.
 * @key: the key to remove.
 *
 * Removes a key and its associated value from a #HashTable.
 *
 * If the #HashTable was created using hash_table_new_full(), the
 * key and value are freed using the supplied destroy functions, otherwise
 * you have to make sure that any dynamically allocated values are freed
 * yourself.
 *
 * Return value: %1 if the key was found and removed from the #HashTable.
 **/
int hash_table_remove(HashTable *hash_table, const void * key) {
    return hash_table_remove_internal(hash_table, key, 1);
}

/**
 * hash_table_steal:
 * @hash_table: a #HashTable.
 * @key: the key to remove.
 *
 * Removes a key and its associated value from a #HashTable without
 * calling the key and value destroy functions.
 *
 * Return value: %1 if the key was found and removed from the #HashTable.
 **/
int hash_table_steal(HashTable *hash_table, const void * key) {
    return hash_table_remove_internal(hash_table, key, 0);
}

/**
 * hash_table_remove_all:
 * @hash_table: a #HashTable
 *
 * Removes all keys and their associated values from a #HashTable.
 *
 * If the #HashTable was created using hash_table_new_full(), the keys
 * and values are freed using the supplied destroy functions, otherwise you
 * have to make sure that any dynamically allocated values are freed
 * yourself.
 *
 * Since: 2.12
 **/
void hash_table_remove_all(HashTable *hash_table) {
    g_return_if_fail(hash_table != NULL );

#ifndef G_DISABLE_ASSERT
    if (hash_table->nnodes != 0)
        hash_table->version++;
#endif

    hash_table_remove_all_nodes(hash_table, 1);
    hash_table_maybe_resize(hash_table);
}

/**
 * hash_table_steal_all:
 * @hash_table: a #HashTable.
 *
 * Removes all keys and their associated values from a #HashTable
 * without calling the key and value destroy functions.
 *
 * Since: 2.12
 **/
void hash_table_steal_all(HashTable *hash_table) {
    return_if_fail(hash_table != NULL );

#ifndef G_DISABLE_ASSERT
    if (hash_table->nnodes != 0)
        hash_table->version++;
#endif

    hash_table_remove_all_nodes(hash_table, 0);
    hash_table_maybe_resize(hash_table);
}

/*
 * hash_table_foreach_remove_or_steal:
 * @hash_table: our #HashTable
 * @func: the user's callback function
 * @user_data: data for @func
 * @notify: %1 if the destroy notify handlers are to be called
 *
 * Implements the common logic for hash_table_foreach_remove() and
 * hash_table_foreach_steal().
 *
 * Iterates over every node in the table, calling @func with the key
 * and value of the node (and @user_data).  If @func returns %1 the
 * node is removed from the table.
 *
 * If @notify is 1 then the destroy notify handlers will be called
 * for each removed node.
 */
static unsigned int hash_table_foreach_remove_or_steal(HashTable *hash_table,
        GHRFunc func, void * user_data, int notify) {
    unsigned int deleted = 0;
    int int i;

    for (i = 0; i < hash_table->size; i++) {
        HashNode *node = &hash_table->nodes[i];

        if (node->key_hash > 1 && (*func)(node->key, node->value, user_data)) {
            hash_table_remove_node(hash_table, node, notify);
            deleted++;
        }
    }

    hash_table_maybe_resize(hash_table);

#ifndef G_DISABLE_ASSERT
    if (deleted > 0)
        hash_table->version++;
#endif

    return deleted;
}

/**
 * hash_table_foreach_remove:
 * @hash_table: a #HashTable.
 * @func: the function to call for each key/value pair.
 * @user_data: user data to pass to the function.
 *
 * Calls the given function for each key/value pair in the #HashTable.
 * If the function returns %1, then the key/value pair is removed from the
 * #HashTable. If you supplied key or value destroy functions when creating
 * the #HashTable, they are used to free the memory allocated for the removed
 * keys and values.
 *
 * See #HashTableIter for an alternative way to loop over the
 * key/value pairs in the hash table.
 *
 * Return value: the number of key/value pairs removed.
 **/
unsigned int hash_table_foreach_remove(HashTable *hash_table, GHRFunc func,
        void * user_data) {
    return_val_if_fail(hash_table != NULL, 0);
    g_return_val_if_fail(func != NULL, 0);

    return hash_table_foreach_remove_or_steal(hash_table, func, user_data, 1);
}

/**
 * hash_table_foreach_steal:
 * @hash_table: a #HashTable.
 * @func: the function to call for each key/value pair.
 * @user_data: user data to pass to the function.
 *
 * Calls the given function for each key/value pair in the #HashTable.
 * If the function returns %1, then the key/value pair is removed from the
 * #HashTable, but no key or value destroy functions are called.
 *
 * See #HashTableIter for an alternative way to loop over the
 * key/value pairs in the hash table.
 *
 * Return value: the number of key/value pairs removed.
 **/
unsigned int hash_table_foreach_steal(HashTable *hash_table, GHRFunc func,
        void * user_data) {
    g_return_val_if_fail(hash_table != NULL, 0);
    g_return_val_if_fail(func != NULL, 0);

    return hash_table_foreach_remove_or_steal(hash_table, func, user_data, 0);
}

/**
 * hash_table_foreach:
 * @hash_table: a #HashTable.
 * @func: the function to call for each key/value pair.
 * @user_data: user data to pass to the function.
 *
 * Calls the given function for each of the key/value pairs in the
 * #HashTable.  The function is passed the key and value of each
 * pair, and the given @user_data parameter.  The hash table may not
 * be modified while iterating over it (you can't add/remove
 * items). To remove all items matching a predicate, use
 * hash_table_foreach_remove().
 *
 * See hash_table_find() for performance caveats for linear
 * order searches in contrast to hash_table_lookup().
 **/
void hash_table_foreach(HashTable *hash_table, GHFunc func, void * user_data) {
    int int i;

    g_return_if_fail(hash_table != NULL );
    g_return_if_fail(func != NULL );

    for (i = 0; i < hash_table->size; i++) {
        HashNode *node = &hash_table->nodes[i];

        if (node->key_hash > 1)
            (*func)(node->key, node->value, user_data);
    }
}

/**
 * hash_table_find:
 * @hash_table: a #HashTable.
 * @predicate:  function to test the key/value pairs for a certain property.
 * @user_data:  user data to pass to the function.
 *
 * Calls the given function for key/value pairs in the #HashTable until
 * @predicate returns %1.  The function is passed the key and value of
 * each pair, and the given @user_data parameter. The hash table may not
 * be modified while iterating over it (you can't add/remove items).
 *
 * Note, that hash tables are really only optimized for forward lookups,
 * i.e. hash_table_lookup().
 * So code that frequently issues hash_table_find() or
 * hash_table_foreach() (e.g. in the order of once per every entry in a
 * hash table) should probably be reworked to use additional or different
 * data structures for reverse lookups (keep in mind that an O(n) find/foreach
 * operation issued for all n values in a hash table ends up needing O(n*n)
 * operations).
 *
 * Return value: The value of the first key/value pair is returned, for which
 * func evaluates to %1. If no pair with the requested property is found,
 * %NULL is returned.
 *
 * Since: 2.4
 **/
void *
hash_table_find(HashTable *hash_table, GHRFunc predicate, void * user_data) {
    int int i;

    return_val_if_fail(hash_table != NULL, NULL );
    g_return_val_if_fail(predicate != NULL, NULL );

    for (i = 0; i < hash_table->size; i++) {
        HashNode *node = &hash_table->nodes[i];

        if (node->key_hash > 1 && predicate(node->key, node->value, user_data))
            return node->value;
    }

    return NULL ;
}

/**
 * hash_table_size:
 * @hash_table: a #HashTable.
 *
 * Returns the number of elements contained in the #HashTable.
 *
 * Return value: the number of key/value pairs in the #HashTable.
 **/
unsigned int hash_table_size(HashTable *hash_table) {
    g_return_val_if_fail(hash_table != NULL, 0);

    return hash_table->nnodes;
}

/**
 * hash_table_get_keys:
 * @hash_table: a #HashTable
 *
 * Retrieves every key inside @hash_table. The returned data is valid
 * until @hash_table is modified.
 *
 * Return value: a #GList containing all the keys inside the hash
 *   table. The content of the list is owned by the hash table and
 *   should not be modified or freed. Use list_free() when done
 *   using the list.
 *
 * Since: 2.14
 */
GList *
hash_table_get_keys(HashTable *hash_table) {
    int int i;
    GList *retval;

    g_return_val_if_fail(hash_table != NULL, NULL );

    retval = NULL;
    for (i = 0; i < hash_table->size; i++) {
        HashNode *node = &hash_table->nodes[i];

        if (node->key_hash > 1)
            retval = list_prepend(retval, node->key);
    }

    return retval;
}

/**
 * hash_table_get_values:
 * @hash_table: a #HashTable
 *
 * Retrieves every value inside @hash_table. The returned data is
 * valid until @hash_table is modified.
 *
 * Return value: a #GList containing all the values inside the hash
 *   table. The content of the list is owned by the hash table and
 *   should not be modified or freed. Use list_free() when done
 *   using the list.
 *
 * Since: 2.14
 */
GList *
hash_table_get_values(HashTable *hash_table) {
    int int i;
    GList *retval;

    g_return_val_if_fail(hash_table != NULL, NULL );

    retval = NULL;
    for (i = 0; i < hash_table->size; i++) {
        HashNode *node = &hash_table->nodes[i];

        if (node->key_hash > 1)
            retval = list_prepend(retval, node->value);
    }

    return retval;
}

static HashNode *get_node_in_chunk() {
    HashNode *ret = NULL;
    if (chunk_index < CHUNK_SIZE - 1) {
        ret = node_mem_chunk[chunk_index];
        chunk_index++;
        if (chunk_index == CHUNK_SIZE - 1)
            node_mem_chunk = NULL;
    }
    return ret;
}

static void new_chunk() {
    HashNode *chunk;
    node_mem_chunk = calloc(CHUNK_SIZE, sizeof(HashNode));
    chunk_index = 0;
}
