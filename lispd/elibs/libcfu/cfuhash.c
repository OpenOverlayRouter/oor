/* Creation date: 2005-06-24 21:22:40
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

#include "cfu.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "cfuhash.h"
#include "cfustring.h"
#include "../../lib/util.h"

#ifdef CFU_DEBUG
#ifdef NDEBUG
#undef NDEBUG
#endif
#else
#ifndef NDEBUG
#define NDEBUG 1
#endif
#endif
#include <assert.h>

typedef struct hash_event_flags {
	int resized:1;
	int pad:31;
} hash_event_flags;

typedef struct hash_entry {
	void *key;
	void *data;
	struct hash_entry *next;
} hash_entry;

struct hash_table {
	libcfu_type type;
	size_t num_buckets;
	size_t entries; /* Total number of entries in the table. */
	hash_entry **buckets;
	pthread_mutex_t mutex;
	u_int32_t flags;
	hash_function_t hash_func;
	size_t each_bucket_index;
	hash_entry *each_chain_entry;
	float high;
	float low;
	hash_free_fn_t free_fn;
	hash_cmp_key_fn_t  key_cmp_fn;
	hash_free_key_fn_t key_free_fn;
	hash_clone_key_fn_t key_clone_fn;
	unsigned int resized_count;
	hash_event_flags event_flags;
};

/* Perl's hash function */
static u_int32_t
str_hash_func(const void *key) {
	register size_t i = strlen((const char*)key) + 1;
	register u_int hv = 0; /* could put a seed here instead of zero */
	register const unsigned char *s = (unsigned char *)key;
	while (i--) {
		hv += *s++;
		hv += (hv << 10);
		hv ^= (hv >> 6);
	}
	hv += (hv << 3);
	hv ^= (hv >> 11);
	hv += (hv << 15);

	return hv;
}

/* makes sure the real size of the buckets array is a power of 2 */
static u_int
hash_size(u_int s) {
	u_int i = 1;
	while (i < s) i <<= 1;
	return i;
}

static inline void *
hash_key_dup(const void *key, hash_clone_key_fn_t clone_key_fn) {
    void *new_key;
    if (clone_key_fn){
        new_key = clone_key_fn(key);
    }else{
        new_key = strdup((const char*)key);
    }
	return (new_key);
}

/* returns the index into the buckets array */
static inline u_int
hash_value(hash_table_t *ht, const void *key, size_t num_buckets) {
	u_int hv = 0;

	if (key) {
	    hv = ht->hash_func(key);
	}

	/* The idea is the following: if, e.g., num_buckets is 32
	   (000001), num_buckets - 1 will be 31 (111110). The & will make
	   sure we only get the first 5 bits which will guarantee the
	   index is less than 32.
	*/
	return hv & (num_buckets - 1);
}

static hash_table_t *
_hash_new(size_t size, u_int32_t flags) {
	hash_table_t *ht;
	
	size = hash_size(size);
	ht = (hash_table_t *)xmalloc(sizeof(hash_table_t));
	memset(ht, '\000', sizeof(hash_table_t));

	ht->type = libcfu_t_hash_table;
	ht->num_buckets = size;
	ht->entries = 0;
	ht->flags = flags;
	ht->buckets = (hash_entry **)xcalloc(size, sizeof(hash_entry *));
	pthread_mutex_init(&ht->mutex, NULL);
	
	ht->hash_func = str_hash_func;
	ht->key_free_fn = (hash_free_key_fn_t)free;
	ht->high = 0.75;
	ht->low = 0.25;
	
	return ht;
}

extern hash_table_t *
hash_new(hash_function_t hash_fn, hash_cmp_key_fn_t key_equal_fn,
        hash_free_key_fn_t free_key_fn, hash_free_fn_t free_val_fn,
        hash_clone_key_fn_t clone_key_fn, u_int32_t flags)
{
    hash_table_t *ht;

    ht = _hash_new(8, HASH_FROZEN_UNTIL_GROWS | flags);
    hash_set_hash_function(ht, hash_fn);
    hash_set_cmp_key_function(ht, key_equal_fn);
    hash_set_free_key_function(ht, free_key_fn);
    hash_set_clone_key_function(ht,clone_key_fn);
    hash_set_free_function(ht, free_val_fn);

	return (ht);
}

extern hash_table_t *
hash_new_with_initial_size(size_t size) {
	if (size == 0) size = 8;
	return _hash_new(size, HASH_FROZEN_UNTIL_GROWS);
}

/* returns the flags */
extern u_int32_t
hash_get_flags(hash_table_t *ht) {
	return ht->flags;
}

/* sets the given flag and returns the old flags value */
extern u_int32_t
hash_set_flag(hash_table_t *ht, u_int32_t new_flag) {
	u_int32_t flags = ht->flags;
	ht->flags = flags | new_flag;
	return flags;
}

extern u_int32_t
hash_clear_flag(hash_table_t *ht, u_int32_t new_flag) {
	u_int32_t flags = ht->flags;
	ht->flags = flags & ~new_flag;
	return flags;
}

extern int
hash_set_thresholds(hash_table_t *ht, float low, float high) {
	float h = high < 0 ? ht->high : high;
	float l = low < 0 ? ht->low : low;

	if (h < l) return -1;

	ht->high = h;
	ht->low = l;

	return 0;
}

/* Sets the hash function for the hash table ht.  Pass NULL for hf to reset to the default */
extern int
hash_set_hash_function(hash_table_t *ht, hash_function_t hf) {
	/* can't allow changing the hash function if the hash already contains entries */
	if (ht->entries) return -1;
	
	ht->hash_func = hf ? hf : str_hash_func;
	return 0;
}

extern int
hash_set_free_function(hash_table_t * ht, hash_free_fn_t ff) {
	if (ff) ht->free_fn = ff;
	return 0;
}

extern int
hash_set_free_key_function(hash_table_t * ht, hash_free_key_fn_t fkf) {
	if (fkf) ht->key_free_fn = fkf;
	return 0;
}

extern int
hash_set_clone_key_function(hash_table_t * ht, hash_clone_key_fn_t ckfn) {
    if (ckfn) ht->key_clone_fn = ckfn;
    return 0;
}

extern int
hash_set_cmp_key_function(hash_table_t * ht, hash_cmp_key_fn_t cmp_f) {
    if (cmp_f) ht->key_cmp_fn = cmp_f;
    return 0;
}

static inline void
lock_hash(hash_table_t *ht) {
	if (!ht) return;
	if (ht->flags & HASH_NO_LOCKING) return;
	pthread_mutex_lock(&ht->mutex);
}

static inline void
unlock_hash(hash_table_t *ht) {
	if (!ht) return;
	if (ht->flags & HASH_NO_LOCKING) return;
	pthread_mutex_unlock(&ht->mutex);
}

extern int
hash_lock(hash_table_t *ht) {
	pthread_mutex_lock(&ht->mutex);
	return 1;
}

extern int
hash_unlock(hash_table_t *ht) {
	pthread_mutex_unlock(&ht->mutex);
	return 1;
}

/* see if this key matches the one in the hash entry */
/* uses the convention that zero means a match, like memcmp */

static inline int
str_hash_cmp(const void *key, hash_entry *he) {
    const char *string1 = key;
    const char *string2 = he->key;
    return (strcmp (string1, string2));
}

static inline hash_entry *
hash_add_entry(hash_table_t *ht, u_int hv, const void *key,	void *data) {
	hash_entry *he = (hash_entry *)xcalloc(1, sizeof(hash_entry));

	assert(hv < ht->num_buckets);

	if (ht->flags & HASH_NOCOPY_KEYS)
		he->key = (void *)key;
	else
		he->key = hash_key_dup(key, ht->key_clone_fn);
	he->data = data;
	he->next = ht->buckets[hv];
	ht->buckets[hv] = he;
	ht->entries++;

	return he;
}

/*
 Returns one if the entry was found, zero otherwise.  If found, r is
 changed to point to the data in the entry.
*/
extern int
hash_get_data(hash_table_t *ht, const void *key, void **r) {
	u_int hv = 0;
	hash_entry *hr = NULL;

	if (!ht) return 0;

	lock_hash(ht);
	hv = hash_value(ht, key, ht->num_buckets);

	assert(hv < ht->num_buckets);

	for (hr = ht->buckets[hv]; hr; hr = hr->next) {
	    if (ht->key_cmp_fn){
	        if (ht->key_cmp_fn(key,hr->key) == 0) break;
	    }else{
	        if (str_hash_cmp(key, hr) == 0) break;
	    }
	}

	if (hr && r) {
		*r = hr->data;
	}

	unlock_hash(ht);
	
	return (hr ? 1 : 0);
}

/*
 Assumes the key is a null-terminated string, returns the data, or NULL if not found.  Note that it is possible for the data itself to be NULL
*/
extern void *
hash_get(hash_table_t *ht, const void *key) {
	void *r = NULL;
	int rv = 0;
	rv = hash_get_data(ht, (const void *)key, &r);
	if (rv) return r; /* found */
	return NULL;
}

/* Returns 1 if an entry exists in the table for the given key, 0 otherwise */
extern int
hash_exists_data(hash_table_t *ht, const void *key) {
	void *r = NULL;
	int rv = hash_get_data(ht, key, &r);
	if (rv) return 1; /* found */
	return 0;
}

/* Same as hash_exists_data(), except assumes key is a null-terminated string */
extern int
hash_exists(hash_table_t *ht, const void *key) {
	return hash_exists_data(ht, (const void *)key);
}

/*
 Add the entry to the hash.  If there is already an entry for the
 given key, the old data value will be returned in r, and the return
 value is zero.  If a new entry is created for the key, the function
 returns 1.
*/
extern int
hash_put_data(hash_table_t *ht, const void *key, void *data, void **r) {
	u_int hv = 0;
	hash_entry *he = NULL;
	int added_an_entry = 0;

	lock_hash(ht);
	hv = hash_value(ht, key, ht->num_buckets);
	assert(hv < ht->num_buckets);
	for (he = ht->buckets[hv]; he; he = he->next) {
	    if (ht->key_cmp_fn){
	        if (ht->key_cmp_fn(key,he->key) == 0) break;
	    }else{
	        if (!str_hash_cmp(key, he)) break;
	    }
	}

	if (he) {
		if (r) *r = he->data;
		if (ht->free_fn) {
			ht->free_fn(he->data);
			if (r) *r = NULL; /* don't return a pointer to a free()'d location */
		}
		he->data = data;
	} else {
		hash_add_entry(ht, hv, key, data);
		added_an_entry = 1;
	}

	unlock_hash(ht);	

	if (added_an_entry && !(ht->flags & HASH_FROZEN)) {
		if ( (float)ht->entries/(float)ht->num_buckets > ht->high ) hash_rehash(ht);
	}

	return added_an_entry;
}

/*
 Same as hash_put_data(), except the key is assumed to be a
 null-terminated string, and the old value is returned if it existed,
 otherwise NULL is returned.
*/
extern void *
hash_put(hash_table_t *ht, const void *key, void *data) {
	void *r = NULL;
	if (!hash_put_data(ht, key, data, &r)) {
		return r;
	}
	return NULL;
}

extern void
hash_clear(hash_table_t *ht) {
	hash_entry *he = NULL;
	hash_entry *hep = NULL;
	size_t i = 0;
	if (!ht){
	    return;
	}

	lock_hash(ht);
	for (i = 0; i < ht->num_buckets; i++) {
		if ( (he = ht->buckets[i]) ) {
			while (he) {
				hep = he;
				he = he->next;
				if (! (ht->flags & HASH_NOCOPY_KEYS) ){
				    ht->key_free_fn(hep->key);
				}
				if (ht->free_fn) ht->free_fn(hep->data);
				free(hep);
			}
			ht->buckets[i] = NULL;
		}
	}
	ht->entries = 0;

	unlock_hash(ht);

	if ( !(ht->flags & HASH_FROZEN) &&
		!( (ht->flags & HASH_FROZEN_UNTIL_GROWS) && !ht->resized_count) ) {
		if ( (float)ht->entries/(float)ht->num_buckets < ht->low ) hash_rehash(ht);
	}

}

static void
_hash_destroy_entry(hash_table_t *ht, hash_entry *he) {
    if (ht->free_fn) {
        ht->free_fn(he->data);
    }
    if ( !(ht->flags & HASH_NOCOPY_KEYS) ) ht->key_free_fn(he->key);
    free(he);
}

extern int
hash_foreach_remove(hash_table_t *ht, hash_remove_fn_t r_fn, void *arg) {
    hash_entry *entry = NULL;
    hash_entry *prev = NULL;
    size_t hv = 0;
    int num_removed = 0;
    hash_entry **buckets = NULL;
    size_t num_buckets = 0;

    if (!ht) return 0;

    lock_hash(ht);

    buckets = ht->buckets;
    num_buckets = ht->num_buckets;
    for (hv = 0; hv < num_buckets; hv++) {
        entry = buckets[hv];
        if (!entry) continue;
        prev = NULL;

        while (entry) {
            if (r_fn(entry->key, entry->data, arg)) {
                num_removed++;
                if (prev) {
                    prev->next = entry->next;
                    _hash_destroy_entry(ht, entry);
                    entry = prev->next;
                } else {
                    buckets[hv] = entry->next;
                    _hash_destroy_entry(ht, entry);
                    entry = buckets[hv];
                }
            } else {
                prev = entry;
                entry = entry->next;
            }
        }
    }

    unlock_hash(ht);

    return num_removed;
}

extern void *
hash_delete_data(hash_table_t *ht, const void *key) {
	u_int hv = 0;
	hash_entry *he = NULL;
	hash_entry *hep = NULL;
	void *r = NULL;

	lock_hash(ht);
	hv = hash_value(ht, key, ht->num_buckets);

	for (he = ht->buckets[hv]; he; he = he->next) {
	    if (ht->key_cmp_fn){
	        if (ht->key_cmp_fn(key,he->key) == 0) break;
	    }else{
	        if (!str_hash_cmp(key, he)) break;
	    }

		hep = he;
	}

	if (he) {
		r = he->data;
		if (hep) hep->next = he->next;
		else ht->buckets[hv] = he->next;

		ht->entries--;
		if (! (ht->flags & HASH_NOCOPY_KEYS) ){
		    ht->key_free_fn(he->key);
		}
		if (ht->free_fn) {
			ht->free_fn(he->data);
			r = NULL; /* don't return a pointer to a free()'d location */
		}
		free(he);
	}

	unlock_hash(ht);

	if (he && !(ht->flags & HASH_FROZEN) &&
		!( (ht->flags & HASH_FROZEN_UNTIL_GROWS) && !ht->resized_count) ) {
		if ( (float)ht->entries/(float)ht->num_buckets < ht->low ) hash_rehash(ht);
	}


	return r;
}

extern void *
hash_delete(hash_table_t *ht, const void *key) {
	return hash_delete_data(ht, key);
}

extern glist_t *
hash_keys(hash_table_t *ht, int fast) {
	glist_t *keys_list = glist_new();
	hash_entry *he = NULL;
	size_t bucket = 0;
	size_t entry_index = 0;

	if (!ht) {
		return (keys_list);
	}

	if (! (ht->flags & HASH_NO_LOCKING) ) lock_hash(ht);
	
	for (bucket = 0; bucket < ht->num_buckets; bucket++) {
		if ( (he = ht->buckets[bucket]) ) {
			for (; he; he = he->next, entry_index++) {
				if (entry_index >= ht->entries) break; /* this should never happen */

				if (fast) {
				    glist_add(he->key, keys_list);
				} else {
				    glist_add(hash_key_dup(he->key,ht->key_clone_fn), keys_list);
				}
			}
		}
	}

	if (! (ht->flags & HASH_NO_LOCKING) ) unlock_hash(ht);

	return keys_list;
}

extern glist_t *
hash_values(hash_table_t *ht) {
    glist_t *data_list = glist_new();
    hash_entry *he = NULL;
    size_t bucket = 0;
    size_t entry_index = 0;

    if (!ht) {
        return (data_list);
    }

    if (! (ht->flags & HASH_NO_LOCKING) ) lock_hash(ht);

    for (bucket = 0; bucket < ht->num_buckets; bucket++) {
        if ( (he = ht->buckets[bucket]) ) {
            for (; he; he = he->next, entry_index++) {
                if (entry_index >= ht->entries) break; /* this should never happen */
                glist_add(he->data, data_list);
            }
        }
    }

    if (! (ht->flags & HASH_NO_LOCKING) ) unlock_hash(ht);

    return data_list;
}


extern size_t
hash_foreach(hash_table_t *ht, hash_foreach_fn_t fe_fn, void *arg) {
	hash_entry *entry = NULL;
	size_t hv = 0;
	size_t num_accessed = 0;
	hash_entry **buckets = NULL;
	size_t num_buckets = 0;
	int rv = 0;
	
	if (!ht) return 0;

	lock_hash(ht);

	buckets = ht->buckets;
	num_buckets = ht->num_buckets;
	for (hv = 0; hv < num_buckets && !rv; hv++) {
		entry = buckets[hv];

		for (; entry && !rv; entry = entry->next) {
			num_accessed++;
			rv = fe_fn(entry->key, entry->data, arg);
		}
	}

	unlock_hash(ht);

	return num_accessed;
}

extern void
hash_destroy(hash_table_t *ht) {
    if (!ht){
        return;
    }
    hash_clear(ht);
    free (ht);
    ht = NULL;
}

typedef struct _pretty_print_arg {
	size_t count;
	FILE *fp;
} _pretty_print_arg;

static int
_pretty_print_foreach(void *key, void *data, void *arg) {
	_pretty_print_arg *parg = (_pretty_print_arg *)arg;
	parg->count += fprintf(parg->fp, "\t\"%s\" => \"%s\",\n", (char *)key, (char *)data);
	return 0;
}

extern int
hash_pretty_print(hash_table_t *ht, FILE *fp) {
	int rv = 0;
	_pretty_print_arg parg;

	parg.fp = fp;
	parg.count = 0;

	rv += fprintf(fp, "{\n");
	
	hash_foreach(ht, _pretty_print_foreach, (void *)&parg);
	rv += parg.count;

	rv += fprintf(fp, "}\n");

	return rv;
}

extern int
hash_rehash(hash_table_t *ht) {
	size_t new_size, i;
	hash_entry **new_buckets = NULL;

	lock_hash(ht);
	new_size = hash_size(ht->entries * 2 / (ht->high + ht->low));
	if (new_size == ht->num_buckets) {
		unlock_hash(ht);
		return 0;
	}
	new_buckets = (hash_entry **)xcalloc(new_size, sizeof(hash_entry *));

	for (i = 0; i < ht->num_buckets; i++) {
		hash_entry *he = ht->buckets[i];
		while (he) {
			hash_entry *nhe = he->next;
			u_int hv = hash_value(ht, he->key, new_size);
			he->next = new_buckets[hv];
			new_buckets[hv] = he;
			he = nhe;
		}
	}

	ht->num_buckets = new_size;
	free(ht->buckets);
	ht->buckets = new_buckets;
	ht->resized_count++;

	unlock_hash(ht);
	return 1;
}

extern size_t
hash_num_entries(hash_table_t *ht) {
	if (!ht) return 0;
	return ht->entries;
}

extern size_t
hash_num_buckets(hash_table_t *ht) {
	if (!ht) return 0;
	return ht->num_buckets;
}

extern size_t
hash_num_buckets_used(hash_table_t *ht) {
	size_t i = 0;
	size_t count = 0;

	if (!ht) return 0;

	lock_hash(ht);

	for (i = 0; i < ht->num_buckets; i++) {
		if (ht->buckets[i]) count++;
	}
	unlock_hash(ht);
	return count;
}

