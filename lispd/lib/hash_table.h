/*
 * Shamelessly copied (but slightly modified) from ghash.h
 */

/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 */

#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

#include "hash.h"

#define CLAMP(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

typedef struct htable htable_t;

typedef unsigned int (*h_key_fct)(const void *);
typedef int (*h_key_eq_fct)(const void *, const void *);
typedef void (*h_key_del_fct)(void *);
typedef void (*h_val_del_fct)(void *);
typedef void (*h_usr_fct)(void *key, void *value, void *user_data);
typedef int (*h_usr_del_fct)(void *key, void *value, void *user_data);


htable_t* htable_new(h_key_fct hash_func, h_key_eq_fct key_equal_func,
        h_key_del_fct key_destroy_func, h_val_del_fct val_destroy_func);
void htable_destroy(htable_t *hash_table);
void htable_insert(htable_t *hash_table, void *key, void *value);
void htable_remove(htable_t *hash_table, const void *key);
void htable_remove_all(htable_t *hash_table);
void *htable_lookup(htable_t *hash_table, const void *key);
int htable_lookup_extended(htable_t *hash_table, const void *lookup_key,
        void **orig_key, void **value);
void htable_foreach(htable_t *hash_table, h_usr_fct func, void *user_data);
unsigned int htable_foreach_remove(htable_t *hash_table, h_usr_del_fct func,
        void *user_data);
unsigned int htable_size(htable_t *hash_table);


#endif /* HASH_TABLE_H_ */
