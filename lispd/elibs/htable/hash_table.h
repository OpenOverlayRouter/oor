/*
 * Shamelessly copied (and slightly modified) from ghash.h
 */

/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 */

#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

#define CLAMP(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

typedef struct htable HashTable;
typedef struct htable htable_t;

typedef unsigned int (*HashFunc)(const void *);
//typedef unsigned int (*CompareFunc) (const void *, const void *);
typedef int (*EqualFunc)(const void *, const void *);
typedef void (*DestroyFunc)(void *);
typedef void (*HFunc)(void *key, void *value, void *user_data);
typedef int (*HRFunc)(void *key, void *value, void *user_data);


typedef struct _HashTableIter HashTableIter;

struct _HashTableIter
{
  /*< private >*/
  void      *dummy1;
  void      *dummy2;
  void      *dummy3;
  int       dummy4;
  int       dummy5;
  void      *dummy6;
};

HashTable*  hash_table_new(HashFunc hash_func, EqualFunc key_equal_func, DestroyFunc key_destroy_func, DestroyFunc val_destroy_func);
void        hash_table_destroy(HashTable *hash_table);
void        hash_table_insert(HashTable *hash_table, void *key, void *value);
void        hash_table_replace(HashTable *hash_table, void *key, void *value);
void        hash_table_add(HashTable *hash_table, void *key);
void        hash_table_remove(HashTable *hash_table, const void *key);
void        hash_table_remove_all(HashTable *hash_table);
int         hash_table_steal(HashTable *hash_table, const void *key);
void        hash_table_steal_all(HashTable *hash_table);
void        *hash_table_lookup(HashTable *hash_table, const void *key);
int         hash_table_contains(HashTable *hash_table, const void *key);
int         hash_table_lookup_extended(HashTable *hash_table, const void *lookup_key, void **orig_key, void **value);
void        hash_table_foreach(HashTable *hash_table, HFunc func, void *user_data);
void       *hash_table_find(HashTable *hash_table, HRFunc predicate, void *user_data);
unsigned int hash_table_foreach_remove(HashTable *hash_table, HRFunc func, void *user_data);
unsigned int hash_table_foreach_steal(HashTable *hash_table, HRFunc func, void *user_data);
unsigned int hash_table_size(HashTable *hash_table);
//GList       *hash_table_get_keys(HashTable *hash_table);
//GList       *hash_table_get_values(HashTable *hash_table);

/* Hash Functions
 */
int g_str_equal(const void * v1, const void * v2);
unsigned int g_str_hash(const void * v);

int g_int_equal(const void * v1, const void * v2);
unsigned int g_int_hash(const void * v);

int g_int64_equal(const void * v1, const void * v2);
unsigned int g_int64_hash(const void * v);

int g_double_equal(const void * v1, const void * v2);
unsigned int g_double_hash(const void * v);

unsigned int g_direct_hash(const void * v);
int g_direct_equal(const void * v1, const void * v2);


#endif /* HASH_TABLE_H_ */
