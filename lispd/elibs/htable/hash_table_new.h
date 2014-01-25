/*
 * Shamelessly copied (and slightly modified) from ghash.h
 */

/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 */

#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

#define CLAMP(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

typedef struct _HashTable  HashTable;

typedef int (*HashFunc) (const void *);
typedef int (*CompareFunc) (const void *, const void *);
typedef int (*EqualFunc) (const void *, const void *);
typedef int (*DestroyFunc)(void *);
typedef void (*HFunc)  (void *key, void *value, void *user_data);
typedef int (*HRFunc)  (void *key, void *value, void *user_data);


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

HashTable*  hash_table_new(HashFunc hash_func, EqualFunc key_equal_func);
HashTable*  hash_table_new_full(HashFunc hash_func, EqualFunc key_equal_func, DestroyFunc key_destroy_func, DestroyFunc value_destroy_func);
void        hash_table_destroy(HashTable *hash_table);
void        hash_table_insert(HashTable *hash_table, void *key, void *value);
void        hash_table_replace(HashTable *hash_table, void *key, void *value);
void        hash_table_add(HashTable *hash_table, void *key);
int         hash_table_remove(HashTable *hash_table, const void * key);
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

void        g_hash_table_iter_init(HashTableIter *iter, HashTable *hash_table);
int         g_hash_table_iter_next(HashTableIter *iter, void * *key, void * *value);
HashTable*  g_hash_table_iter_get_hash_table(HashTableIter *iter);
void        g_hash_table_iter_remove(HashTableIter *iter);
void        g_hash_table_iter_replace(HashTableIter *iter, void * value);
void        g_hash_table_iter_steal(HashTableIter *iter);

HashTable*  g_hash_table_ref(HashTable *hash_table);
void        g_hash_table_unref(HashTable *hash_table);

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







static const unsigned int g_primes[] =
{
  11,
  19,
  37,
  73,
  109,
  163,
  251,
  367,
  557,
  823,
  1237,
  1861,
  2777,
  4177,
  6247,
  9371,
  14057,
  21089,
  31627,
  47431,
  71143,
  106721,
  160073,
  240101,
  360163,
  540217,
  810343,
  1215497,
  1823231,
  2734867,
  4102283,
  6153409,
  9230113,
  13845163,
};

/**
 * spaced_primes_closest:
 * @num: a #unsigned int
 *
 * Gets the smallest prime number from a built-in array of primes which
 * is larger than @num. This is used within GLib to calculate the optimum
 * size of a #GHashTable.
 *
 * The built-in array of primes ranges from 11 to 13845163 such that
 * each prime is approximately 1.5-2 times the previous prime.
 *
 * Returns: the smallest prime number from a built-in array of primes
 *     which is larger than @num
 */
unsigned int
spaced_primes_closest (unsigned int num)
{
  int i;

  for (i = 0; i < G_N_ELEMENTS (g_primes); i++)
    if (g_primes[i] > num)
      return g_primes[i];

  return g_primes[G_N_ELEMENTS (g_primes) - 1];
}

#endif /* HASH_TABLE_H_ */
