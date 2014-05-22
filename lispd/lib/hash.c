/*
 * Shamelessly copied (and slightly modified) from glib.c
 *
 * Modified by the GLib Team and others 1997-1999.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */

#include <string.h>

#include "hash.h"

/**
 * g_str_hash:
 * @v: a string key
 *
 * Converts a string to a hash value.
 *
 * This function implements the widely used "djb" hash apparently
 * posted by Daniel Bernstein to comp.lang.c some time ago.  The 32
 * bit unsigned hash value starts at 5381 and for each byte 'c' in
 * the string, is updated: `hash = hash * 33 + c`. This function
 * uses the signed value of each byte.
 *
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using non-%NULL strings as keys in a #htable_t.
 *
 * Returns: a hash value corresponding to the key
 */

unsigned int
g_str_hash (const void *v)
{
  const signed char *p;
  unsigned int h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + *p;

  return h;
}

/**
 * g_str_equal:
 * @v1: a key
 * @v2: a key to compare with @v1
 *
 * Compares two strings for byte-by-byte equality and returns %TRUE
 * if they are equal. It can be passed to g_hash_table_new() as the
 * @key_equal_func parameter, when using non-%NULL strings as keys in a
 * #htable_t.
 *
 * Note that this function is primarily meant as a hash table comparison
 * function. For a general-purpose, %NULL-safe string comparison function,
 * see g_strcmp0().
 *
 * Returns: %TRUE if the two keys match
 */
int
g_str_equal(const void *v1, const void *v2)
{
  const char *string1 = v1;
  const char *string2 = v2;

  return strcmp (string1, string2) == 0;
}


/**
 * g_int_equal:
 * @v1: a pointer to a #int key
 * @v2: a pointer to a #int key to compare with @v1
 *
 * Compares the two #int values being pointed to and returns
 * %TRUE if they are equal.
 * It can be passed to g_hash_table_new() as the @key_equal_func
 * parameter, when using non-%NULL pointers to integers as keys in a
 * #htable_t.
 *
 * Note that this function acts on pointers to #int, not on #int
 * directly: if your hash table's keys are of the form
 * `GINT_TO_POINTER (n)`, use g_direct_equal() instead.
 *
 * Returns: %TRUE if the two keys match.
 */
int
g_int_equal(const void *v1, const void *v2)
{
  return *((const int*) v1) == *((const int*) v2);
}

/**
 * g_int_hash:
 * @v: a pointer to a #int key
 *
 * Converts a pointer to a #int to a hash value.
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using non-%NULL pointers to integer values as keys in a #htable_t.
 *
 * Note that this function acts on pointers to #int, not on #int
 * directly: if your hash table's keys are of the form
 * `GINT_TO_POINTER (n)`, use g_direct_hash() instead.
 *
 * Returns: a hash value corresponding to the key.
 */
unsigned int
g_int_hash (const void *v)
{
  return *(const int*) v;
}


