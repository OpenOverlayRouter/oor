/*
 * Shamelessly copied (and slightly modified) from glib.c
 */

/*
 * Modified by the GLib Team and others 1997-1999.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */

#include "hash_table.h"
#include "stdlib.h"
#include <string.h>

#define HASH_TABLE_MIN_SIZE 11
#define HASH_TABLE_MAX_SIZE 13845163

typedef struct _HashNode HashNode;

struct _HashNode {
    void *key;
    void *value;
    HashNode *next;
};

struct _HashTable {
    int size;
    int nnodes;
    unsigned int frozen;
    HashNode **nodes;
    HashFunc hash_func;
    EqualFunc key_equal_func;
    DestroyFunc key_destroy_func;
    DestroyFunc val_destroy_func;
};

static void hash_table_resize(HashTable *hash_table);
static HashNode** hash_table_lookup_node(HashTable *hash_table, const void * key);
static HashNode* hash_node_new(void * key, void * value);
static void hash_node_destroy(HashNode *hash_node, DestroyFunc key_destroy_func, DestroyFunc val_destroy_func);
static void hash_nodes_destroy(HashNode *hash_node, DestroyFunc key_destroy_func, DestroyFunc val_destroy_func);
static HashNode *get_node_in_chunk();
static void get_new_chunk();

#define CHUNK_SIZE 100
#define ARRAY_SIZE(x) ((sizeof x) / (sizeof *x))

/* keep track of chunks allocated, to free on destroy*/
struct mem_chunk_lst {
    struct mem_chunk_lst    *next;
    HashNode                *chunk;
};

static struct mem_chunk_lst *chunk_lst = NULL;
static unsigned int chunk_index;
static HashNode *node_mem_chunk = NULL;
static HashNode *node_free_list = NULL;

static const unsigned int g_primes[] = { 11, 19, 37, 73, 109, 163, 251, 367,
        557, 823, 1237, 1861, 2777, 4177, 6247, 9371, 14057, 21089, 31627,
        47431, 71143, 106721, 160073, 240101, 360163, 540217, 810343, 1215497,
        1823231, 2734867, 4102283, 6153409, 9230113, 13845163, };

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
static unsigned int spaced_primes_closest(unsigned int num) {
    int i;

    for (i = 0; i < ARRAY_SIZE(g_primes); i++)
        if (g_primes[i] > num)
            return g_primes[i];

    return g_primes[ARRAY_SIZE(g_primes) - 1];
}

HashTable*
hash_table_new(HashFunc hash_func, EqualFunc key_equal_func, DestroyFunc key_destroy_func, DestroyFunc val_destroy_func) {
    HashTable *hash_table;
    unsigned int i;

    hash_table = calloc(1, sizeof(HashTable));
    hash_table->size = HASH_TABLE_MIN_SIZE;
    hash_table->nnodes = 0;
    hash_table->frozen = 0;
    hash_table->hash_func = hash_func;
    hash_table->key_equal_func = key_equal_func;
    hash_table->key_destroy_func = key_destroy_func;
    hash_table->val_destroy_func = val_destroy_func;
    hash_table->nodes = calloc(hash_table->size, sizeof(HashNode*));

    for (i = 0; i < hash_table->size; i++)
        hash_table->nodes[i] = NULL;

    return hash_table;
}

void hash_table_destroy(HashTable *hash_table) {
    unsigned int i;
    struct mem_chunk_lst *it, *next;

    if (!hash_table)
        return;

    for (i = 0; i < hash_table->size; i++)
        hash_nodes_destroy(hash_table->nodes[i], hash_table->key_destroy_func, hash_table->val_destroy_func);

    /* free allocated nodes */
    it = chunk_lst;
    while(it->next) {
        next = it->next;
        free(it->chunk);
        free(it);
        it = next;
    }

    free(hash_table->nodes);
    free(hash_table);
}

static inline HashNode**
hash_table_lookup_node(HashTable *hash_table, const void * key) {
    HashNode **node;

    node = &hash_table->nodes[(*hash_table->hash_func)(key) % hash_table->size];

    /* Hash table lookup needs to be fast.
     *  We therefore remove the extra conditional of testing
     *  whether to call the key_compare_func or not from
     *  the inner loop.
     */
    if (hash_table->key_equal_func)
        while (*node && !(*hash_table->key_equal_func)((*node)->key, key))
            node = &(*node)->next;
    else
        while (*node && (*node)->key != key)
            node = &(*node)->next;

    return node;
}

void *
hash_table_lookup(HashTable *hash_table, const void * key) {
    HashNode *node;

    if (!hash_table)
        return NULL ;

    node = *hash_table_lookup_node(hash_table, key);

    return node ? node->value : NULL ;
}

void hash_table_insert(HashTable *hash_table, void *key, void * value) {
    HashNode **node;

    if (!hash_table)
        return;

    node = hash_table_lookup_node(hash_table, key);

    if (*node) {
        /* do not reset node->key in this place, keeping
         * the old key might be intended.
         * a hash_table_remove/hash_table_insert pair
         * can be used otherwise.
         *
         * node->key = key; */
        (*node)->value = value;
    } else {
        *node = hash_node_new(key, value);
        hash_table->nnodes++;
        if (!hash_table->frozen)
            hash_table_resize(hash_table);
    }
}

void hash_table_remove(HashTable *hash_table, const void * key) {
    HashNode **node, *dest;

    if (!hash_table)
        return;

    node = hash_table_lookup_node(hash_table, key);

    if (*node) {
        dest = *node;
        (*node) = dest->next;
        hash_node_destroy(dest, hash_table->key_destroy_func, hash_table->val_destroy_func);
        hash_table->nnodes--;

        if (!hash_table->frozen)
            hash_table_resize(hash_table);
    }
}

int hash_table_lookup_extended(HashTable *hash_table, const void * lookup_key,
        void **orig_key, void **value) {
    HashNode *node;

    if (!hash_table)
        return 0;

    node = *hash_table_lookup_node(hash_table, lookup_key);

    if (node) {
        if (orig_key)
            *orig_key = node->key;
        if (value)
            *value = node->value;
        return 1;
    } else
        return 0;
}

void hash_table_freeze(HashTable *hash_table) {
    if (!hash_table)
        return;
    hash_table->frozen++;
}

void hash_table_thaw(HashTable *hash_table) {
    if (!hash_table)
        return;

    if (hash_table->frozen)
        if (!(--hash_table->frozen))
            hash_table_resize(hash_table);
}

unsigned int hash_table_foreach_remove(HashTable *hash_table, HRFunc func,
        void * user_data) {
    HashNode *node, *prev;
    unsigned int i;
    unsigned int deleted = 0;

    if (!hash_table || !func)
        return 0;

    for (i = 0; i < hash_table->size; i++) {
        restart:

        prev = NULL;

        for (node = hash_table->nodes[i]; node; prev = node, node = node->next) {
            if ((*func)(node->key, node->value, user_data)) {
                deleted += 1;

                hash_table->nnodes -= 1;

                if (prev) {
                    prev->next = node->next;
                    hash_node_destroy(node, hash_table->key_destroy_func, hash_table->val_destroy_func);
                    node = prev;
                } else {
                    hash_table->nodes[i] = node->next;
                    hash_node_destroy(node, hash_table->key_destroy_func, hash_table->val_destroy_func);
                    goto restart;
                }
            }
        }
    }

    if (!hash_table->frozen)
        hash_table_resize(hash_table);

    return deleted;
}

void hash_table_foreach(HashTable *hash_table, HFunc func, void * user_data) {
    HashNode *node;
    int i;

    if (!hash_table || !func)
        return;

    for (i = 0; i < hash_table->size; i++)
        for (node = hash_table->nodes[i]; node; node = node->next)
            (*func)(node->key, node->value, user_data);
}

/* Returns the number of elements contained in the hash table. */
unsigned int hash_table_size(HashTable *hash_table) {
    if (!hash_table)
        return 0;

    return hash_table->nnodes;
}

static void hash_table_resize(HashTable *hash_table) {
    HashNode **new_nodes;
    HashNode *node;
    HashNode *next;
    float nodes_per_list;
    unsigned int hash_val;
    int new_size;
    int i;

    nodes_per_list = (float) hash_table->nnodes / (float) hash_table->size;

    if ((nodes_per_list > 0.3 || hash_table->size <= HASH_TABLE_MIN_SIZE)
            && (nodes_per_list < 3.0 || hash_table->size >= HASH_TABLE_MAX_SIZE))
        return;

    new_size = CLAMP(spaced_primes_closest (hash_table->nnodes),
            HASH_TABLE_MIN_SIZE,
            HASH_TABLE_MAX_SIZE);
    new_nodes = calloc(new_size, sizeof(HashNode*));

    for (i = 0; i < hash_table->size; i++)
        for (node = hash_table->nodes[i]; node; node = next) {
            next = node->next;

            hash_val = (*hash_table->hash_func)(node->key) % new_size;

            node->next = new_nodes[hash_val];
            new_nodes[hash_val] = node;
        }

    free(hash_table->nodes);
    hash_table->nodes = new_nodes;
    hash_table->size = new_size;
}

static HashNode*
hash_node_new(void * key, void * value) {
    HashNode *hash_node;

    if (node_free_list) {
        hash_node = node_free_list;
        node_free_list = node_free_list->next;
    } else {
        //        if (!node_mem_chunk)
        //            node_mem_chunk = g_mem_chunk_new("hash node mem chunk",
        //                    sizeof(HashNode), 1024, G_ALLOC_ONLY);
        //
        //        hash_node = g_chunk_new(HashNode, node_mem_chunk);
        if (!node_mem_chunk)
            get_new_chunk();
        hash_node = get_node_in_chunk();
    }

    hash_node->key = key;
    hash_node->value = value;
    hash_node->next = NULL;

    return hash_node;
}

static void hash_node_destroy(HashNode *hash_node, DestroyFunc key_destroy_func, DestroyFunc val_destroy_func) {
    if (key_destroy_func) key_destroy_func(hash_node->key);
    if (val_destroy_func) val_destroy_func(hash_node->value);
    hash_node->next = node_free_list;
    node_free_list = hash_node;
}

static void hash_nodes_destroy(HashNode *hash_node, DestroyFunc key_destroy_func, DestroyFunc val_destroy_func) {
    if (hash_node) {
        HashNode *node = hash_node;

        while (node->next) {
            node = node->next;
            if (key_destroy_func) key_destroy_func(node->key);
            if (val_destroy_func) val_destroy_func(node->value);
        }

        node->next = node_free_list;
        node_free_list = hash_node;
    }

}

static HashNode *get_node_in_chunk() {
    HashNode *ret = NULL;
    if (chunk_index < CHUNK_SIZE - 1) {
        ret = &node_mem_chunk[chunk_index];
        chunk_index++;
        if (chunk_index == CHUNK_SIZE - 1)
            node_mem_chunk = NULL;
    }
    return ret;
}

static void get_new_chunk() {
    struct mem_chunk_lst *chunk, *it;

    node_mem_chunk = calloc(CHUNK_SIZE, sizeof(HashNode));
    chunk_index = 0;

    chunk = calloc(1, sizeof(struct mem_chunk_lst));
    chunk->chunk = node_mem_chunk;

    if (!chunk_lst)
        chunk_lst = chunk;
    else {
        it = chunk_lst;
        while (it->next) {
            it = it->next;
        }
        it->next = chunk;
    }

}


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
 * when using non-%NULL strings as keys in a #GHashTable.
 *
 * Returns: a hash value corresponding to the key
 */
unsigned int g_str_hash (const void *v)
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
 * #GHashTable.
 *
 * Note that this function is primarily meant as a hash table comparison
 * function. For a general-purpose, %NULL-safe string comparison function,
 * see g_strcmp0().
 *
 * Returns: %TRUE if the two keys match
 */
int g_str_equal(const void *v1,
                const void *v2)
{
  const char *string1 = v1;
  const char *string2 = v2;

  return strcmp (string1, string2) == 0;
}


/**
 * g_int_equal:
 * @v1: a pointer to a #gint key
 * @v2: a pointer to a #gint key to compare with @v1
 *
 * Compares the two #gint values being pointed to and returns
 * %TRUE if they are equal.
 * It can be passed to g_hash_table_new() as the @key_equal_func
 * parameter, when using non-%NULL pointers to integers as keys in a
 * #GHashTable.
 *
 * Note that this function acts on pointers to #gint, not on #gint
 * directly: if your hash table's keys are of the form
 * `GINT_TO_POINTER (n)`, use g_direct_equal() instead.
 *
 * Returns: %TRUE if the two keys match.
 */
int  g_int_equal(const void *v1,
                 const void *v2)
{
  return *((const int*) v1) == *((const int*) v2);
}

/**
 * g_int_hash:
 * @v: a pointer to a #gint key
 *
 * Converts a pointer to a #gint to a hash value.
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using non-%NULL pointers to integer values as keys in a #GHashTable.
 *
 * Note that this function acts on pointers to #gint, not on #gint
 * directly: if your hash table's keys are of the form
 * `GINT_TO_POINTER (n)`, use g_direct_hash() instead.
 *
 * Returns: a hash value corresponding to the key.
 */
unsigned int g_int_hash (const void *v)
{
  return *(const int*) v;
}


