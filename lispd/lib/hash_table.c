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
#include "util.h"
#include "stdlib.h"

#define HASH_TABLE_MIN_SIZE 11
#define HASH_TABLE_MAX_SIZE 13845163

typedef struct hnode hnode_t;

struct hnode {
    void *key;
    void *value;
    hnode_t *next;
};

struct htable {
    int size;
    int nnodes;
    unsigned int frozen;
    hnode_t **nodes;
    h_key_fct hash_func;
    h_key_eq_fct key_equal_func;
    h_key_del_fct key_destroy_func;
    h_key_del_fct val_destroy_func;
};

static void htable_resize(htable_t *hash_table);
static hnode_t** htable_lookup_node(htable_t *hash_table,
        const void * key);
static hnode_t* hnode_new(void * key, void * value);
static void hnode_destroy(hnode_t *hash_node, h_key_del_fct key_destroy_func,
        h_key_del_fct val_destroy_func);
static void hnodes_destroy(hnode_t *hash_node,
        h_key_del_fct key_destroy_func, h_key_del_fct val_destroy_func);
static hnode_t *get_node_in_chunk();
static void get_new_chunk();

#define CHUNK_SIZE 100

/* keep track of chunks allocated, to free on destroy*/
struct mem_chunk_lst {
    struct mem_chunk_lst *next;
    hnode_t *chunk;
};

static struct mem_chunk_lst *chunk_lst = NULL;
static unsigned int chunk_index;
static hnode_t *node_mem_chunk = NULL;
static hnode_t *node_free_list = NULL;

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
 * size of a #htable_t.
 *
 * The built-in array of primes ranges from 11 to 13845163 such that
 * each prime is approximately 1.5-2 times the previous prime.
 *
 * Returns: the smallest prime number from a built-in array of primes
 *     which is larger than @num
 */
static unsigned int
spaced_primes_closest(unsigned int num)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(g_primes); i++)
        if (g_primes[i] > num)
            return g_primes[i];

    return g_primes[ARRAY_SIZE(g_primes) - 1];
}

htable_t*
htable_new(h_key_fct hash_func, h_key_eq_fct key_equal_func,
        h_key_del_fct key_destroy_func, h_val_del_fct val_destroy_func)
{
    htable_t *hash_table;
    unsigned int i;

    hash_table = xzalloc(sizeof(htable_t));
    hash_table->size = HASH_TABLE_MIN_SIZE;
    hash_table->nnodes = 0;
    hash_table->frozen = 0;
    hash_table->hash_func = hash_func;
    hash_table->key_equal_func = key_equal_func;
    hash_table->key_destroy_func = key_destroy_func;
    hash_table->val_destroy_func = val_destroy_func;
    hash_table->nodes = xcalloc(hash_table->size, sizeof(hnode_t*));

    for (i = 0; i < hash_table->size; i++)
        hash_table->nodes[i] = NULL;

    return hash_table;
}

void
htable_destroy(htable_t *hash_table) {
    unsigned int i;
    struct mem_chunk_lst *it, *next;

    if (!hash_table)
        return;

    for (i = 0; i < hash_table->size; i++)
        hnodes_destroy(hash_table->nodes[i], hash_table->key_destroy_func,
                hash_table->val_destroy_func);

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

static inline hnode_t**
htable_lookup_node(htable_t *hash_table, const void * key)
{
    hnode_t **node;

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
htable_lookup(htable_t *hash_table, const void * key)
{
    hnode_t *node;

    if (!hash_table)
        return NULL ;

    node = *htable_lookup_node(hash_table, key);

    return node ? node->value : NULL ;
}

void
htable_insert(htable_t *hash_table, void *key, void *value)
{
    hnode_t **node;

    if (!hash_table)
        return;

    node = htable_lookup_node(hash_table, key);

    if (*node) {
        /* do not reset node->key in this place, keeping
         * the old key might be intended.
         * a hash_table_remove/hash_table_insert pair
         * can be used otherwise.
         *
         * node->key = key; */
        (*node)->value = value;
    } else {
        *node = hnode_new(key, value);
        hash_table->nnodes++;
        if (!hash_table->frozen)
            htable_resize(hash_table);
    }
}

void
htable_remove(htable_t *hash_table, const void *key)
{
    hnode_t **node, *dest;

    if (!hash_table)
        return;

    node = htable_lookup_node(hash_table, key);

    if (*node) {
        dest = *node;
        (*node) = dest->next;
        hnode_destroy(dest, hash_table->key_destroy_func,
                hash_table->val_destroy_func);
        hash_table->nnodes--;

        if (!hash_table->frozen)
            htable_resize(hash_table);
    }
}

int
htable_lookup_extended(htable_t *hash_table, const void * lookup_key,
        void **orig_key, void **value)
{
    hnode_t *node;

    if (!hash_table)
        return 0;

    node = *htable_lookup_node(hash_table, lookup_key);

    if (node) {
        if (orig_key)
            *orig_key = node->key;
        if (value)
            *value = node->value;
        return 1;
    } else
        return 0;
}

void
hash_table_freeze(htable_t *hash_table)
{
    if (!hash_table)
        return;
    hash_table->frozen++;
}

void hash_table_thaw(htable_t *hash_table)
{
    if (!hash_table)
        return;

    if (hash_table->frozen)
        if (!(--hash_table->frozen))
            htable_resize(hash_table);
}

unsigned int
htable_foreach_remove(htable_t *hash_table, h_usr_del_fct func,
        void *user_data)
{
    hnode_t *node, *prev;
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
                    hnode_destroy(node, hash_table->key_destroy_func, hash_table->val_destroy_func);
                    node = prev;
                } else {
                    hash_table->nodes[i] = node->next;
                    hnode_destroy(node, hash_table->key_destroy_func, hash_table->val_destroy_func);
                    goto restart;
                }
            }
        }
    }

    if (!hash_table->frozen)
        htable_resize(hash_table);

    return deleted;
}

void
htable_foreach(htable_t *hash_table, h_usr_fct func, void * user_data)
{
    hnode_t *node;
    int i;

    if (!hash_table || !func)
        return;

    for (i = 0; i < hash_table->size; i++)
        for (node = hash_table->nodes[i]; node; node = node->next)
            (*func)(node->key, node->value, user_data);
}

/* Returns the number of elements contained in the hash table. */
unsigned int
htable_size(htable_t *hash_table)
{
    if (!hash_table)
        return 0;

    return hash_table->nnodes;
}

static void
htable_resize(htable_t *hash_table)
{
    hnode_t **new_nodes;
    hnode_t *node;
    hnode_t *next;
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
    new_nodes = xcalloc(new_size, sizeof(hnode_t*));

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

static hnode_t*
hnode_new(void *key, void *value)
{
    hnode_t *hash_node;

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

static void
hnode_destroy(hnode_t *hash_node, h_key_del_fct key_destroy_func,
        h_key_del_fct val_destroy_func)
{
    if (key_destroy_func) key_destroy_func(hash_node->key);
    if (val_destroy_func) val_destroy_func(hash_node->value);
    hash_node->next = node_free_list;
    node_free_list = hash_node;
}

static void
hnodes_destroy(hnode_t *hash_node,
        h_key_del_fct key_destroy_func, h_key_del_fct val_destroy_func)
{
    if (hash_node) {
        hnode_t *node = hash_node;

        while (node->next) {
            node = node->next;
            if (key_destroy_func) key_destroy_func(node->key);
            if (val_destroy_func) val_destroy_func(node->value);
        }

        node->next = node_free_list;
        node_free_list = hash_node;
    }

}

static hnode_t *
get_node_in_chunk()
{
    hnode_t *ret = NULL;
    if (chunk_index < CHUNK_SIZE - 1) {
        ret = &node_mem_chunk[chunk_index];
        chunk_index++;
        if (chunk_index == CHUNK_SIZE - 1)
            node_mem_chunk = NULL;
    }
    return ret;
}

static void
get_new_chunk()
{
    struct mem_chunk_lst *chunk, *it;

    node_mem_chunk = xcalloc(CHUNK_SIZE, sizeof(hnode_t));
    chunk_index = 0;

    chunk = xzalloc(sizeof(struct mem_chunk_lst));
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

