/*
 * lispd_map_cache_db.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include <math.h>

/*
 *  Patricia tree based databases
 */

patricia_tree_t *AF4_map_cache           = NULL;
patricia_tree_t *AF6_map_cache           = NULL;


/*
 * create_tables
 */
void map_cache_init()
{
  lispd_log_msg(LISP_LOG_DEBUG_2,  " Creating map cache...");

  AF4_map_cache = New_Patricia(sizeof(struct in_addr) * 8);
  AF6_map_cache = New_Patricia(sizeof(struct in6_addr) * 8);


  if (!AF4_map_cache || !AF6_map_cache){
      lispd_log_msg(LISP_LOG_CRIT, "map_cache_init: Unable to allocate memory for map cache database");
      exit(EXIT_FAILURE);
  }
}

/*
 * Return map cache data base
 */
patricia_tree_t* get_map_cache_db(int afi)
{
    if (afi == AF_INET)
        return (AF4_map_cache);
    else
        return (AF6_map_cache);
}

/*
 *  Add a map cache entry to the database.
 */
int add_map_cache_entry_to_db(lispd_map_cache_entry *entry)
{
    prefix_t                *prefix             = NULL;
    patricia_node_t         *node               = NULL;
    lispd_map_cache_entry   *entry2             = NULL;
    lisp_addr_t             eid_prefix;
    int                     eid_prefix_length   = 0;

    eid_prefix = entry->mapping->eid_prefix;
    eid_prefix_length = entry->mapping->eid_prefix_length;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry: Unable to allocate memory for patrica_node_t: %s", strerror(errno));
        return(ERR_MALLOC);
    }

    switch(eid_prefix.afi) {
    case AF_INET:
        if ((prefix = New_Prefix(AF_INET, &(eid_prefix.address.ip), eid_prefix_length)) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry: Unable to allocate memory for prefix_t  (AF_INET): %s", strerror(errno));
            free(node);
            return(ERR_MALLOC);
        }
        node = patricia_lookup(AF4_map_cache, prefix);
        break;
    case AF_INET6:
        if ((prefix = New_Prefix(AF_INET6, &(eid_prefix.address.ipv6), eid_prefix_length)) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry: Unable to allocate memory for prefix_t  (AF_INET6): %s", strerror(errno));
            free(node);
            return(ERR_MALLOC);
        }
        node = patricia_lookup(AF6_map_cache, prefix);
        break;
    default:
        free(node);
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_map_cache_entry: Unknown afi (%d) when allocating prefix_t", eid_prefix.afi);
        return(ERR_AFI);
    }
    Deref_Prefix(prefix);
    if (node->data != NULL){            /* The node already exists */
        entry2 = (lispd_map_cache_entry *)node->data;
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_map_cache_entry: Map cache entry (%s/%d) already installed in the data base",
                get_char_from_lisp_addr_t(entry2->mapping->eid_prefix),entry2->mapping->eid_prefix_length);
        return (BAD);
    }
    node->data = (lispd_map_cache_entry *) entry;
    lispd_log_msg(LISP_LOG_DEBUG_2, "Added map cache entry for EID: %s/%d",
            get_char_from_lisp_addr_t(entry->mapping->eid_prefix),eid_prefix_length);
    return (GOOD);
}



/*
 * Given an eid , return the best patricai node in the map cache database (the most
 * specific prefix that contains the EID) or NULL if no one is found
 */

patricia_node_t *lookup_map_cache_node(lisp_addr_t eid)
{
    patricia_node_t   *node = NULL;
    prefix_t          prefix;

    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = 32;
        prefix.ref_count = 0;
        prefix.add.sin.s_addr = eid.address.ip.s_addr;
        node = patricia_search_best(AF4_map_cache, &prefix);
        break;
    case AF_INET6:
        prefix.family = AF_INET6;
        prefix.bitlen = 128;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
        node = patricia_search_best(AF6_map_cache, &prefix);
        break;
    default:
        break;
    }

    if (node==NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_map_cache_node: The entry %s is not found in the map cache", get_char_from_lisp_addr_t(eid));
    }

    return(node);
}

/*
 * Given an eid , return the node in the map cache database  of this EID
 * or NULL if it doesn't exist
 */
patricia_node_t * lookup_map_cache_exact_node(
        lisp_addr_t     eid,
        int             prefixlen)
{
    patricia_node_t     *node = NULL;
    prefix_t            prefix;

    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = prefixlen;
        prefix.ref_count = 0;
        prefix.add.sin.s_addr = eid.address.ip.s_addr;
        node = patricia_search_exact(AF4_map_cache, &prefix);
        break;
    case AF_INET6:
        prefix.family = AF_INET6;
        prefix.bitlen = prefixlen;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
        node = patricia_search_exact(AF6_map_cache, &prefix);
        break;
    default:
        break;
    }

    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_map_cache_exact_node: The entry %s/%d is not found in the map cache", get_char_from_lisp_addr_t(eid),prefixlen);
    }

    return(node);
}

/*
 * Look up a given eid in the database, returning the
 * lispd_map_cache_entry of this EID if it exists or NULL.
 */

lispd_map_cache_entry *lookup_map_cache(lisp_addr_t eid)
{
  patricia_node_t           *node  = NULL;
  lispd_map_cache_entry     *entry = NULL;

  node = lookup_map_cache_node(eid);
  if ( node == NULL ){
      return(NULL);
  }
  entry = (lispd_map_cache_entry *)(node->data);

  return(entry);
}


/*
 * Find an exact match for a prefix/prefixlen if possible
 */

lispd_map_cache_entry *lookup_map_cache_exact(
        lisp_addr_t             eid,
        int                     prefixlen)
{
    lispd_map_cache_entry   *entry = NULL;
    patricia_node_t         *node  = NULL;

    node = lookup_map_cache_exact_node(eid,prefixlen);
    if ( node == NULL ){
          return(NULL);
    }
    entry = (lispd_map_cache_entry *)(node->data);

    return(entry);
}

/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(
        int         eid_afi,
        uint64_t    nonce)
{
    patricia_tree_t         *tree;
    patricia_node_t         *node;
    lispd_map_cache_entry   *entry;

    if (eid_afi == AF_INET)
        tree = AF4_map_cache;
    else
        tree = AF6_map_cache;

    PATRICIA_WALK(tree->head, node) {
        entry = ((lispd_map_cache_entry *)(node->data));
        if (!entry->active && check_nonce(entry->nonces,nonce)){
            entry->nonces = NULL;
            return (entry);
        }
    } PATRICIA_WALK_END;

    return (NULL);
}


/*
 * del_map_cache_entry()
 *
 * Delete an EID mapping from the cache
 */
void del_map_cache_entry_from_db(
        lisp_addr_t eid,
        int prefixlen)
{
    lispd_map_cache_entry *entry    = NULL;
    patricia_node_t       *node   = NULL;

    node = lookup_map_cache_exact_node(eid, prefixlen);
    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"del_map_cache_entry: Unable to locate cache entry %s/%d for deletion",get_char_from_lisp_addr_t(eid),prefixlen);
        return;
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"Deleting map cache entry: %s/%d", get_char_from_lisp_addr_t(eid),prefixlen);
    }

    /*
     * Remove the entry from the trie
     */
    entry = (lispd_map_cache_entry *)(node->data);
    if (eid.afi==AF_INET)
        patricia_remove(AF4_map_cache, node);
    else
        patricia_remove(AF6_map_cache, node);

    free_map_cache_entry(entry);
}

/*
 * Remove the map cache entry from the database and reintroduce it with the new eid.
 * This function is used when the map reply report a prefix that includes the requested prefix.
 */

int change_map_cache_prefix_in_db(
        lisp_addr_t             new_eid_prefix,
        int                     new_eid_prefix_length,
        lispd_map_cache_entry   *cache_entry)
{
    patricia_node_t         *node = NULL;
    lisp_addr_t             old_eid_prefix;
    int                     old_eid_prefix_length;

    /* Get the node to be modified from the database */
    node = lookup_map_cache_exact_node(cache_entry->mapping->eid_prefix, cache_entry->mapping->eid_prefix_length);
    if (node == NULL){
        return (BAD);
    }
    /* Remove the node from the database*/
    if (cache_entry->mapping->eid_prefix.afi==AF_INET)
        patricia_remove(AF4_map_cache, node);
    else
        patricia_remove(AF6_map_cache, node);

    old_eid_prefix = cache_entry->mapping->eid_prefix;
    old_eid_prefix_length = cache_entry->mapping->eid_prefix_length;
    cache_entry->mapping->eid_prefix = new_eid_prefix;
    cache_entry->mapping->eid_prefix_length = new_eid_prefix_length;

    if ((err=add_map_cache_entry_to_db(cache_entry))!= GOOD){
        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
        lispd_log_msg(LISP_LOG_DEBUG_2,"change_eid_prefix_in_db: Couldn't change EID prefix of the inactive "
                "map cahce entry (%s/%d -> %s/%d). Releasing it",
                get_char_from_lisp_addr_t(old_eid_prefix),
                old_eid_prefix_length,
                get_char_from_lisp_addr_t(new_eid_prefix),
                new_eid_prefix_length);
        free_map_cache_entry(cache_entry);
        return (BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_2,"EID prefix of the map cache entry %s/%d changed to %s/%d.",
            get_char_from_lisp_addr_t(old_eid_prefix),
            old_eid_prefix_length,
            get_char_from_lisp_addr_t(new_eid_prefix),
            new_eid_prefix_length);
    return (GOOD);
}

/*
 * map_cache_entry_expiration()
 *
 * Called when the timer associated with an EID entry expires.
 */
void map_cache_entry_expiration(
        timer   *t,
        void    *arg)
{
    lispd_map_cache_entry *entry = (lispd_map_cache_entry *)arg;

    lispd_log_msg(LISP_LOG_DEBUG_1,"Got expiration for EID %s/%d", get_char_from_lisp_addr_t(entry->mapping->eid_prefix),
            entry->mapping->eid_prefix_length);
    del_map_cache_entry_from_db(entry->mapping->eid_prefix, entry->mapping->eid_prefix_length);
}


/*
 * dump_map_cache
 */
void dump_map_cache_db(int log_level)
{
    patricia_tree_t 	*dbs [2] = {AF4_map_cache, AF6_map_cache};
    int					ctr;

    patricia_node_t             *node;
    lispd_map_cache_entry       *entry;


    lispd_log_msg(log_level,"**************** LISP Mapping Cache ******************\n");

    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(dbs[ctr]->head, node) {
            entry = ((lispd_map_cache_entry *)(node->data));
            dump_map_cache_entry (entry, log_level);
        } PATRICIA_WALK_END;
    }
    lispd_log_msg(log_level,"*******************************************************\n");
}
