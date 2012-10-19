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


#include "lispd_map_cache_db.h"
#include "lispd_lib.h"
#include "patricia/patricia.h"


/*
 *  Patricia tree based databases
 */

patricia_tree_t *AF4_eid_cache           = NULL;
patricia_tree_t *AF6_eid_cache           = NULL;

// A populated count to bit table for lsb setup.
// This is for when we assume all locators are
// available when setting up an entry. i.e.
// 3 locators --> 0000000....00000111
int lsb_table[32 + 1];
void build_lsb_table(void);

/*
 * create_tables
 */
void map_cache_init(void)
{
  syslog(LOG_INFO,  " Creating map cache...");

  AF4_eid_cache = New_Patricia(sizeof(struct in_addr) * 8);
  AF6_eid_cache = New_Patricia(sizeof(struct in6_addr) * 8);


  if (!AF4_eid_cache || !AF6_eid_cache)
      syslog(LOG_ERR,  "FAILED to create Map Cache.");

  // XXX Replace with mutex // XXX Replace with mutex spin_lock_init(&table_lock);

  build_lsb_table();
}

void build_lsb_table(void)
{
    int i, j;
    lsb_table[0] = 0;
    for (i = 1; i <= 32; i++) {
        lsb_table[i] = 0;
        for (j = 0; j < i; j++) {
            lsb_table[i] |= 1 << j;
        }
    }
}

/*
 *  Add a map cache entry to the database.
 *  Returns:
 *      GOD:
 */
int add_map_cache_entry(lispd_map_cache_entry *entry)
{
    prefix_t            *prefix;
    patricia_node_t     *node;
    lisp_addr_t         eid_prefix;
    int                 eid_prefix_length;

    eid_prefix = entry->identifier.eid_prefix;
    eid_prefix_length = entry->identifier.eid_prefix_length;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        syslog(LOG_ERR, "can't allocate patrica_node_t");
        return(BAD);
    }

    switch(eid_prefix.afi) {
    case AF_INET:
        if ((prefix = New_Prefix(AF_INET, &(eid_prefix.address.ip), eid_prefix_length)) == NULL) {
            syslog(LOG_ERR, "couldn't alocate prefix_t for AF_INET");
            free(node);
            return(BAD);
        }
        node = patricia_lookup(AF4_eid_cache, prefix);
        break;
    case AF_INET6:
        if ((prefix = New_Prefix(AF_INET6, &(eid_prefix.address.ipv6), eid_prefix_length)) == NULL) {
            syslog(LOG_ERR, "couldn't alocate prefix_t for AF_INET6");
            free(node);
            return(BAD);
        }
        node = patricia_lookup(AF6_eid_cache, prefix);
        break;
    default:
        free(node);
        syslog(LOG_ERR, "Unknown afi (%d) when allocating prefix_t", eid_prefix.afi);
        return(BAD);
    }
    Deref_Prefix(prefix);

    if (node->data == NULL){            /* its a new node */
        node->data = (lispd_map_cache_entry *) entry;
        return (GOOD);
    }else{
        syslog(LOG_ERR, "WARNING: Map cache entry (%s/%d) already installed in the data base",
                get_char_from_lisp_addr_t(eid_prefix),eid_prefix_length);
        return (BAD);
    }


}



/*
 * lookup_eid_cache_node()
 *
 * Given an eid ,look up the best node in the cache, returning true and filling
 * in the patricia_node_t pointer if found, or false if not found.
 */
int lookup_eid_cache_node(lisp_addr_t eid, patricia_node_t **node)
{
  prefix_t prefix;

  switch(eid.afi) {
        case AF_INET:
            prefix.family = AF_INET;
            prefix.bitlen = 32;
            prefix.ref_count = 0;
            prefix.add.sin.s_addr = eid.address.ip.s_addr;
            *node = patricia_search_best(AF4_eid_cache, &prefix);
            break;
        case AF_INET6:
            prefix.family = AF_INET6;
            prefix.bitlen = 128;
            prefix.ref_count = 0;
            memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
            *node = patricia_search_best(AF6_eid_cache, &prefix);
            break;
        default:
            break;
    }

  if (!node)
  {
      syslog (LOG_DEBUG, "The entry %s is not found in the map cache", get_char_from_lisp_addr_t(eid));
      return(BAD);
  }
  return(GOOD);
}

/*
 * lookup_eid_cache_exact()
 * Look up a given eid in the cache, returning true and filling
 * in the patricia_node_t pointer if found, or false if not found.
 */
int lookup_eid_cache_exact_node(lisp_addr_t eid, int prefixlen, patricia_node_t **node)
{
    prefix_t prefix;

    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = prefixlen;
        prefix.ref_count = 0;
        prefix.add.sin.s_addr = eid.address.ip.s_addr;
        *node = patricia_search_exact(AF4_eid_cache, &prefix);
        break;
    case AF_INET6:
        prefix.family = AF_INET6;
        prefix.bitlen = prefixlen;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
        *node = patricia_search_exact(AF6_eid_cache, &prefix);
        break;
    default:
        break;
    }

    if (!node)
    {
        syslog (LOG_DEBUG, "The entry %s/%d is not found in the map cache", get_char_from_lisp_addr_t(eid),prefixlen);
        return(BAD);
    }

    return(GOOD);
}

/*
 * lookup_eid_cache_v4()
 *
 * Look up a given ipv4 eid in the cache, returning true and
 * filling in the entry pointer if found, or false if not found.
 */
int lookup_eid_cache(lisp_addr_t eid, lispd_map_cache_entry **entry)
{
  patricia_node_t *node;
  if (!lookup_eid_cache_node(eid,&node))
      return(BAD);
  *entry = (lispd_map_cache_entry *)(node->data);
  return(GOOD);
}


/*
 * lookup_eid_cache_exact()
 *
 * Find an exact match for a prefix/prefixlen if possible
 */
int lookup_eid_cache_exact(lisp_addr_t eid, int prefixlen, lispd_map_cache_entry **entry)
{
    patricia_node_t *node;
    if (!lookup_eid_cache_exact_node(eid,prefixlen,&node))
          return(BAD);

    *entry = (lispd_map_cache_entry *)(node->data);
    return(GOOD);
}


int check_nonce(lispd_map_cache_entry   *entry, uint64_t nonce){
    int i,j;
    for (i=0;i<entry->nonces->retransmits;i++){
        if (entry->nonces->nonce[i] == nonce){
            for (j=0;j<entry->nonces->retransmits;j++)
                entry->nonces->nonce[j] = 0;
            entry->nonces->retransmits = 0;
            return (GOOD);
        }
    }
    return (BAD);
}


/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(int eid_afi, uint64_t nonce){

    patricia_tree_t         *tree;
    patricia_node_t         *node;
    lispd_map_cache_entry   *entry;

    if (eid_afi == AF_INET)
        tree = AF4_eid_cache;
    else
        tree = AF6_eid_cache;

    PATRICIA_WALK(tree->head, node) {
        entry = ((lispd_map_cache_entry *)(node->data));
        if (!entry->active && check_nonce(entry,nonce))
            return (entry);
    } PATRICIA_WALK_END;

    return (NULL);
}



void free_lispd_map_cache_entry(lispd_map_cache_entry *entry){
    /*
     * Free the locators list
     */
    free_locator_list(entry->identifier.head_locators_list);
    entry->identifier.head_locators_list = NULL;

    /*
     * Free the entry
     */
    if (entry->how_learned) {
        if (entry->expiry_cache_timer){
            stop_timer(entry->expiry_cache_timer);
            free (entry->expiry_cache_timer);
        }
        if (entry->request_retry_timer){
            stop_timer(entry->request_retry_timer);
            free (entry->request_retry_timer);
        }
        if (entry->smr_timer){
            stop_timer(entry->smr_timer);
            free (entry->smr_timer);
        }
    }
    if (entry->probe_timer){
        stop_timer(entry->probe_timer);
        free(entry->probe_timer);
    }

    free(entry);
}


/*
 * del_eid_cache_entry()
 *
 * Delete an EID mapping from the cache
 */
void del_eid_cache_entry(lisp_addr_t eid,
        int prefixlen)
{
    lispd_map_cache_entry *entry;
    patricia_node_t      *result;

    if (!lookup_eid_cache_exact_node(eid, prefixlen, &result)){
        syslog(LOG_ERR,"   Unable to locate cache entry %s/%d for deletion",get_char_from_lisp_addr_t(eid),prefixlen);
        return;
    } else {
        syslog(LOG_DEBUG,"   Deleting map cache EID entry %s/%d", get_char_from_lisp_addr_t(eid),prefixlen);
    }

    /*
     * Remove the entry from the trie
     */
    entry = (lispd_map_cache_entry *)(result->data);
    if (eid.afi==AF_INET)
        patricia_remove(AF4_eid_cache, result);
    else
        patricia_remove(AF6_eid_cache, result);

    free_lispd_map_cache_entry(entry);
}

/*
 * Remove the map cache entry from the database and reintroduce it with the new eid.
 * This function is used when the map reply report a prefix that includes the requested prefix.
 */

int change_eid_prefix_in_db(lisp_addr_t         new_eid_prefix,
        int                                     new_eid_prefix_length,
        lispd_map_cache_entry                   *cache_entry)
{
    patricia_node_t *node;
    lookup_eid_cache_exact_node(cache_entry->identifier.eid_prefix, cache_entry->identifier.eid_prefix_length, &node);
    if (cache_entry->identifier.eid_prefix.afi==AF_INET)
        patricia_remove(AF4_eid_cache, node);
    else
        patricia_remove(AF6_eid_cache, node);

    cache_entry->identifier.eid_prefix = new_eid_prefix;
    cache_entry->identifier.eid_prefix_length = new_eid_prefix_length;

    if (add_map_cache_entry(cache_entry)== BAD){
        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
        free_lispd_map_cache_entry(cache_entry);
        return (BAD);
    }

    return (GOOD);
}

/*
 * eid_entry_expiration()
 *
 * Called when the timer associated with an EID entry expires.
 */
void eid_entry_expiration(timer *t, void *arg)
{
    lispd_map_cache_entry *entry = (lispd_map_cache_entry *)arg;

    syslog (LOG_DEBUG,"Got expiration for EID %s/%d", get_char_from_lisp_addr_t(entry->identifier.eid_prefix),
            entry->identifier.eid_prefix_length);
    del_eid_cache_entry(entry->identifier.eid_prefix, entry->identifier.eid_prefix_length);
}



