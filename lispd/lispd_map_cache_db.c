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
#include <math.h>

/*
 *  Patricia tree based databases
 */

patricia_tree_t *AF4_map_cache           = NULL;
patricia_tree_t *AF6_map_cache           = NULL;



// A populated count to bit table for lsb setup.
// This is for when we assume all locators are
// available when setting up an entry. i.e.
// 3 locators --> 0000000....00000111
int lsb_table[32 + 1];
void build_lsb_table(void);
/*
 *  Add a map cache entry to the database.
 */
int add_map_cache_entry(lispd_map_cache_entry *entry);

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
  // XXX Replace with mutex // XXX Replace with mutex spin_lock_init(&table_lock);

  build_lsb_table();
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
 */
int add_map_cache_entry(lispd_map_cache_entry *entry)
{
    prefix_t            *prefix;
    patricia_node_t     *node;
    lisp_addr_t         eid_prefix;
    int                 eid_prefix_length;

    eid_prefix = entry->identifier->eid_prefix;
    eid_prefix_length = entry->identifier->eid_prefix_length;

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
    if (node->data != NULL){            /* its a new node */
        lispd_map_cache_entry *entry2 = (lispd_map_cache_entry *)node->data;
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_map_cache_entry: Map cache entry (%s/%d) already installed in the data base",
                get_char_from_lisp_addr_t(entry2->identifier->eid_prefix),entry2->identifier->eid_prefix_length);
        return (BAD);
    }
    node->data = (lispd_map_cache_entry *) entry;
    lispd_log_msg(LISP_LOG_DEBUG_2, "Added map cache entry for EID: %s/%d",
            get_char_from_lisp_addr_t(entry->identifier->eid_prefix),eid_prefix_length);
    return (GOOD);
}

/*
 * Create a map cache entry and save it in the database
 */

lispd_map_cache_entry *new_map_cache_entry (
        lisp_addr_t     eid_prefix,
        int             eid_prefix_length,
        int             how_learned,
        uint16_t        ttl)
{
    lispd_map_cache_entry *map_cache_entry;
    /* Create map cache entry */
    if ((map_cache_entry = malloc(sizeof(lispd_map_cache_entry))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING,"new_map_cache_entry: Unable to allocate memory for lispd_map_cache_entry: %s", strerror(errno));
        return(NULL);
    }
    memset(map_cache_entry,0,sizeof(lispd_map_cache_entry));
    if ((map_cache_entry->identifier = malloc(sizeof(lispd_mapping_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING,"new_map_cache_entry: Unable to allocate memory for lispd_mapping_elt: %s", strerror(errno));
        free (map_cache_entry);
        return(NULL);
    }

    init_mapping(map_cache_entry->identifier);
    map_cache_entry->identifier->eid_prefix = eid_prefix;
    map_cache_entry->identifier->eid_prefix_length = eid_prefix_length;
    map_cache_entry->active_witin_period = FALSE;
    map_cache_entry->probe_left = 0;
    map_cache_entry->how_learned = how_learned;
    map_cache_entry->ttl = ttl;
    if (how_learned == DYNAMIC_MAP_CACHE_ENTRY){
        map_cache_entry->active = NO_ACTIVE;
    }
    else{
        map_cache_entry->active = ACTIVE;
    }
    map_cache_entry->expiry_cache_timer = NULL;
    map_cache_entry->probe_timer = NULL;
    map_cache_entry->smr_timer = NULL;
    map_cache_entry->request_retry_timer = NULL;
    map_cache_entry->nonces = NULL;
    /* Add entry to the data base */
    if (add_map_cache_entry (map_cache_entry)==BAD){
        free(map_cache_entry);
        return (NULL);
    }
    map_cache_entry->timestamp = time(NULL);
    time(NULL);
    return (map_cache_entry);
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



void free_lispd_map_cache_entry(lispd_map_cache_entry *entry){

    free_lispd_mapping_elt(entry->identifier);
    /*
     * Free the entry
     */
    if (entry->how_learned == DYNAMIC_MAP_CACHE_ENTRY) {
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
    if (entry->nonces){
        free(entry->nonces);
    }
    free(entry);
}


/*
 * del_map_cache_entry()
 *
 * Delete an EID mapping from the cache
 */
void del_map_cache_entry(
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

    free_lispd_map_cache_entry(entry);
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

    node = lookup_map_cache_exact_node(cache_entry->identifier->eid_prefix, cache_entry->identifier->eid_prefix_length);
    if (node == NULL){
        return (BAD);
    }
    if (cache_entry->identifier->eid_prefix.afi==AF_INET)
        patricia_remove(AF4_map_cache, node);
    else
        patricia_remove(AF6_map_cache, node);

    old_eid_prefix = cache_entry->identifier->eid_prefix;
    old_eid_prefix_length = cache_entry->identifier->eid_prefix_length;
    cache_entry->identifier->eid_prefix = new_eid_prefix;
    cache_entry->identifier->eid_prefix_length = new_eid_prefix_length;

    if ((err=add_map_cache_entry(cache_entry))!= GOOD){
        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
        lispd_log_msg(LISP_LOG_DEBUG_2,"change_eid_prefix_in_db: Couldn't change EID prefix of the inactive "
                "map cahce entry (%s/%d -> %s/%d). Releasing it",
                get_char_from_lisp_addr_t(old_eid_prefix),
                old_eid_prefix_length,
                get_char_from_lisp_addr_t(new_eid_prefix),
                new_eid_prefix_length);
        free_lispd_map_cache_entry(cache_entry);
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

    lispd_log_msg(LISP_LOG_DEBUG_1,"Got expiration for EID %s/%d", get_char_from_lisp_addr_t(entry->identifier->eid_prefix),
            entry->identifier->eid_prefix_length);
    del_map_cache_entry(entry->identifier->eid_prefix, entry->identifier->eid_prefix_length);
}



/*
 * format_uptime
 *
 * Create a string in HH:MM:ss format given a number of seconds
 */
void format_uptime(int seconds, char *buffer)
{
    double hours = seconds / 3600.0;
    int    wholehours = floor(hours);
    double    frachours = hours - wholehours;
    double minutes = frachours * 60.0;
    int   wholemins = floor(minutes);
    double   fracmins = minutes - wholemins;
    int   new_seconds = fracmins * 60.0;

    sprintf(buffer, "%02d:%02d:%02d", wholehours, wholemins, new_seconds);
}



/*
 * dump_map_cache
 */
void dump_map_cache(int log_level)
{
	patricia_tree_t 	*dbs [2] = {AF4_map_cache, AF6_map_cache};
    char 				buf[256], buf2[256];
    time_t              uptime;
    time_t              expiretime;
    int					ctr, ctr1;

    patricia_node_t             *node;
    lispd_map_cache_entry       *entry;
    lispd_locators_list         *locator_iterator_array[2];
    lispd_locators_list         *locator_iterator;
    lispd_locator_elt           *locator;

   lispd_log_msg(log_level,"*** LISP Mapping Cache ***\n\n");

    for (ctr = 0 ; ctr < 2 ; ctr++){
    	PATRICIA_WALK(dbs[ctr]->head, node) {
    		entry = ((lispd_map_cache_entry *)(node->data));
    		lispd_log_msg(log_level,"%s/%d (IID = %d), ", get_char_from_lisp_addr_t(entry->identifier->eid_prefix),
    				entry->identifier->eid_prefix_length, entry->identifier->iid);
    		uptime = time(NULL);
    		uptime = uptime - entry->timestamp;
            strftime(buf, 20, "%H:%M:%S", localtime(&uptime));
    		expiretime = (entry->ttl * 60) - uptime;
    		if (expiretime > 0)
    		    strftime(buf2, 20, "%H:%M:%S", localtime(&expiretime));

    		lispd_log_msg(log_level,"uptime: %s, expires: %s, via ", buf, expiretime > 0 ? buf2 : "EXPIRED");

    		if (entry->how_learned == STATIC_LOCATOR)
    			lispd_log_msg(log_level,"static ");
    		else
    			lispd_log_msg(log_level,"map-reply ");
    		lispd_log_msg(log_level,"active: %s\n", entry->active == TRUE ? "Yes" : "No");


    		if (entry->identifier->locator_count > 0){
    			lispd_log_msg(log_level,"       Locator     State    Priority/Weight  Data In/Out  %d\n",entry->identifier->locator_count);
    			locator_iterator_array[0] = entry->identifier->head_v4_locators_list;
    			locator_iterator_array[1] = entry->identifier->head_v6_locators_list;
    			// Loop through the locators and print each
    			for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){
    			    locator_iterator = locator_iterator_array[ctr1];
    			    while (locator_iterator != NULL) {
    			        locator = locator_iterator->locator;
    			       lispd_log_msg(log_level," %15s ", get_char_from_lisp_addr_t(*(locator->locator_addr)));
    			       lispd_log_msg(log_level," %5s ", locator->state ? "Up" : "Down");
    			       lispd_log_msg(log_level,"         %3d/%-3d ", locator->priority, locator->weight);
    			       lispd_log_msg(log_level,"      %5d/%-5d\n", locator->data_packets_in,
    			                locator->data_packets_out);
    			        locator_iterator = locator_iterator->next;
    			    }
    			}
    			lispd_log_msg(log_level,"\n");
    		}

    	} PATRICIA_WALK_END;
    }
}
