/*
 * lispd_referral_cache_db.h
 *
 *  Created on: Sep 26, 2013
 *      Author: alopez
 */

#ifndef LISPD_REFERRAL_CACHE_DB_H_
#define LISPD_REFERRAL_CACHE_DB_H_

#include "lispd_referral_cache.h"

#define DDT_ALL_DATABASES                    0
#define DDT_END_PREFIX_DATABASES            1
#define DDT_NOT_END_PREFIX_DATABASES        2

/**
 * Creates referral cache databases
 */
void init_referral_cache();

/**
 * Removes referral cache databases
 */
void drop_referral_cache();

/*
 *  Add a referral cache entry to the database.
 */
int add_referral_cache_entry_to_db(lispd_referral_cache_entry *entry);

/*
 * It search if there is a referral cache entry for the specified EID prefix. If not exists, it creates the entry.
 * In both cases it adds the new locator. This function is used to add the root ddt nodes.
 */

int add_update_ddt_static_entry_to_db (
        lisp_addr_t     eid_prefix,
        int             eid_prefix_length,
        int             iid,
        lisp_addr_t     *ddt_locator_address,
        int             priority,
        int             weight,
        int             ttl);

/**
 * Remove a referral cache entry from the database and all its children nodes.
 * To remove the node from the list of childrens of its parent, call firstly the function
 * remove_referral_cache_entry_from_parent_node
 * @param entry Referral cache node to be removed from the database
 */
void del_referral_cache_entry_from_db(lispd_referral_cache_entry  *entry);

/**
 * Remove from the database all lispd_referral_cache_entry of a lispd_referral_cache_list.
 * @param referral_cache_list List of referral cache elements to be removed
 */
void del_referral_cache_list_from_db(lispd_referral_cache_list *referral_list);

/**
 * Look for in the indicated group of databases a lispd_map_cache_entry that match exactly the specified prefix/prefixlen.
 * @param eid Network address to search
 * @param prefixlen Network prefix length to search
 * @param databases_to_use Where we do the search: DDT_ALL_DATABSES, DDT_END_PREFIX_DATABASES, DDT_NOT_END_PREFIX_DATABASES
 * @return The lispd_referral_cache_entry that match the search or NULL otherwise
 */
lispd_referral_cache_entry *lookup_referral_cache_exact(
        lisp_addr_t     eid,
        int             prefixlen,
        int             databases_to_use);

/**
 * Look for in the indicated group of databases a lispd_map_cache_entry that contains the specified eid. Get the most specific node
 * @param eid Address to look for
 * @param databases_to_use Where we do the search: DDT_ALL_DATABASES, DDT_END_PREFIX_DATABASES, DDT_NOT_END_PREFIX_DATABASES
 * @return The lispd_referral_cache_entry that match the search or NULL otherwise
 */
lispd_referral_cache_entry *lookup_referral_cache(
        lisp_addr_t     eid,
        int             databases_to_use);

/*
 * Return TRUE if no ddt root nodes present
 */
int is_referral_db_empty();

/**
 * Returns the lispd_referral_cache_entry which represents the root prefix according to the IP afi
 * @param afi Afi of the root referral cache node to be returned. AF_INET or AF_INET6
 * @return Return the lispd_referral_cache_entry representing the root prefix or NULL if DDT database is empty.
 */
lispd_referral_cache_entry *get_root_referral_cache(int afi);

/*
 * dump_referral_cache
 */
void dump_referral_cache_db(int log_level);


#endif /* LISPD_REFERRAL_CACHE_DB_H_ */
