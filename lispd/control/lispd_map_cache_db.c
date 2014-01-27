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
#include "lispd_rloc_probing.h"
#include <math.h>


int mcache_update_mapping_eid(lisp_addr_t *new_eid, lispd_map_cache_entry *mce) {
//    lcaf_addr_t             *lcaf;
    lisp_addr_t             *old_eid;

    /* Get the node to be modified from the database
     * NOTE: This works assuming that both mc and ip addresses
     * are stored in the same pt. Also, mc prefix length is set
     * to be S prefix length. */

    old_eid = mapping_get_eid_addr(mcache_entry_get_mapping(mce));
    if (!mce) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "mcache_update_mapping_eid: requested to update EID %s but it is "
                "not present in the mappings cache!", lisp_addr_to_char(old_eid));
        return(BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_2,"EID prefix of the map cache entry %s will be changed to %s.",
            lisp_addr_to_char(old_eid), lisp_addr_to_char(new_eid));

    /* does not delete the data */
    mdb_remove_entry(mdb, old_eid);

    mcache_entry_set_eid_addr(mce, new_eid);
    mdb_add_entry(mdb, new_eid, mce);

    return (GOOD);
}

/*
 * create_tables
 */
void map_cache_init()
{
    mdb = mdb_new();
    if (!mdb) {
        lispd_log_msg(LISP_LOG_CRIT, "Could not initialize the mappings cache! Exiting .. ");
        exit(1);
    }
}

int mcache_add_mapping(lispd_mapping_elt *mapping) {
    lispd_map_cache_entry   *mce;
    lisp_addr_t             *addr;

    addr = mapping_get_eid_addr(mapping);
    mce = mcache_entry_init(mapping);
    return(mdb_add_entry(mdb, addr, mce));
}

int mcache_add_static_mapping(lispd_mapping_elt *mapping) {
    lispd_map_cache_entry   *mce;
    lisp_addr_t             *addr;

    addr = mapping_get_eid_addr(mapping);
    mce = mcache_entry_init_static(mapping);

    /*
     * Programming rloc probing timer
     */
    programming_rloc_probing(mce);

    return(mdb_add_entry(mdb, addr, mce));
}

int mcache_del_mapping(lisp_addr_t *laddr) {
    void *data;
    data = mdb_remove_entry(mdb, laddr);
    free_map_cache_entry((lispd_map_cache_entry *)data);
    return(GOOD);
}

lispd_mapping_elt *mcache_lookup_mapping(lisp_addr_t *laddr) {

    lispd_map_cache_entry *mce;
    mce = mdb_lookup_entry(mdb, laddr, 0);

    if ((mce == NULL) || (mce->active == NO_ACTIVE) )
        return(NULL);
    else
        return(mcache_entry_get_mapping(mce));
}

lispd_mapping_elt *mcache_lookup_mapping_exact(lisp_addr_t *laddr) {
    lispd_map_cache_entry *mce;

    mce = mdb_lookup_entry(mdb, laddr, 1);

    if ((mce == NULL) || (mce->active == NO_ACTIVE) )
        return(NULL);
    else
        return(mcache_entry_get_mapping(mce));
}
















/* NOTE
 * The following functions require that their callers know what a map_cache_entry element is.
 * This is too much detail to be exposed so it is advisable to use the functions above.
 */




int map_cache_add_entry(lispd_map_cache_entry *entry){
    return(mdb_add_entry(mdb, mapping_get_eid_addr(mcache_entry_get_mapping(entry)), entry));
}

















/*
 * Look up a given lisp_addr_t in the database, returning the
 * lispd_map_cache_entry of this lisp_addr_t if it exists or NULL.
 */
lispd_map_cache_entry *map_cache_lookup(lisp_addr_t *laddr)
{
    lispd_map_cache_entry *mce;
    mce = mdb_lookup_entry(mdb, laddr, 0);
    return(mce);
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
lispd_map_cache_entry *map_cache_lookup_exact(lisp_addr_t *laddr)
{
    lispd_map_cache_entry *mce;
    mce = mdb_lookup_entry(mdb, laddr, 1);
    return(mce);
}












///*
// * Remove the map cache entry from the database and reintroduce it with the new eid.
// * This function is used when the map reply report a prefix that includes the requested prefix.
// */
//
//int map_cache_replace_entry(
//        lisp_addr_t             *new_addr,
//        lispd_map_cache_entry   *centry)
//{
//    lisp_addr_t             *old_eid_addr;
//
//    /* Get the node to be modified from the database
//     * NOTE: This works assuming that both mc and ip addresses
//     * are stored in the same pt. Also, mc prefix length is set
//     * be S prefix length. */
//
//    old_eid_addr = mapping_get_eid_addr(mcache_entry_get_mapping(centry));
//
//    lispd_log_msg(LISP_LOG_DEBUG_2,"EID prefix of the map cache entry %s will be changed to %s",
//            lisp_addr_to_char(old_eid_addr), lisp_addr_to_char(new_addr));
//
//
//
//
////    map_cache_del_entry(old_eid_addr);
//
////    mcache_entry_set_eid_addr(centry, new_addr);
//
//    if ((err=map_cache_add_entry(centry))!= GOOD){
//        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
//        lispd_log_msg(LISP_LOG_DEBUG_2,"change_eid_prefix_in_db: Couldn't change EID prefix of the inactive "
//                "map cache entry (%s -> %s). Releasing it",
//                lisp_addr_to_char(old_eid_addr),
//                lisp_addr_to_char(new_addr));
//        free_map_cache_entry(centry);
//        return (BAD);
//    }
//    return (GOOD);
//}



/*
 * map_cache_entry_expiration()
 *
 * Called when the timer associated with an EID entry expires.
 */
void map_cache_entry_expiration(
        timer   *t,
        void    *arg)
{
    lispd_map_cache_entry   *entry      = NULL;
    lispd_mapping_elt       *mapping    = NULL;
    lisp_addr_t             *addr       = NULL;
    uint8_t                 plen        = 0;

    entry = (lispd_map_cache_entry *)arg;
    mapping = mcache_entry_get_mapping(entry);
    addr = mapping_get_eid_addr(mapping);
    lispd_log_msg(LISP_LOG_DEBUG_1,"Got expiration for EID",
            lisp_addr_to_char(addr), plen);

    mcache_del_mapping(addr);
}

/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(lisp_addr_t *eid, uint64_t nonce)
{
    void                    *it;
    lispd_map_cache_entry   *mce;


    mdb_foreach_entry(mdb, it) {
        mce = (lispd_map_cache_entry *)it;
        if (mce->active == FALSE){
            if (check_nonce(mce->nonces,nonce) == GOOD){
                free(mce->nonces);
                mce->nonces = NULL;
                return(mce);
            }
        }
    } mdb_foreach_entry_end;

    return (NULL);
}



void map_cache_dump_db(int log_level)
{
    lispd_map_cache_entry   *mce;
    void                    *it;

    lispd_log_msg(log_level,"**************** LISP Mapping Cache ******************\n");
    mdb_foreach_entry(mdb, it) {
        mce = (lispd_map_cache_entry *)it;
        dump_map_cache_entry(mce, log_level);
    } mdb_foreach_entry_end;
    lispd_log_msg(log_level,"*******************************************************\n");

}






