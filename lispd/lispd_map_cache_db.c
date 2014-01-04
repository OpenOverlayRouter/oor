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
#include "lispd_rloc_probing.h"
#include <math.h>

/*
 *  Patricia tree based databases
 */

patricia_tree_t *AF4_map_cache           = NULL;
patricia_tree_t *AF6_map_cache           = NULL;


lispd_map_cache_entry       *map_cache_lookup_ip(ip_addr_t* ipaddr);
lispd_map_cache_entry       *map_cache_lookup_ippref(ip_prefix_t *ippref);
lispd_map_cache_entry       *map_cache_lookup_mc(lcaf_addr_t *mcaddr);
lispd_map_cache_entry       *map_cache_lookup_mc_exact(lcaf_addr_t *mcaddr);

int                         map_cache_del_ippref_entry(ip_prefix_t *ippref);
int                         map_cache_del_mc_entry(lcaf_addr_t *mcaddr);
int                         map_cache_add_ippref_entry(void *entry, ip_prefix_t *ippref);
int                         map_cache_add_mc_entry(void *entry, lcaf_addr_t *addr);

int                         pt_add_ippref(patricia_tree_t *pt, ip_prefix_t *ippref, void *data);
void                        *pt_lookup_ip(patricia_tree_t *pt, ip_addr_t *ipaddr);
void                        *pt_lookup_ip_exact(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t plen);
void                        *pt_lookup_ippref(patricia_tree_t *pt, ip_prefix_t *ippref);
int                         pt_remove_ippref(patricia_tree_t *pt, ip_prefix_t *ippref);
int                         pt_update_ippref(patricia_tree_t *pt, ip_prefix_t *ippref, void *data);

int                         pt_add_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr, void *data);
void                        *pt_lookup_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr);
void                        *pt_lookup_mc_addr_exact(patricia_tree_t *pt, lcaf_addr_t *mcaddr);
int                         pt_remove_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr);
int                         pt_update_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr, void *data);

patricia_node_t             *pt_add_node(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen, void *data);
patricia_node_t             *pt_add_mc_node(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen);
patricia_node_t             *pt_find_ip_node(patricia_tree_t *pt, ip_addr_t *ipaddr);
patricia_node_t             *pt_find_ip_node_exact(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen);
patricia_node_t             *pt_find_mc_node(patricia_tree_t *pt, lcaf_addr_t *mcaddr);
patricia_node_t             *pt_find_mc_node_exact(patricia_tree_t *pt, lcaf_addr_t *mcaddr);
//void                        pt_remove_node(patricia_tree_t *pt, patricia_node_t *node);

uint8_t                     pt_test_if_empty(patricia_tree_t *pt);
prefix_t                    *pt_make_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen);

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
      exit_cleanup();
  }
}

patricia_node_t *_find_node(lisp_addr_t *addr) {
    lcaf_addr_t *lcaf;

    switch (lisp_addr_get_afi(addr)) {
        case LM_AFI_IP:
            return(pt_find_ip_node(pt_get_from_afi(lisp_addr_get_ip_afi(addr)), lisp_addr_get_ip(addr)));
        case LM_AFI_IPPREF:
            return(pt_find_ip_node(pt_get_from_afi(lisp_addr_get_ip_afi(addr)), ip_prefix_get_addr(lisp_addr_get_ippref(addr))));
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(addr);
            switch (lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    /* lol ..*/
                    return(pt_find_mc_node(pt_get_from_afi(lcaf_mc_get_afi(lcaf)), lcaf));
                default:
                    lispd_log_msg(LISP_LOG_DEBUG_3, "_find_node: Unsupported LCAF type %d", lcaf_addr_get_type(lcaf));
                    return(NULL);
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_3, "_find_node: Unsupported AFI %d", lisp_addr_get_afi(addr));
    }
    return(NULL);
}

static patricia_node_t *_find_node_exact(lisp_addr_t *addr) {
    lcaf_addr_t *lcaf;

    switch (lisp_addr_get_afi(addr)) {
//        case LM_AFI_IP:
//            return(pt_find_ip_node_exact(pt_get_from_afi(lisp_addr_get_ip_afi(addr)), lisp_addr_get_ip(addr)));
        case LM_AFI_IPPREF:
            return(pt_find_ip_node_exact(pt_get_from_afi(lisp_addr_get_ip_afi(addr)),
                    ip_prefix_get_addr(lisp_addr_get_ippref(addr)), ip_prefix_get_plen(lisp_addr_get_ippref(addr))));
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(addr);
            switch (lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    /* lol ..*/
                    return(pt_find_mc_node_exact(pt_get_from_afi(lcaf_mc_get_afi(lcaf)), lcaf));
                default:
                    lispd_log_msg(LISP_LOG_DEBUG_3, "_find_node_exact: Unsupported LCAF type %d", lcaf_addr_get_type(lcaf));
                    return(NULL);
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_3, "_find_node_exact: Unsupported AFI %d", lisp_addr_get_afi(addr));
            return(NULL);
    }
    return(NULL);
}

static patricia_tree_t *_get_pt_for_addr(lisp_addr_t *addr) {
    switch(lisp_addr_get_afi(addr)) {
    case LM_AFI_IP:
    case LM_AFI_IPPREF:
        return(pt_get_from_afi(lisp_addr_get_ip_afi(addr)));
    case LM_AFI_LCAF:
        switch (lcaf_addr_get_type(lisp_addr_get_lcaf(addr))) {
        case LCAF_MCAST_INFO:
            return(pt_get_from_afi(lcaf_mc_get_afi(lisp_addr_get_lcaf(addr))));
        default:
            lispd_log_msg(LISP_LOG_DEBUG_3, "_find_node_exact: Unsupported LCAF type %d",
                    lcaf_addr_get_type(lisp_addr_get_lcaf(addr)));
            return(NULL);
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_3, "_find_node_exact: Unsupported AFI %d", lisp_addr_get_afi(addr));
        return(NULL);
    }
    return(NULL);
}

static int _add_entry(lisp_addr_t *addr, lispd_map_cache_entry *mce) {
    lcaf_addr_t             *lcaf;
    switch(lisp_addr_get_afi(addr)) {
        case LM_AFI_IP:
        case LM_AFI_IP6:
            lispd_log_msg(LISP_LOG_WARNING, "map_cache_add_mapping: mapping stores an IP not a prefix. It shouldn't!");
            break;
        case LM_AFI_IPPREF:
            return(map_cache_add_ippref_entry(mce, lisp_addr_get_ippref(addr)));
            break;
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(addr);
            switch(lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    return(map_cache_add_mc_entry(mce, lcaf));
                default:
                    lispd_log_msg(LISP_LOG_WARNING, "map_cache_add_mapping: unsupported LCAF type:%u",
                            lcaf_addr_get_type(lcaf));
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_WARNING, "map_cache_add_mapping: called with unknown AFI:%u",
                    lisp_addr_get_afi(addr));
            break;
    }
    return(GOOD);
}

static int _update_mapping_eid(lisp_addr_t *new_eid, lispd_map_cache_entry *mce) {
//    lispd_map_cache_entry   *mce;
//    lcaf_addr_t             *lcaf;
    lisp_addr_t             *old_eid;
    patricia_node_t         *node;

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

    node = _find_node_exact(old_eid);
    /* removes the node from the trie BUT it doesn't free the cache entry */
    patricia_remove(_get_pt_for_addr(old_eid), node);

    mcache_entry_set_eid_addr(mce, new_eid);
    map_cache_add_entry(mce);

    return (GOOD);
}





int mcache_add_mapping(lispd_mapping_elt *mapping) {
    lispd_map_cache_entry   *mce;
    lisp_addr_t             *addr;

    addr = mapping_get_eid_addr(mapping);
    mce = mcache_entry_init(mapping);
    return(_add_entry(addr, mce));
}

int mcache_add_static_mapping(lispd_mapping_elt *mapping) {
    lispd_map_cache_entry   *mce;
    lisp_addr_t             *addr;

    addr = mapping_get_eid_addr(mapping);
    mce = mcache_entry_init_static(mapping);
    return(_add_entry(addr, mce));
}

int mcache_del_mapping(lisp_addr_t *laddr) {
    map_cache_del_entry(laddr);
    return(GOOD);
}

lispd_mapping_elt *mcache_lookup_mapping(lisp_addr_t *laddr) {
    lispd_map_cache_entry *mce;

    mce = map_cache_lookup(laddr);
    return(mcache_entry_get_mapping(mce));
}

lispd_mapping_elt *mcache_lookup_mapping_exact(lisp_addr_t *laddr) {
    lispd_map_cache_entry *mce;

    mce = map_cache_lookup_exact(laddr);
    return(mcache_entry_get_mapping(mce));
}

int mcache_activate_mapping(lisp_addr_t *eid, uint64_t nonce, lispd_locators_list *locators, uint8_t action, uint16_t ttl) {

    lispd_map_cache_entry                   *cache_entry            = NULL;
    uint8_t                                 new_mapping             = FALSE;

    /*
     * Check if the map reply corresponds to a not active map cache
     */
    cache_entry = lookup_nonce_in_no_active_map_caches(lisp_addr_get_afi(eid), nonce);

    if (cache_entry != NULL){
        if (lisp_addr_cmp_for_mcache_install(mapping_get_eid_addr(mcache_entry_get_mapping(cache_entry)), eid) != GOOD) {
//        if (!lisp_addr_cmp_iids(mapping_get_eid_addr(mcache_entry_get_mapping(cache_entry)), eid)) {
//            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  Instance ID of the map reply doesn't match with the inactive map cache entry");
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record: The EID in the Map-Reply does not match the one in the Map-Request!");
            lisp_addr_del(eid);
            return (BAD);
        }
        /*
         * If the eid prefix of the received map reply doesn't match the inactive map cache entry (x.x.x.x/32 or x:x:x:x:x:x:x:x/128),then
         * we remove the inactie entry from the database and store it again with the correct eix prefix (for instance /24).
         */

//        if (map_cache_replace_entry(eid, cache_entry) == BAD){
        if (_update_mapping_eid(eid, cache_entry) == BAD) {
            lisp_addr_del(eid);
            return (BAD);
        }

        cache_entry->active = 1;
        stop_timer(cache_entry->request_retry_timer);
        cache_entry->request_retry_timer = NULL;
        lispd_log_msg(LISP_LOG_DEBUG_2,"Activating map cache entry %s", lisp_addr_to_char(eid));
        lisp_addr_del(eid);
        new_mapping = TRUE;
    }
    /* If the nonce is not found in the no active cache enties, then it should be an active cache entry */
    else {
        /* Serch map cache entry exist*/
        cache_entry = map_cache_lookup_exact(eid);
        if (cache_entry == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  No map cache entry found for %s",
                    lisp_addr_to_char(eid));
            lisp_addr_del(eid);
            return (BAD);
        }
        /* Check if the found map cache entry contains the nonce of the map reply*/
        if (check_nonce(cache_entry->nonces,nonce)==BAD){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  The nonce of the Map-Reply doesn't match the nonce of the generated Map-Request. Discarding message ...");
            lisp_addr_del(eid);
            return (BAD);

        } else {
            free(cache_entry->nonces);
            cache_entry->nonces = NULL;
        }

        /* Stop timer of Map Requests retransmits */
        if (cache_entry->smr_inv_timer != NULL){
            stop_timer(cache_entry->smr_inv_timer);
            cache_entry->smr_inv_timer = NULL;
        }
        /* Check instance id.*/
        if (!lisp_addr_cmp_for_mcache_install(mapping_get_eid_addr(mcache_entry_get_mapping(cache_entry)), eid)) {
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  Instance ID of the map reply doesn't match with the map cache entry");
            lisp_addr_del(eid);
            return (BAD);
        }
        lispd_log_msg(LISP_LOG_DEBUG_2,"  A map cache entry already exists for %s, replacing locators list of this entry",
                lisp_addr_to_char(mapping_get_eid_addr(mcache_entry_get_mapping(cache_entry))));
        free_locator_list(cache_entry->mapping->head_v4_locators_list);
        free_locator_list(cache_entry->mapping->head_v6_locators_list);
        cache_entry->mapping->head_v4_locators_list = NULL;
        cache_entry->mapping->head_v6_locators_list = NULL;
        lisp_addr_del(eid);
    }

    cache_entry->actions = action ;
    cache_entry->ttl = ttl;
    cache_entry->active_witin_period = 1;
    cache_entry->timestamp = time(NULL);
    //locator_count updated when adding the processed locators

//    /* Read the locators */
//    for (ctr=0 ; ctr < record->locator_count ; ctr++){
//        if ((process_map_reply_locator (offset, cache_entry->mapping)) == BAD){
//            return(BAD);
//        }
//    }


    if (locators)
        mapping_add_locators(cache_entry->mapping, locators);


    /* Must free the locators list container.
     * TODO: add locators list directly to the mapping, and within the list
     * split between ipv4 and ipv6 ... and others
     */
    locator_list_free(locators,0);

    /* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
    if (cache_entry->mapping->locator_count != 0){
        calculate_balancing_vectors (
                cache_entry->mapping,
                &(((rmt_mapping_extended_info *)cache_entry->mapping->extended_info)->rmt_balancing_locators_vecs));
    }

    /*
     * Reprogramming timers
     */
    /* Expiration cache timer */
    if (!cache_entry->expiry_cache_timer){
        cache_entry->expiry_cache_timer = create_timer (EXPIRE_MAP_CACHE_TIMER);
    }
    start_timer(cache_entry->expiry_cache_timer, cache_entry->ttl*60, (timer_callback)map_cache_entry_expiration,
                     (void *)cache_entry);
    lispd_log_msg(LISP_LOG_DEBUG_1,"The map cache entry %s will expire in %d minutes.",
            lisp_addr_to_char(mapping_get_eid_addr(mcache_entry_get_mapping(cache_entry))), cache_entry->ttl);

    /* RLOC probing timer */
    if (new_mapping == TRUE && RLOC_PROBING_INTERVAL != 0){
        programming_rloc_probing(cache_entry);
    }

    map_cache_dump_db(LISP_LOG_DEBUG_3);

    return (GOOD);
}








/* NOTE
 * The following functions require that their callers know what a map_cache_entry element is.
 * This is too much detail to be exposed so it is advisable to use the functions above.
 */




int map_cache_add_entry(lispd_map_cache_entry *entry){
    return(_add_entry(mapping_get_eid_addr(mcache_entry_get_mapping(entry)), entry));
}

int map_cache_add_ippref_entry(void *entry, ip_prefix_t *ippref) {

    if (pt_add_ippref(pt_get_from_afi(ip_prefix_get_afi(ippref)), ippref, entry) != GOOD){
        lispd_log_msg(LISP_LOG_WARNING, "map_cache_add_ippref_entry: Attempting to "
                "insert (%s) in the map-cache but couldn't add the entry to the pt!",
                ip_prefix_to_char(ippref));
        return(BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_2, "map_cache_add_ippref_entry: Added map cache data for %s",
                ip_prefix_to_char(ippref));
    return(GOOD);
}

int map_cache_add_mc_entry(void *entry, lcaf_addr_t *mcaddr) {
    lisp_addr_t         *src            = NULL;
    ip_addr_t           *srcip          = NULL;

    src = lcaf_mc_get_src(mcaddr);
    srcip = lisp_addr_get_ip(src);

    if (pt_add_mc_addr(pt_get_from_afi(ip_addr_get_afi(srcip)), mcaddr, entry) != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "map_cache_add_mc_entry: Attempting to "
                "insert %s to map cache but failed! ", mc_type_to_char(mcaddr));
        return(BAD);
    }

    return(GOOD);
}

void map_cache_del_entry(lisp_addr_t *laddr)
{
    /* TODO: support removal of mcast channel from prefix */
    lcaf_addr_t *lcaf;


    switch(lisp_addr_get_afi(laddr)){
        case LM_AFI_IPPREF:
            map_cache_del_ippref_entry(lisp_addr_get_ippref(laddr));
            break;
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(laddr);
            switch(lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    /* hack to avoid supporting group prefix in del_map_cache_entry_from_db */
            //        gplen = (ip_addr_get_afi(lisp_addr_get_mc_grp(laddr)) == AF_INET) ? 32 : 128;
                    map_cache_del_mc_entry(lcaf);
                    break;
                default:
                    lispd_log_msg(LISP_LOG_WARNING, "del_map_cache_entry_from_db: called with unknown LCAF type:%u",
                            lcaf_addr_get_type(lcaf));
                    break;
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_WARNING, "del_map_cache_entry_from_db: called with unknown AFI:%u",
                    lisp_addr_get_afi(laddr));
            break;
    }

}

int map_cache_del_ippref_entry(ip_prefix_t *ippref)
{
    pt_remove_ippref(pt_get_from_afi(ip_prefix_get_afi(ippref)), ippref);
    return(GOOD);

}

int map_cache_del_mc_entry(lcaf_addr_t *mcaddr)
{
    ip_addr_t               *srcip    = NULL;

    if (lisp_addr_get_afi(lcaf_mc_get_src(mcaddr)) != LM_AFI_IP || lisp_addr_get_afi(lcaf_mc_get_grp(mcaddr)) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "map_cache_del_entry_mc: Multicast address %s has either source or group not IP! Discarding ..",
                lcaf_addr_to_char(mcaddr));
        return(BAD);
    }

    srcip = lisp_addr_get_ip(lcaf_mc_get_src(mcaddr));

    if(pt_remove_mc_addr(pt_get_from_afi(ip_addr_get_afi(srcip)), mcaddr) != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "map_cache_del_entry_mc: Could not delete multicast addr %s",
                lcaf_addr_to_char(mcaddr));
        return(BAD);
    }

    return (GOOD);
}













/*
 * Look up a given lisp_addr_t in the database, returning the
 * lispd_map_cache_entry of this lisp_addr_t if it exists or NULL.
 */
lispd_map_cache_entry *map_cache_lookup(lisp_addr_t *laddr)
{
    lcaf_addr_t     *lcaf   = NULL;

    switch(lisp_addr_get_afi(laddr)) {
        case LM_AFI_IP:
        case LM_AFI_IP6:
            return(map_cache_lookup_ip(lisp_addr_get_ip(laddr)));
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(laddr);
            switch (lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    return(map_cache_lookup_mc(lcaf));
                    break;
                default:
                    lispd_log_msg(LISP_LOG_WARNING, "map_cache_lookup: Unknown LCAF type %u",
                            lisp_addr_get_afi(laddr));
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_WARNING, "map_cache_lookup: unsupported AFI %d", lisp_addr_get_afi(laddr));
            break;
    }

    return(NULL);
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
lispd_map_cache_entry *map_cache_lookup_exact(lisp_addr_t *laddr)
{
    lcaf_addr_t     *lcaf = NULL;

    switch(lisp_addr_get_afi(laddr)){
        case LM_AFI_IP:
        case LM_AFI_IP6:
            lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_map_cache_exact: called with IP  %s instead of a prefix!",
                            lisp_addr_to_char(laddr));
            break;
        case LM_AFI_IPPREF:
            return(map_cache_lookup_ippref(lisp_addr_get_ippref(laddr)));
            break;
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(laddr);
            switch (lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    return(map_cache_lookup_mc_exact(lcaf));
                    break;
                default:
                    lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_map_cache_exact: Unknown LCAF type %u",
                            lisp_addr_get_afi(laddr));
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_map_cache_exact: Unknown AFI %u",
                    lcaf_addr_get_type(lisp_addr_get_lcaf(laddr)));
            return(NULL);
            break;
    }

    return(NULL);
}


lispd_map_cache_entry *map_cache_lookup_ip(ip_addr_t *ipaddr) {

    void *data;

    data = pt_lookup_ip(pt_get_from_afi(ip_addr_get_afi(ipaddr)), ipaddr);
    if (!data) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "map_cache_lookup_ip: The entry %s was"
                " not found in the map cache", ip_addr_to_char(ipaddr));
        return(NULL);
    }

    return((lispd_map_cache_entry *)data);
}

lispd_map_cache_entry *map_cache_lookup_ippref(ip_prefix_t *ippref) {

    void *data;

    data = pt_lookup_ippref(pt_get_from_afi(ip_prefix_get_afi(ippref)), ippref);
    if (!data) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "map_cache_lookup_ippref: The entry %s was"
                " not found in the map cache", ip_prefix_to_char(ippref));
        return(NULL);
    }

    return((lispd_map_cache_entry *)data);
}

/*
 * Look up a given mc eid in the database. Return the
 * associated lispd_map_cache_entry if it exists or NULL otherwise.
 */
lispd_map_cache_entry *map_cache_lookup_mc(lcaf_addr_t *mcaddr) {
    /* fcoras: this piggybacks the unicast lookup.
     * TODO: If a smarter search/data structure  will be used in the future
     * for multicast, change here!
     */

    ip_addr_t           *srcip          = NULL;
    void                *data           = NULL;

    srcip = lisp_addr_get_ip(lcaf_mc_get_src(mcaddr));
    data = pt_lookup_mc_addr_exact(pt_get_from_afi(ip_addr_get_afi(srcip)), mcaddr);

    if(!data)
        return(NULL);
    else
        return( (lispd_map_cache_entry *)data);

}

lispd_map_cache_entry *map_cache_lookup_mc_exact(lcaf_addr_t *mcaddr) {
    /* fcoras: this piggybacks the unicast lookup.
     * TODO: If a smarter search/data structure  will be used in the future
     * for multicast, change here!
     */

    ip_addr_t           *srcip          = NULL;
    void                *data           = NULL;

    srcip = lisp_addr_get_ip(lcaf_mc_get_src(mcaddr));
    data = pt_lookup_mc_addr_exact(pt_get_from_afi(ip_addr_get_afi(srcip)), mcaddr);

    if(!data)
        return(NULL);
    else
        return( (lispd_map_cache_entry *)data);

}



/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(
        uint16_t    eid_afi,
        uint64_t    nonce)
{
    patricia_tree_t         *tree;
    patricia_node_t         *node;
    lispd_map_cache_entry   *entry;

    tree = pt_get_from_afi(eid_afi);

    PATRICIA_WALK(tree->head, node) {
        entry = ((lispd_map_cache_entry *)(node->data));
        if (entry->active == FALSE){
            if (check_nonce(entry->nonces,nonce) == GOOD){
                free(entry->nonces);
                entry->nonces = NULL;
                return(entry);
            }
        }
    } PATRICIA_WALK_END;

    return (NULL);
}



/*
 * Remove the map cache entry from the database and reintroduce it with the new eid.
 * This function is used when the map reply report a prefix that includes the requested prefix.
 */

int map_cache_replace_entry(
        lisp_addr_t             *new_addr,
        lispd_map_cache_entry   *centry)
{
    lisp_addr_t             *old_eid_addr;

    /* Get the node to be modified from the database
     * NOTE: This works assuming that both mc and ip addresses
     * are stored in the same pt. Also, mc prefix length is set
     * be S prefix length. */

    old_eid_addr = mapping_get_eid_addr(mcache_entry_get_mapping(centry));

    lispd_log_msg(LISP_LOG_DEBUG_2,"EID prefix of the map cache entry %s will be changed to %s",
            lisp_addr_to_char(old_eid_addr), lisp_addr_to_char(new_addr));




//    map_cache_del_entry(old_eid_addr);

//    mcache_entry_set_eid_addr(centry, new_addr);

    if ((err=map_cache_add_entry(centry))!= GOOD){
        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
        lispd_log_msg(LISP_LOG_DEBUG_2,"change_eid_prefix_in_db: Couldn't change EID prefix of the inactive "
                "map cache entry (%s -> %s). Releasing it",
                lisp_addr_to_char(old_eid_addr),
                lisp_addr_to_char(new_addr));
        free_map_cache_entry(centry);
        return (BAD);
    }
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
    lispd_map_cache_entry   *entry      = NULL;
    lispd_mapping_elt       *mapping    = NULL;
    lisp_addr_t             *addr       = NULL;
    uint8_t                 plen        = 0;

    entry = (lispd_map_cache_entry *)arg;
    mapping = mcache_entry_get_mapping(entry);
    addr = mapping_get_eid_addr(mapping);
    lispd_log_msg(LISP_LOG_DEBUG_1,"Got expiration for EID",
            lisp_addr_to_char(addr), plen);

    map_cache_del_entry(addr);
}

/*
 * dump_map_cache
 */
void map_cache_dump_db(int log_level)
{
    patricia_tree_t     *dbs [2] = {AF4_map_cache, AF6_map_cache};
    int                 ctr;

    patricia_node_t             *node;
    patricia_node_t             *mnode;
    lispd_map_cache_entry       *entry;
    lispd_map_cache_entry       *mentry;


    lispd_log_msg(log_level,"**************** LISP Mapping Cache ******************\n");

    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(dbs[ctr]->head, node) {
            entry = ((lispd_map_cache_entry *)(node->data));
            dump_map_cache_entry (entry, log_level);

            /* dump multicast also */
            if (node->mc_data){
                lispd_log_msg(log_level, "======= Start Multicast =======\n");
                PATRICIA_WALK( ((patricia_tree_t *)node->mc_data)->head, mnode){
                    mentry = ((lispd_map_cache_entry *)mnode->data);
                    dump_map_cache_entry(mentry, log_level);
                } PATRICIA_WALK_END;
                dump_map_cache_entry(entry, log_level);
                lispd_log_msg(log_level, "======= End Multicast =======\n");
            }
        } PATRICIA_WALK_END;
    }
    lispd_log_msg(log_level,"*******************************************************\n");
}





/*
 * Patricia trie specific functions
 */



/* interface to insert entries into patricia */
int pt_add_ippref(patricia_tree_t *pt, ip_prefix_t *ippref, void *data) {
    patricia_node_t *node       = NULL;

    node = pt_add_node(pt, ip_prefix_get_addr(ippref), ip_prefix_get_plen(ippref), data);

    if (!node)
        return(BAD);
    else
        return(GOOD);

}

int pt_remove_ippref(patricia_tree_t *pt, ip_prefix_t *ippref) {
    patricia_node_t         *node   = NULL;
    patricia_tree_t         *entry  = NULL;

    node = pt_find_ip_node_exact(pt, ip_prefix_get_addr(ippref), ip_prefix_get_plen(ippref));

    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3,"pt_remove_ip_addr: Unable to locate cache entry %s for deletion",
                ip_prefix_to_char(ippref));
        return(BAD);
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_3,"pt_remove_ip_addr: Deleting map cache entry: %s",
                ip_prefix_to_char(ippref));
    }

    /* free the cache entry */
    free_map_cache_entry((lispd_map_cache_entry *)node->data);

    /* remove node only if it has no multicast data */
    if (!(entry = node->mc_data))
        patricia_remove(pt, node);

    return(GOOD);
}

int pt_update_ippref(patricia_tree_t *pt, ip_prefix_t *ippref, void *data) {
    patricia_node_t *node = NULL;
    lispd_log_msg(LISP_LOG_DEBUG_2,"Updating mapping cache entry for %s", ip_prefix_to_char(ippref));
    node = pt_find_ip_node_exact(pt, ip_prefix_get_addr(ippref), ip_prefix_get_plen(ippref));
    if (!node)
        return(BAD);

    node->data = data;
    return(GOOD);
}


int pt_add_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr, void *data) {
    patricia_node_t     *snode          = NULL;
    patricia_node_t     *gnode          = NULL;
    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;
    uint8_t             splen, gplen;


    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

    srcip = lisp_addr_get_ip(src);
    grpip = lisp_addr_get_ip(grp);

    splen = lcaf_mc_get_src_plen(mcaddr);
    gplen = lcaf_mc_get_grp_plen(mcaddr);

    if (ip_addr_get_afi(srcip) != LM_AFI_IP || ip_addr_get_afi(grpip) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_WARNING, "pt_add_mc_addr: only IP type supported for S and G for now!");
        return(BAD);
    }

    /* insert src prefix in main db but without any data*/
    snode = pt_add_mc_node(pt, srcip, splen);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_mc_addr: Attempting to "
                "insert S-EID %s/%d in pt but failed", ip_addr_to_char(srcip), splen);
        return(BAD);
    }

    /* insert the G in the user1 field of the unicast pt node */
    if(!snode->mc_data){
        /* create the patricia if not initialized */
        snode->mc_data = (patricia_tree_t *)New_Patricia(ip_addr_get_size(grpip) * 8);

        if (!snode->mc_data){
            lispd_log_msg(LISP_LOG_WARNING, "pt_add_mc_addr: Can't create group pt!");
            return(BAD);
        }
    }

    /* insert grp in node->user1 db with the entry*/
    gnode = pt_add_node((patricia_tree_t *)snode->mc_data, grpip, gplen, data);
    if (gnode == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Attempting to "
                "insert G %s/%d in the group pt but failed! ", ip_addr_to_char(grpip), gplen);
        return(BAD);
    }

    return(GOOD);
}

int pt_remove_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr) {
    patricia_node_t     *snode          = NULL;
    patricia_node_t     *gnode          = NULL;
    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;
    uint8_t             splen, gplen;

    patricia_tree_t         *strie  = NULL;
    patricia_tree_t         *gtrie  = NULL;

    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

    srcip = lisp_addr_get_ip(src);
    grpip = lisp_addr_get_ip(grp);

    splen = lcaf_mc_get_src_plen(mcaddr);
    gplen = lcaf_mc_get_grp_plen(mcaddr);

    strie = pt_get_from_afi(ip_addr_get_afi(srcip));

    snode = pt_find_ip_node_exact(strie, srcip, splen);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_remove_mc_addr: The source "
                "prefix %s/%d does not exist in the map cache",
                ip_addr_to_char(srcip), splen);
        return(BAD);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->mc_data;
    if (!gtrie){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_remove_mc_addr: The source  "
                "prefix %s/%d does not have a multicast particia trie "
                "associated", ip_addr_to_char(srcip), splen);
        return(BAD);
    }

    gnode = pt_find_ip_node_exact(gtrie, grpip, gplen);

    if (!gnode){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_remove_mc_addr: The group prefix"
                "%s/%d does not have a multicast map cache entry associated",
                ip_addr_to_char(grpip), gplen);
        return(BAD);
    } else {
        free_map_cache_entry((lispd_map_cache_entry *)gnode->data);
        patricia_remove(gtrie, gnode);

        /* remove strie entry if both gtrie and strie are empty */
        if(pt_test_if_empty(gtrie)){
            Destroy_Patricia(gtrie, free_map_cache_entry);
            if (snode->data == NULL)
                patricia_remove(strie, snode);
        }
    }

    return(GOOD);

}

int pt_update_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr, void *data) {
    patricia_node_t *node = NULL;

    node = pt_lookup_mc_addr_exact(pt, mcaddr);
    if (!node)
        return(BAD);

    node->data = data;
    return(GOOD);
}


patricia_node_t *pt_add_node(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen, void *data) {
    patricia_node_t *node;
    prefix_t        *prefix;

    prefix = pt_make_ip_prefix(ipaddr, prefixlen);
    node = patricia_lookup(pt, prefix);
    Deref_Prefix(prefix);

    /* node already exists */
    if (node->data){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_node: Trying to overwrite a pt entry!");
        return(NULL);
    }

    node->data = data;
    return(node);
}

patricia_node_t *pt_add_mc_node(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen) {
    patricia_node_t *node;
    prefix_t        *prefix;

    prefix = pt_make_ip_prefix(ipaddr, prefixlen);
    node = patricia_lookup(pt, prefix);
    Deref_Prefix(prefix);

    return(node);
}

//void pt_remove_node(patricia_tree_t *pt, patricia_node_t *node) {
//    lispd_map_cache_entry   *entry  = NULL;
//
//    /* unicast */
//    entry = ((lispd_map_cache_entry *)node->data);
//    free_map_cache_entry(entry);
//
//    /* multicast */
//    if ((entry = node->mc_data))
//        Destroy_Patricia((patricia_tree_t *)entry, free_map_cache_entry);
//
//    patricia_remove(pt, node);
//}


patricia_node_t *pt_find_ip_node(patricia_tree_t *pt, ip_addr_t *ipaddr) {
    patricia_node_t *node;
    prefix_t        *prefix;
    uint8_t         default_plen;

    default_plen = (ip_addr_get_afi(ipaddr) == AF_INET) ? 32: 128;
    prefix = pt_make_ip_prefix(ipaddr, default_plen);
    node =  patricia_search_best(pt, prefix);
    Deref_Prefix(prefix);

    return(node);
}

patricia_node_t *pt_find_ip_node_exact(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen) {
    patricia_node_t *node;
    prefix_t        *prefix;

    prefix = pt_make_ip_prefix(ipaddr, prefixlen);
    node = patricia_search_exact(pt, prefix);
    Deref_Prefix(prefix);

    return(node);
}

patricia_node_t *pt_find_mc_node(patricia_tree_t *pt, lcaf_addr_t *mcaddr) {
    patricia_node_t     *snode          = NULL;
    patricia_node_t     *gnode          = NULL;
    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;
    uint8_t             splen;

    patricia_tree_t         *strie  = NULL;
    patricia_tree_t         *gtrie  = NULL;

    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

    srcip = lisp_addr_get_ip(src);
    grpip = lisp_addr_get_ip(grp);

    splen = lcaf_mc_get_src_plen(mcaddr);

    if (ip_addr_get_afi(srcip) != LM_AFI_IP || ip_addr_get_afi(grpip) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_WARNING, "pt_lookup_mc_addr_exact: only IP type supported for S and G for now!");
        return(BAD);
    }

    strie = pt_get_from_afi(ip_addr_get_afi(srcip));

    snode = pt_lookup_ip(strie, srcip);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr_exact: The source "
                "prefix %s/%d does not exist in the map cache",
                ip_addr_to_char(srcip), splen);
        return(NULL);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->mc_data;
    if (!gtrie){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr_exact: The source  "
                "prefix %s/%d does not have a multicast particia trie "
                "associated", ip_addr_to_char(srcip), splen);
        return(NULL);
    }

    gnode = pt_lookup_ip(gtrie, grpip);

    return(gnode);
}

patricia_node_t *pt_find_mc_node_exact(patricia_tree_t *pt, lcaf_addr_t *mcaddr) {
    patricia_node_t     *snode          = NULL;
    patricia_node_t     *gnode          = NULL;
    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;
    uint8_t             splen, gplen;

    patricia_tree_t         *strie  = NULL;
    patricia_tree_t         *gtrie  = NULL;

    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

    srcip = lisp_addr_get_ip(src);
    grpip = lisp_addr_get_ip(grp);

    splen = lcaf_mc_get_src_plen(mcaddr);
    gplen = lcaf_mc_get_grp_plen(mcaddr);

    if (ip_addr_get_afi(srcip) != LM_AFI_IP || ip_addr_get_afi(grpip) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_WARNING, "pt_lookup_mc_addr_exact: only IP type supported for S and G for now!");
        return(BAD);
    }

    strie = pt_get_from_afi(ip_addr_get_afi(srcip));

    snode = pt_lookup_ip_exact(strie, srcip, splen);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr_exact: The source "
                "prefix %s/%d does not exist in the map cache",
                ip_addr_to_char(srcip), splen);
        return(NULL);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->mc_data;
    if (!gtrie){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr_exact: The source  "
                "prefix %s/%d does not have a multicast particia trie "
                "associated", ip_addr_to_char(srcip), splen);
        return(NULL);
    }

    gnode = pt_lookup_ip_exact(gtrie, grpip, gplen);

    return(gnode);
}

void *pt_lookup_ip(patricia_tree_t *pt, ip_addr_t *ipaddr) {
    patricia_node_t     *node   = NULL;

    node = pt_find_ip_node(pt, ipaddr);

    if (!node)
        return(NULL);
    else
        return(node->data);
}

void *pt_lookup_ip_exact(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t plen) {
    patricia_node_t     *node   = NULL;

    node = pt_find_ip_node_exact(pt, ipaddr, plen);

    if (!node)
        return(NULL);

    return(node->data);
}

void *pt_lookup_ippref(patricia_tree_t *pt, ip_prefix_t *ippref) {
    return(pt_lookup_ip_exact(pt, ip_prefix_get_addr(ippref), ip_prefix_get_plen(ippref)));
}

void *pt_lookup_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr) {
    lispd_log_msg(LISP_LOG_DEBUG_3, "pt_lookup_mc_addr_exact: (S-prefix, G-prefix) support is not implemented!");
    return(NULL);
}

void *pt_lookup_mc_addr_exact(patricia_tree_t *pt, lcaf_addr_t *mcaddr) {

    patricia_node_t *node;
    node = pt_find_mc_node_exact(pt, mcaddr);
    if (!node){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr_exact: The group prefix"
                "%s/%d does not have a multicast map cache entry associated",
                lcaf_addr_to_char(mcaddr));
        return(NULL);
    }
    return(node->data);
}

uint8_t pt_test_if_empty(patricia_tree_t *pt) {
    assert(pt);
    if (pt->num_active_node > 0)
        return(1);
    else
        return(0);
}

/*
 * Return map cache data base
 */
patricia_tree_t *pt_get_from_afi(ip_afi_t afi) {
    patricia_tree_t *pt = NULL;
    switch(afi) {
        case AF_INET:
            pt = AF4_map_cache;
            break;
        case AF_INET6:
            pt = AF6_map_cache;
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_1,"get_db_from_afi: AFI %u not recognized!", afi);
            break;
    }

    return(pt);
}

prefix_t *pt_make_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen) {
    ip_afi_t        afi         = 0;
    prefix_t        *prefix     = NULL;

    afi = ip_addr_get_afi(ipaddr);

    if (afi != AF_INET && afi != AF_INET6) {
        lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unsupported afi %s", afi);
        return(NULL);
    }

    (afi == AF_INET) ? assert(prefixlen <= 32) : assert(prefixlen <= 128);
    prefix = New_Prefix(afi, ip_addr_get_addr(ipaddr), prefixlen);
    if (!prefix) {
        lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unable to allocate memory for prefix %s: %s",
                ip_addr_to_char(ipaddr), strerror(errno));
        return(NULL);
    }

    return(prefix);
}

