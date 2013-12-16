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

int                         map_cache_del_ip_entry(ip_prefix_t *ippref);
int                         map_cache_del_mc_entry(mc_t *mcaddr);
int                         map_cache_add_ip_entry(void *entry, ip_prefix_t *ippref);
int                         map_cache_add_mc_entry(void *entry, mc_t *addr);
lispd_map_cache_entry       *map_cache_lookup_ip(ip_addr_t *ipaddr, uint8_t prefixlen);
lispd_map_cache_entry       *map_cache_lookup_mc(mc_t *mcaddr);

int                         pt_add_ip_addr(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen, void *data);
void                        *pt_lookup_ip_addr(patricia_tree_t *pt, ip_addr_t *addr, uint8_t prefixlen);
int                         pt_remove_ip_addr(patricia_tree_t *pt, ip_addr_t *addr, uint8_t prefixlen);

int                         pt_add_mc_addr(patricia_tree_t *pt, ip_addr_t *src, uint8_t splen, ip_addr_t *grp, uint8_t gplen, void *data);
void                        *pt_lookup_mc_addr(patricia_tree_t *pt, ip_addr_t *src, uint8_t splen, ip_addr_t *grp, uint8_t gplen);
int                         pt_remove_mc_addr(patricia_tree_t *pt, ip_addr_t *src, uint8_t splen, ip_addr_t *grp, uint8_t gplen);

patricia_node_t             *pt_add_entry(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen);
patricia_node_t             *pt_lookup_entry(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen);
void                        pt_remove_entry(patricia_tree_t *pt, patricia_node_t *node);

uint8_t                     pt_test_if_empty(patricia_tree_t *pt);
prefix_t                    *make_pt_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen);

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

patricia_tree_t* get_map_cache_db(lm_afi_t afi){
    lispd_log_msg(LISP_LOG_INFO, "In get_map_cache_db: This function shouldn't be called from outside! Don't know why it existed!");
    return(NULL);
}

/*
 *  Add a map cache entry to the database.
 */

int map_cache_add_entry(lispd_map_cache_entry *entry){
    lispd_mapping_elt       *mapping    = NULL;
    lisp_addr_t             *addr       = NULL;
    lcaf_addr_t             *lcaf       = NULL;

    mapping = mcache_entry_get_mapping(entry);
    addr = mapping_get_eid_addr(mapping);

    switch(lisp_addr_get_afi(addr)) {
        case LM_AFI_IP:
        case LM_AFI_IP6:
            return(map_cache_add_ip_entry(entry, lisp_addr_get_ippref(addr)));
            break;
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(addr);
            switch(lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    return(map_cache_add_mc_entry(entry, lcaf_addr_get_mc(lcaf)));
                default:
                    lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_to_db: unknown LCAF type:%u",
                            lcaf_addr_get_type(lcaf));
            }
            return(map_cache_add_mc_entry(entry, lcaf_addr_get_mc(lcaf)));
            break;
        default:
            lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_to_db: called with unknown AFI:%u",
                    lisp_addr_get_afi(addr));
            break;
    }

    return(GOOD);

}

int map_cache_add_ip_entry(void *entry, ip_prefix_t *ippref) {

    if (pt_add_ip_addr(
            pt_get_from_afi(ip_prefix_get_afi(ippref)),
            ip_prefix_get_addr(ippref),
            ip_prefix_get_plen(ippref),
            entry) != GOOD){
        lispd_log_msg(LISP_LOG_WARNING, "map_cache_add_ip_entry: Attempting to "
                "insert (%s) in the map-cache but couldn't add the entry to the pt!",
                ip_prefix_to_char(ippref));
        return(BAD);
    }

    return(GOOD);
}

int map_cache_add_mc_entry(void *entry, mc_t *mcaddr) {

    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;

    src = mc_type_get_src(mcaddr);
    grp = mc_type_get_grp(mcaddr);

    srcip = lisp_addr_get_ip(src);
    grpip = lisp_addr_get_ip(grp);

    if (ip_addr_get_afi(srcip) != LM_AFI_IP || ip_addr_get_afi(grpip) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: only IP type supported for S and G for now!");
        return(BAD);
    }

    if (pt_add_mc_addr(
            pt_get_from_afi(ip_addr_get_afi(srcip)),
            srcip, mc_type_get_src_plen(mcaddr), grpip,
            mc_type_get_grp_plen(mcaddr),
            entry) != GOOD) {
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
    case LM_AFI_IP:
    case LM_AFI_IP6:
        map_cache_del_ip_entry(lisp_addr_get_ippref(laddr));
        break;
    case LM_AFI_LCAF:
        lcaf = lisp_addr_get_lcaf(laddr);
        switch(lcaf_addr_get_type(lcaf)) {
            case LCAF_MCAST_INFO:
                /* hack to avoid supporting group prefix in del_map_cache_entry_from_db */
        //        gplen = (ip_addr_get_afi(lisp_addr_get_mc_grp(laddr)) == AF_INET) ? 32 : 128;
                map_cache_del_mc_entry(lcaf_addr_get_mc(lcaf));
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

/*
 * del_map_cache_entry()
 *
 * Delete an EID mapping from the cache
 */

int map_cache_del_ip_entry(ip_prefix_t *ippref)
{

    pt_remove_ip_addr(
                pt_get_from_afi(ip_prefix_get_afi(ippref)),
                ip_prefix_get_addr(ippref),
                ip_prefix_get_plen(ippref));
    return(GOOD);

}

int map_cache_del_mc_entry(mc_t *mcaddr)
{
    ip_addr_t               *src    = NULL;
    ip_addr_t               *grp    = NULL;
    uint8_t                 splen, gplen;

    if (lisp_addr_get_afi(mc_type_get_src(mcaddr)) != LM_AFI_IP || lisp_addr_get_afi(mc_type_get_grp(mcaddr)) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "map_cache_del_entry_mc: Multicast address %s has either source or group not IP! Discarding ..",
                mc_type_to_char(mcaddr));
        return(BAD);
    }

    src = lisp_addr_get_ip(mc_type_get_src(mcaddr));
    grp = lisp_addr_get_ip(mc_type_get_grp(mcaddr));
    splen = mc_type_get_src_plen(mcaddr);
    gplen = mc_type_get_grp_plen(mcaddr);

    if(pt_remove_mc_addr(pt_get_from_afi(ip_addr_get_afi(src)), src, splen, grp, gplen) != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "map_cache_del_entry_mc: Could not delete multicast addr %s",
                mc_type_to_char(mcaddr));
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
    ip_prefix_t     *pref = NULL;
    lcaf_addr_t     *lcaf = NULL;

    switch(lisp_addr_get_afi(laddr)) {
        case LM_AFI_IP:
        case LM_AFI_IP6:
            pref = lisp_addr_get_ippref(laddr);
            return(map_cache_lookup_ip(ip_prefix_get_addr(pref), (ip_prefix_get_afi(pref) == AF_INET) ? 32: 128));
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(laddr);
            switch (lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    return(map_cache_lookup_mc(lcaf_addr_get_mc(lcaf)));
                    break;
                default:
                    lispd_log_msg(LISP_LOG_WARNING, "lookup_map_cache_exact: Unknown LCAF type %u",
                            lisp_addr_get_afi(laddr));
            }
            break;
        default:
            break;
    }

    return(NULL);
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
lispd_map_cache_entry *map_cache_lookup_exact(lisp_addr_t *laddr)
{
    ip_prefix_t     *pref = NULL;
    lcaf_addr_t     *lcaf = NULL;

    switch(lisp_addr_get_afi(laddr)){
        case LM_AFI_IP:
        case LM_AFI_IP6:
            pref = lisp_addr_get_ippref(laddr);
            return(map_cache_lookup_ip(ip_prefix_get_addr(pref), ip_prefix_get_plen(pref)));
            break;
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(laddr);
            switch (lcaf_addr_get_type(lcaf)) {
                case LCAF_MCAST_INFO:
                    return(map_cache_lookup_mc(lcaf_addr_get_mc(lcaf)));
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

/*
 * Look up a given ip eid in the database, returning the
 * lispd_map_cache_entry of this eid if it exists or NULL.
 */
lispd_map_cache_entry *map_cache_lookup_ip(ip_addr_t *ipaddr, uint8_t prefixlen) {

    void *data;

    data = pt_lookup_ip_addr(pt_get_from_afi(ip_addr_get_afi(ipaddr)),ipaddr, prefixlen);

    if (!data) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "pt_lookup_ip_addr: The entry %s/%d was"
                " not found in the map cache", ip_addr_to_char(ipaddr), prefixlen);
        return(NULL);
    }

    return((lispd_map_cache_entry *)data);
}

/*
 * Look up a given mc eid in the database. Return the
 * associated lispd_map_cache_entry if it exists or NULL otherwise.
 */
lispd_map_cache_entry *map_cache_lookup_mc(mc_t *mcaddr) {
    /* fcoras: this piggybacks the unicast lookup.
     * TODO: If a smarter search/data structure  will be used in the future
     * for multicast, change here!
     */

    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;
    void                *data           = NULL;

    src = mc_type_get_src(mcaddr);
    grp = mc_type_get_grp(mcaddr);

    srcip = lisp_addr_get_ip(src);
    grpip = lisp_addr_get_ip(grp);

    if (ip_addr_get_afi(srcip) != LM_AFI_IP || ip_addr_get_afi(grpip) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: only IP type supported for S and G for now!");
        return(BAD);
    }

    data = pt_lookup_mc_addr(
            pt_get_from_afi(ip_addr_get_afi(srcip)),
            srcip,
            mc_type_get_src_plen(mcaddr),
            grpip,
            mc_type_get_grp_plen(mcaddr));

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
                return (entry);
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
    map_cache_del_entry(old_eid_addr);

    mcache_entry_set_eid_addr(centry, new_addr);


    if ((err=map_cache_add_entry(centry))!= GOOD){
        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
        lispd_log_msg(LISP_LOG_DEBUG_2,"change_eid_prefix_in_db: Couldn't change EID prefix of the inactive "
                "map cache entry (%s -> %s). Releasing it",
                lisp_addr_to_char(old_eid_addr),
                lisp_addr_to_char(new_addr));
        free_map_cache_entry(centry);
        return (BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_2,"EID prefix of the map cache entry %s changed to %s.",
            lisp_addr_to_char(old_eid_addr),
            lisp_addr_to_char(new_addr));
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
int pt_add_ip_addr(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen, void *data) {
    patricia_node_t *node       = NULL;

    node = pt_add_entry(pt, ipaddr, prefixlen);

    node->data = data;
    lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_ip_addr: Added map cache data for %s/%d",
            ip_addr_to_char(ipaddr), prefixlen);

    return(GOOD);

}


void *pt_lookup_ip_addr(patricia_tree_t *pt, ip_addr_t *addr, uint8_t prefixlen){

    patricia_node_t     *node   = NULL;
    prefix_t            *prefix;

    prefix = New_Prefix(ip_addr_get_afi(addr), ip_addr_get_addr(addr), prefixlen);
//    switch(ip_addr_get_afi(addr)) {
//    case AF_INET:
//        assert(prefixlen <= 32);
//        prefix = New_Prefix(AF_INET, ip_addr_get_v4(addr), (prefixlen) ? prefixlen: 32);
//        break;
//    case AF_INET6:
//        assert(prefixlen <=128);
//        prefix = New_Prefix(AF_INET6, ip_addr_get_v6(addr), (prefixlen) ? prefixlen: 128);
//        break;
//    default:
//        lispd_log_msg(LISP_LOG_DEBUG_1, "lookup_map_cache_node: Unknown afi %d!", ip_addr_get_afi(addr) );
//        return(NULL);
//    }

    if (!prefix){
        lispd_log_msg(LISP_LOG_DEBUG_1, "pt_lookup_ip_addr: Couldn't allocate prefix!");
        return(NULL);
    }

    node = (prefixlen) ? patricia_search_exact(pt, prefix) : patricia_search_best(pt, prefix);
    Deref_Prefix(prefix);

    if (!node)
        return(NULL);
    else
        return(node->data);
}

int pt_remove_ip_addr(patricia_tree_t *pt, ip_addr_t *addr, uint8_t prefixlen) {
    patricia_node_t         *node   = NULL;

    node = pt_lookup_entry(pt, addr, prefixlen);

    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"pt_remove_ip_addr: Unable to locate cache entry %s/%d for deletion",
                ip_addr_to_char(addr), prefixlen);
        return(BAD);
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"pt_remove_ip_addr: Deleting map cache entry: %s/%d",
                ip_addr_to_char(addr), prefixlen);
    }

    /* Avoid removing nodes that still have multicast mappings */
    if (!node->mc_data)
        pt_remove_entry(pt, node);
    else
        free_map_cache_entry((lispd_map_cache_entry *)node->data);

    return(GOOD);
}


int pt_add_mc_addr(patricia_tree_t *pt, ip_addr_t *src, uint8_t splen, ip_addr_t *grp, uint8_t gplen, void *data) {
    patricia_node_t     *snode          = NULL;
    patricia_node_t     *gnode          = NULL;


    /* insert src prefix in main db but without any data*/
    snode = pt_add_entry(pt, src, splen);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_mc_addr: Attempting to "
                "insert S-EID %s/%d in pt but failed", ip_addr_to_char(src), splen);
        return(BAD);
    }

    /* insert the G in the user1 field of the unicast pt node */
    if(!snode->mc_data){
        /* create the patricia if not initialized */
        snode->mc_data = (patricia_tree_t *)New_Patricia(ip_addr_get_size(grp) * 8);

        if (!snode->mc_data){
            lispd_log_msg(LISP_LOG_WARNING, "pt_add_mc_addr: Can't create group pt!");
            return(BAD);
        }
    }

    /* insert grp in node->user1 db with the entry*/
    gnode = pt_add_entry((patricia_tree_t *)snode->mc_data, grp, gplen);
    if (gnode == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Attempting to "
                "insert G %s/%d in the group pt but failed! ", ip_addr_to_char(grp), gplen);
        return(BAD);
    }

    gnode->data = data;
    return(GOOD);
}


int pt_remove_mc_addr(patricia_tree_t *pt, ip_addr_t *src, uint8_t splen, ip_addr_t *grp, uint8_t gplen) {
    patricia_node_t         *snode  = NULL;
    patricia_node_t         *gnode  = NULL;
    patricia_tree_t         *strie  = NULL;
    patricia_tree_t         *gtrie  = NULL;

    strie = pt_get_from_afi(ip_addr_get_afi(src));

    snode = pt_lookup_ip_addr(strie, src, splen);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr: The source "
                "prefix %s/%d does not exist in the map cache",
                ip_addr_to_char(src), splen);
        return(BAD);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->mc_data;
    if (!gtrie){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr: The source  "
                "prefix %s/%d does not have a multicast particia trie "
                "associated", ip_addr_to_char(src), splen);
        return(BAD);
    }


    gnode = pt_lookup_ip_addr(gtrie, grp, gplen);

    if (!gnode){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr: The group prefix"
                "%s/%d does not have a multicast map cache entry associated",
                ip_addr_to_char(grp), gplen);
        return(BAD);
    } else {
        /* remove strie entry if both gtrie and strie are empty */
        if(pt_test_if_empty(gtrie)){
            Destroy_Patricia(gtrie, free_map_cache_entry);
            if (snode->data == NULL)
                pt_remove_entry(strie, snode);
        }
    }

    return(GOOD);

}

void *pt_lookup_mc_addr(patricia_tree_t *pt, ip_addr_t *src, uint8_t splen, ip_addr_t *grp, uint8_t gplen) {

    patricia_node_t         *snode  = NULL;
    patricia_node_t         *gnode  = NULL;
    patricia_tree_t         *strie  = NULL;
    patricia_tree_t         *gtrie  = NULL;

    strie = pt_get_from_afi(ip_addr_get_afi(src));

    snode = pt_lookup_ip_addr(strie, src, splen);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr: The source "
                "prefix %s/%d does not exist in the map cache",
                ip_addr_to_char(src), splen);
        return(NULL);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->mc_data;
    if (!gtrie){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr: The source  "
                "prefix %s/%d does not have a multicast particia trie "
                "associated", ip_addr_to_char(src), splen);
        return(NULL);
    }


    gnode = pt_lookup_ip_addr(gtrie, grp, gplen);

    if (!gnode){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_lookup_mc_addr: The group prefix"
                "%s/%d does not have a multicast map cache entry associated",
                ip_addr_to_char(grp), gplen);
        return(NULL);
    }

    return(gnode->data);
}


void pt_remove_entry(patricia_tree_t *pt, patricia_node_t *node) {
    lispd_map_cache_entry   *entry  = NULL;

    /* unicast */
    entry = ((lispd_map_cache_entry *)node->data);
    free_map_cache_entry(entry);

    /* multicast */
    if ((entry = ((lispd_map_cache_entry *)node->data)))
        free_map_cache_entry(entry);
    patricia_remove(pt, node);
}

patricia_node_t *pt_add_entry(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen) {
    patricia_node_t *node;
    prefix_t        *prefix;

    prefix = make_pt_ip_prefix(ipaddr, prefixlen);
    node = patricia_lookup(pt, prefix);
    Deref_Prefix(prefix);

    /* node already exists */
    if (node->data){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_entry: Trying to overwrite a map cache entry!");
        return(NULL);
    }
    return(node);
}

patricia_node_t *pt_lookup_entry(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen) {
    patricia_node_t *node;
    prefix_t        *prefix;
    uint8_t         default_plen;

    if (!prefixlen) {
        default_plen = (ip_addr_get_afi(ipaddr) == AF_INET) ? 32: 128;
        prefix = make_pt_ip_prefix(ipaddr, default_plen);
        node =  patricia_search_best(pt, prefix);
    } else {
        prefix = make_pt_ip_prefix(ipaddr, prefixlen);
        node = patricia_search_exact(pt, prefix);
    }

    Deref_Prefix(prefix);

    return(node);
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
        lispd_log_msg(LISP_LOG_DEBUG_1,"get_db_from_afi: AFI %u not recognized!", afi );
    }

    return pt;
}

prefix_t *make_pt_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen) {
    ip_afi_t        afi         = 0;
    prefix_t        *prefix     = NULL;

    afi = ip_addr_get_afi(ipaddr);

    switch(afi){
    case AF_INET:
        assert(prefixlen <= 32);
        if(!(prefix = New_Prefix(AF_INET, ip_addr_get_v4(ipaddr), prefixlen))) {
            lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unable to "
                    "allocate memory for prefix_t (AF_INET): %s", strerror(errno));
            return(NULL);
        }
        break;
    case AF_INET6:
        assert(prefixlen <= 128);
        if(!(prefix = New_Prefix(AF_INET, ip_addr_get_v6(ipaddr), prefixlen))) {
            lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unable to "
                    "allocate memory for prefix_t (AF_INET6): %s", strerror(errno));
            return(NULL);
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unknown AFI %d "
                "for address %s", afi, ip_addr_to_char(ipaddr));
        return(NULL);
    }

    return(prefix);
}

