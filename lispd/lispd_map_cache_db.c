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
 *    Florin Coras      <fcoras@ac.upc.edu>
 */

#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include <math.h>

/*
 *  Patricia tree based databases
 */

patricia_tree_t *AF4_map_cache           = NULL;
patricia_tree_t *AF6_map_cache           = NULL;

int                         del_map_cache_entry_from_db_ip(lisp_addr_t *ipaddr, uint8_t prefixlen);
int                         del_map_cache_entry_from_db_mc(mc_addr_t *mcaddr, uint8_t splen, uint8_t gplen);
int                         add_map_cache_entry_ip(lispd_map_cache_entry *entry, ip_addr_t *ipaddr);
int                         add_map_cache_entry_mc(lispd_map_cache_entry *entry, mc_addr_t *addr);
lispd_map_cache_entry       *lookup_map_cache_ip(ip_addr_t *ipaddr, uint8_t prefixlen);
lispd_map_cache_entry       *lookup_map_cache_mc(mc_addr_t *mcaddr, uint8_t prefixlen);
patricia_node_t             *pt_add_entry(ip_addr_t *ipaddr, uint8_t prefixlen);
patricia_node_t             *pt_lookup_ip_addr(lisp_addr_t *addr, uint8_t prefixlen, patricia_tree_t *pt);
void                        pt_remove_entry(patricia_tree_t *pt, patricia_node_t *node);
uint8_t                     pt_test_if_empty(patricia_tree_t *pt);
patricia_node_t             *make_pt_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen);

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

patricia_tree_t* get_map_cache_db(lisp_afi_t afi){
    lisp_log_msg(LISP_LOG_INFO, "In get_map_cache_db: This function shouldn't be called from outside! Don't know why it existed!");
    return(NULL);
}

/*
 *  Add a map cache entry to the database.
 */

int add_map_cache_entry_to_db(lispd_map_cache_entry *entry){
    lisp_mapping_cache_elt  *mapping    = NULL;
    lisp_addr_t             *addr       = NULL;

    mapping = get_mcache_entry_mapping(entry);
    addr = get_mapping_eid_addr(mapping);

    switch(get_lisp_addr_afi(addr)) {
    case LM_AFI_IP:
        return add_map_cache_entry_ip(entry, get_lisp_addr_ip(addr));
        break;
    case LM_AFI_IP6:
        return add_map_cache_entry_ip(entry, get_lisp_addr_ip(addr));
        break;
    case LM_AFI_MC:
        return add_map_cache_entry_mc(entry, get_lisp_addr_mc(addr));
        break;
    default:
        lisp_log_msg(LISP_LOG_WARNING, "del_map_cache_entry_from_db: called with unknown AFI:%u",
                get_lisp_addr_afi(laddr));
        break;
    }



}

int add_map_cache_entry_ip(lispd_map_cache_entry *entry, ip_addr_t *ipaddr) {
    patricia_node_t     *node   = NULL;

    /* Insert prefix in pt */
    if (node = pt_add_entry(NULL, ipaddr, get_mapping_ip_eid_plen(entry)) == NULL){
        lisp_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Attempting to "
                "insert (%s) in the map-cache but couldn't add the entry to the pt!".
                get_mcache_entry_eid_prefix_to_char(entry));
    }

    /* node already exists */
    if (node->data){
        lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_ip_entry: Map cache entry (%s) already installed in the database",
                get_mcache_entry_eid_prefix_to_char((lispd_map_cache_entry *)node->data));
        return (BAD);
    }

    node->data = (lispd_map_cache_entry *)entry;
    lispd_log_msg(LISP_LOG_DEBUG_2, "pt_add_ip_entry: Added map cache data for EID: %s",
            get_mcache_entry_eid_prefix_to_char(entry));

    return (GOOD);
}

int add_map_cache_entry_mc(lispd_map_cache_entry *entry, mc_addr_t *mcaddr) {
    patricia_node_t *snode       = NULL;
    patricia_node_t *gnode       = NULL;
    ip_addr_t       *src        = NULL;
    ip_addr_t       *grp        = NULL;
    uint8_t         safi        = 0;
    uint8_t         gafi        = 0;

    src = get_lisp_addr_mc_src(mcaddr);
    grp = get_lisp_addr_mc_grp(mcaddr);
    safi = get_ip_addr_afi(src);
    gafi = get_ip_addr_afi(grp);

    if (safi != gafi || safi == 0 || gafi == 0 ){
        lisp_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Attempting to "
                "insert multicast channel %s but it has AFIs problems for "
                "S and G!", get_mcache_entry_eid_prefix_to_char(entry));
        return(BAD);
    }


    /* insert src prefix in main db but without any data*/
    snode = pt_add_entry(src, get_mcache_entry_eid_plen(entry));
    if (snode == NULL){
        lisp_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Attempting to "
                "insert multicast channel %s in map-cache but couldn't add"
                " S to the pt!", get_mcache_entry_eid_prefix_to_char(entry));
        return(BAD);
    }

    /* insert the G in the user1 field of the unicast pt node */
    if(snode->user1 == NULL){
        /* create the patricia if not initialized */
        snode->user1 = (patricia_tree_t *)New_Patricia(get_ip_addr_size(grp) * 8);

        if (!snode->user1){
            lisp_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Can't create "
                    "group pt! ");
            return(BAD);
        }
    }

    /* insert grp in node->user1 db with the entry*/
    gnode = pt_add_entry(snode->user1, grp, get_mapping_mc_eid_grp_plen(get_mcache_entry_mapping(entry)));
    if (gnode == NULL){
        lisp_log_msg(LISP_LOG_WARNING, "add_map_cache_entry_mc: Attempting to "
                "insert multicast channel %s map-cache but couldn't add "
                "G to the pt!", get_mcache_entry_eid_prefix_to_char(entry));
        return(BAD);
    }

    gnode->data = (lispd_map_cache_entry *)entry;

    return(GOOD);
}

void del_map_cache_entry_from_db(
        lisp_addr_t *laddr,
        uint8_t prefixlen)
{
    /* TODO: support removal of mcast channel from prefix */
    uint8_t         gplen   = 0;


    switch(get_lisp_addr_afi(laddr)){
    case LM_AFI_IP:
        del_map_cache_entry_from_db_ip(get_lisp_addr_ip(laddr), prefixlen);
        break;
    /* compatibility */
    case LM_AFI_IP6:
        del_map_cache_entry_from_db_ip(get_lisp_addr_ip(laddr), prefixlen);
        break;
    case LM_AFI_MC:
        /* hack to avoid supporting group prefix in del_map_cache_entry_from_db */
        gplen = (get_ip_addr_afi(get_lisp_addr_mc_grp(laddr)) == AF_INET) ? 32 : 128;
        del_map_cache_entry_from_db_mc(get_lisp_addr_mc(laddr), prefixlen, gplen);
        break;
    default:
        lisp_log_msg(LISP_LOG_WARNING, "del_map_cache_entry_from_db: called with unknown AFI:%u",
                get_lisp_addr_afi(laddr));
        break;
    }

}

/*
 * del_map_cache_entry()
 *
 * Delete an EID mapping from the cache
 */

void del_map_cache_entry_from_db_ip(
        ip_addr_t *ipaddr,
        int prefixlen)
{
    patricia_node_t         *node   = NULL;
    patricia_tree_t         *pt     = NULL;

    node = pt_lookup_ip_addr(ipaddr, prefixlen, get_pt_from_afi(get_ip_addr_afi(ipaddr)));
    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"del_map_cache_entry: Unable to locate cache entry %s/%d for deletion",
                get_ip_addr_to_char(ipaddr), prefixlen);
        return(BAD);
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"Deleting map cache entry: %s/%d",
                get_ip_addr_to_char(ipaddr), prefixlen);
    }

    /*
     * Remove the entry from the trie
     */

    /* Avoid removing nodes that still have multicast mappings */
    if (node->user1 == NULL) {
        pt_remove_entry(pt, node);
    }else{
        node->data = NULL;
    }

    return(GOOD);

}

int del_map_cache_entry_from_db_mc(
        mc_addr_t *mcaddr,
        uint8_t splen,
        uint8_t gplen)
{
    patricia_node_t         *snode  = NULL;
    patricia_node_t         *gnode  = NULL;
    patricia_tree_t         *strie  = NULL;
    patricia_tree_t         *gtrie  = NULL;
    ip_addr_t               *src    = NULL;
    ip_addr_t               *grp    = NULL;

    src = get_lisp_addr_mc_src(mcaddr);
    strie = get_pt_from_afi(get_ip_addr_afi(src));

    snode = pt_lookup_ip_addr(src, prefixlen, strie);
    if (snode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_mc: The source "
                "prefix %s/%d does not exist in the map cache",
                get_ip_addr_to_char(src), prefixlen);
        return(BAD);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->user1;
    if (gtrie == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_mc: The source  "
                "prefix %s/%d does not have a multicast particia trie "
                "associated", get_ip_addr_to_char(src), prefixlen);
        return(BAD);
    }

    grp = get_lisp_addr_mc_grp(mcaddr);
    gnode = pt_lookup_ip_addr(grp, gplen, gtrie);

    if (gnode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_mc: The group prefix"
                "%s/%d does not have a multicast map cache entry associated",
                get_ip_addr_to_char(grp), gplen);
        return(BAD);
    }else{
        /* remove gtrie entry */
        pt_remove_entry(gtrie, pt);

        /* remove strie entry if both gtrie and strie are empty */
        if(pt_test_if_empty(gtrie)){
            Destroy_Patricia(gtrie);
            if (snode->data == NULL)
                pt_remove_entry(strie, pt);
        }
    }

    return (GOOD);
}



/*
 * Look up a given lisp_addr_t in the database, returning the
 * lispd_map_cache_entry of this lisp_addr_t if it exists or NULL.
 */
lispd_map_cache_entry *lookup_map_cache(lisp_addr_t addr)
{
    /* if prefixlen is 0 the search is not strict */
    return lookup_map_cache_exact(addr, 0);
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
lispd_map_cache_entry *lookup_map_cache_exact(
        lisp_addr_t             addr,
        int                     prefixlen)
{
    lispd_map_cache_entry       *entry = NULL;
    lisp_addr_t                 *laddr = NULL;
    laddr = &addr;

    switch(get_lisp_addr_afi(laddr)){
    case LM_AFI_IP:
        entry = lookup_map_cache_ip(laddr, prefixlen);
        break;
    /* compatibility */
    case LM_AFI_IP6:
        entry = lookup_map_cache_ip(laddr, prefixlen);
        break;
    case LM_AFI_MC:
        entry = lookup_map_cache_mc(laddr, prefixlen);
        break;
    default:
        lisp_log_msg(LISP_LOG_WARNING, "lookup_map_cache_exact: Unknown AFI %u",
                get_lisp_addr_afi(laddr));
        break;
    }

    return(entry);
}

/*
 * Look up a given ip eid in the database, returning the
 * lispd_map_cache_entry of this eid if it exists or NULL.
 */
lispd_map_cache_entry *lookup_map_cache_ip(ip_addr_t *ipaddr, uint8_t prefixlen) {

    patricia_node_t     *node   = NULL;
    patricia_tree_t     *pt     = NULL;

    pt = get_pt_from_afi(get_ip_addr_afi(ipaddr));

    node = pt_lookup_ip_addr(ipaddr, prefixlen, pt);
    if (!node){
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_ip: The source entry %s/%d does not exist in the map cache",
                get_ip_addr_to_char(ipaddr), prefixlen);
        return(NULL);
    }

    return((lispd_map_cache_entry *)node->data);
}

/*
 * Look up a given mc eid in the database. Return the
 * associated lispd_map_cache_entry if it exists or NULL otherwise.
 */
lispd_map_cache_entry *lookup_map_cache_mc(mc_addr_t *mcaddr, uint8_t prefixlen) {
    /* fcoras: this piggybacks the unicast lookup.
     * TODO: If a smarter search/data structure  will be used in the future
     * for multicast, change here!
     */

    patricia_node_t *snode  = NULL;
    patricia_node_t *gnode  = NULL;
    patricia_tree_t *strie  = NULL;
    patricia_tree_t *gtrie  = NULL;
    ip_addr_t       *src    = NULL;
    ip_addr_t       *grp    = NULL;

    src = get_lisp_addr_mc_src(mcaddr);
    strie = get_pt_from_afi(get_ip_addr_afi(src));

    snode =  pt_lookup_ip_addr(src, prefixlen, strie);
    pt_lookup_ip_addr(src, prefixlen, strie);

    if (!snode){
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_mc: The source entry %s/%d does not exist in the map cache",
                get_ip_addr_to_char(src), prefixlen);
        return(NULL);
    }

    /* using field user1 of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *)snode->user1;
    if (gtrie == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_mc: The source entry %s does not have a multicast particia trie associated",
                get_ip_addr_to_char(src));
        return(NULL);
    }
    
    grp = get_lisp_addr_mc_grp(mcaddr);
    gnode = pt_lookup_ip_addr(grp, prefixlen, gtrie);
    
    if (gnode == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "lookup_map_cache_mc: The group entry %s does not have a multicast map cache entry associated",
                get_ip_addr_to_char(grp));
        return(NULL);
    } else {
        return((lispd_map_cache_entry *)gnode->data);
    }

}

void pt_remove_entry(patricia_tree_t *pt, patricia_node_t *node) {
    lispd_map_cache_entry   *entry  = NULL;
    entry = ((lispd_map_cache_entry *)node->data);
    patricia_remove(pt, node);
    free_map_cache_entry(entry);
}

/* interface to insert entries into patricia */
patricia_node_t *pt_add_entry(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen) {
    prefix_t        *prefix     = NULL;
    patricia_node_t *node       = NULL;

    if (!pt)
        pt = get_pt_from_afi(get_ip_addr_afi(ipaddr));

    prefix = make_pt_ip_prefix(ipaddr, prefixlen);
    node = patricia_lookup(pt, prefix);
    Deref_Prefix(prefix);

    return(node);
}

patricia_node_t *pt_lookup_ip_addr(ip_addr_t *addr, uint8_t prefixlen, patricia_tree_t *pt){
    patricia_node_t     *node = NULL;
    prefix_t            *prefix;

    switch(get_ip_addr_afi(addr)) {
    case AF_INET:
        assert(prefixlen <= 32);
        prefix = New_Prefix(AF_INET, get_ip_addr_v4(addr), (prefixlen) ? prefixlen: 32);
        break;
    case AF_INET6:
        assert(prefixlen <=128);
        prefix = New_Prefix(AF_INET6, get_ip_addr_v6(addr), (prefixlen) ? prefixlen: 128);
        break;
    default:
        lispd_log_msg(LSIP_LOG_DEBUG_1, "lookup_map_cache_node: Unknown afi %d!", get_ip_addr_afi(addr) );
        return(NULL);
    }

    if (prefix == NULL){
        lispd_log_msg(LSIP_LOG_DEBUG_1, "lookup_map_cache_node: Couldn't allocate prefix!");
        return(NULL);
    }

    /*prefixlen = 0 means the search is not exact */
    node = (prefixlen) ? patricia_search_exact(pt, prefix) : patricia_search_best(pt, prefix);

    Deref_Prefix(prefix);

    if (node==NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_map_cache_node: The entry %s is"
                " not found in the map cache", get_char_from_lisp_addr_t(eid));
    }

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
patricia_tree_t *get_pt_from_afi(ip_afi_t afi) {
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

patricia_node_t *make_pt_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen) {
    ip_afi_t        afi         = 0;
    prefix_t        *prefix     = NULL;

    afi = get_ip_addr_afi(ipaddr);

    switch(afi){
    case AF_INET:
        assert(prefixlen <= 32);
        if(prefix = New_Prefix(AF_INET, get_ip_addr_v4(ipaddr), prefixlen) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unable to "
                    "allocate memory for prefix_t (AF_INET): %s", strerror(errno));
            return(NULL);
        }
        break;
    case AF_INET6:
        assert(prefixlen <= 128);
        if(prefix = New_Prefix(AF_INET, get_ip_addr_v6(ipaddr), prefixlen) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unable to "
                    "allocate memory for prefix_t (AF_INET6): %s", strerror(errno));
            return(NULL);
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_WARNING, "make_ip_prefix_for_pt: Unknown AFI %d "
                "for address %s", afi, get_ip_addr_to_char(ipaddr));
        return(NULL);
    }

    return(prefix);
}


/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(
        lisp_afi_t  eid_afi,
        uint64_t    nonce)
{
    patricia_tree_t         *tree;
    patricia_node_t         *node;
    lispd_map_cache_entry   *entry;

    tree = get_pt_from_afi(eid_afi);

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

int replace_map_cache_entry(
        lisp_addr_t             *new_addr,
        uint8_t                 new_plen,
        lispd_map_cache_entry   *centry)
{
    patricia_node_t         *node = NULL;
    lisp_addr_t             old_eid_addr;
    int                     old_eid_plen;

    /* Get the node to be modified from the database
     * NOTE: This works assuming that both mc and ip addresses
     * are stored in the same pt. Also, mc prefix length is set
     * be S prefix length. */
    del_map_cache_entry_from_db(get_mcache_entry_eid_addr(centry), get_mcache_entry_eid_plen(centry) );

    old_eid_addr = get_mcache_entry_eid_addr(centry);
    old_eid_plen = get_mcache_entry_eid_plen(centry);

    set_mcache_entry_eid_addr(centry, new_addr);
    set_mcache_entry_eid_plen(centry, new_plen);


    if ((err=add_map_cache_entry_to_db(centry))!= GOOD){
        /*XXX  if the process doesn't finish correctly, the map cache entry is released */
        lispd_log_msg(LISP_LOG_DEBUG_2,"change_eid_prefix_in_db: Couldn't change EID prefix of the inactive "
                "map cache entry (%s/%d -> %s/%d). Releasing it",
                get_lisp_addr_to_char(old_eid_addr),
                old_eid_plen,
                get_lisp_addr_to_char(new_addr),
                new_plen);
        free_map_cache_entry(centry);
        return (BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_2,"EID prefix of the map cache entry %s/%d changed to %s/%d.",
            get_lisp_addr_to_char(old_eid_addr),
            old_eid_plen,
            get_lisp_addr_to_char(new_addr),
            new_plen);
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
    mapping = get_mcache_entry_mapping(entry);
    addr = get_mapping_eid_addr(mapping);
    plen = (get_lisp_addr_afi(addr) == LM_AFI_IP) ?
            get_mapping_ip_eid_plen(mapping) :
            get_mapping_mc_eid_src_plen(mapping);

    lispd_log_msg(LISP_LOG_DEBUG_1,"Got expiration for EID",
            get_mapping_eid_prefix_to_char(addr), plen);

    del_map_cache_entry_from_db(addr, plen);
}

/*
 * dump_map_cache
 */
void dump_map_cache_db(int log_level)
{
    patricia_tree_t 	*dbs [2] = {AF4_map_cache, AF6_map_cache};
    int					ctr;

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
            if (node->user1){
                lisp_log_msg(log_level, "======= Start Multicast =======\n");
                PATRICIA_WALK( (patricia_tree_t *)node->user1, mnode){
                    mentry = ((lispd_map_cache_entry *)mnode->data);
                    dump_map_cache_entry(mentry, log_level);
                } PATRICIA_WALK_END;
                dump_map_cache_entry(entry, log_level);
                lisp_log_msg(log_level, "======= End Multicast =======\n");
            }
        } PATRICIA_WALK_END;
    }
    lispd_log_msg(log_level,"*******************************************************\n");
}
