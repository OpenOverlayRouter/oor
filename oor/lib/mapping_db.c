/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This defines a mappings database (mdb) that relies on patricia tries and hash tables
 * to store IP and LCAF based EIDs. Among the supported LCAFs are multicast of type (S,G) and IID.
 * It is used to implement both the mappings cache and the local mapping db.
 */

#include <assert.h>

#include "mapping_db.h"
#include "oor_log.h"

patricia_node_t *pt_add_node(patricia_tree_t *pt, ip_addr_t *ipaddr,
        uint8_t prefixlen, void *data);
int pt_add_ippref(patricia_tree_t *pt, ip_prefix_t *ippref, void *data);
int pt_add_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr, void *data);

void *pt_remove_mc_addr(patricia_tree_t *pt, lcaf_addr_t *mcaddr);
void *pt_remove_ippref(patricia_tree_t *pt, ip_prefix_t *ippref);

patricia_node_t *pt_find_ip_node(patricia_tree_t *pt, ip_addr_t *ipaddr);
patricia_node_t *pt_find_ip_node_exact(patricia_tree_t *pt, ip_addr_t *ipaddr,
        uint8_t prefixlen);
patricia_node_t *pt_find_mc_node(patricia_tree_t *pt, lcaf_addr_t *mcaddr,
        uint8_t exact);
void pt_remove_node(patricia_tree_t *pt, patricia_node_t *node);

uint8_t pt_test_if_empty(patricia_tree_t *pt);
prefix_t *pt_make_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen);

void mdb_for_each_entry_cb(mdb_t *mdb, void (*callback)(void *, void *),
        void *cb_data);

static int _add_iid_entry(mdb_t *db, void *entry, lcaf_addr_t *iidaddr);
static void *_rm_iid_entry(mdb_t *db, lcaf_addr_t *iidaddr);
static patricia_node_t *_find_iid_node(mdb_t *db, lcaf_addr_t *iidaddr, uint8_t exact);


/*
 * Return map cache data base
 */
static patricia_tree_t *
get_ip_pt_from_afi(mdb_t *db, uint16_t afi)
{
    switch (afi) {
    case AF_INET:
        return (db->AF4_ip_db->head->data);
        break;
    case AF_INET6:
        return (db->AF6_ip_db->head->data);
        break;
    default:
        OOR_LOG(LDBG_1, "get_ip_pt_from_afi: AFI %u not recognized!", afi);
        break;
    }

    return (NULL);
}


static patricia_tree_t *
get_iid_pt_from_lcaf(mdb_t *db, lcaf_addr_t *iidaddr)
{
    patricia_tree_t *pt;
    int_htable *ht;
    lisp_addr_t *addr;
    uint32_t iid;
    uint16_t afi;
    iid = iid_type_get_iid(lcaf_addr_get_iid(iidaddr));
    addr = iid_type_get_addr(lcaf_addr_get_iid(iidaddr));
    if (lisp_addr_lafi(addr) == LM_AFI_LCAF){
        OOR_LOG(LDBG_1, "get_iid_pt_from_lcaf: Concurrent lcaf address not supported");
        return (NULL);
    }
    afi = lisp_addr_ip_afi(addr);
    switch (afi){
    case AF_INET:
        ht = db->AF4_iid_db;
        break;
    case AF_INET6:
        ht = db->AF6_iid_db;
        break;
    default:
        OOR_LOG(LDBG_1, "get_iid_pt_from_lcaf: AFI %u not recognized!", afi);
        return (NULL);
    }
    pt = int_htable_lookup(ht,iid);
    if (!pt){
        return (NULL);
    }
    return (pt->head->data);
}


static patricia_tree_t *
get_mc_pt_from_lcaf(mdb_t *db, lcaf_addr_t *lcaf)
{
    uint16_t afi = lcaf_mc_get_afi(lcaf);
    switch (afi) {
    case AF_INET:
        return (db->AF4_mc_db);
        break;
    case AF_INET6:
        return (db->AF6_mc_db);
        break;
    default:
        OOR_LOG(LDBG_1, "_get_mc_pt_from_lcaf: AFI %u not recognized!", afi);
        break;
    }

    return (NULL);
}

static patricia_node_t *
_find_ip_node(mdb_t *db, lisp_addr_t *laddr, uint8_t exact)
{
    patricia_tree_t *pt = get_ip_pt_from_afi(db, lisp_addr_ip_afi(laddr));

    if (exact) {
        return (pt_find_ip_node_exact(pt, lisp_addr_ip_get_addr(laddr),
                lisp_addr_ip_get_plen(laddr)));
    } else {
        return (pt_find_ip_node(pt, lisp_addr_ip_get_addr(laddr)));
    }
}

static patricia_node_t *
_find_lcaf_node(mdb_t *db, lcaf_addr_t *lcaf, uint8_t exact)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (_find_iid_node(db,lcaf,exact));
    case LCAF_MCAST_INFO:
        return (pt_find_mc_node(get_mc_pt_from_lcaf(db, lcaf),
                lcaf, exact));
    default:
        OOR_LOG(LWRN, "_find_lcaf_node: Unknown LCAF type %u",
                lcaf_addr_get_type(lcaf));
    }
    return (NULL);
}

static patricia_node_t *
_find_node(mdb_t *db, lisp_addr_t *laddr, uint8_t exact)
{
    switch (lisp_addr_lafi(laddr)) {
    case LM_AFI_IP:
    case LM_AFI_IPPREF:
        return (_find_ip_node(db, laddr, exact));
    case LM_AFI_LCAF:
        return (_find_lcaf_node(db, lisp_addr_get_lcaf(laddr), exact));
        break;
    default:
        OOR_LOG(LWRN, "_find_node: unsupported AFI %d", lisp_addr_lafi(laddr));
        break;
    }

    return (NULL);
}

static patricia_tree_t *
_get_grp_pt_for_mc_addr(patricia_tree_t *strie, lcaf_addr_t *mcaddr,
        uint8_t exact)
{
    patricia_node_t *snode = NULL;
    lisp_addr_t *src = NULL;
    ip_addr_t *srcip = NULL;
    uint8_t splen;

    patricia_tree_t *gtrie = NULL;

    src = lcaf_mc_get_src(mcaddr);
    srcip = lisp_addr_ip(src);

    if (lisp_addr_lafi(src) != LM_AFI_IP) {
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: only IP AFI supported for S and G");
        return (NULL);
    }

    splen = lcaf_mc_get_src_plen(mcaddr);
    if (exact) {
        /* exact lookup for src node */
        snode = pt_find_ip_node_exact(strie, srcip, splen);
    } else {
        /* longest prefix match to find the S/S-prefix node */
        snode = pt_find_ip_node(strie, srcip);
    }

    if (snode == NULL) {
        OOR_LOG(LDBG_3, "_get_pt_for_mc_addr: The source prefix %s/%d does not"
                " exist in the map cache", ip_addr_to_char(srcip), splen);
        return (NULL);
    }

    /* using field data of a patricia node as pointer to a G lookup table */
    gtrie = (patricia_tree_t *) snode->data;

    return (gtrie);
}

static int
_add_ippref_entry(mdb_t *db, void *entry, ip_prefix_t *ippref)
{
    if (pt_add_ippref(get_ip_pt_from_afi(db, ip_prefix_afi(ippref)), ippref,
            entry) != GOOD) {
        OOR_LOG(LDBG_3, "_add_ippref_entry: Attempting to insert (%s) in the "
                "map-cache but couldn't add the entry to the pt!",
                ip_prefix_to_char(ippref));
        return (BAD);
    }

    OOR_LOG(LDBG_3, "_add_ippref_entry: Added map cache data for %s",
            ip_prefix_to_char(ippref));
    return (GOOD);
}

static int
_db_add_iid(mdb_t *db, uint32_t iid, uint16_t afi){
    patricia_tree_t *pt;
    int_htable *ht;
    ip_addr_t ip;
    size_t size;

    memset(&ip, 0, sizeof(ip_addr_t));

    switch (afi){
    case AF_INET:
        ip_addr_set_afi(&ip, AF_INET);
        size = sizeof(struct in_addr);
        pt = New_Patricia( size * 8);
        ht = db->AF4_iid_db;
        break;
    case AF_INET6:
        ip_addr_set_afi(&ip, AF_INET6);
        size = sizeof(struct in6_addr);
        pt = New_Patricia(size * 8);
        ht = db->AF6_iid_db;
        break;
    default:
        OOR_LOG(LDBG_1, "_db_add_iid: AFI %u not recognized!", afi);
        return (BAD);
    }

    /* MC is stored as patricia in patricia, what follows is a HACK
     * to have compatible walk methods for both IP and MC. */
    pt_add_node(pt, &ip, 0,(void *) New_Patricia(size * 8));

    int_htable_insert(ht, iid, pt);

    return (GOOD);
}


static int
_add_iid_entry(mdb_t *db, void *entry, lcaf_addr_t *iidaddr)
{
    uint32_t iid;
    lisp_addr_t *ip_pref;
    patricia_tree_t *pt;
    uint16_t afi;

    iid = lcaf_iid_get_iid(iidaddr);
    ip_pref = lcaf_get_ip_pref_addr(iidaddr);
    if (!ip_pref){
        return (BAD);
    }
    afi = lisp_addr_ip_afi(ip_pref);
    pt = get_iid_pt_from_lcaf(db, iidaddr);
    if (!pt){
        if ((_db_add_iid(db,iid,afi))!=GOOD){
            return (BAD);
        }
        pt = get_iid_pt_from_lcaf(db, iidaddr);
    }

    if (pt_add_ippref(pt, lisp_addr_get_ippref(ip_pref),entry) != GOOD) {
        OOR_LOG(LDBG_3, "_add_iid_entry: Attempting to insert (%s) in the "
                "map-cache but couldn't add the entry to the patricia tree!",
                lcaf_addr_to_char(iidaddr));
        return (BAD);
    }

    OOR_LOG(LDBG_3, "_add_iid_entry: Added map cache data for %s",
            lcaf_addr_to_char(iidaddr));
    return (GOOD);
}

static void *
_rm_iid_entry(mdb_t *db, lcaf_addr_t *iidaddr)
{
    lisp_addr_t *ip_pref;
    patricia_tree_t *pt;

    pt = get_iid_pt_from_lcaf(db, iidaddr);
    if (!pt){
        OOR_LOG(LDBG_3, "_rm_iid_entry: Attempting to remove (%s) in the "
                "map-cache but it doesn't exist",
                lcaf_addr_to_char(iidaddr));
        return (NULL);
    }
    ip_pref = lcaf_get_ip_pref_addr(iidaddr);
    if (!ip_pref){
        return (NULL);
    }

    return (pt_remove_ippref(pt, lisp_addr_get_ippref(ip_pref)));
}

static patricia_node_t *
_find_iid_node(mdb_t *db, lcaf_addr_t *iidaddr, uint8_t exact)
{
    patricia_node_t * node;
    lisp_addr_t *ip_pref;
    patricia_tree_t *pt;

    pt = get_iid_pt_from_lcaf(db, iidaddr);
    if (!pt){
        OOR_LOG(LDBG_3, "_find_iid_entry: Couldn't find (%s) in the "
                "map-cache. No iid",lcaf_addr_to_char(iidaddr));
        return (NULL);
    }


    if (exact){
        ip_pref = lcaf_get_ip_pref_addr(iidaddr);
        if (!ip_pref){
            return (NULL);
        }
        node = pt_find_ip_node_exact(pt, lisp_addr_ip_get_addr(ip_pref), lisp_addr_ip_get_plen(ip_pref));
    }else{
        ip_pref = lcaf_get_ip_addr(iidaddr);
        if (!ip_pref){
            ip_pref = lcaf_get_ip_pref_addr(iidaddr);
            if (!ip_pref){
                return (NULL);
            }
        }
        node = pt_find_ip_node(pt, lisp_addr_ip_get_addr(ip_pref));
    }

    return (node);
}



static int
_add_mc_entry(mdb_t *db, void *entry, lcaf_addr_t *mcaddr)
{
    if (pt_add_mc_addr(get_mc_pt_from_lcaf(db, mcaddr), mcaddr,
            entry) != GOOD) {
        OOR_LOG(LDBG_2, "_add_mc_entry: Attempting to insert %s to map cache "
                "but failed! ", mc_type_to_char(mcaddr));
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "_add_mc_entry: Added entry %s to mdb!",
                lcaf_addr_to_char(mcaddr));
    }

    return (GOOD);
}

static void *
_rm_mc_entry(mdb_t *db, lcaf_addr_t *mcaddr)
{
    patricia_tree_t *pt;

    pt = get_mc_pt_from_lcaf(db,mcaddr);
    return (pt_remove_mc_addr(pt, mcaddr));
}


static int
_add_lcaf_entry(mdb_t *db, void *entry, lcaf_addr_t *lcaf)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (_add_iid_entry(db, entry, lcaf));
    case LCAF_MCAST_INFO:
        return (_add_mc_entry(db, entry, lcaf));
    default:
        OOR_LOG(LDBG_3, "_add_lcaf_entry: LCAF type %d not supported!",
                lcaf_addr_get_type(lcaf));
    }
    return (BAD);
}

static void *
_del_lcaf_entry(mdb_t *db, lcaf_addr_t *lcaf)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (_rm_iid_entry(db,lcaf));
    case LCAF_MCAST_INFO:
        return (_rm_mc_entry(db,lcaf));
    default:
        OOR_LOG(LDBG_3, "_del_lcaf_entry: called with unknown LCAF type:%u",
                lcaf_addr_get_type(lcaf));
        break;
    }
    return (NULL);
}

patricia_tree_t *
_get_local_db_for_lcaf_addr(mdb_t *db, lcaf_addr_t *lcaf)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (get_iid_pt_from_lcaf(db,lcaf));
    case LCAF_MCAST_INFO:
        return (get_mc_pt_from_lcaf(db, lcaf));
    default:
        OOR_LOG(LDBG_3, "_get_local_db_for_lcaf_addr: LCAF type %d not supported!",
                lcaf_addr_get_type(lcaf));
        break;
    }
    return (NULL);
}

patricia_tree_t *
_get_local_db_for_addr(mdb_t *db, lisp_addr_t *addr)
{
    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
    case LM_AFI_IPPREF:
        return (get_ip_pt_from_afi(db, lisp_addr_ip_afi(addr)));
    case LM_AFI_LCAF:
        return (_get_local_db_for_lcaf_addr(db, lisp_addr_get_lcaf(addr)));
    default:
        OOR_LOG(LDBG_3, "_get_db_for_addr: called with unsupported afi(%d)",
                lisp_addr_lafi(addr));
    }
    return (NULL);
}

mdb_t *
mdb_new()
{
    mdb_t *db = xzalloc(sizeof(mdb_t));
    OOR_LOG(LDBG_3, " Creating mdb...");

    db->AF4_ip_db = New_Patricia(sizeof(struct in_addr) * 8);
    db->AF6_ip_db = New_Patricia(sizeof(struct in6_addr) * 8);
    /* IID TABLES*/
    db->AF4_iid_db = int_htable_new();
    db->AF6_iid_db = int_htable_new();


    /* MC is stored as patricia in patricia, what follows is a HACK
     * to have compatible walk methods for both IP and MC. */
    ip_addr_t ipv4, ipv6;
    memset(&ipv4, 0, sizeof(ip_addr_t));
    ip_addr_set_afi(&ipv4, AF_INET);
    memset(&ipv6, 0, sizeof(ip_addr_t));
    ip_addr_set_afi(&ipv6, AF_INET6);
    pt_add_node(db->AF4_ip_db, &ipv4, 0,
            (void *) New_Patricia(sizeof(struct in_addr) * 8));
    pt_add_node(db->AF6_ip_db, &ipv6, 0,
            (void *) New_Patricia(sizeof(struct in6_addr) * 8));

    db->AF4_mc_db = New_Patricia(sizeof(struct in_addr) * 8);
    db->AF6_mc_db = New_Patricia(sizeof(struct in6_addr) * 8);

    if (!db->AF4_ip_db->head->data || !db->AF6_ip_db->head->data
        || !db->AF4_mc_db || !db->AF6_mc_db) {
        OOR_LOG(LCRIT, "mdb_init: Unable to allocate memory for mdb");
        return(BAD);
    }

    db->n_entries = 0;

    return (db);
}

void
mdb_del(mdb_t *db, mdb_del_fct del_fct)
{
    patricia_node_t *node;
    void *value;
    Destroy_Patricia(db->AF4_ip_db->head->data, del_fct);
    Destroy_Patricia(db->AF4_ip_db, NULL);

    Destroy_Patricia(db->AF6_ip_db->head->data, del_fct);
    Destroy_Patricia(db->AF6_ip_db, NULL);

    /* Remove IID db */
    int_htable_foreach_value(db->AF4_iid_db, value){
        Destroy_Patricia(((patricia_tree_t *)value)->head->data, del_fct);
        Destroy_Patricia(value, NULL);
    }int_htable_foreach_value_end;
    int_htable_destroy(db->AF4_iid_db);

    int_htable_foreach_value(db->AF6_iid_db, value){
        Destroy_Patricia(((patricia_tree_t *)value)->head->data, del_fct);
        Destroy_Patricia(value, NULL);
    }int_htable_foreach_value_end;
    int_htable_destroy(db->AF6_iid_db);

    if (db->AF4_mc_db->head) {
        PATRICIA_WALK(db->AF4_mc_db->head, node) {
            Destroy_Patricia(node->data, del_fct);
        } PATRICIA_WALK_END;
    }
    Destroy_Patricia(db->AF4_mc_db, NULL);

    if (db->AF6_mc_db->head) {
        PATRICIA_WALK(db->AF6_mc_db->head, node) {
            Destroy_Patricia(node->data, del_fct);
        } PATRICIA_WALK_END;
    }
    Destroy_Patricia(db->AF6_mc_db, NULL);
    free(db);
}

int
mdb_add_entry(mdb_t *db, lisp_addr_t *addr, void *data)
{
    int retval = 0;
    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
        OOR_LOG(LWRN, "mdb_add_entry: mapping stores an IP prefix not an IP!");
        break;
    case LM_AFI_IPPREF:
        retval = _add_ippref_entry(db, data, lisp_addr_get_ippref(addr));
        break;
    case LM_AFI_LCAF:
        retval = _add_lcaf_entry(db, data, lisp_addr_get_lcaf(addr));
        break;
    default:
        retval = BAD;
        OOR_LOG(LWRN, "mdb_add_entry: called with unknown AFI:%u",
                lisp_addr_lafi(addr));
        break;
    }

    if (retval != GOOD) {
        OOR_LOG(LDBG_3, "mdb_add_entry: failed to insert entry %s",
                lisp_addr_to_char(addr));
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "mdb_add_entry: inserted %s", lisp_addr_to_char(addr));
        db->n_entries++;
        return (GOOD);
    }
}

void *
mdb_remove_entry(mdb_t *db, lisp_addr_t *laddr)
{
    ip_prefix_t *ippref;
    lisp_addr_t *taddr;
    void *ret = NULL;

    switch (lisp_addr_lafi(laddr)) {
    case LM_AFI_IP:
        /* make ippref */
        taddr = lisp_addr_clone(laddr);
        lisp_addr_ip_to_ippref(taddr);
        ippref = lisp_addr_get_ippref(taddr);
        ret = pt_remove_ippref(get_ip_pt_from_afi(db, ip_prefix_afi(ippref)), ippref);
        lisp_addr_del(taddr);
        break;
    case LM_AFI_IPPREF:
        ippref = lisp_addr_get_ippref(laddr);
        ret = pt_remove_ippref(
                get_ip_pt_from_afi(db, ip_prefix_afi(ippref)), ippref);
        break;
    case LM_AFI_LCAF:
        ret = _del_lcaf_entry(db, lisp_addr_get_lcaf(laddr));
        break;
    default:
        OOR_LOG(LWRN, "mdb_del_entry: called with unknown AFI:%u",
                lisp_addr_lafi(laddr));
        break;
    }

    if (ret) {
        db->n_entries--;
    }
    return (ret);
}

void *
mdb_lookup_entry(mdb_t *db, lisp_addr_t *laddr)
{
    patricia_node_t *node;

    node = _find_node(db, laddr, NOT_EXACT);
    if (node){
        return(node->data);
    }else{
        return(NULL);
    }
}

void *
mdb_lookup_entry_exact(mdb_t *db, lisp_addr_t *laddr)
{
    patricia_node_t *node;
    node = _find_node(db, laddr, EXACT);
    if (node){
        return(node->data);
    }else{
        return(NULL);
    }
}

/*
 * Patricia trie wrappers
 */

/* interface to insert entries into patricia */
int
pt_add_ippref(patricia_tree_t *pt, ip_prefix_t *ippref, void *data)
{
    patricia_node_t *node = NULL;

    node = pt_add_node(pt, ip_prefix_addr(ippref), ip_prefix_get_plen(ippref),
            data);

    if (!node) {
        return(BAD);
    } else {
        return(GOOD);
    }

}

int
pt_add_mc_addr(patricia_tree_t *strie, lcaf_addr_t *mcaddr, void *data)
{
    patricia_node_t     *snode          = NULL;
    patricia_node_t     *gnode          = NULL;
    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;
    ip_addr_t           *srcip          = NULL;
    ip_addr_t           *grpip          = NULL;
    uint8_t             splen, gplen;


    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

    if (lisp_addr_lafi(src) != LM_AFI_IP || lisp_addr_lafi(grp) != LM_AFI_IP) {
        OOR_LOG(LWRN, "pt_add_mc_addr: only IP type supported for S %s and G %s for now!",
                lisp_addr_to_char(src), lisp_addr_to_char(grp));
        return(BAD);
    }

    srcip = lisp_addr_ip(src);
    grpip = lisp_addr_ip(grp);

    splen = lcaf_mc_get_src_plen(mcaddr);
    gplen = lcaf_mc_get_grp_plen(mcaddr);



    /* insert src prefix in main db but without any data*/
    snode = pt_add_node(strie, srcip, splen, NULL);
    if (snode == NULL) {
        OOR_LOG(LDBG_3, "pt_add_mc_addr: Attempting to "
                "insert S-EID %s/%d in strie pt but failed", ip_addr_to_char(srcip), splen);
        return(BAD);
    }

    /* insert the G in the user1 field of the unicast pt node */
    if(!snode->data){
        /* create the patricia if not initialized */
        snode->data = (patricia_tree_t *)New_Patricia(ip_addr_get_size(grpip) * 8);

        if (!snode->data){
            OOR_LOG(LDBG_3, "pt_add_mc_addr: Can't create group pt!");
            return(BAD);
        }
    }

    /* insert grp in node->user1 db with the entry*/
    gnode = pt_add_node((patricia_tree_t *)snode->data, grpip, gplen, data);
    if (gnode == NULL){
        OOR_LOG(LDBG_3, "pt_add_mc_addr: Attempting to "
                "insert G %s/%d in the group pt but failed! ", ip_addr_to_char(grpip), gplen);
        return(BAD);
    }

    patricia_node_t *tnode;
    PATRICIA_WALK(((patricia_tree_t *)snode->data)->head, tnode) {
        printf("1");
    } PATRICIA_WALK_END;

    return(GOOD);
}

void *
pt_remove_ippref(patricia_tree_t *pt, ip_prefix_t *ippref)
{
    patricia_node_t         *node   = NULL;
    void                    *data   = NULL;

    node = pt_find_ip_node_exact(pt, ip_prefix_addr(ippref), ip_prefix_get_plen(ippref));

    if (node == NULL){
        OOR_LOG(LDBG_3,"pt_remove_ip_addr: Unable to locate cache entry %s for deletion",
                ip_prefix_to_char(ippref));
        return(BAD);
    } else {
        OOR_LOG(LDBG_3,"pt_remove_ip_addr: removing entry with key: %s",
                ip_prefix_to_char(ippref));
    }

    data = node->data;
    pt_remove_node(pt, node);

    return(data);
}

void *
pt_remove_mc_addr(patricia_tree_t *strie, lcaf_addr_t *mcaddr)
{
    patricia_node_t *gnode  = NULL;
    patricia_tree_t *gtrie  = NULL;
    lisp_addr_t     *src    = NULL;
    lisp_addr_t     *grp    = NULL;
    void            *data   = NULL;

    if (!strie) {
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: strie for %s not initialized. Aborting!",
                lcaf_addr_to_char(mcaddr));
        return(NULL);
    }

    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

    if (lisp_addr_lafi(src) != LM_AFI_IP || lisp_addr_lafi(grp) != LM_AFI_IP) {
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: only IP AFI supported for S and G");
        return(NULL);
    }


    gtrie = _get_grp_pt_for_mc_addr(strie, mcaddr, 1);

    if (!gtrie){
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: Couldn't find a group trie for mc "
                "address %s", lcaf_addr_to_char(mcaddr));
        return(NULL);
    }

    gnode = pt_find_ip_node_exact(gtrie, lisp_addr_ip(grp),
            lcaf_mc_get_grp_plen(mcaddr));

    if (!gnode){
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: The multicast address %s could not"
                " be found!", lcaf_addr_to_char(mcaddr));
        return(NULL);
    }

    data = gnode->data;
    pt_remove_node(gtrie, gnode);


    if (pt_test_if_empty(gtrie)){
        Destroy_Patricia(gtrie, NULL);
        pt_remove_node(strie, pt_find_ip_node_exact(strie, lisp_addr_ip(src),
                lcaf_mc_get_src_plen(mcaddr)));
    }

    return(data);
}

patricia_node_t *
pt_add_node(patricia_tree_t *pt, ip_addr_t *ipaddr, uint8_t prefixlen,
        void *data)
{
    patricia_node_t *node;
    prefix_t *prefix;

    prefix = pt_make_ip_prefix(ipaddr, prefixlen);
    node = patricia_lookup(pt, prefix);
    Deref_Prefix(prefix);

    if (!node) {
        OOR_LOG(LDBG_3, "pt_add_node: patricia_lookup did not return a node!");
        return(NULL);
    }

    /* node already exists */
    if (node->data) {
        OOR_LOG(LDBG_3, "pt_add_node: Node with prefix %s exists! Data won't be"
                " changed", ip_addr_to_char(ipaddr));
        return(node);
    }

    node->data = data;
    return(node);
}

inline void
pt_remove_node(patricia_tree_t *pt, patricia_node_t *node)
{
    patricia_remove(pt, node);
}


patricia_node_t *
pt_find_ip_node(patricia_tree_t *pt, ip_addr_t *ipaddr)
{
    patricia_node_t *node;
    prefix_t        *prefix;
    uint8_t         default_plen;

    default_plen = (ip_addr_afi(ipaddr) == AF_INET) ? 32: 128;
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

patricia_node_t *pt_find_mc_node(patricia_tree_t *strie, lcaf_addr_t *mcaddr, uint8_t exact) {
    patricia_node_t     *gnode          = NULL;
    lisp_addr_t         *src            = NULL;
    lisp_addr_t         *grp            = NULL;

    patricia_tree_t         *gtrie  = NULL;

    if (!strie) {
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: no S trie. Aborting");
        return(NULL);
    }

    src = lcaf_mc_get_src(mcaddr);
    grp = lcaf_mc_get_grp(mcaddr);

//    src = lcaf_mc_get_src(mcaddr);
//    grp = lcaf_mc_get_grp(mcaddr);

    if (lisp_addr_lafi(src) != LM_AFI_IP || lisp_addr_lafi(grp) != LM_AFI_IP) {
        OOR_LOG(LDBG_3, "pt_remove_mc_addr: only IP AFI supported for S and G");
        return(NULL);
    }

    gtrie = _get_grp_pt_for_mc_addr(strie, mcaddr, exact);

    if (!gtrie){
        OOR_LOG(LDBG_3, "pt_find_mc_node: Couldn't find a group trie for mc address %s",
                lcaf_addr_to_char(mcaddr));
        return(NULL);
    }

//    if (exact)
//        gnode = pt_find_ip_node_exact(gtrie, lisp_addr_get_ip(grp), lcaf_mc_get_grp_plen(mcaddr));
//    else
        gnode = pt_find_ip_node(gtrie, lisp_addr_ip(grp));


    return(gnode);
}


uint8_t pt_test_if_empty(patricia_tree_t *pt) {
    if (pt->num_active_node > 0)
        return(0);
    else
        return(1);
}

prefix_t
*pt_make_ip_prefix(ip_addr_t *ipaddr, uint8_t prefixlen)
{
    int afi = 0;
    prefix_t *prefix = NULL;

    afi = ip_addr_afi(ipaddr);

    if (afi != AF_INET && afi != AF_INET6) {
        OOR_LOG(LWRN, "make_ip_prefix_for_pt: Unsupported afi %s", afi);
        return(NULL);
    }

    (afi == AF_INET) ? assert(prefixlen <= 32) : assert(prefixlen <= 128);
    prefix = New_Prefix(afi, ip_addr_get_addr(ipaddr), prefixlen);
    if (!prefix) {
        OOR_LOG(LWRN, "make_ip_prefix_for_pt: Unable to allocate memory for "
                "prefix %s: %s", ip_addr_to_char(ipaddr), strerror(errno));
        return(NULL);
    }

    return(prefix);
}


/*
 * use this function to access all entries in the map-cache
 */
void mdb_for_each_entry_cb(mdb_t *mdb, void (*callback)(void *, void *), void *cb_data) {
    void    *it;

    mdb_foreach_ip_entry(mdb, it) {
        callback(it, cb_data);
    } mdb_foreach_ip_entry_end;

    mdb_foreach_mc_entry(mdb, it) {
        callback(it, cb_data);
    } mdb_foreach_mc_entry_end;

}


