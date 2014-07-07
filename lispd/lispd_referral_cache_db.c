/*
 * lispd_referral_cache_db.c
 *
 *  Created on: Sep 26, 2013
 *      Author: alopez
 */

#include "lispd_lib.h"
#include "lispd_map_referral.h"
#include "lispd_referral_cache_db.h"
#include "patricia/patricia.h"


patricia_tree_t *ipv4_referral_cache           = NULL;
patricia_tree_t *ipv6_referral_cache           = NULL;
/* Database to store the Map Server referrals */
patricia_tree_t *ipv4_ms_referral_cache        = NULL;
patricia_tree_t *ipv6_ms_referral_cache        = NULL;

/*********************************** FUNCTIONS DECLARATION ************************/

/*
 * Given an eid , return the best patricai node in the map cache database (the most
 * specific prefix that contains the EID) or NULL if no one is found
 */
patricia_node_t *lookup_referral_cache_node(
        lisp_addr_t     eid,
        int             databases_to_use);

/*
 * Given an eid , return the node in the referral cache database  of this EID
 * or NULL if it doesn't exist
 */
patricia_node_t *lookup_referral_cache_exact_node(
        lisp_addr_t     eid,
        int             prefixlen,
        int             databases_to_use);


/************************************ FUNCTIONS  **********************************/

/*
 * Create referral cache database
 */
void init_referral_cache()
{
    lispd_log_msg(LISP_LOG_DEBUG_2,  " Creating referral cache...");

    ipv4_referral_cache = New_Patricia(sizeof(struct in_addr) * 8);
    ipv6_referral_cache = New_Patricia(sizeof(struct in6_addr) * 8);
    ipv4_ms_referral_cache = New_Patricia(sizeof(struct in_addr) * 8);
    ipv6_ms_referral_cache = New_Patricia(sizeof(struct in6_addr) * 8);


    if (ipv4_referral_cache == NULL || ipv6_referral_cache == NULL || ipv4_ms_referral_cache == NULL || ipv6_ms_referral_cache == NULL ){
        lispd_log_msg(LISP_LOG_CRIT, "init_referral_cache: Unable to allocate memory for referral cache database");
        exit_cleanup();
    }
}

/*
 * Remove referral cache database
 */
void drop_referral_cache()
{
    patricia_tree_t                 **dbs [4]        = {&ipv4_referral_cache, &ipv6_referral_cache,
            &ipv4_ms_referral_cache, &ipv6_ms_referral_cache};
    int                             ctr             = 0;

    lispd_log_msg(LISP_LOG_DEBUG_2,  " Droping referral cache...");

    for (ctr = 0 ; ctr < 4 ; ctr++){
        if (*dbs[ctr] != NULL){
            Destroy_Patricia (*dbs[ctr], free_referral_cache_entry);
            *dbs[ctr] = NULL;
        }
    }
}


/*
 *  Add a referral cache entry to the database.
 */
int add_referral_cache_entry_to_db(lispd_referral_cache_entry *entry)
{
    prefix_t                    *prefix             = NULL;
    patricia_node_t             *node               = NULL;
    lispd_referral_cache_entry  *entry2             = NULL;
    lisp_addr_t                 eid_prefix;
    int                         eid_prefix_length   = 0;

    eid_prefix = entry->mapping->eid_prefix;
    eid_prefix_length = entry->mapping->eid_prefix_length;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_referral_cache_entry_to_db: Unable to allocate memory for patrica_node_t: %s", strerror(errno));
        return(ERR_MALLOC);
    }

    switch(eid_prefix.afi) {
    case AF_INET:
        if ((prefix = New_Prefix(AF_INET, &(eid_prefix.address.ip), eid_prefix_length)) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "add_referral_cache_entry_to_db: Unable to allocate memory for prefix_t  (AF_INET): %s", strerror(errno));
            free(node);
            return(ERR_MALLOC);
        }
        if (entry->act_entry_type == MS_ACK || entry->act_entry_type == MS_NOT_REGISTERED){
            node = patricia_lookup(ipv4_ms_referral_cache, prefix);
        }else{
            node = patricia_lookup(ipv4_referral_cache, prefix);
        }
        break;
    case AF_INET6:
        if ((prefix = New_Prefix(AF_INET6, &(eid_prefix.address.ipv6), eid_prefix_length)) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "add_referral_cache_entry_to_db: Unable to allocate memory for prefix_t  (AF_INET6): %s", strerror(errno));
            free(node);
            return(ERR_MALLOC);
        }
        if (entry->act_entry_type == MS_ACK || entry->act_entry_type == MS_NOT_REGISTERED){
            node = patricia_lookup(ipv6_ms_referral_cache, prefix);
        }else{
            node = patricia_lookup(ipv6_referral_cache, prefix);
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_referral_cache_entry_to_db: Unknown afi (%d) when allocating prefix_t", eid_prefix.afi);
        free(node);
        return(ERR_AFI);
    }
    Deref_Prefix(prefix);
    if (node->data != NULL){            /* The node already exists */
        entry2 = (lispd_referral_cache_entry *)node->data;
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_referral_cache_entry_to_db: Referral cache entry (%s/%d) already installed in the data base",
                get_char_from_lisp_addr_t(entry2->mapping->eid_prefix),entry2->mapping->eid_prefix_length);
        return (BAD);
    }
    node->data = (lispd_referral_cache_entry *) entry;
    lispd_log_msg(LISP_LOG_DEBUG_2, "Added referral cache entry for EID: %s/%d",
            get_char_from_lisp_addr_t(entry->mapping->eid_prefix),eid_prefix_length);
    return (GOOD);
}

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
        int             ttl)
{
    lispd_referral_cache_entry      *referral_cache_entry   = NULL;
    lispd_mapping_elt               *mapping                = NULL;
    lispd_locator_elt               *locator                = NULL;
    uint8_t                         is_new                  = FALSE;

    referral_cache_entry = lookup_referral_cache_exact (eid_prefix, eid_prefix_length,DDT_NOT_END_PREFIX_DATABASES);
    /* If entry not exit, add the referral entry to the database */
    if (referral_cache_entry == NULL){
        if ((mapping = new_mapping(eid_prefix, eid_prefix_length, iid)) == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_1, "add_update_ddt_static_entry_to_db: Couldn't generate ddt mapping");
            return (BAD);
        }
        if ((referral_cache_entry = new_referral_cache_entry (mapping, NODE_REFERRAL, ttl)) == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_1, "add_update_ddt_static_entry_to_db: Couldn't generate referral cache entry");
            free_mapping_elt(mapping);
            return (BAD);
        }
        if ((add_referral_cache_entry_to_db(referral_cache_entry)) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1, "add_update_ddt_static_entry_to_db: Couldn't add referral cache entry to the database");
            free_referral_cache_entry (referral_cache_entry);
            return (BAD);
        }
        is_new = TRUE;
    }

    if ((locator = new_static_rmt_locator ( ddt_locator_address, UP, priority, weight, 255, 0)) == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"add_update_ddt_static_entry_to_db: Unable to generate locator");
        if (is_new == TRUE){
            del_referral_cache_entry_from_db(referral_cache_entry);
        }
        return (BAD);
    }

    if ((err=add_locator_to_mapping (referral_cache_entry->mapping,locator))!=GOOD){
        // We don't call free_locator because ddt_locator_address is allocated outside this function
    	free_locator(locator);
        if (is_new == TRUE){
            del_referral_cache_entry_from_db(referral_cache_entry);
        }
        return (BAD);
    }

    return (GOOD);
}


/*
 * Remove a referral cache entry from the database and all its children nodes.
 * To remove the node from the list of childrens of its parent, call firstly the function
 * remove_referral_cache_entry_from_parent_node
 * @param entry Referral cache node to be removed from the database
 */
void del_referral_cache_entry_from_db(lispd_referral_cache_entry  *entry)
{
    patricia_node_t             *node                                   = NULL;

    if (entry->children_nodes != NULL){
        del_referral_cache_list_from_db(entry->children_nodes);
        entry->children_nodes = NULL;
    }

    if (entry->act_entry_type == MS_ACK || entry->act_entry_type == MS_NOT_REGISTERED){
        node = lookup_referral_cache_exact_node(entry->mapping->eid_prefix, entry->mapping->eid_prefix_length,DDT_END_PREFIX_DATABASES);
    }else{
        node = lookup_referral_cache_exact_node(entry->mapping->eid_prefix, entry->mapping->eid_prefix_length,DDT_NOT_END_PREFIX_DATABASES);
    }
    if (node != NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"del_referral_cache_entry_from_db: Deleting referral cache entry: %s/%d",
                        get_char_from_lisp_addr_t(entry->mapping->eid_prefix),entry->mapping->eid_prefix_length);
        /*
         * Remove the entry from the database
         */
        if (entry->mapping->eid_prefix.afi==AF_INET){
            if (entry->act_entry_type == MS_ACK || entry->act_entry_type == MS_NOT_REGISTERED){
                patricia_remove(ipv4_ms_referral_cache, node);
            }else{
                patricia_remove(ipv4_referral_cache, node);
            }
        }else{
            if (entry->act_entry_type == MS_ACK || entry->act_entry_type == MS_NOT_REGISTERED){
                patricia_remove(ipv6_ms_referral_cache, node);
            }else{
                patricia_remove(ipv6_referral_cache, node);
            }
        }
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_2,"del_referral_cache_entry_from_db: Unable to locate referral cache entry %s/%d for deletion",
                        get_char_from_lisp_addr_t(entry->mapping->eid_prefix),entry->mapping->eid_prefix_length);
    }

    reset_pending_referrals_with_expired_previous_referral(entry);

    free_referral_cache_entry(entry);
}

/*
 * Remove from the database all lispd_referral_cache_entry of a lispd_referral_cache_list.
 * @param referral_cache_list List of referral cache elements to be removed
 */
void del_referral_cache_list_from_db(lispd_referral_cache_list *referral_cache_list)
{
    lispd_referral_cache_entry  *referral_entry     = NULL;
    lispd_referral_cache_list   *aux_referral_list  = NULL;

    while (referral_cache_list != NULL){
        referral_entry = referral_cache_list->referral_cache_entry;
        del_referral_cache_entry_from_db(referral_entry);
        aux_referral_list = referral_cache_list;
        referral_cache_list = referral_cache_list->next;
        free(aux_referral_list);
    }
}

/*
 * Given an eid , return the best patricai node in the map cache database (the most
 * specific prefix that contains the EID) or NULL if no one is found
 */

patricia_node_t *lookup_referral_cache_node(
        lisp_addr_t     eid,
        int             databases_to_use)
{
    patricia_node_t   *node = NULL;
    prefix_t          prefix;

    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = 32;
        prefix.ref_count = 0;
        prefix.add.sin.s_addr = eid.address.ip.s_addr;
        switch (databases_to_use){
        case DDT_ALL_DATABASES:
            node = patricia_search_best(ipv4_ms_referral_cache, &prefix);
            if (node == NULL){
                node = patricia_search_best(ipv4_referral_cache, &prefix);
            }
            break;
        case DDT_END_PREFIX_DATABASES:
            node = patricia_search_best(ipv4_ms_referral_cache, &prefix);
            break;
        case DDT_NOT_END_PREFIX_DATABASES:
            node = patricia_search_best(ipv4_referral_cache, &prefix);
            break;
        }
        break;
        case AF_INET6:
            prefix.family = AF_INET6;
            prefix.bitlen = 128;
            prefix.ref_count = 0;
            memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
            node = patricia_search_best(ipv6_ms_referral_cache, &prefix);
            switch (databases_to_use){
            case DDT_ALL_DATABASES:
                node = patricia_search_best(ipv6_ms_referral_cache, &prefix);
                if (node == NULL){
                    node = patricia_search_best(ipv6_referral_cache, &prefix);
                }
                break;
            case DDT_END_PREFIX_DATABASES:
                node = patricia_search_best(ipv6_ms_referral_cache, &prefix);
                break;
            case DDT_NOT_END_PREFIX_DATABASES:
                node = patricia_search_best(ipv6_referral_cache, &prefix);
                break;
            }
            break;
            default:
                break;
    }

    if (node==NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_referral_cache_node: The entry %s is not found in the referral cache", get_char_from_lisp_addr_t(eid));
    }

    return(node);
}

/*
 * Given an eid , return the node in the referral cache database  of this EID
 * or NULL if it doesn't exist
 */
patricia_node_t * lookup_referral_cache_exact_node(
        lisp_addr_t     eid,
        int             prefixlen,
        int             databases_to_use)
{
    patricia_node_t     *node = NULL;
    prefix_t            prefix;

    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = prefixlen;
        prefix.ref_count = 0;
        prefix.add.sin.s_addr = eid.address.ip.s_addr;
        switch (databases_to_use){
        case DDT_ALL_DATABASES:
            node = patricia_search_exact(ipv4_ms_referral_cache, &prefix);
            if (node == NULL){
                node = patricia_search_exact(ipv4_referral_cache, &prefix);
            }
            break;
        case DDT_END_PREFIX_DATABASES:
            node = patricia_search_exact(ipv4_ms_referral_cache, &prefix);
            break;
        case DDT_NOT_END_PREFIX_DATABASES:
            node = patricia_search_exact(ipv4_referral_cache, &prefix);
            break;
        }
        break;
    case AF_INET6:
        prefix.family = AF_INET6;
        prefix.bitlen = prefixlen;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
        switch (databases_to_use){
        case DDT_ALL_DATABASES:
            node = patricia_search_exact(ipv6_ms_referral_cache, &prefix);
            if (node == NULL){
                node = patricia_search_exact(ipv6_referral_cache, &prefix);
            }
            break;
        case DDT_END_PREFIX_DATABASES:
            node = patricia_search_exact(ipv6_ms_referral_cache, &prefix);
            break;
        case DDT_NOT_END_PREFIX_DATABASES:
            node = patricia_search_exact(ipv6_referral_cache, &prefix);
            break;
        }
        break;
    default:
        break;
    }

    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "lookup_referral_cache_exact_node: The entry %s/%d is not found in the referral cache", get_char_from_lisp_addr_t(eid),prefixlen);
    }

    return(node);
}

/*
 * Look up a given eid in the database, returning the
 * lispd_referral_cache_entry of this EID if it exists or NULL.
 */

lispd_referral_cache_entry *lookup_referral_cache(
        lisp_addr_t     eid,
        int             databases_to_use)
{
    patricia_node_t           *node  = NULL;
    lispd_referral_cache_entry     *entry = NULL;

    node = lookup_referral_cache_node(eid, databases_to_use);
    if ( node == NULL ){
        return(NULL);
    }
    entry = (lispd_referral_cache_entry *)(node->data);

    return(entry);
}


/*
 * Find an exact match for a prefix/prefixlen if possible
 */
lispd_referral_cache_entry *lookup_referral_cache_exact(
        lisp_addr_t     eid,
        int             prefixlen,
        int             databases_to_use)
{
    lispd_referral_cache_entry   *entry = NULL;
    patricia_node_t              *node  = NULL;

    node = lookup_referral_cache_exact_node(eid,prefixlen,databases_to_use);
    if ( node == NULL ){
        return(NULL);
    }
    entry = (lispd_referral_cache_entry *)(node->data);

    return(entry);
}

/*
 * Returns the lispd_referral_cache_entry which represents the root prefix according to the IP afi
 */
lispd_referral_cache_entry *get_root_referral_cache(int afi)
{
    lispd_referral_cache_entry      *root_referral_entry    = NULL;
    lisp_addr_t                     root_eid_prefix         = {.afi=AF_UNSPEC};
    int                             root_eid_prefix_length  = 0;

    switch (afi){
    case AF_INET:
        get_lisp_addr_from_char ("0.0.0.0", &root_eid_prefix);
        break;
    case AF_INET6:
        get_lisp_addr_from_char ("0::0", &root_eid_prefix);
        break;
    }

    root_referral_entry = lookup_referral_cache_exact(root_eid_prefix,root_eid_prefix_length,DDT_NOT_END_PREFIX_DATABASES);

    return (root_referral_entry);
}

/*
 * Return TRUE if no ddt root nodes present
 */
int is_referral_db_empty()
{

    lispd_referral_cache_entry     *entry   = NULL;
    lisp_addr_t                    address  = {.afi=AF_UNSPEC};
    get_lisp_addr_from_char("0.0.0.0",&address);
    entry =lookup_referral_cache_exact(address,0,DDT_NOT_END_PREFIX_DATABASES);
    if (entry != NULL){
        return (FALSE);
    }
    get_lisp_addr_from_char("0::0",&address);
    entry =lookup_referral_cache_exact(address,0,DDT_NOT_END_PREFIX_DATABASES);
    if (entry != NULL){
        return (FALSE);
    }
    return (TRUE);
}

/*
 * dump_referral_cache
 */
void dump_referral_cache_db(int log_level)
{
    patricia_tree_t     *dbs [2]    = {ipv4_referral_cache, ipv6_referral_cache};
    patricia_tree_t     *ms_dbs [2] = {ipv4_ms_referral_cache, ipv6_ms_referral_cache};
    int                 ctr         = 0;

    patricia_node_t                 *node;
    lispd_referral_cache_entry      *entry;


    lispd_log_msg(log_level,"**************** DDT: LISP Referral Cache ******************\n");
    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(dbs[ctr]->head, node) {
            entry = ((lispd_referral_cache_entry *)(node->data));
            dump_referral_cache_entry (entry, log_level);
        } PATRICIA_WALK_END;
    }
    lispd_log_msg(log_level,"**************** DDT: LISP MS Referral Cache ******************\n");
    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(ms_dbs[ctr]->head, node) {
            entry = ((lispd_referral_cache_entry *)(node->data));
            dump_referral_cache_entry (entry, log_level);
        } PATRICIA_WALK_END;
    }
    lispd_log_msg(log_level,"*******************************************************\n");
}
