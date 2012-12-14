/*
 * lispd_local_db.h
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



#include <netinet/in.h>
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include "patricia/patricia.h"


/*
 *  Patricia tree based databases
 */
patricia_tree_t *EIDv4_database           = NULL;
patricia_tree_t *EIDv6_database           = NULL;


/*
 *  Add a EID entry to the database.
 */
int add_identifier(lispd_identifier_elt *identifier);

patricia_node_t *lookup_eid_node(lisp_addr_t eid);

patricia_node_t *lookup_eid_exact_node(
        lisp_addr_t eid,
        int         eid_prefix_length);


/*
 * Initialize databases
 */

void db_init(void)
{
    EIDv4_database  = New_Patricia(sizeof(struct in_addr)  * 8);
    EIDv6_database  = New_Patricia(sizeof(struct in6_addr) * 8);

    if (!EIDv4_database || !EIDv6_database) {
        lispd_log_msg(LISP_LOG_CRIT, "db_init: Unable to allocate memory for database");
        exit(EXIT_FAILURE);
    };
}

patricia_tree_t* get_local_db(int afi)
{
    if (afi == AF_INET)
        return EIDv4_database;
    else
        return EIDv6_database;
}


void init_identifier (lispd_identifier_elt *identifier)
{
    int i = 0;
    identifier->eid_prefix.afi = -1;
    identifier->iid = -1;
    identifier->locator_count = 0;
    identifier->head_v4_locators_list = NULL;
    identifier->head_v6_locators_list = NULL;
    for (i = 0 ; i < 20 ; i++)
        identifier->v4_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
        identifier->v6_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
        identifier->locator_hash_table[i] = NULL;
}



/*
 *  Add a EID entry to the database.
 */
int add_identifier(lispd_identifier_elt *identifier)
{
    prefix_t            *prefix;
    patricia_node_t     *node;
    lisp_addr_t         eid_prefix;
    int                 eid_prefix_length;

    eid_prefix = identifier->eid_prefix;
    eid_prefix_length = identifier->eid_prefix_length;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_identifier: Unable to allocate memory for patrica_node_t: %s", strerror(errno));
        return(ERR_MALLOC);
    }

    switch(eid_prefix.afi) {
    case AF_INET:
        if ((prefix = New_Prefix(AF_INET, &(eid_prefix.address.ip), eid_prefix_length)) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "add_identifier: Unable to allocate memory for prefix_t (AF_INET): %s", strerror(errno));
            free(node);
            return(ERR_MALLOC);
        }
        node = patricia_lookup(EIDv4_database, prefix);
        break;
    case AF_INET6:
        if ((prefix = New_Prefix(AF_INET6, &(eid_prefix.address.ipv6), eid_prefix_length)) == NULL) {
            lispd_log_msg(LISP_LOG_WARNING, "add_identifier: Unable to allocate memory for prefix_t (AF_INET): %s", strerror(errno));
            free(node);
            return(ERR_MALLOC);
        }
        node = patricia_lookup(EIDv6_database, prefix);
        break;
    default:
        free(node);
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_identifier: Unknown afi (%d) when allocating prefix_t", eid_prefix.afi);
        return(ERR_AFI);
    }
    Deref_Prefix(prefix);

    if (node->data == NULL){            /* its a new node */
        node->data = (lispd_identifier_elt *) identifier;
        lispd_log_msg(LISP_LOG_DEBUG_2, "Identifier %s/%d inserted in the database",
                get_char_from_lisp_addr_t(identifier->eid_prefix),
                identifier->eid_prefix_length);
        return (GOOD);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_identifier: Identifier entry (%s/%d) already installed in the data base",
                get_char_from_lisp_addr_t(eid_prefix),eid_prefix_length);
        return (BAD);
    }
}

/*
 * Creates an identifier and add it into the database
 */

lispd_identifier_elt *new_identifier(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_identifier_elt *identifier;
    int i;

    if ((identifier=malloc(sizeof(lispd_identifier_elt)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"Couldn't allocate memory for lispd_identifier_elt: %s", strerror(errno));
        return (NULL);
    }
    identifier->eid_prefix =  eid_prefix;
    identifier->eid_prefix_length = eid_prefix_length;
    identifier->iid = iid;
    identifier->locator_count = 0;
    identifier->head_v4_locators_list = NULL;
    identifier->head_v6_locators_list = NULL;
    for (i = 0 ; i < 20 ; i++)
        identifier->v4_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
        identifier->v6_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
        identifier->locator_hash_table[i] = NULL;

    /*Add identifier to the data base */
    if (add_identifier(identifier)!=GOOD)
        return (NULL);
    return (identifier);
}


patricia_node_t *lookup_eid_node(lisp_addr_t eid)
{
    patricia_node_t *node = NULL;
    prefix_t prefix;

    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = 32;
        prefix.ref_count = 0;
        prefix.add.sin.s_addr = eid.address.ip.s_addr;
        node = patricia_search_best(EIDv4_database, &prefix);
        break;
    case AF_INET6:
        prefix.family = AF_INET6;
        prefix.bitlen = 128;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
        node = patricia_search_best(EIDv6_database, &prefix);
        break;
    default:
        break;
    }

    if ( node==NULL ){
        lispd_log_msg(LISP_LOG_DEBUG_2, "The entry %s is not found in the data base", get_char_from_lisp_addr_t(eid));
    }
    return(node);
}

patricia_node_t *lookup_eid_exact_node(
        lisp_addr_t eid,
        int         eid_prefix_length)
{
    patricia_node_t *node = NULL;
    prefix_t prefix;
    switch(eid.afi) {
    case AF_INET:
        prefix.family = AF_INET;
        prefix.bitlen = eid_prefix_length;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin), &(eid.address.ip), sizeof(struct in_addr));
        node = patricia_search_exact(EIDv4_database, &prefix);
        break;
    case AF_INET6:
        prefix.family = AF_INET6;
        prefix.bitlen = eid_prefix_length;
        prefix.ref_count = 0;
        memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
        node = patricia_search_exact(EIDv6_database, &prefix);
        break;
    default:
        break;
    }

    if (node == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "The entry %s is not found in the data base", get_char_from_lisp_addr_t(eid));
    }
    return(node);
}


/*
 * lookup_eid_in_db
 *
 * Look up a given eid in the database, returning the
 * lispd_identifier_elt of this EID if it exists or NULL.
 */
lispd_identifier_elt *lookup_eid_in_db(lisp_addr_t eid)
{
    lispd_identifier_elt *identifier;
    patricia_node_t *result;

    result = lookup_eid_node(eid);
    if (result == NULL){
        return(NULL);
    }
    identifier = (lispd_identifier_elt *)(result->data);
    return(identifier);
}

/*
 * lookup_eid_in_db
 *
 *  Look up a given eid in the database, returning the
 * lispd_identifier_elt containing the exact EID if it exists or NULL.
 */
lispd_identifier_elt *lookup_eid_exact_in_db(lisp_addr_t eid_prefix, int eid_prefix_length)
{
    lispd_identifier_elt *identifier;
    patricia_node_t *result;
    result = lookup_eid_exact_node(eid_prefix,eid_prefix_length);
    if (result == NULL){
        return(NULL);
    }
    identifier = (lispd_identifier_elt *)(result->data);

    return(identifier);
}


/*
 * Generets a locator element and add it to locators list
 */

lispd_locator_elt   *new_locator (
        lispd_identifier_elt 		*identifier,
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     locator_type,
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight
)
{
    lispd_locators_list 	*locator_list, *aux_locator_list_prev, *aux_locator_list_next;
    lispd_locator_elt 		*locator;
    int 					cmp;

    if ((locator_list = malloc(sizeof(lispd_locators_list))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_locator: Unable to allocate memory for lispd_locator_list: %s", strerror(errno));
        return(NULL);
    }
    if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        free(locator_list);
        return(NULL);
    }

    locator_list->next = NULL;
    locator_list->locator = locator;
    /* Initialize locator */
    locator->locator_addr = locator_addr;
    locator->locator_type = locator_type;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;
    locator->rloc_probing_nonces = NULL;
    locator->state = state;


    /* Add the locator into the list*/
    if (locator_addr->afi == AF_INET)
    {
        if (locator_type == LOCAL_LOCATOR){/* If it's a local locator, we should store it in order*/
            if (identifier->head_v4_locators_list == NULL){
                identifier->head_v4_locators_list = locator_list;
            }else{
                aux_locator_list_prev = NULL;
                aux_locator_list_next = identifier->head_v4_locators_list;
                while (aux_locator_list_next){
                    cmp = memcmp(&(locator_addr->address.ip),&(aux_locator_list_next->locator->locator_addr->address.ip),sizeof(struct in_addr));
                    if (cmp < 0)
                        break;
                    if (cmp == 0){
                        lispd_log_msg(LISP_LOG_DEBUG_2, "new_locator: The locator %s already exists in the identifier %s/%d",
                                get_char_from_lisp_addr_t(*locator_addr),
                                get_char_from_lisp_addr_t(identifier->eid_prefix),
                                identifier->eid_prefix_length);
                        free (locator_list);
                        free (locator);
                        return (aux_locator_list_next->locator);
                    }
                    aux_locator_list_prev = aux_locator_list_next;
                    aux_locator_list_next = aux_locator_list_next->next;
                }
                if (aux_locator_list_prev == NULL){
                    locator_list->next = aux_locator_list_next;
                    identifier->head_v4_locators_list = locator_list;
                }else{
                    aux_locator_list_prev->next = locator_list;
                    locator_list->next = aux_locator_list_next;
                }
            }
        }else{
            if (identifier->head_v4_locators_list == NULL){
                identifier->head_v4_locators_list = locator_list;
            }else{
                aux_locator_list_prev = identifier->head_v4_locators_list;
                while (aux_locator_list_prev->next)
                    aux_locator_list_prev = aux_locator_list_prev->next;
                aux_locator_list_prev->next = locator_list;
            }
        }
    }else if (AF_INET6){
        if (locator_type == LOCAL_LOCATOR){/* If it's a local locator, we should store it in order*/
            if (identifier->head_v6_locators_list == NULL){
                identifier->head_v6_locators_list = locator_list;
            }else{
                aux_locator_list_prev = NULL;
                aux_locator_list_next = identifier->head_v6_locators_list;
                while (aux_locator_list_next){
                    cmp = memcmp(&(locator_addr->address.ipv6),&(aux_locator_list_next->locator->locator_addr->address.ipv6),sizeof(struct in6_addr));
                    if (cmp < 0)
                        break;
                    if (cmp == 0){
                        lispd_log_msg(LISP_LOG_DEBUG_2, "The locator %s already exists in the identifier %s/%d",
                                get_char_from_lisp_addr_t(*locator_addr),
                                get_char_from_lisp_addr_t(identifier->eid_prefix),
                                identifier->eid_prefix_length);
                        free (locator_list);
                        free (locator);
                        return (aux_locator_list_next->locator);
                    }
                    aux_locator_list_prev = aux_locator_list_next;
                    aux_locator_list_next = aux_locator_list_next->next;
                }
                if (aux_locator_list_prev == NULL){
                    locator_list->next = aux_locator_list_next;
                    identifier->head_v6_locators_list = locator_list;
                }else{
                    aux_locator_list_prev->next = locator_list;
                    locator_list->next = aux_locator_list_next;
                }
            }
        }else{
            if (identifier->head_v6_locators_list == NULL){
                identifier->head_v6_locators_list = locator_list;
            }else{
                aux_locator_list_prev = identifier->head_v6_locators_list;
                while (aux_locator_list_prev->next)
                    aux_locator_list_prev = aux_locator_list_prev->next;
                aux_locator_list_prev->next = locator_list;
            }
        }
    }
    identifier->locator_count++;

    return (locator);
}





/*
 * del_identifier_entry()
 *
 * Delete an EID mapping from the data base
 */
void del_identifier_entry(
        lisp_addr_t eid,
        int prefixlen,
        uint8_t local_identifier)
{
    lispd_identifier_elt *entry;
    patricia_node_t      *result;
    result = lookup_eid_exact_node(eid, prefixlen);
    if (result == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"del_identifier_entry: Unable to locate eid entry %s/%d for deletion",
                get_char_from_lisp_addr_t(eid),prefixlen);
        return;
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"Deleting EID entry %s/%d", get_char_from_lisp_addr_t(eid),prefixlen);
    }

    /*
     * Remove the entry from the trie
     */
    entry = (lispd_identifier_elt *)(result->data);
    if (eid.afi==AF_INET)
        patricia_remove(EIDv4_database, result);
    else
        patricia_remove(EIDv6_database, result);
    free_locator_list(entry->head_v4_locators_list, local_identifier);
    free_locator_list(entry->head_v6_locators_list, local_identifier);
    free(entry);
}

/*
 * Free memory of lispd_locator_list. If it's a local locator, we don't remove
 * the address as it can be used for other locators of other EIDs
 */

void free_locator_list(
        lispd_locators_list     *list,
        uint8_t                 local_locator)
{
    lispd_locators_list  * locator_list, *aux_locator_list;
    /*
     * Free the locators
     */
    locator_list = list;
    while (locator_list)
    {
        if (locator_list->locator->rloc_probing_nonces)
            free (locator_list->locator->rloc_probing_nonces);
        if (local_locator == FALSE){
            free (locator_list->locator->locator_addr);
            free (locator_list->locator->state);
        }
        free (locator_list->locator);
        aux_locator_list = locator_list;
        locator_list = locator_list->next;
        free (aux_locator_list);
    }
}

/*
 * Free memory of lispd_identifier_elt. We indicate if the identifier is local or remote
 */
void free_lispd_identifier_elt(
        lispd_identifier_elt    *identifier,
        uint8_t                 local_identifier)
{
    /*
     * Free the locators list
     */
    free_locator_list(identifier->head_v4_locators_list, local_identifier);
    free_locator_list(identifier->head_v6_locators_list, local_identifier);
    free(identifier);

}

//modified by arnatal
lisp_addr_t get_main_eid(int afi){
    lisp_addr_t               eid;
    patricia_node_t           *node;
    lispd_identifier_elt        *entry;
    patricia_tree_t *database;

    switch (afi){
    case AF_INET:
        database = EIDv4_database;
        break;
    case AF_INET6:
        database = EIDv6_database;
        break;
    }

    PATRICIA_WALK(database->head, node) {
        entry = ((lispd_identifier_elt *)(node->data));
        eid = entry->eid_prefix;
    } PATRICIA_WALK_END;

    return (eid);
}

/*
 * dump local identifier
 */
void dump_identifier(
        lispd_identifier_elt    *identifier,
        int                     log_level)
{
    lispd_locators_list         *locator_iterator_array[2]= {NULL,NULL};
    lispd_locators_list         *locator_iterator = NULL;
    lispd_locator_elt           *locator = NULL;
    int                         ctr = 0;

    lispd_log_msg(log_level,"%s/%d (IID = %d)\n ", get_char_from_lisp_addr_t(identifier->eid_prefix),
            identifier->eid_prefix_length, identifier->iid);

    if (identifier->locator_count > 0){
        lispd_log_msg(log_level,"       Locator               State    Priority/Weight\n");
        locator_iterator_array[0] = identifier->head_v4_locators_list;
        locator_iterator_array[1] = identifier->head_v6_locators_list;
        // Loop through the locators and print each

        for (ctr = 0 ; ctr < 2 ; ctr++){
            locator_iterator = locator_iterator_array[ctr];
            while (locator_iterator != NULL) {
                locator = locator_iterator->locator;
                lispd_log_msg(log_level," %15s ", get_char_from_lisp_addr_t(*(locator->locator_addr)));
                if (locator->locator_addr->afi == AF_INET)
                    lispd_log_msg(log_level," %15s ", locator->state ? "Up" : "Down");
                else
                    lispd_log_msg(log_level," %5s ", locator->state ? "Up" : "Down");
                lispd_log_msg(log_level,"         %3d/%-3d \n", locator->priority, locator->weight);
                locator_iterator = locator_iterator->next;
            }
        }
        lispd_log_msg(log_level,"\n");
    }
}



/*
 * dump local identifier list
 */
void dump_local_eids(int log_level)
{
    patricia_tree_t     *dbs [2] = {EIDv4_database, EIDv6_database};
    int                 ctr;

    patricia_node_t             *node;
    lispd_identifier_elt        *entry;


    lispd_log_msg(LOG_DEBUG,"*** LISP Local EIDs ***\n\n");

    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(dbs[ctr]->head, node) {
            entry = ((lispd_identifier_elt *)(node->data));
            dump_identifier(entry, log_level);
        } PATRICIA_WALK_END;
    }
}

