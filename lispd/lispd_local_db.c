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

#include "lispd_local_db.h"
#include "patricia/patricia.h"


/*
 *  Patricia tree based databases
 */
patricia_tree_t *EIDv4_database           = NULL;
patricia_tree_t *EIDv6_database           = NULL;


/*
 *  Add a map cache entry to the database.
 */
int add_identifier(lispd_identifier_elt *identifier);

int lookup_eid_node(lisp_addr_t eid, patricia_node_t **node);

int lookup_eid_exact_node(lisp_addr_t eid, int eid_prefix_length, patricia_node_t **node);


/*
 * Initialize databases
 */

int db_init(void) {
    EIDv4_database  = New_Patricia(sizeof(struct in_addr)  * 8);
    EIDv6_database  = New_Patricia(sizeof(struct in6_addr) * 8);

    if (!EIDv4_database || !EIDv6_database) {
        syslog(LOG_CRIT, "malloc (database): %s", strerror(errno));
        return(BAD);
    }
    return(GOOD);
}

void init_identifier (lispd_identifier_elt *identifier)
{
	int i = 0;
	identifier->eid_prefix.afi = -1;
    identifier->iid = 0;
    identifier->locator_count = 0;
    identifier->head_v4_locators_list = NULL;
    identifier->head_v6_locators_list = NULL;
    for (i = 0 ; i < 100 ; i++)
    	identifier->v4_locator_has_table[i] = NULL;
    for (i = 0 ; i < 100 ; i++)
        identifier->v6_locator_has_table[i] = NULL;
}



/*
 *  Add a map cache entry to the database.
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
        syslog(LOG_ERR, "caouldn't allocate patrica_node_t");
        return(BAD);
    }

    switch(eid_prefix.afi) {
    case AF_INET:
        if ((prefix = New_Prefix(AF_INET, &(eid_prefix.address.ip), eid_prefix_length)) == NULL) {
            syslog(LOG_ERR, "couldn't alocate prefix_t for AF_INET");
            free(node);
            return(BAD);
        }
        node = patricia_lookup(EIDv4_database, prefix);
        break;
    case AF_INET6:
        if ((prefix = New_Prefix(AF_INET6, &(eid_prefix.address.ipv6), eid_prefix_length)) == NULL) {
            syslog(LOG_ERR, "couldn't alocate prefix_t for AF_INET6");
            free(node);
            return(BAD);
        }
        node = patricia_lookup(EIDv6_database, prefix);
        break;
    default:
        free(node);
        syslog(LOG_ERR, "Unknown afi (%d) when allocating prefix_t", eid_prefix.afi);
        return(ERR_AFI);
    }
    Deref_Prefix(prefix);

    if (node->data == NULL){            /* its a new node */
        node->data = (lispd_identifier_elt *) identifier;
        return (GOOD);
    }else{
        syslog(LOG_ERR, "WARNING: Identifier entry (%s/%d) already installed in the data base",
                get_char_from_lisp_addr_t(eid_prefix),eid_prefix_length);
        return (BAD);
    }
}

/*
 * Creates an identifier and add it into the database
 */

lispd_identifier_elt *new_identifier(lisp_addr_t    eid_prefix,
        uint8_t                                     eid_prefix_length,
        int                                         iid)
{
    lispd_identifier_elt *identifier;
    int i;

    if ((identifier=malloc(sizeof(lispd_identifier_elt)))==NULL){
        syslog (LOG_ERR,"Couldn't allocate memory for lispd_identifier_elt");
        return (NULL);
    }
    identifier->eid_prefix =  eid_prefix;
    identifier->eid_prefix_length = eid_prefix_length;
    identifier->iid = iid;
    identifier->head_v4_locators_list = NULL;
    identifier->head_v6_locators_list = NULL;
    for (i = 0 ; i < 100 ; i++)
            identifier->v4_locator_has_table[i] = NULL;
    for (i = 0 ; i < 100 ; i++)
            identifier->v6_locator_has_table[i] = NULL;

    /*Add identifier to the data base */
    if (add_identifier(identifier)!=GOOD)
        return NULL;
    return identifier;
}


int lookup_eid_node(lisp_addr_t eid, patricia_node_t **node)
{
  prefix_t prefix;

  switch(eid.afi) {
        case AF_INET:
            prefix.family = AF_INET;
            prefix.bitlen = 32;
            prefix.ref_count = 0;
            prefix.add.sin.s_addr = eid.address.ip.s_addr;
            *node = patricia_search_best(EIDv4_database, &prefix);
            break;
        case AF_INET6:
            prefix.family = AF_INET6;
            prefix.bitlen = 128;
            prefix.ref_count = 0;
            memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
            *node = patricia_search_best(EIDv6_database, &prefix);
            break;
        default:
            break;
    }

  if (!node)
  {
      syslog (LOG_DEBUG, "The entry %s is not found in the data base", get_char_from_lisp_addr_t(eid));
      return(BAD);
  }
  return(GOOD);
}

int lookup_eid_exact_node(lisp_addr_t eid, int eid_prefix_length, patricia_node_t **node)
{
  prefix_t prefix;

  switch(eid.afi) {
        case AF_INET:
            prefix.family = AF_INET;
            prefix.bitlen = eid_prefix_length;
            prefix.ref_count = 0;
            prefix.add.sin.s_addr = eid.address.ip.s_addr;
            *node = patricia_search_exact(EIDv4_database, &prefix);
            break;
        case AF_INET6:
            prefix.family = AF_INET6;
            prefix.bitlen = eid_prefix_length;
            prefix.ref_count = 0;
            memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
            *node = patricia_search_exact(EIDv6_database, &prefix);
            break;
        default:
            break;
    }

  if (!node)
  {
      syslog (LOG_DEBUG, "The entry %s is not found in the data base", get_char_from_lisp_addr_t(eid));
      return(BAD);
  }
  return(GOOD);
}


/*
 * lookup_eid_in_db
 *
 * Look up a given ipv4 eid in the database, returning true and
 * filling in the entry pointer if found, or false if not found.
 */
int lookup_eid_in_db(lisp_addr_t eid, lispd_identifier_elt **identifier)
{
  patricia_node_t *result;

  if (lookup_eid_node(eid,&result)!=GOOD){
      syslog (LOG_DEBUG, "The entry %s is not found in the local data base.", get_char_from_lisp_addr_t(eid));
      return(BAD);
  }

  *identifier = (lispd_identifier_elt *)(result->data);

  return(TRUE);
}

/*
 * lookup_eid_in_db
 *
 * Look up a given ipv4 eid in the database, returning true and
 * filling in the entry pointer if found the exact entry, or false if not found.
 */
int lookup_eid_exact_in_db(lisp_addr_t eid_prefix, int eid_prefix_length, lispd_identifier_elt **identifier)
{
  patricia_node_t *result;

  if (lookup_eid_exact_node(eid_prefix,eid_prefix_length, &result)!=GOOD)
  {
      syslog (LOG_DEBUG, "The entry %s is not found in the local data base.", get_char_from_lisp_addr_t(eid_prefix));
      return(BAD);
  }

  *identifier = (lispd_identifier_elt *)(result->data);

  return(TRUE);
}


/*
 * Generets a locator element and add it to locators list
 */

lispd_locator_elt   *new_locator (
		lispd_identifier_elt 		*identifier,
		lisp_addr_t                 locator_addr,
		uint8_t                     locator_type,
		uint8_t                     priority,
		uint8_t                     weight,
		uint8_t                     mpriority,
		uint8_t                     mweight,
		uint8_t                     state    /* UP , DOWN */
		)
{
        lispd_locators_list *locator_list, *aux_locator_list, *aux1_locator_list;
        lispd_locator_elt *locator;

        if ((locator_list = malloc(sizeof(lispd_locators_list))) == NULL) {
            syslog(LOG_ERR, "can't allocate lispd_locator_list");
            return(NULL);
        }
        if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
            syslog(LOG_ERR, "can't allocate lispd_locator_elt");
            free(locator_list);
            return(NULL);
        }
        /* Add the locator into the list*/
        if (locator_addr.afi == AF_INET)
        {
            if (locator_type == LOCAL_LOCATOR){/* If it's a local locator, we should store it in order*/
                if (identifier->head_v4_locators_list == NULL){
                    identifier->head_v4_locators_list = locator_list;
                }else{
                    aux_locator_list = NULL;
                    aux1_locator_list = identifier->head_v4_locators_list;
                    while (aux1_locator_list->next){
                        if (locator_addr.address.ip < aux1_locator_list->locator->locator_addr.address.ip){

                        }

                        aux_locator_list = aux_locator_list->next;
                    }

                    aux_locator_list->next = locator_list;
                }
            }else{
                if (identifier->head_v4_locators_list == NULL){
                    identifier->head_v4_locators_list = locator_list;
                }else{
                    aux_locator_list = identifier->head_v4_locators_list;
                    while (aux_locator_list->next)
                        aux_locator_list = aux_locator_list->next;
                    aux_locator_list->next = locator_list;
                }
            }
        }else if (AF_INET6){
            if (locator_addr.afi == AF_INET)
            {
                if (identifier->head_v6_locators_list == NULL){
                    identifier->head_v6_locators_list = locator_list;
                }else{
                    aux_locator_list = identifier->head_v6_locators_list;
                    while (aux_locator_list->next)
                        aux_locator_list = aux_locator_list->next;
                    aux_locator_list->next = locator_list;
                }
            }
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

        identifier->locator_count++;
        return (locator);
}





/*
 * del_identifier_entry()
 *
 * Delete an EID mapping from the data base
 */
void del_identifier_entry(lisp_addr_t eid,
        int prefixlen)
{
    lispd_identifier_elt *entry;
    patricia_node_t      *result;

    if (!lookup_eid_exact_node(eid, prefixlen, &result)){
        syslog(LOG_ERR,"   Unable to locate eid entry %s/%d for deletion",get_char_from_lisp_addr_t(eid),prefixlen);
        return;
    } else {
        syslog(LOG_DEBUG,"   Deleting EID entry %s/%d", get_char_from_lisp_addr_t(eid),prefixlen);
    }

    /*
     * Remove the entry from the trie
     */
    entry = (lispd_map_cache_entry *)(result->data);
    if (eid.afi==AF_INET)
        patricia_remove(EIDv4_database, result);
    else
        patricia_remove(EIDv6_database, result);
    free_locator_list(entry->head_v4_locators_list);
    free_locator_list(entry->head_v6_locators_list);
    free(entry);
}

/*
 * Free memory of lispd_locator_list
 */

void free_locator_list(lispd_locators_list *list){
    lispd_locators_list  * locator_list, *aux_locator_list;
    /*
     * Free the locators
     */
    locator_list = list;
    while (locator_list)
    {
        if (locator_list->locator->rloc_probing_nonces)
            free (locator_list->locator->rloc_probing_nonces);
        free (locator_list->locator);
        aux_locator_list = locator_list;
        locator_list = locator_list->next;
        free (aux_locator_list);
    }
}


