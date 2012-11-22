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
    for (i = 0 ; i < 20 ; i++)
            identifier->v4_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
            identifier->v6_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
            identifier->locator_hash_table[i] = NULL;

    /*Add identifier to the data base */
    if (add_identifier(identifier)!=GOOD)
        return NULL;
    return identifier;
}


int lookup_eid_node(lisp_addr_t eid, patricia_node_t **node)
{
  prefix_t prefix;
  *node=NULL;

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

  if (*node==NULL)
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
            memcpy (&(prefix.add.sin), &(eid.address.ip), sizeof(struct in_addr));
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

  if (!*node)
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
      return(FALSE);
  }
  *identifier = (lispd_identifier_elt *)(result->data);

  return(TRUE);
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
		syslog(LOG_ERR, "can't allocate lispd_locator_list");
		return(NULL);
	}
	if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
		syslog(LOG_ERR, "can't allocate lispd_locator_elt");
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
						syslog (LOG_WARNING, "The locator %s already exists in the identifier %s/%d",
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
						syslog (LOG_WARNING, "The locator %s already exists in the identifier %s/%d",
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
    entry = (lispd_identifier_elt *)(result->data);
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

void free_locator_list(lispd_locators_list *list)
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
        free (locator_list->locator->locator_addr);
        free (locator_list->locator->state);
        free (locator_list->locator);
        aux_locator_list = locator_list;
        locator_list = locator_list->next;
        free (aux_locator_list);
    }
}

void free_lispd_identifier_elt(lispd_identifier_elt *identifier)
{
    /*
     * Free the locators list
     */
    free_locator_list(identifier->head_v4_locators_list);
    free_locator_list(identifier->head_v6_locators_list);
    free(identifier);

}

/*
 * dump local identifier list
 */
void dump_local_eids()
{
    patricia_tree_t     *dbs [2] = {EIDv4_database, EIDv6_database};
    int                 ctr, ctr1;

    patricia_node_t             *node;
    lispd_identifier_elt        *entry;
    lispd_locators_list         *locator_iterator_array[2];
    lispd_locators_list         *locator_iterator;
    lispd_locator_elt           *locator;

    printf("LISP Local EIDs\n\n");

    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(dbs[ctr]->head, node) {
            entry = ((lispd_identifier_elt *)(node->data));
            printf("%s/%d (IID = %d)\n ", get_char_from_lisp_addr_t(entry->eid_prefix),
                    entry->eid_prefix_length, entry->iid);

            if (entry->locator_count > 0){
                printf("       Locator               State    Priority/Weight\n");
                locator_iterator_array[0] = entry->head_v4_locators_list;
                locator_iterator_array[1] = entry->head_v6_locators_list;
                // Loop through the locators and print each

                for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){
                    locator_iterator = locator_iterator_array[ctr1];
                    while (locator_iterator != NULL) {
                        locator = locator_iterator->locator;
                        printf(" %15s ", get_char_from_lisp_addr_t(*(locator->locator_addr)));
                        if (locator->locator_addr->afi == AF_INET)
                            printf(" %15s ", locator->state ? "Up" : "Down");
                        else
                            printf(" %5s ", locator->state ? "Up" : "Down");
                        printf("         %3d/%-3d \n", locator->priority, locator->weight);
                        locator_iterator = locator_iterator->next;
                    }
                }
                printf("\n");
            }
        } PATRICIA_WALK_END;
    }
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
    
    return eid;
}
