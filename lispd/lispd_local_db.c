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
patricia_tree_t *AF4_database           = NULL;
patricia_tree_t *AF6_database           = NULL;


/*
 * Initialize databases
 */

int db_init(void) {
    AF4_database  = New_Patricia(sizeof(struct in_addr)  * 8);
    AF6_database  = New_Patricia(sizeof(struct in6_addr) * 8);

    if (!AF4_database || !AF6_database) {
        syslog(LOG_CRIT, "malloc (database): %s", strerror(errno));
        return(BAD);
    }
    return(GOOD);
}

void init_identifier (lispd_identifier_elt *identifier)
{
    identifier->iid = 0;
    identifier->locator_count = 0;
}


/*
 *  make_and_lookup for network format prefix
 */
patricia_node_t *make_and_lookup_network(int afi, void *addr, int mask_len)
{
    struct in_addr      *addr4;
    struct in6_addr     *addr6;
    prefix_t            *prefix;
    patricia_node_t     *node;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        syslog(LOG_ERR, "can't allocate patrica_node_t");
        return(NULL);
    }

    switch(afi) {
    case AF_INET:
        addr4 = (struct in_addr *) addr;
        if ((prefix = New_Prefix(AF_INET, addr4, mask_len)) == NULL) {
            syslog(LOG_ERR, "couldn't alocate prefix_t for AF_INET");
            free(node);
            return(NULL);
        }
        node = patricia_lookup(AF4_database, prefix);
        break;
    case AF_INET6:
        addr6 = (struct in6_addr *)addr;
        if ((prefix = New_Prefix(AF_INET6, addr6, mask_len)) == NULL) {
            syslog(LOG_ERR, "couldn't alocate prefix_t for AF_INET6");
            free(node);
            return(NULL);
        }
        node = patricia_lookup(AF6_database, prefix);
        break;
    default:
        free(node);
        syslog(LOG_ERR, "Unknown afi (%d) when allocating prefix_t", afi);
        return(NULL);
    }
    Deref_Prefix(prefix);
    return(node);
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
  prefix_t prefix;

  switch(eid.afi) {
      case AF_INET:
          prefix.family = AF_INET;
          prefix.bitlen = 32;
          prefix.ref_count = 0;
          prefix.add.sin.s_addr = eid.address.ip.s_addr;
          result = patricia_search_best(AF4_database, &prefix);
          break;
      case AF_INET6:
          prefix.family = AF_INET6;
          prefix.bitlen = 128;
          prefix.ref_count = 0;
          memcpy (&(prefix.add.sin6), &(eid.address.ipv6), sizeof(struct in6_addr));
          result = patricia_search_best(AF6_database, &prefix);
          break;
      default:
          break;
  }

  if (!result)
  {
      syslog (LOG_DEBUG, "The entry %s is not found in the local data base.", get_char_from_lisp_addr_t(eid));
      return(BAD);
  }

  *identifier = (lispd_identifier_elt *)(result->data);

  return(TRUE);
}
/*
 * Generets a empty locator element and add it to locators list
 */

lispd_locator_elt   *make_and_add_locator (lispd_identifier_elt *identifier)
{
        lispd_locators_list *locator_list, *aux_locator_list;
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
        if (identifier->head_locators_list == NULL){
            identifier->head_locators_list = locator_list;
        }else{
            aux_locator_list = identifier->head_locators_list;
            while (aux_locator_list->next)
                aux_locator_list = aux_locator_list->next;
            aux_locator_list->next = locator_list;
        }
        locator_list->next = NULL;
        locator_list->locator = locator;
        return (locator);
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


