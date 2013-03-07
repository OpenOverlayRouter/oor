/*
 * lispd_mapping.c
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
#include "lispd_local_db.h"
#include "lispd_log.h"
#include "lispd_mapping.h"



/*
 * Creates a mapping and add it to the database
 */

lispd_mapping_elt *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt *mapping = NULL;
    int i;

    if ((mapping=malloc(sizeof(lispd_mapping_elt)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"Couldn't allocate memory for lispd_mapping_elt: %s", strerror(errno));
        return (NULL);
    }
    mapping->eid_prefix =  eid_prefix;
    mapping->eid_prefix_length = eid_prefix_length;
    mapping->iid = iid;
    mapping->locator_count = 0;
    mapping->head_v4_locators_list = NULL;
    mapping->head_v6_locators_list = NULL;
    for (i = 0 ; i < 20 ; i++)
        mapping->v4_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
        mapping->v6_locator_hash_table[i] = NULL;
    for (i = 0 ; i < 20 ; i++)
        mapping->locator_hash_table[i] = NULL;

    /*Add identifier to the data base */
    if (add_mapping_to_db(mapping)!=GOOD)
        return (NULL);
    return (mapping);
}

void init_mapping (lispd_mapping_elt *identifier)
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
 * Add a locator into the locators list of the mapping.
 */

int add_locator_to_mapping(
        lispd_mapping_elt           *mapping,
        lispd_locator_elt           *locator)
{
    if (locator->locator_addr->afi == AF_INET){
        err = add_locator_to_list (&(mapping->head_v4_locators_list), locator);
    }else {
        err = add_locator_to_list (&(mapping->head_v6_locators_list), locator);
    }
    if (err == GOOD){
        mapping->locator_count++;
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_locator_to_mapping: The locator %s has been added to the EID %s/%d.",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length);
        return (GOOD);
    }else if (err == ERR_EXIST){
        free_locator (locator);
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_locator_to_mapping: The locator %s already exists for the EID %s/%d.",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length);
        return (GOOD);
    }
    free_locator (locator);
    return (BAD);
}

/*
 * Free memory of lispd_mapping_elt.
 */
void free_lispd_mapping_elt(lispd_mapping_elt    *identifier)
{
    /*
     * Free the locators list
     */
    free_locator_list(identifier->head_v4_locators_list);
    free_locator_list(identifier->head_v6_locators_list);
    free(identifier);

}

/*
 * dump mapping
 */
void dump_mapping_entry(
        lispd_mapping_elt       *mapping,
        int                     log_level)
{
    lispd_locators_list         *locator_iterator_array[2]= {NULL,NULL};
    lispd_locators_list         *locator_iterator = NULL;
    lispd_locator_elt           *locator = NULL;
    int                         ctr = 0;

    lispd_log_msg(log_level,"%s/%d (IID = %d)\n ", get_char_from_lisp_addr_t(mapping->eid_prefix),
            mapping->eid_prefix_length, mapping->iid);

    if (mapping->locator_count > 0){
        lispd_log_msg(log_level,"       Locator               State    Priority/Weight\n");
        locator_iterator_array[0] = mapping->head_v4_locators_list;
        locator_iterator_array[1] = mapping->head_v6_locators_list;
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

