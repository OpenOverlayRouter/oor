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

/*********************************** FUNCTIONS DECLARATION ************************/

/*
 * Generates a basic mapping
 */

inline lispd_mapping_elt *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/************************************ FUNCTIONS  **********************************/

/*
 * Generates a basic mapping
 */

inline lispd_mapping_elt *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt *mapping = NULL;

    if ((mapping = (lispd_mapping_elt *)malloc(sizeof(lispd_mapping_elt)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"Couldn't allocate memory for lispd_mapping_elt: %s", strerror(errno));
        return (NULL);
    }
    mapping->eid_prefix =  eid_prefix;
    mapping->eid_prefix_length = eid_prefix_length;
    mapping->iid = iid;
    mapping->locator_count = 0;
    mapping->head_v4_locators_list = NULL;
    mapping->head_v6_locators_list = NULL;

    return (mapping);
}

/*
 * Generates a mapping with the local extended info
 */

lispd_mapping_elt *new_local_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt           *mapping        = NULL;
    lcl_mapping_extended_info   *extended_info  = NULL;
    int                         ctr             = 0;

    if ((mapping = new_mapping (eid_prefix, eid_prefix_length, iid)) == NULL){
        return (NULL);
    }

    if ((extended_info=(lcl_mapping_extended_info *)malloc(sizeof(lcl_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_local_mapping: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free (mapping);
        return (NULL);
    }
    mapping->extended_info = (void *)extended_info;

    for (ctr = 0 ; ctr < LOCATOR_HASH_TABLE_POSITIONS ; ctr++){
        extended_info->outgoing_locator_hash_tables.v4_locator_hash_table[ctr] = NULL;
    }
    for (ctr = 0 ; ctr < LOCATOR_HASH_TABLE_POSITIONS ; ctr++){
        extended_info->outgoing_locator_hash_tables.v6_locator_hash_table[ctr] = NULL;
    }
    for (ctr = 0 ; ctr < LOCATOR_HASH_TABLE_POSITIONS ; ctr++){
        extended_info->outgoing_locator_hash_tables.locator_hash_table[ctr] = NULL;
    }

    return (mapping);
}

/*
 * Generates a mapping with the remote extended info
 */

lispd_mapping_elt *new_map_cache_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt           *mapping        = NULL;
    rmt_mapping_extended_info   *extended_info  = NULL;
    int                         ctr             = 0;

    if ((mapping = new_mapping (eid_prefix, eid_prefix_length, iid)) == NULL){
        return (NULL);
    }

    if ((extended_info=(rmt_mapping_extended_info *)malloc(sizeof(lcl_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_mapping: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free (mapping);
        return (NULL);
    }
    mapping->extended_info = (void *)extended_info;

    for (ctr = 0 ; ctr < LOCATOR_HASH_TABLE_POSITIONS ; ctr++){
        extended_info->rmt_locator_hash_tables.v4_locator_hash_table[ctr] = NULL;
    }
    for (ctr = 0 ; ctr < LOCATOR_HASH_TABLE_POSITIONS ; ctr++){
        extended_info->rmt_locator_hash_tables.v6_locator_hash_table[ctr] = NULL;
    }
    for (ctr = 0 ; ctr < LOCATOR_HASH_TABLE_POSITIONS ; ctr++){
        extended_info->rmt_locator_hash_tables.locator_hash_table[ctr] = NULL;
    }

    return (mapping);
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
void free_mapping_elt(lispd_mapping_elt *mapping, int local)
{
    /* Free the locators list*/
    free_locator_list(mapping->head_v4_locators_list);
    free_locator_list(mapping->head_v6_locators_list);
    /* Free extended info */
    if (local == TRUE){
        free ((lcl_mapping_extended_info *)mapping->extended_info);
    }else{
        free ((rmt_mapping_extended_info *)mapping->extended_info);
    }
    free(mapping);

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

