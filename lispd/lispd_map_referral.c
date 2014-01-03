/*
 * lispd_map_referral.c
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

#include "lispd.h"
#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_map_referral.h"
#include "lispd_map_request.h"
#include "lispd_mapping.h"
#include "lispd_nonce.h"
#include "lispd_referral_cache.h"
#include "lispd_referral_cache_db.h"



/********************************** Function declaration ********************************/

int process_map_referral_record(
        uint8_t                 **offset,
        uint64_t                nonce);

int process_map_referral_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping);

int process_map_referral_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping);

int process_node_referral_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry);

int process_ms_referral_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry);

int process_ms_ack_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry);

int process_ms_not_registered_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry);

int process_delegation_hole_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry);

int process_not_authoritative_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry);

/*
 * Send ddt Map Request to next locator of the referral cache entry. If all locators has been tried and the initial petition didn't start in ddt-root,
 * start again from ddt-root.
 * @param pending_referral_entry lispd_pending_referral_cache_entry containing information of the petition that is being replied
 * @return GOOD if could send ddt map request or an error code otherwise
 */
inline int try_next_referral_node_or_go_through_root (lispd_pending_referral_cache_entry *pending_referral_entry);

/*
 * Program timer to remove referral cache entry after TTL
 * If the timer was already programed, it reprogram it with the new time to expiry
 */
void program_referral_expiry_timer(lispd_referral_cache_entry *referral_entry);

/*
 * Timer function to remove a referral and all its offspring
 */
int referral_expiry(timer *t,void    *arg);

/****************************************************************************************/

int process_map_referral(uint8_t *packet)
{
    uint8_t                     *cur_ptr            = NULL;
    lispd_pkt_map_referral_t    *map_referral_pkt   = NULL;
    uint64_t                    nonce;
    int                         record_count;
    int                         ctr;


    map_referral_pkt    = (lispd_pkt_map_referral_t *)packet;
    nonce               = map_referral_pkt->nonce;
    record_count        = map_referral_pkt->record_count;

    lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_referral: Nonce of the Map Referral is: %s", get_char_from_nonce(nonce));

    cur_ptr = CO(packet, sizeof(lispd_pkt_map_referral_t));
    for (ctr=0;ctr<record_count;ctr++){
        if ((process_map_referral_record(&cur_ptr,nonce))==BAD){
            return (BAD);
        }
    }
    return (TRUE);
}


int process_map_referral_record(
        uint8_t **offset,
        uint64_t nonce)
{
    uint8_t                                 *cur_ptr                    = NULL;
    lispd_pkt_referral_mapping_record_t     *record                     = NULL;
    lispd_referral_cache_entry              *referral_entry             = NULL;
    lispd_referral_cache_entry              *previous_referral_entry    = NULL;
    lispd_mapping_elt                       *referral_mapping           = NULL;
    lispd_pending_referral_cache_entry      *pending_referral_entry     = NULL;
    lispd_map_cache_entry                   *map_cache_entry            = NULL;
    lisp_addr_t                             ddt_node_locator_addr       = {.afi=AF_UNSPEC};
    lisp_addr_t                             aux_eid_prefix;
    int                                     aux_eid_prefix_length       = 0;
    int                                     aux_iid                     = 0;
    int                                     ctr                         = 0;
    int                                     result                      = GOOD;
    int                                     detected_loop               = FALSE;

    cur_ptr = *offset;

    record = (lispd_pkt_referral_mapping_record_t *)(cur_ptr);


    pending_referral_entry = lookup_pending_referral_cache_entry_by_nonce (nonce);

    if (pending_referral_entry == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_referral_record:  The nonce of the Map-Referral doesn't match the nonce of any generated Map-Request. Discarding message ...");
        free_mapping_elt(referral_mapping);
        return (BAD);
    }else {
        if (pending_referral_entry->previous_referral->act_entry_type == MS_NOT_REGISTERED){
            previous_referral_entry = pending_referral_entry->previous_referral->parent_node;
            ddt_node_locator_addr = get_ddt_locator_addr_at_position(pending_referral_entry->previous_referral->parent_node,
                    ctrl_supported_afi, pending_referral_entry->tried_locators);
        }else{
            previous_referral_entry = pending_referral_entry->previous_referral;
            ddt_node_locator_addr = get_ddt_locator_addr_at_position(pending_referral_entry->previous_referral,
                    ctrl_supported_afi, pending_referral_entry->tried_locators);
        }
    }

    free(pending_referral_entry->nonces);
    pending_referral_entry->nonces = NULL;

    /* Stop the timer to not retry to send the map request */
    stop_timer(pending_referral_entry->ddt_request_retry_timer);
    pending_referral_entry->ddt_request_retry_timer = NULL;


    /* Fill a auxiliar mapping with the information of the packet */
    referral_mapping = new_mapping(aux_eid_prefix,aux_eid_prefix_length,aux_iid);
    if (referral_mapping == NULL){
        return (BAD);
    }
    cur_ptr = (uint8_t *)&(record->eid_prefix_afi);
    if (pkt_process_eid_afi(&cur_ptr,referral_mapping) != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_referral_record:  Error processing the EID of the map reply record");
        free_mapping_elt(referral_mapping);
        return (BAD);
    }
    referral_mapping->eid_prefix_length = record->eid_prefix_length;

    /* Check that the requested EID belongs to the returned prefix in the referral */
    if (is_prefix_b_part_of_a (
            referral_mapping->eid_prefix,
            referral_mapping->eid_prefix_length,
            pending_referral_entry->map_cache_entry->mapping->eid_prefix,
            pending_referral_entry->map_cache_entry->mapping->eid_prefix_length) == FALSE){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_referral_record: The requested EID doesn't belong to the prefix received "
                            "in the map referral: EID: %s  -   received prefix: %s/%d",
                            get_char_from_lisp_addr_t(pending_referral_entry->map_cache_entry->mapping->eid_prefix),
                            get_char_from_lisp_addr_t(referral_mapping->eid_prefix),referral_mapping->eid_prefix_length);
        err = try_next_referral_node_or_go_through_root (pending_referral_entry);
        if (err != GOOD){
            if (err == ERR_DST_ADDR){
                err = activate_negative_map_cache (pending_referral_entry->map_cache_entry,
                        pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                        pending_referral_entry->map_cache_entry->mapping->eid_prefix_length,
                        1,MAPPING_ACT_NO_ACTION);
                if (err != GOOD){
                    del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                            pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
                }
            }
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
        }
        free_mapping_elt(referral_mapping);

        return (BAD);
    }


    /*
     * Avoid loops:
     *   - Check that the returned referral has a more specific prefix than the previous referral
     *   - If received referral is: MS_REFERRAL or NODE_REFERRAL, Check that its prefix is diferent from the previous one.
     */

    if (is_prefix_b_part_of_a (
            previous_referral_entry->mapping->eid_prefix,
            previous_referral_entry->mapping->eid_prefix_length,
            referral_mapping->eid_prefix,
            referral_mapping->eid_prefix_length) == FALSE){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_referral_record: Loop detected in the ddt process-> "
                "received prefix: %s/%d  -   previous prefix: %s/%d. Trying next ddt node",
                get_char_from_lisp_addr_t(referral_mapping->eid_prefix),referral_mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(previous_referral_entry->mapping->eid_prefix),
                previous_referral_entry->mapping->eid_prefix_length);
        detected_loop = TRUE;
    }else if ((previous_referral_entry->mapping->eid_prefix_length == referral_mapping->eid_prefix_length) &&
            (record->action == NODE_REFERRAL || record->action == MS_REFERRAL)){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_referral_record: Loop detected in the ddt process-> "
                "%s message contains same prefix as last referral iteration : %s/%d",
                (record->action == NODE_REFERRAL ? "Node referral" : "MS referral"),
                get_char_from_lisp_addr_t(referral_mapping->eid_prefix),
                referral_mapping->eid_prefix_length);
        detected_loop = TRUE;
    }

    if ( detected_loop == TRUE){
        /* Try with the next ddt node*/
        err = try_next_referral_node_or_go_through_root (pending_referral_entry);
        if (err != GOOD){
            if (err == ERR_DST_ADDR){
                lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_referral_record: Loop detected in the ddt process-> "
                        "error in the ddt tree");
                err = activate_negative_map_cache (pending_referral_entry->map_cache_entry,
                        previous_referral_entry->mapping->eid_prefix,
                        previous_referral_entry->mapping->eid_prefix_length,
                        1,MAPPING_ACT_NO_ACTION);
                if (err != GOOD){
                    del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                            pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
                }
            }
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
        }

        free_mapping_elt(referral_mapping);
        return (BAD);
    }

    map_cache_entry = pending_referral_entry->map_cache_entry;

    if (map_cache_entry->mapping->iid != referral_mapping->iid){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_referral_record:  Instance ID of the map referral doesn't match with the pending referral cache entry");
        free_mapping_elt(referral_mapping);
        remove_pending_referral_cache_entry_from_list(pending_referral_entry);
        return (BAD);
    }
    /* Create the referral cache entry */
    referral_entry = new_referral_cache_entry(referral_mapping, record->action, ntohl(record->ttl));
    referral_entry->src_inf_ddt_node_locator_addr = ddt_node_locator_addr;

    /* Get the locators list */
    for (ctr=0 ; ctr < record->locator_count ; ctr++){
        if ((process_map_referral_locator (&cur_ptr, referral_entry->mapping)) != GOOD){
            return(BAD);
        }
    }

    lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_referral_record:Answer from %s : Authoritative: %d , Incomplete: %d",
            get_char_from_lisp_addr_t(referral_entry->src_inf_ddt_node_locator_addr),record->authoritative,record->incomplete);

    dump_referral_cache_entry(referral_entry,LISP_LOG_DEBUG_2);

    switch (referral_entry->act_entry_type){
        case NODE_REFERRAL:
            result = process_node_referral_reply(referral_entry,pending_referral_entry);
            break;
        case MS_REFERRAL:
            result = process_ms_referral_reply(referral_entry,pending_referral_entry);
            break;
        case MS_ACK:
            result = process_ms_ack_reply(referral_entry,pending_referral_entry);
            break;
        case MS_NOT_REGISTERED:
            result = process_ms_not_registered_reply(referral_entry,pending_referral_entry);
            break;
        case DELEGATION_HOLE:
            result = process_delegation_hole_reply(referral_entry,pending_referral_entry);
            break;
        case NOT_AUTHORITATIVE:
            result = process_not_authoritative_reply(referral_entry,pending_referral_entry);
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_referral_record: Referral record %s/%d  with not supported action: %d",
                    get_char_from_lisp_addr_t(referral_mapping->eid_prefix),referral_mapping->eid_prefix_length,referral_entry->act_entry_type);
            result = BAD;
            break;
    }

    return (result);
}



int process_map_referral_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping)
{
    lispd_pkt_referral_mapping_record_locator_t     *pkt_locator    = NULL;
    lispd_locator_elt                               *locator        = NULL;
    uint8_t                                         *cur_ptr        = NULL;
    uint8_t                                         status          = UP;

    cur_ptr = *offset;
    pkt_locator = (lispd_pkt_referral_mapping_record_locator_t *)(cur_ptr);

    cur_ptr = (uint8_t *)&(pkt_locator->locator_afi);

    locator = new_rmt_locator (&cur_ptr,status,
            pkt_locator->priority, pkt_locator->weight,
            pkt_locator->mpriority, pkt_locator->mweight);

    if (locator != NULL){
        if ((err=add_locator_to_mapping (mapping, locator)) != GOOD){
            free_locator(locator);
            return (BAD);
        }
    }else{
        return (BAD);
    }

    *offset = cur_ptr;
    return (GOOD);
}


int process_node_referral_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry)
{
    lispd_referral_cache_entry              *db_referral_entry = NULL;

    if (pending_referral_entry->previous_referral->act_entry_type == MS_NOT_REGISTERED ){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_node_referral_reply: Previous ddt referral was a MS_NOT_REGISTERED "
                "reply and the current one is a NODE REFERRAL. This should never happend. Try next node");
        /* Try with the next ddt node*/
        err = try_next_referral_node_or_go_through_root (pending_referral_entry);
        if (err != GOOD){
            if (err == ERR_DST_ADDR){
                lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_referral_record: Error detected in the ddt process-> "
                        "error in the ddt tree");
                err = activate_negative_map_cache (pending_referral_entry->map_cache_entry,
                        pending_referral_entry->previous_referral->mapping->eid_prefix,
                        pending_referral_entry->previous_referral->mapping->eid_prefix_length,
                        1,MAPPING_ACT_NO_ACTION);
                if (err != GOOD){
                    del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                            pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
                }
            }
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
        }

        free_referral_cache_entry(referral_entry);
        return (BAD);
    }

    db_referral_entry = lookup_referral_cache_exact(
            referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_NOT_END_PREFIX_DATABASES);
    if (db_referral_entry == NULL){
        /*
         * If we receive a node referral mesage for and EID prefix for which we have ms-ack in the database but not a node-referral,
         * then remove the ms-ack entry from the database and add the node referral entry with same prefix. Probably the ms-ack entry
         * will be generated again in the next iteration of ddt.
         */
        db_referral_entry = lookup_referral_cache_exact(
                    referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_END_PREFIX_DATABASES);
        if (db_referral_entry != NULL){
            del_referral_cache_entry_from_db(db_referral_entry);
            db_referral_entry = NULL;
        }
    }
    /* Add referral cache entry to database */
    if (db_referral_entry == NULL){
        if (add_referral_cache_entry_to_db(referral_entry) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"process_node_referral_reply: Coudn't add referral cache entry for prefix %s/%d",
                    get_char_from_lisp_addr_t(referral_entry->mapping->eid_prefix), referral_entry->mapping->eid_prefix_length);
            free_referral_cache_entry(referral_entry);
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
            return (BAD);
        }
        add_referral_cache_entry_to_tree(pending_referral_entry->previous_referral,referral_entry);
    }else{
        /* Entry already exist. Replace it with the new data. Valid if the previous entry was a node referral, ms referral or delegation hole*/
        update_referral_cache_data(db_referral_entry, referral_entry);
        free_referral_cache_entry(referral_entry);
        referral_entry = db_referral_entry;
    }
    /* Program expiry time */
    program_referral_expiry_timer(referral_entry);
    /* Update pending referral cache and proceed with the search in the ddt tree */
    pending_referral_entry->previous_referral = referral_entry;
    pending_referral_entry->tried_locators = 0;
    if (send_ddt_map_request_miss(NULL,(void *)pending_referral_entry)!=GOOD){
        return (BAD);
    }

    return (GOOD);
}


int process_ms_referral_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry)
{
    lispd_referral_cache_entry              *db_referral_entry = NULL;

    if (pending_referral_entry->previous_referral->act_entry_type == MS_NOT_REGISTERED ){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_node_referral_reply: Previous ddt referral was a MS_NOT_REGISTERED "
                "reply and the current one is a NODE REFERRAL. This should never happend. Try next node");
        /* Try with the next ddt node*/
        err = try_next_referral_node_or_go_through_root (pending_referral_entry);
        if (err != GOOD){
            if (err == ERR_DST_ADDR){
                lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_referral_record: Error detected in the ddt process-> "
                        "error in the ddt tree");
                err = activate_negative_map_cache (pending_referral_entry->map_cache_entry,
                        pending_referral_entry->previous_referral->mapping->eid_prefix,
                        pending_referral_entry->previous_referral->mapping->eid_prefix_length,
                        1,MAPPING_ACT_NO_ACTION);
                if (err != GOOD){
                    del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                            pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
                }
            }
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
        }

        free_referral_cache_entry(referral_entry);
        return (BAD);
    }

    db_referral_entry = lookup_referral_cache_exact(
            referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_NOT_END_PREFIX_DATABASES);
    if (db_referral_entry == NULL){
        /*
         * If we receive a node referral mesage for and EID prefix for which we have ms-ack in the database but not a node-referral,
         * then remove the ms-ack entry from the database and add the node referral entry with same prefix. Probably the ms-ack entry
         * will be generated again in the next iteration of ddt.
         */
        db_referral_entry = lookup_referral_cache_exact(
                referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_END_PREFIX_DATABASES);
        if (db_referral_entry != NULL){
            del_referral_cache_entry_from_db(db_referral_entry);
            db_referral_entry = NULL;
        }
    }else{
        /* Entry already exist. Replace it with the new data. Valid if the previous entry was a node referral, ms referral or delegation hole */
        update_referral_cache_data(db_referral_entry, referral_entry);
        free_referral_cache_entry(referral_entry);
        referral_entry = db_referral_entry;
    }
    /* Add referral cache entry to database */
    if (db_referral_entry == NULL){
        if (add_referral_cache_entry_to_db(referral_entry) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"process_ms_referral_reply: Coudn't add referral cache entry for prefix %s/%d",
                    get_char_from_lisp_addr_t(referral_entry->mapping->eid_prefix), referral_entry->mapping->eid_prefix_length);
            free_referral_cache_entry(referral_entry);
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
            return (BAD);
        }
        add_referral_cache_entry_to_tree(pending_referral_entry->previous_referral,referral_entry);
    }
    /* Program expiry time */
    program_referral_expiry_timer(referral_entry);
    /* Update pending referral cache and proceed with the search in the ddt tree */
    pending_referral_entry->previous_referral = referral_entry;
    pending_referral_entry->tried_locators = 0;
    if (send_ddt_map_request_miss(NULL,(void *)pending_referral_entry)!=GOOD){
        return (BAD);
    }

    return (GOOD);
}

int process_ms_ack_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry)
{
    lispd_referral_cache_entry              *db_referral_entry = NULL;

    db_referral_entry = lookup_referral_cache_exact(
            referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_END_PREFIX_DATABASES);

    /* Add referral cache entry to database */
    if (db_referral_entry == NULL){
        if (add_referral_cache_entry_to_db(referral_entry) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"process_ms_ack_reply: Coudn't add referral cache entry for prefix %s/%d",
                    get_char_from_lisp_addr_t(referral_entry->mapping->eid_prefix), referral_entry->mapping->eid_prefix_length);
            free_referral_cache_entry(referral_entry);
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
            return (BAD);
        }
        add_referral_cache_entry_to_tree(pending_referral_entry->previous_referral,referral_entry);
    }else{
        /* Entry already exist. Replace it with the new data. Valid if the previous entry was a ms ack or ms not registered ack */
        update_referral_cache_data(db_referral_entry, referral_entry);
        free_referral_cache_entry(referral_entry);
        referral_entry = db_referral_entry;
    }

    /* Program expiry time */
    program_referral_expiry_timer(referral_entry);
    /* Finish process and remove the pending referral cache from the list */
    if (pending_referral_entry->map_cache_entry->active == TRUE){
        // We have received a map reply
        remove_pending_referral_cache_entry_from_list(pending_referral_entry);
    }
    else{
        if (pending_referral_entry->ddt_request_retry_timer == NULL){
            pending_referral_entry->ddt_request_retry_timer = create_timer (DDT_MAP_REQ_RETRY_MS_ACK_TIMER);
        }
        pending_referral_entry->previous_referral = referral_entry;
        start_timer(pending_referral_entry->ddt_request_retry_timer, LISPD_INITIAL_MRQ_TIMEOUT,
                send_map_request_ddt_map_reply_miss, (void *)pending_referral_entry);
    }

    return (GOOD);
}


int process_ms_not_registered_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry)
{
    lispd_referral_cache_entry              *db_referral_entry = NULL;

    db_referral_entry = lookup_referral_cache_exact(
            referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_END_PREFIX_DATABASES);

    /* Add referral cache entry to database */
    if (db_referral_entry == NULL){
        if (add_referral_cache_entry_to_db(referral_entry) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"process_ms_not_registered_reply: Coudn't add referral cache entry for prefix %s/%d",
                    get_char_from_lisp_addr_t(referral_entry->mapping->eid_prefix), referral_entry->mapping->eid_prefix_length);
            free_referral_cache_entry(referral_entry);
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
            return (BAD);
        }
        add_referral_cache_entry_to_tree(pending_referral_entry->previous_referral,referral_entry);
        pending_referral_entry->previous_referral = referral_entry;
    }else{
        /* Entry already exist. Replace it with the new data. Valid if the previous entry was a ms ack or ms not registered ack */
        update_referral_cache_data(db_referral_entry, referral_entry);
        free_referral_cache_entry(referral_entry);
        referral_entry = db_referral_entry;
    }
    /* Try with the next ddt node*/
    pending_referral_entry->tried_locators = pending_referral_entry->tried_locators + 1;
    lispd_log_msg(LISP_LOG_DEBUG_1,"process_ms_not_registered_reply: Receive a MS_NOT_REGISTERED referral. Trying next node");
    err = send_ddt_map_request_miss(NULL,(void *)pending_referral_entry);
    /* If we asked to all MS where prefix is delegated and all reply  MS_NOT_REGISTERED, remove entry from pending list
     * and activate map cache*/
    if (err == ERR_DST_ADDR){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_ms_not_registered_reply: Tried all noedes. Activate negative map reply");
        if (activate_negative_map_cache (pending_referral_entry->map_cache_entry, referral_entry->mapping->eid_prefix,
                referral_entry->mapping->eid_prefix_length,referral_entry->ttl,MAPPING_ACT_NO_ACTION) != GOOD){
            del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                    pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
        }
        remove_pending_referral_cache_entry_from_list(pending_referral_entry);
        /* Program expiry time */
        program_referral_expiry_timer(referral_entry);
    }
    return (GOOD);
}

int process_delegation_hole_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry)
{

    lispd_referral_cache_entry              *db_referral_entry = NULL;

    db_referral_entry = lookup_referral_cache_exact(
            referral_entry->mapping->eid_prefix, referral_entry->mapping->eid_prefix_length, DDT_END_PREFIX_DATABASES);

    if (db_referral_entry != NULL && db_referral_entry->act_entry_type != DELEGATION_HOLE){
        del_referral_cache_entry_from_db(db_referral_entry);
        db_referral_entry = NULL;
    }
    if (db_referral_entry == NULL){
        /* Add referral cache entry to database */

        if (add_referral_cache_entry_to_db(referral_entry) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"process_delegation_hole_reply: Coudn't add referral cache entry for prefix %s/%d",
                    get_char_from_lisp_addr_t(referral_entry->mapping->eid_prefix), referral_entry->mapping->eid_prefix_length);
            free_referral_cache_entry(referral_entry);
            remove_pending_referral_cache_entry_from_list(pending_referral_entry);
            return (BAD);
        }
        add_referral_cache_entry_to_tree(pending_referral_entry->previous_referral,referral_entry);
    }else{
        /* Entry already exist. Replace it with the new data.*/
        update_referral_cache_data(db_referral_entry, referral_entry);
        free_referral_cache_entry(referral_entry);
        referral_entry = db_referral_entry;
    }
    /*Remove entry from pending list and activate map cache*/
    if (activate_negative_map_cache (pending_referral_entry->map_cache_entry, referral_entry->mapping->eid_prefix,
            referral_entry->mapping->eid_prefix_length,referral_entry->ttl,MAPPING_ACT_NO_ACTION)!=GOOD){
        del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                           pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
    }
    remove_pending_referral_cache_entry_from_list(pending_referral_entry);
    /* Program expiry time */
    program_referral_expiry_timer(referral_entry);
    return(GOOD);
}
int process_not_authoritative_reply(
        lispd_referral_cache_entry              *referral_entry,
        lispd_pending_referral_cache_entry      *pending_referral_entry)
{
    lispd_log_msg(LISP_LOG_DEBUG_2,"process_not_authoritative_reply: Node %s is not authoritative for the requested prefix %s/%d. "
            "Asking next ddt node.", get_char_from_lisp_addr_t(referral_entry->src_inf_ddt_node_locator_addr),
            get_char_from_lisp_addr_t(pending_referral_entry->map_cache_entry->mapping->eid_prefix),
            pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);

    err = try_next_referral_node_or_go_through_root (pending_referral_entry);
    if (err != GOOD){
        if (err == ERR_DST_ADDR){
            err = activate_negative_map_cache (pending_referral_entry->map_cache_entry, referral_entry->mapping->eid_prefix,
                    referral_entry->mapping->eid_prefix_length,1,MAPPING_ACT_NO_ACTION);
            if (err != GOOD){
                del_map_cache_entry_from_db(pending_referral_entry->map_cache_entry->mapping->eid_prefix,
                        pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
            }
        }
        remove_pending_referral_cache_entry_from_list(pending_referral_entry);
    }
    free_referral_cache_entry(referral_entry);

    return (err);
}

/*
 * Send ddt Map Request to next locator of the referral cache entry. If all locators has been tried and the initial petition didn't start in ddt-root,
 * start again from ddt-root.
 * @param pending_referral_entry lispd_pending_referral_cache_entry containing information of the petition that is being replied
 * @return GOOD if could send ddt map request or an error code otherwise
 */
inline int try_next_referral_node_or_go_through_root (lispd_pending_referral_cache_entry *pending_referral_entry)
{
    pending_referral_entry->tried_locators = pending_referral_entry->tried_locators + 1;
    err = send_ddt_map_request_miss(NULL,(void *)pending_referral_entry);
    /*
     * If we asked to all Referral Nodes for this prefix without obtaing and authoritative answer:
     *      gone through root: Activate negative map cache. Remove pending referral
     *      not gone through root: Start again process through root
     */
    if (err == ERR_DST_ADDR){
        if (pending_referral_entry->request_through_root == TRUE){
            lispd_log_msg(LISP_LOG_DEBUG_2,"try_next_referral_node_or_go_through_root: Tried all ddt node locators without positive answer.");
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_2,"try_next_referral_node_or_go_through_root: Tried all ddt node locators without positive answer."
                    "Restart process from ddt root.");
            pending_referral_entry->previous_referral = get_root_referral_cache(pending_referral_entry->map_cache_entry->mapping->eid_prefix.afi);
            pending_referral_entry->tried_locators = 0;
            err = send_ddt_map_request_miss(NULL,(void *)pending_referral_entry);
        }
    }

    return (err);
}

/*
 * Program timer to remove referral cache entry after TTL
 * If the timer was already programed, it reprogram it with the new time to expiry
 */
void program_referral_expiry_timer(lispd_referral_cache_entry *referral_entry)
{
    if (referral_entry->expiry_ddt_cache_timer == NULL){
        referral_entry->expiry_ddt_cache_timer = create_timer(DDT_EXPIRE_MAP_REFERRAL);
    }
    start_timer(referral_entry->expiry_ddt_cache_timer, referral_entry->ttl*60, referral_expiry, (void *)referral_entry);
}

/*
 * Remove a referral and all its offspring
 */
int referral_expiry(
        timer   *t,
        void    *arg)
{
    lispd_referral_cache_entry *referral_entry = (lispd_referral_cache_entry *)arg;

    lispd_log_msg(LISP_LOG_DEBUG_1,"referral_expiry: The referral entry with prefix %s/%d has expired. "
            "Removing it and all its offspring", get_char_from_lisp_addr_t(referral_entry->mapping->eid_prefix),
            referral_entry->mapping->eid_prefix_length);

    remove_referral_cache_entry_from_parent_node(referral_entry);
    del_referral_cache_entry_from_db(referral_entry);
    dump_referral_cache_db(LISP_LOG_DEBUG_3);
    return (GOOD);
}
