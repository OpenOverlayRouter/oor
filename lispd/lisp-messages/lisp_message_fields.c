/*
 * lispd_message_fields.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 *    Florin Coras  <fcoras@ac.upc.edu>
 *
 */

#include "lisp_message_fields.h"


/*
 * address
 */

inline address_field *address_field_new() {
    return(calloc(1, sizeof(address_field)));
}

inline void address_field_del(address_field *addr) {
    free(addr);
}

address_field *address_field_parse(uint8_t *offset) {

    address_field *addr;
    addr = calloc(1, sizeof(address_field));
//    addr->afi = ntohs(*((uint16_t *)offset));
    addr->data = offset;
    switch (address_field_afi(addr)) {
    case LISP_AFI_IP:
        addr->len = sizeof(struct in_addr);
        break;
    case LISP_AFI_IPV6:
        addr->len = sizeof(struct in6_addr);
        break;
    case LISP_AFI_NO_ADDR:
        addr->len = sizeof(uint16_t);
        break;
    case LISP_AFI_LCAF:
        addr->len = sizeof(generic_lcaf_hdr) + ((generic_lcaf_hdr *)addr->data)->len;
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_3, "address_field_parse: Unsupported AFI %d", address_field_afi(addr));
        break;
    }
    addr->len += sizeof(uint16_t);
    return(addr);
}








/*
 * locator
 */

inline locator_field *locator_field_new() {
    return(calloc(1, sizeof(locator_field)));
}

inline void locator_field_del(locator_field *locator) {
    if (!locator)
        return;
    if (locator->address)
        address_field_del(locator->address);
    free(locator);
}

locator_field *locator_field_parse(uint8_t *offset) {
    locator_field *locator;
    locator = locator_field_new();
    locator->data = offset;
    locator->address = address_field_parse(locator_field_addr_ptr(locator));
    if (!locator->address) {
        free(locator);
        return(NULL);
    }

    locator->len = sizeof(locator_hdr_t)+ address_field_len(locator->address);
    return(locator);
}






/*
 * mapping record
 */

inline mapping_record *mapping_record_new() {
    return(calloc(1, sizeof(mapping_record)));
}

void mapping_record_del(mapping_record *record) {
    if (record->eid)
        address_field_del(record->eid);
    if (record->locators)
        glist_destroy(record->locators);
    free(record);
}


mapping_record *mapping_record_parse(uint8_t *offset) {
    mapping_record  *record;
    locator_field   *locator;
    uint8_t         *ptr;
    int i;


    ptr = offset;
    record = calloc(1, sizeof(mapping_record));
    record->data = offset;

    ptr = CO(record->data, sizeof(mapping_record_hdr_t));

    record->eid = address_field_parse(ptr);
    if (!record->eid)
        goto err;

    ptr = CO(ptr, address_field_len(record->eid));
    record->locators = glist_new(NO_CMP, (glist_del_fct)locator_field_del);
    if (!record->locators)
        goto err;

    for (i = 0; i < mapping_record_hdr(record)->locator_count; i++) {
        locator = locator_field_parse(ptr);
        if (!locator)
            goto err;
        glist_add_tail(locator, record->locators);
        ptr = CO(ptr, locator_field_len(locator));
    }
    record->len = ptr - offset;

    return(record);
err:
    if (record->eid)
        address_field_del(record->eid);
    if (record->locators)
        glist_destroy(record->locators);
    free(record);
    return(NULL);
}

locator_field *mapping_record_allocate_locator(mapping_record *record, int size) {
    locator_field *locator = NULL;
    if (!record->locators)
        record->locators = glist_new(NO_CMP, (glist_del_fct)locator_field_del);

    locator = locator_field_new();
    glist_add(locator, record->locators);
    locator_field_set_data(locator, CO(record->data, record->len));
    record->len += size;
    return(locator);
}




/*
 * EID prefix record
 */

inline eid_prefix_record *eid_prefix_record_new() {
    return(calloc(1, sizeof(eid_prefix_record)));
}

void eid_prefix_record_del(eid_prefix_record *record) {
    if (!record)
        return;
    if (record->eid)
        address_field_del(record->eid);
    free(record);
}


eid_prefix_record *eid_prefix_record_parse(uint8_t *offset) {
    eid_prefix_record *record;
    record = eid_prefix_record_new();
    record->data = offset;
    record->eid = address_field_parse(CO(record->data, sizeof(eid_prefix_record_hdr)));
    record->len = sizeof(eid_prefix_record_hdr) + address_field_len(record->eid);
    return(record);
}





/*
 * Authentication field (Map-Register and Map-Notify)
 */


auth_field *auth_field_new() {
    return(calloc(1, sizeof(auth_field)));
}

auth_field *auth_field_parse(uint8_t *offset) {
    auth_field *af = auth_field_new();
    int ad_len = 0;

    af->data = offset;
    ad_len = ntohs(auth_field_hdr(af)->auth_data_len);
    offset = CO(offset, sizeof(auth_field_hdr_t));
    af->auth_data = offset;
    af->len = sizeof(auth_field_hdr_t) + ad_len;
    return(af);
}

void auth_field_del(auth_field *af) {
    if (!af)
        return;
    free(af);
}

/*
 * Returns the length of the auth data field based on the key_id value
 */

uint16_t auth_data_get_len_for_type(lisp_key_type key_id)

{
    switch (key_id) {
    default: // HMAC_SHA_1_96
        return (LISP_SHA1_AUTH_DATA_LEN);   //TODO support more auth algorithms
    }
}


/* RTR auth */

rtr_auth_field *rtr_auth_field_new() {
    return(calloc(1, sizeof(rtr_auth_field)));
}

rtr_auth_field *rtr_auth_field_parse(uint8_t *offset) {
    rtr_auth_field *raf = rtr_auth_field_new();
    int ad_len = 0;

    raf->bits = offset;
    /* we only know how to parse RTR_AUTH_DATA */
    if (rtr_auth_field_get_hdr(raf)->ad_type != RTR_AUTH_DATA)
        return(NULL);
    ad_len = ntohs(rtr_auth_field_get_hdr(raf)->rtr_auth_data_len);
    offset = CO(raf->bits, sizeof(rtr_auth_field_hdr));
    raf->rtr_auth_data = offset;
    raf->len = sizeof(rtr_auth_field_hdr) + ad_len;
    return(raf);
}

void rtr_auth_field_del(rtr_auth_field *raf) {
    if (!raf)
        return;
    free(raf);
}


