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
    addr->afi = ntohs(*((uint16_t *)offset));
    addr->data = offset;
    switch (addr->afi) {
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
        lispd_log_msg(LISP_LOG_DEBUG_3, "address_field_parse: Unsupported AFI %d", addr->afi);
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
    if (locator->address)
        address_field_del(locator->address);
    free(locator);
}

locator_field *locator_field_parse(uint8_t *offset) {
    locator_field *locator;
    locator = locator_field_new();
    locator->data = offset;
    locator->address = address_field_parse(locator_field_get_afi_ptr(locator));
    if (!locator->address) {
        free(locator);
        return(NULL);
    }

    locator->len = sizeof(locator_hdr)+ address_field_get_len(locator->address);
    return(locator);
}






/*
 * mapping record
 */

inline mapping_record *mapping_record_new() {
    return(calloc(1, sizeof(mapping_record)));
}

void mapping_record_del(mapping_record *record) {
    int i;

    if (record->eid)
        address_field_del(record->eid);
    if (record->locators)
        for (i=0; i<mapping_record_get_hdr(record)->locator_count; i++)
            if (record->locators[i])
               locator_field_del(record->locators[i]);
    free(record);
}


mapping_record *mapping_record_parse(uint8_t *offset) {
    mapping_record  *record;
    int i;


    record = calloc(1, sizeof(mapping_record));
    record->data = offset;
    record->len = 0;

    offset = CO(record->data, sizeof(mapping_record_hdr));

    record->eid = address_field_parse(offset);
    if (!record->eid)
        goto err;

    offset = CO(offset, address_field_get_len(record->eid));
    record->locators = calloc(mapping_record_get_hdr(record)->locator_count, sizeof(locator_field*));

    for (i = 0; i < mapping_record_get_hdr(record)->locator_count; i++) {
        record->locators[i] = locator_field_parse(offset);
        if (!record->locators[i])
            goto err;
        offset = CO(offset, locator_field_get_len(record->locators[i]));
    }

    return(record);
err:
    if (record->eid)
        address_field_del(record->eid);
    if (record->locators) {
        for (i=0; i < mapping_record_get_hdr(record)->locator_count; i++)
            if (record->locators[i])
                locator_field_del(record->locators[i]);
        free(record->locators);
    }
    free(record);
    return(NULL);
}






/*
 * EID prefix record
 */

inline eid_prefix_record *eid_prefix_record_new() {
    return(calloc(1, sizeof(eid_prefix_record)));
}

void eid_prefix_record_del(eid_prefix_record *record) {
    if (record->eid)
        address_field_del(record->eid);
    free(record);
}


eid_prefix_record *eid_prefix_record_parse(uint8_t *offset) {
    eid_prefix_record *record;
    record = eid_prefix_record_new();
    record->data = offset;
    record->eid = address_field_parse(CO(record->data, sizeof(eid_prefix_record_hdr)));
    record->len = sizeof(eid_prefix_record_hdr) + address_field_get_len(record->eid);
    return(record);
}


