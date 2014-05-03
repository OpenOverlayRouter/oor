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

void
mapping_record_init_hdr(mapping_record_hdr_t *h) {
    h->ttl                  = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    h->locator_count        = 1;
    h->eid_prefix_length    = 0;
    h->action               = 0;
    h->authoritative        = 1;
    h->version_hi           = 0;
    h->version_low          = 0;

    h->reserved1 = 0;
    h->reserved2 = 0;
    h->reserved3 = 0;
}

static char *
action_to_char(int act) {
    static char buf[10];
    switch(act) {
    case 0:
        sprintf(buf, "no-action");
        break;
    case 1:
        sprintf(buf, "native-forward");
        break;
    case 2:
        sprintf(buf, "send-map-request");
        break;
    case 3:
        sprintf(buf, "drop");
        break;
    default:
        sprintf(buf, "unknown-action");
    }
    return(buf);
}

char *
mapping_record_hdr_to_char(mapping_record_hdr_t *h)
{
    static char buf[100];
    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Mapping-record -> ttl: %d loc-count: %d action: %s auth: %d"
            " map-version: %d", ntohl(h->ttl), h->locator_count,
            action_to_char(h->action), h->authoritative, MAP_REC_VERSION(h));
    return(buf);
}



char *
locator_record_flags_to_char(locator_hdr_t *h)
{
    static char buf[5];
    h->local ? sprintf(buf+strlen(buf), "L") : sprintf(buf+stlen(buf), "l");
    h->probed ? sprintf(buf+strlen(buf), "p") : sprintf(buf+stlen(buf), "P");
    h->reachable ? sprintf(buf+strlen(buf), "R") : sprintf(buf+stlen(buf), "r");
    return(buf);
}

char *
locator_record_hdr_to_char(locator_hdr_t *h)
{
   static char buf[100];
   if (!h) {
       return(NULL);
   }

   sprintf(buf, "Locator-record -> flags: %s p/w: %d/%d %d/%d",
           locator_record_flags_to_char(h), h->priority, h->weight,
           h->mpriority, h->mweight);
   return(buf);
}

/* Returns the length of the auth data field based on the key_id value */
uint16_t
auth_data_get_len_for_type(lisp_key_type key_id)
{
    switch (key_id) {
    default: // HMAC_SHA_1_96
        return (LISP_SHA1_AUTH_DATA_LEN);   //TODO support more auth algorithms
    }
}


