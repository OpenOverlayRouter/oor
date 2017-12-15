/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <netinet/in.h>

#include "lisp_message_fields.h"


void
mapping_record_init_hdr(mapping_record_hdr_t *h) {
    h->ttl                  = htonl(DEFAULT_DATA_CACHE_TTL);
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

char *
mapping_action_to_char(int act) {
    static char buf[30];

    *buf = '\0';
    switch(act) {
    case ACT_NO_ACTION:
        sprintf(buf, "no-action");
        break;
    case ACT_NATIVE_FWD:
        sprintf(buf, "native-forward");
        break;
    case ACT_SEND_MREQ:
        sprintf(buf, "send-map-request");
        break;
    case ACT_DROP:
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
    *buf = '\0';
    snprintf(buf,sizeof(buf), "Mapping-record -> ttl: %d loc-count: %d action: %s auth: %d"
            " map-version: %d", ntohl(h->ttl), h->locator_count,
            mapping_action_to_char(h->action), h->authoritative,
            MAP_REC_VERSION(h));

    return(buf);
}



char *
locator_record_flags_to_char(locator_hdr_t *h)
{
    static char buf[15];
    *buf = '\0';
    h->local ? sprintf(buf+strlen(buf), "L=1,") : sprintf(buf+strlen(buf), "L=0,");
    h->probed ? sprintf(buf+strlen(buf), "p=1,") : sprintf(buf+strlen(buf), "p=0,");
    h->reachable ? sprintf(buf+strlen(buf), "R=1") : sprintf(buf+strlen(buf), "R=0");
    return(buf);
}

char *
locator_record_hdr_to_char(locator_hdr_t *h)
{
   static char buf[100];

   if (!h) {
       return(NULL);
   }
   *buf = '\0';
   snprintf(buf,sizeof(buf), "Locator-record -> flags: %s, p/w: %d/%d %d/%d",
           locator_record_flags_to_char(h), h->priority, h->weight,
           h->mpriority, h->mweight);
   return(buf);
}

/* Returns the length of the auth data field based on the key_id value */
uint16_t
auth_data_get_len_for_type(lisp_key_type_e key_id)
{
    switch (key_id) {
    case (NO_KEY):
        return (0);
    case (HMAC_SHA_1_96):
        return (LISP_SHA1_AUTH_DATA_LEN);
    default:
        return (LISP_SHA1_AUTH_DATA_LEN);
    }
}

void
eid_rec_hdr_init(eid_record_hdr_t *ptr)
{
    ptr->eid_prefix_length = 0;
    ptr->reserved = 0;
}


