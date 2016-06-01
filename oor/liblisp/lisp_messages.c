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

#include <string.h>
#include <netinet/in.h>

#include "lisp_messages.h"
#include "../lib/mem_util.h"
//#include <defs.h>

/* The maximum length of the headers, when we have IPv6 encapsulated control messages
 * is 100 bytes. Allocate 150 for safety
 */
#define MAX_HEADERS_LEN 150


void
map_request_hdr_init(void *ptr)
{
    map_request_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_REQUEST;
    mrp->authoritative = 0;
    mrp->map_data_present = 0;          /* default no map-data present */
    mrp->rloc_probe = 0;                /* default not rloc probe */
    mrp->solicit_map_request = 0;       /* default not smr */
    mrp->smr_invoked = 0;               /* default not smr-invoked */
    mrp->additional_itr_rloc_count = 0; /* to be filled in later  */
    mrp->record_count = 0;              /* to be filled in later */
    mrp->nonce = 0;                     /* to be filled in later */
    mrp->pitr = 0;                      /* default not sent by PITR */
    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
}

void
map_reply_hdr_init(void *ptr)
{
    map_reply_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_REPLY;
    mrp->rloc_probe = 0;        /* default not rloc-probe */
    mrp->record_count = 0;      /* to be filled in later */
    mrp->echo_nonce  = 0;       /* default not reply to echo nonce req */
    mrp->security = 0;          /* default no security */
    mrp->nonce = 0;             /* to be filled in later */

    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
    mrp->reserved3 = 0;

}

void
map_register_hdr_init(void *ptr)
{
    map_register_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_REGISTER;
    mrp->proxy_reply = 0;               /* default no proxy-map-reply */
    mrp->map_notify = 1;                /* default want map-notify */
    mrp->nonce = 0;                     /* to be filled in later */
    mrp->record_count = 0;              /* to be filled in later */
    mrp->rbit = 0;                      /* default not NATT */
    mrp->ibit = 0;                      /* default not NATT */

    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
    mrp->reserved3 = 0;
}

void
map_notify_hdr_init(void *ptr)
{
    map_notify_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_NOTIFY;
    mrp->record_count = 0;          /* to be filled in later */
    mrp->rtr_auth_present = 0;      /* to be filled in later */
    mrp->xtr_id_present = 0;        /* to be filled in later */
    mrp->nonce = 0;                 /* to be filled in later */

    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
}

void
ecm_hdr_init(void *ptr)
{
    ecm_hdr_t *ecm = ptr;
    ecm->type = LISP_ENCAP_CONTROL_TYPE;
    ecm->s_bit = 0;
    ecm->d_bit = 0;
    ecm->r_bit = 0;
    memset(ecm->reserved2, 0, sizeof(ecm->reserved2));
}

void
info_nat_hdr_init(void *ptr)
{
    info_nat_hdr_t *irp = ptr;
    irp->type = LISP_INFO_NAT;
    irp->nonce = 0;
    irp->r_bit_info_reply = INFO_REQUEST;
    irp->reserved1 = 0;
    irp->reserved2[0] = 0;
    irp->reserved2[1] = 0;
    irp->reserved2[2] = 0;
}

void
info_nat_hdr_2_init(void *ptr)
{
    info_nat_hdr_2_t *irp = ptr;
    irp->eid_mask_len = 0;
    irp->ttl = 0;
    irp->reserved = 0;
}


char *
mreq_flags_to_char(map_request_hdr_t *h)
{
    static char buf[25];

    *buf = '\0';
    h->authoritative ? sprintf(buf+strlen(buf), "a=1,") : sprintf(buf+strlen(buf), "a=0,");
    h->map_data_present ?  sprintf(buf+strlen(buf), "m=1,") : sprintf(buf+strlen(buf), "m=0,");
    h->rloc_probe ? sprintf(buf+strlen(buf), "p=1,") : sprintf(buf+strlen(buf), "p=0,");
    h->solicit_map_request ? sprintf(buf+strlen(buf), "s=1,") : sprintf(buf+strlen(buf), "s=0,");
    h->pitr ? sprintf(buf+strlen(buf), "P=1,") : sprintf(buf+strlen(buf), "P=0,");
    h->smr_invoked ? sprintf(buf+strlen(buf), "S=1") : sprintf(buf+strlen(buf), "S=0");
    return(buf);
}


char *
map_request_hdr_to_char(map_request_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }
    *buf = '\0';
    sprintf(buf+strlen(buf), BOLD "Map-Request" RESET"-> flags:%s, irc: %d (+1), record-count: %d, "
            "nonce: %"PRIx64, mreq_flags_to_char(h), h->additional_itr_rloc_count,
            h->record_count,  h->nonce);
    return(buf);
}

char *
mrep_flags_to_char(map_reply_hdr_t *h)
{
    static char buf[10];

    *buf = '\0';
    h->rloc_probe ? sprintf(buf+strlen(buf), "P=1,") : sprintf(buf+strlen(buf), "P=0,");
    h->echo_nonce ? sprintf(buf+strlen(buf), "E=1,") : sprintf(buf+strlen(buf), "E=0,");
    h->security ? sprintf(buf+strlen(buf), "S=1") : sprintf(buf+strlen(buf), "S=0,");
    return(buf);
}

char *
map_reply_hdr_to_char(map_reply_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }
    *buf = '\0';
    sprintf(buf, BOLD "Map-Reply" RESET "-> flags:%s, record-count: %d, nonce: %"PRIx64,
            mrep_flags_to_char(h), h->record_count, h->nonce);
    return(buf);
}

char *
info_nat_hdr_to_char(info_nat_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }
    *buf = '\0';
    if (INF_REQ_R_bit(h) == INFO_REQUEST){
        sprintf(buf, BOLD "Info Request" RESET " -> nonce %"PRIx64,h->nonce);
    }else{
        sprintf(buf, BOLD "Info Reply" RESET " -> nonce %"PRIx64,h->nonce);
    }

    return(buf);
}

char *
mreg_flags_to_char(map_register_hdr_t *h)
{
    static char buf[10];

    *buf = '\0';
    h->proxy_reply ? sprintf(buf+strlen(buf), "P") : sprintf(buf+strlen(buf), "p");
    h->ibit ? sprintf(buf+strlen(buf), "I") : sprintf(buf+strlen(buf), "i");
    h->rbit ? sprintf(buf+strlen(buf), "R") : sprintf(buf+strlen(buf), "r");
    h->map_notify ? sprintf(buf+strlen(buf), "M") : sprintf(buf+strlen(buf), "m");
    return(buf);
}


char *
map_register_hdr_to_char(map_register_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }
    *buf = '\0';
    sprintf(buf, BOLD "Map-Register" RESET " -> flags:%s record-count: %d nonce %"PRIx64,
            mreg_flags_to_char(h), h->record_count, h->nonce);
    return(buf);
}

char *
mntf_flags_to_char(map_notify_hdr_t *h)
{
    static char buf[5];

    *buf = '\0';
    h->xtr_id_present ? sprintf(buf+strlen(buf), "I") : sprintf(buf+strlen(buf), "i");
    h->rtr_auth_present ? sprintf(buf+strlen(buf), "R") : sprintf(buf+strlen(buf), "r");
    return(buf);
}

char *
map_notify_hdr_to_char(map_notify_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, BOLD "Map-Notify" RESET "-> flags:%s, record-count: %d, nonce %"PRIX64,
            mntf_flags_to_char(h), h->record_count, h->nonce);
    return(buf);
}


char *
ecm_flags_to_char(ecm_hdr_t *h)
{
    static char buf[10];

    *buf = '\0';
    h->s_bit ? sprintf(buf+strlen(buf), "S") : sprintf(buf+strlen(buf), "s");
    return(buf);
}

char *
ecm_hdr_to_char(ecm_hdr_t *h)
{
    static char buf[50];

    if (!h) {
        return(NULL);
    }
    *buf = '\0';
    sprintf(buf, BOLD "ECM" RESET " -> flags:%s", ecm_flags_to_char(h));
    return(buf);
}





/* Given the start of an address field, @addr, checks if the address is an
 * MCAST_INFO LCAF that carries mrsignaling flags */
uint8_t
is_mrsignaling(address_hdr_t *addr)
{
    return(ntohs(LCAF_AFI(addr)) == LISP_AFI_LCAF
            && LCAF_TYPE(addr) == LCAF_MCAST_INFO
            && (MCINFO_JBIT(addr) || MCINFO_LBIT(addr)));
}

/* Given the start of an address field, @addr, checks if the address is used
 * for mrsignaling, in which case it returns the mrsignaling flags */
mrsignaling_flags_t
mrsignaling_flags(address_hdr_t *addr)
{
    lcaf_mcinfo_hdr_t   *hdr;
    mrsignaling_flags_t mc_flags = {.rbit = 0, .jbit = 0, .lbit = 0};

    if (!is_mrsignaling(addr)) {
        return(mc_flags);
    }

    hdr = (lcaf_mcinfo_hdr_t *)addr;

    if (hdr->J == 1 && hdr->L == 1) {
//        lmlog(LDBG_1, "Both join and leave flags are set in "
//                "mrsignaling msg. Discarding!");
        return(mc_flags);
    }

    mc_flags = (mrsignaling_flags_t){.rbit = hdr->R, .jbit = hdr->J, .lbit = hdr->L};
    return(mc_flags);
}


/**
 * @offset: pointer to start of the mapping record
 */
void
mrsignaling_set_flags_in_pkt(uint8_t *offset, mrsignaling_flags_t *mrsig)
{

    lcaf_mcinfo_hdr_t *mc_ptr;

//    offset = CO(offset, sizeof(mapping_record_hdr_t) + sizeof(uint16_t));
    mc_ptr = (lcaf_mcinfo_hdr_t *) offset;
    mc_ptr->J = mrsig->jbit;
    mc_ptr->L = mrsig->lbit;
    mc_ptr->R = mrsig->rbit;

}

