/*
 * lisp_messages.c
 *
 * This file is part of LISP Mobile Node Implementation.
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
 */

#include "lisp_messages.h"
#include "lisp_nonce.h"
//#include <defs.h>
#include <string.h>



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
    ecm->reserved = 0;
    memset(ecm->reserved2, 0, sizeof(ecm->reserved2));
}


static char *
mreq_flags_to_char(map_request_hdr_t *h)
{
    static char buf[10];

    *buf = '\0';
    h->authoritative ? sprintf(buf+strlen(buf), "A") : sprintf(buf+strlen(buf), "a");
    h->map_data_present ?  sprintf(buf+strlen(buf), "M") : sprintf(buf+strlen(buf), "m");
    h->rloc_probe ? sprintf(buf+strlen(buf), "P") : sprintf(buf+strlen(buf), "p");
    h->solicit_map_request ? sprintf(buf+strlen(buf), "S") : sprintf(buf+strlen(buf), "s");
    h->pitr ? sprintf(buf+strlen(buf), "p") : sprintf(buf+strlen(buf), "P");
    h->smr_invoked ? sprintf(buf+strlen(buf), "s") : sprintf(buf+strlen(buf), "S");
    return(buf);
}


char *
map_request_hdr_to_char(map_request_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Map-Request -> flags:%s, irc: %d (+1), record-count: %d, "
            "nonce: %s", mreq_flags_to_char(h), h->additional_itr_rloc_count,
            h->record_count,  nonce_to_char(h->nonce));
    return(buf);
}

char *
mrep_flags_to_char(map_reply_hdr_t *h)
{
    static char buf[10];
    *buf = '\0';
    h->rloc_probe ? sprintf(buf+strlen(buf), "P") : sprintf(buf+strlen(buf), "p");
    h->echo_nonce ? sprintf(buf+strlen(buf), "E") : sprintf(buf+strlen(buf), "e");
    h->security ? sprintf(buf+strlen(buf), "S") : sprintf(buf+strlen(buf), "s");
    return(buf);
}

char *
map_reply_hdr_to_char(map_reply_hdr_t *h)
{
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Map-Reply -> flags:%s, record-count: %d, nonce: %s",
            mrep_flags_to_char(h), h->record_count, nonce_to_char(h->nonce));
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

    sprintf(buf, "Map-Register -> flags:%s record-count: %d nonce %s",
            mreg_flags_to_char(h), h->record_count, nonce_to_char(h->nonce));
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

    sprintf(buf, "Map-Notify -> flags:%s, record-count: %d, nonce %s",
            mntf_flags_to_char(h), h->record_count, nonce_to_char(h->nonce));
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

    sprintf(buf, "ECM -> flags:%s", ecm_flags_to_char(h));
    return(buf);
}





/* Given the start of an address field, @addr, checks if the address is an
 * MCAST_INFO LCAF that carries mrsignaling flags */
uint8_t is_mrsignaling(address_hdr_t *addr)
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
//        lmlog(DBG_1, "Both join and leave flags are set in "
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

