/*
 * liblisp.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "liblisp.h"

static lisp_msg_type_t
lisp_msg_type(lbuf_t *b) {
    ecm_hdr_t *hdr = lbuf_lisp(b);
    return(hdr->type);
}

int
lisp_msg_parse_type(lbuf_t *b, lisp_msg_type_t *t) {
    lbuf_reset_lisp(b);
    lbuf_pull(b, sizeof(uint8_t));
    t = lisp_msg_type(b);
    return(GOOD);
}

static void *lbuf_pull_ecm_hdr(struct lbuf *b) {
    return(lbuf_pull(b, sizeof(ecm_hdr_t)));
}

/* Process encapsulated map request header:  lisp header and the interal IP and
 * UDP header */
int
lisp_msg_ecm_decap(lbuf_t *pkt, uint16_t *dst_port) {
    uint16_t ipsum = 0;
    uint16_t udpsum = 0;
    int udp_len = 0;
    struct udphdr *udph;
    struct ip *iph;
    void *hdr;

    hdr = lbuf_pull_ecm_hdr(pkt);
    iph = pkt_pull_ip(pkt);
    udph = lbuf_data(pkt);

    lmlog(DBG_2, "%s inner IP: %s -> %s inner UDP %d -> %d",
            lisp_msg_hdr_to_char(hdr),
            ip_to_char(iph->ip_src, ip_version_to_sock_afi(iph->ip_v)),
            ip_to_char(iph->ip_dst, ip_version_to_sock_afi(iph->ip_v)),
            ntohs(udph->source), ntohs(udph->dest));

    /* This should overwrite the external port (dst_port in map-reply =
     * inner src_port in encap map-request) */
    *dst_port = ntohs(udph->source);

 #ifdef BSD
    udp_len = ntohs(udph->uh_ulen);
    // sport   = ntohs(udph->uh_sport);
 #else
    udp_len = ntohs(udph->len);
    // sport   = ntohs(udph->source);
 #endif

    /* Verify the checksums. */
    if (iph->ip_v == IPVERSION) {
        ipsum = ip_checksum((uint16_t *) iph, sizeof(struct ip));
        if (ipsum != 0) {
            lmlog(DBG_2, "IP checksum failed.");
        }
        if ((udpsum = udp_checksum(udph, udp_len, iph, AF_INET))
                == -1) {
            return (BAD);
        }
        if (udpsum != 0) {
            lmlog(DBG_2, "UDP checksum failed.");
            return (BAD);
        }
    }

    //Pranathi: Added this
    if (iph->ip_v == IP6VERSION) {

        if ((udpsum = udp_checksum(udph, udp_len, iph, AF_INET6))
                == -1) {
            return (BAD);
        }
        if (udpsum != 0) {
            lmlog(DBG_2, "v6 UDP checksum failed.");
            return (BAD);
        }
    }

    /* jump the udp header */
    lbuf_pull(pkt, udp_len);
    return (GOOD);
}

int
lisp_msg_parse_addr(lbuf_t *msg, lisp_addr_t *eid) {
    int len = lisp_addr_parse(lbuf_data(msg), eid);
    if (len < 0)
        return(BAD);
    lbuf_pull(msg, len);
    return(GOOD);
}

/* Given a message buffer @msg, extracts the EID out of an EID prefix field
 * and stores it in @eid. */
int
lisp_msg_parse_eid_rec(lbuf_t *msg, lisp_addr_t *eid) {
    eid_record_hdr_t *hdr = lbuf_data(msg);
    int len = lisp_addr_parse(EID_REC_ADDR(hdr), eid);
    lbuf_pull(msg, len);

    return(GOOD);
}

int
lisp_msg_parse_itr_rlocs(lbuf_t *b, glist_t *rlocs) {
    lisp_addr_t tloc;
    void *mreq_hdr = lbuf_lisp(b);
    int i;

    for (i = 0; i < MREQ_ITR_RLOC_COUNT(mreq_hdr) + 1; i++) {
        if (lisp_msg_parse_addr(b, tloc) != GOOD) {
            return(BAD);
        }
        glist_add(rlocs, lisp_addr_clone(&tloc));
        lmlog(DBG_1," itr-rloc: %s", lisp_addr_to_char(tloc));
    }
    return(GOOD);
}


int
lisp_msg_parse_loc(lbuf_t *b, locator_t *loc) {
    int len;
    void *hdr;
    lisp_addr_t addr;

    hdr = lbuf_data(b);

    len = locator_parse(lbuf_data(b), loc);
    if (len <= 0) {
        return(BAD);
    }

    lbuf_pull(b, len);

    lmlog(DBG_1, "%s addr: %s", locator_record_hdr_to_char(hdr),
            lisp_addr_to_char(locator_addr(loc)));

    return(GOOD);
}

int
lisp_msg_parse_mapping_record_split(lbuf_t *b, lisp_addr_t *eid,
        glist_t *loc_list, locator_t *probed) {
    lisp_addr_t eid;
    void *mrec_hdr, *loc_hdr;
    locator_t *loc;
    int i;

    probed = NULL;
    mrec_hdr = lbuf_data(b);
    lbuf_pull(b, sizeof(mapping_record_hdr_t));

    int len = lisp_addr_parse(lbuf_data(b), &eid);
    if (len <= 0) {
        return(BAD);
    }

    lmlog(DBG_1, "%s eid: %s", mapping_record_hdr_to_char(mrec_hdr),
            lisp_addr_to_char(&eid));

    for (i = 0; i < MAP_REC_LOC_COUNT(mrec_hdr); i++) {
        loc_hdr = lbuf_data(b);

        loc = locator_new();
        if (lisp_msg_parse_loc(b, loc) != GOOD) {
            return(BAD);
        }

        glist_add(loc_list, loc);

        if (LOC_PROBED(loc_hdr)) {
            if (probed) {
                lmlog(DBG_1, "Multiple probed locators! Aborting");
                return(BAD);
            }
            probed = loc;
        }
    }

    return(GOOD);
}

/* extracts a mapping record out of lbuf @b and stores it into @m. @m must
 * be preallocated. If a locator is probed, a pointer to it is stored in
 * @probed. */
int
lisp_msg_parse_mapping_record(lbuf_t *b, mapping_t *m, locator_t *probed) {
    glist_t *loc_list;
    glist_entry_t *lit;
    int ret;
    void *hdr;

    if (!m) {
        return(BAD);
    }

    hdr = lbuf_data(b);
    mapping_set_ttl(m, MAP_REC_TTL(hdr));
    mapping_set_action(m, MAP_REC_ACTION(hdr));
    mapping_set_auth(m, MAP_REC_AUTH(hdr));

    /* no free is called when destroyed*/
    loc_list = glist_new();

    ret = lisp_msg_parse_mapping_record_split(b, mapping_eid(m), loc_list,
                                              probed);
    if (ret != GOOD) {
        goto err;
    }

    glist_for_each_entry(lit, loc_list) {
        if (mapping_add_locator(m, lit) != GOOD) {
            goto err;
        }
    }

    return(GOOD);

err:
    glist_destroy(loc_list);
    return(BAD);
}

static unsigned int
msg_type_to_hdr_len(lisp_msg_type_t type) {
    switch(type) {
    case LISP_MAP_REQUEST:
        return(sizeof(map_request_hdr_t));
    case LISP_MAP_REPLY:
        return(sizeof(map_reply_hdr_t));
    case LISP_MAP_REGISTER:
        return(sizeof(map_register_hdr_t));
    case LISP_MAP_NOTIFY:
        return(sizeof(map_notify_hdr_t));
    default:
        return(0);
    }
}

void *
lisp_msg_pull_hdr(lbuf_t *b) {
    lisp_msg_type_t type = lisp_msg_type(b);
    return(lbuf_pull(b, msg_type_to_hdr_len(type)));
}

void *
lisp_msg_pull_auth_field(lbuf_t *b) {
    void *hdr;
    lisp_key_type_t keyid;

    hdr = lbuf_pull(b, sizeof(auth_record_hdr_t));
    keyid = noths(AUTH_REC_KEY_ID(hdr));
    lbuf_pull(b, auth_data_get_len_for_type(keyid));
    return(hdr);
}


void *
lisp_msg_put_addr(lbuf_t *b, lisp_addr_t *addr) {
    void *ptr;
    int len;

    /* make sure there's enough space */
    ptr = lbuf_put_uninit(b, lisp_addr_size_to_write(addr));
    if ((len = lisp_addr_write(ptr, addr)) <= 0) {
        lmlog(DBG_3, "lisp_msg_put_addr: failed to write address %s",
                lisp_addr_to_char(addr));
        return(NULL);
    }

    return(ptr);
}

void *
lisp_msg_put_locator(lbuf_t *msg, locator_t *locator) {
    locator_hdr_t *loc_ptr;
    lisp_addr_t *addr;
    int len = 0;

    lcl_locator_extended_info * lct_extended_info;

    loc_ptr = lbuf_put_uninit(msg, sizeof(locator_hdr_t));

    if (*(locator->state) == UP){
        loc_ptr->priority    = locator->priority;
    } else {
        /* If the locator is DOWN, set the priority to 255
         * -> Locator should not be used */
        loc_ptr->priority    = UNUSED_RLOC_PRIORITY;
    }
    loc_ptr->weight      = locator->weight;
    loc_ptr->mpriority   = locator->mpriority;
    loc_ptr->mweight     = locator->mweight;
    loc_ptr->local       = 1;
    loc_ptr->reachable   = *(locator->state);

    /* TODO: FC should take RTR stuff out in the near future */
    lct_extended_info = locator->extended_info;
    if (lct_extended_info->rtr_locators_list != NULL){
        addr = &(lct_extended_info->rtr_locators_list->locator->address);
    } else {
        addr = locator_addr(locator);
    }

    lisp_msg_put_addr(msg, addr);
    return(loc_ptr);
}


static void
increment_record_count(lbuf_t *b) {
    void *hdr = lbuf_lisp(b);

    switch(lisp_msg_type(b)) {
    case LISP_MAP_REQUEST:
        MREQ_REC_COUNT(hdr) += 1;
        break;
    case LISP_MAP_REPLY:
        MREP_REC_COUNT(hdr) += 1;
        break;
    case LISP_MAP_REGISTER:
        MREG_REC_COUNT(hdr) += 1;
        break;
    case LISP_MAP_NOTIFY:
        MNTF_REC_COUNT(hdr) += 1;
        break;
    default:
        return;
    }

}

void *
lisp_msg_put_mapping_hdr(lbuf_t *b) {
    void *hdr = lbuf_put_uninit(b, sizeof(mapping_record_hdr_t));
    mapping_record_init_hdr(lbuf_data(b));
    return(hdr);
}

void *
lisp_msg_put_mapping(lbuf_t *b, mapping_t *m, locator_t *probed_loc) {

    locators_list_t *loc_list[2]   = {NULL,NULL};
    locator_t loc;
    int ctr, probed = 0;
    mapping_record_hdr_t *rec;
    locator_hdr_t *ploc;
    lisp_addr_t *eid;

    eid = mapping_eid(m);
    rec = lisp_msg_put_mapping_hdr(b);
    MAP_REC_EID_PLEN(rec) = lisp_addr_get_plen(eid);
    MAP_REC_LOC_COUNT(rec) = m->locator_count;

    if (lisp_msg_put_addr(b, eid) != GOOD) {
        return(NULL);
    }

    loc_list[0] = m->head_v4_locators_list;
    loc_list[1] = m->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (loc_list[ctr]) {
            loc = loc_list[ctr]->locator;
            ploc = lisp_msg_put_locator(b, loc);
            if (probed_loc
                && lisp_addr_cmp(locator_addr(loc), probed_loc) == 0) {
                LOC_PROBED(ploc) = 1;
            }
            loc_list[ctr] = loc_list[ctr]->next;
        }
    }

    increment_record_count(b);

    return(rec);
}

void *
lisp_msg_put_itr_rlocs(lbuf_t *b, glist_t *itr_rlocs) {
    glist_entry_t *it;
    lisp_addr_t *rloc;
    void *hdr, *data;

    data = lbuf_data(b);
    glist_for_each_entry(it, itr_rlocs) {
        rloc = glist_entry_data(it);
        lisp_msg_put_addr(b, rloc);
    }

    hdr = lisp_msg_hdr(b);
    MREQ_ITR_RLOC_COUNT(b) = glist_size(itr_rlocs)-1;
    return(data);
}

void *
lisp_msg_put_eid_rec(lbuf_t *b, lisp_addr_t *eid) {
    eid_record_hdr_t *hdr;
    hdr = lbuf_put_uinit(b, sizeof(eid_record_hdr_t));
    hdr->eid_prefix_length = lisp_addr_get_plen(eid);
    lisp_msg_put_addr(b, eid);
    return(hdr);
}

void *
lisp_msg_push_ecm_encap(lbuf_t *b, uconn_t *uc) {
    void *data, *hdr;

    data = lbuf_data(b);

    /* inner hdr */
    pkt_push_udp_and_ip(b, &uc->lp, &uc->rp, lisp_addr_ip(&uc->la),
            lisp_addr_ip(&uc->ra));

    hdr = lbuf_push_uninit(b, sizeof(ecm_hdr_t));
    ecm_hdr_init(hdr);

    return(data);
}


lbuf_t*
lisp_msg_create(lisp_msg_type_t type) {
    lbuf_t* b;
    void *hdr;

    b = lbuf_new_with_headroom(MAX_IP_PKT_LEN, MAX_LISP_MSG_ENCAP_LEN);
    lbuf_lisp_reset(b);

    switch(type) {
    case LISP_MAP_REQUEST:
        hdr = lbuf_put_uninit(b, sizeof(map_request_hdr_t));
        map_request_hdr_init(hdr);
        break;
    case LISP_MAP_REPLY:
        hdr = lbuf_put_uninit(b, sizeof(map_reply_hdr_t));
        map_reply_hdr_init(hdr);
        break;
    case LISP_MAP_REGISTER:
        hdr = lbuf_put_uninit(b, sizeof(map_register_hdr_t));
        map_register_hdr_init(hdr);
        break;
    case LISP_MAP_NOTIFY:
        hdr = lbuf_put_uninit(b, sizeof(map_notify_hdr_t));
        map_notify_hdr_init(hdr);
        break;
    case LISP_INFO_NAT:
//        hdr = lbuf_put_uninit(b, sizeof(info_nat_hdr_t));
//        info_nat_hdr_init(hdr);
        break;
    case LISP_ENCAP_CONTROL_TYPE:
        /* nothing to do */
        break;
    default:
        lisp_log_msg(DBG_3, "lisp_msg_create: Unknown LISP message "
                "type %s", type);
    }

    return(b);
}

int
lisp_msg_mreq_init(lbuf_t *b, lisp_addr_t *seid, glist_t *itr_rlocs,
        lisp_addr_t *deid) {
    lisp_msg_put_addr(b, seid);
    lisp_msg_put_itr_rlocs(b, itr_rlocs);
    lisp_msg_put_eid_rec(b, deid);
    return(GOOD);
}

char *
lisp_msg_hdr_to_char(lbuf_t *b) {
    void *h = lbuf_lisp(b);
    switch(lisp_msg_type(b)) {
    case LISP_MAP_REQUEST:
        return(map_request_hdr_to_char(h));
    case LISP_MAP_REPLY:
        return(map_reply_hdr_to_char(h));
    case LISP_MAP_REGISTER:
        return(map_register_hdr_to_char(h));
    case LISP_MAP_NOTIFY:
        return(map_notify_hdr_to_char(h));
    case LISP_INFO_NAT:
        return(NULL);
    case LISP_ENCAP_CONTROL_TYPE:
        return(ecm_hdr_to_char(h));
    default:
        lisp_log_msg(DBG_3, "Unknown LISP message type %s",
                lisp_msg_type(h));
        return(NULL);
    }
}



/* Compute and fill auth data field
 * TODO Support more than SHA1 */
static int
auth_data_fill(uint8_t *msg, int msg_len, lisp_key_type_t key_id,
        const char *key, uint8_t *md, uint32_t *md_len) {
    switch(key_id) {
    case NO_KEY:
        /* FC XXX: what happens here? */
        *md_len = 0;
        return(GOOD);
    case HMAC_SHA_1_96:
        if (!HMAC((const EVP_MD *) EVP_sha1(),
                (const void *) key, strlen(key),
                (uchar *) msg, msg_len,
                (uchar *) md, md_len)) {
            lmlog(LISP_LOG_DEBUG_1, "HMAC_SHA_1_96 computation failed!");
            return(BAD);
        }
        break;
    case HMAC_SHA_256_128:
        return(BAD);
    default:
        return(BAD);
    }
    return(GOOD);
}

int
lisp_msg_fill_auth_data(lbuf_t *b, lisp_key_type_t keyid, const char *key) {
    uint32_t    md_len  = 0;

    void *hdr = lisp_msg_auth_record(b);
    if (auth_data_fill(lbuf_lisp(b), lbuf_size(b), keyid, key,
            AUTH_REC_DATA(hdr), &md_len) != GOOD) {
        return(BAD);
    }

//    AUTH_REC_KEY_ID(hdr) = htons(keyid);
//    AUTH_REC_DATA_LEN(hdr) = htons(md_len);

    return(GOOD);
}



/* Checks auth field of Map-Reply and Map-Request messages
 * Returns 1 if validation succeeded and 0 otherwise */
int
lisp_msg_check_auth_field(lbuf_t *b, const char *key) {
    uint8_t     *auth_data_cpy;
    uint32_t    md_len  = 0;
    uint8_t     *adptr  = NULL;
    uint16_t    ad_len;
    lisp_key_type_t keyid;

    auth_record_hdr_t *hdr;

    hdr = lisp_msg_auth_record(b);

    keyid = ntohs(AUTH_REC_KEY_ID(hdr));
    ad_len = auth_data_get_len_for_type(keyid);
    if (ad_len != ntohs(AUTH_REC_DATA_LEN(hdr))) {
        return(0);
    }
    auth_data_cpy = calloc(1, ad_len*sizeof(uint8_t));

    /* set auth field in 0 prior to computing the HMAC (see draft) */
    adptr = lbuf_data(b);
    memcpy(auth_data_cpy, adptr, ad_len*sizeof(uint8_t));
    memset(adptr, 0, ad_len*sizeof(uint8_t));

    if (auth_data_fill(lbuf_lisp(b), lbuf_size(b), keyid, key, adptr, &md_len)
            != GOOD) {
        return(0);
    }

    if ((strncmp((char *)adptr, (char *)auth_data_cpy, (size_t)ad_len)) == 0)
        return(1);
    else
        return(0);
}

void *
lisp_msg_put_empty_auth_record(lbuf_t *b, lisp_key_type_t keyid) {
    void *hdr;
    int len = auth_data_get_len_for_type(keyid);
    hdr = lbuf_put(b, sizeof(auth_record_hdr_t) + len);
    AUTH_REC_KEY_ID(hdr) = htons(keyid);
    AUTH_REC_DATA_LEN(hdr) = htons(len);
    memset(AUTH_REC_DATA(hdr), 0, len);
    return(hdr);
}




