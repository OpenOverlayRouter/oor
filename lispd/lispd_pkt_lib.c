/*
 * lispd_pkt_lib.c
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
 *    Lorand Jakab  <ljakab@ac.upc.edu>
 *
 */


#include "lispd_external.h"


extern int pkt_get_mapping_record_length(lispd_locator_chain_t *locator_chain) {
    lispd_locator_chain_elt_t *locator_chain_elt;
    int afi_len   = 0;
    int loc_len   = 0;
    int lcaf_len  = 0;
#ifdef LISPMOBMH
    /*We have the loop here as it counts two vars*/
    int loc_count = 0;

    iface_list_elt *elt = NULL;

    get_lisp_afi(locator_chain->eid_prefix.afi, &afi_len);
    locator_chain_elt = locator_chain->head;

    while (locator_chain_elt) {
        elt = search_iface_list(locator_chain_elt->db_entry->locator_name);
        if(elt!=NULL && elt->ready){
            switch (locator_chain_elt->db_entry->locator.afi) {
            case AF_INET:
                loc_len += sizeof(struct in_addr);
                loc_count++;
                break;
            case AF_INET6:
                loc_len += sizeof(struct in6_addr);
                loc_count++;
                break;
            default:
                syslog(LOG_DAEMON, "Unknown AFI (%d) for %s",
                        locator_chain_elt->db_entry->locator.afi,
                        locator_chain_elt->db_entry->locator_name);
                break;
            }
        }
        locator_chain_elt = locator_chain_elt->next;
    }
#else
    locator_chain_elt = locator_chain->head;
    loc_len = get_locator_length(locator_chain_elt);
    get_lisp_afi(locator_chain->eid_prefix.afi, &afi_len);
#endif
    if (locator_chain->iid >= 0)
        lcaf_len += sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_lcaf_iid_t);


#ifdef LISPMOBMH
    return sizeof(lispd_pkt_mapping_record_t) + afi_len + lcaf_len +
           (loc_count * sizeof(lispd_pkt_mapping_record_locator_t)) +
           loc_len;
#else
    return sizeof(lispd_pkt_mapping_record_t) + afi_len + lcaf_len +
           (locator_chain->locator_count * sizeof(lispd_pkt_mapping_record_locator_t)) +
           loc_len;
#endif
}


extern void *pkt_fill_eid_from_locator_chain(offset, loc_chain)
    void                    *offset;
    lispd_locator_chain_t   *loc_chain;
{
    return pkt_fill_eid(offset, &(loc_chain->eid_prefix), loc_chain->iid);
}

extern void *pkt_fill_eid(offset, eid, iid)
    void                    *offset;
    lisp_addr_t             *eid;
    lispd_iid_t              iid;
{
    uint16_t                *afi_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;
    void                    *eid_ptr;
    uint16_t                 eid_afi;

    afi_ptr = (uint16_t *)offset;
    eid_afi = get_lisp_afi(eid->afi, NULL);

    /* For negative IID values, we skip LCAF/IID field */
    if (iid < 0) {
        *afi_ptr = htons(eid_afi);
        eid_ptr  = CO(offset, sizeof(uint16_t));
    } else {
        *afi_ptr = htons(LISP_AFI_LCAF);

        lcaf_ptr = (lispd_pkt_lcaf_t *) CO(offset, sizeof(uint16_t));
        iid_ptr  = (lispd_pkt_lcaf_iid_t *) CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        eid_ptr  = (void *) CO(iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));

        lcaf_ptr->rsvd1 = 0;
        lcaf_ptr->flags = 0;
        lcaf_ptr->type  = 2;
        lcaf_ptr->rsvd2 = 0;    /* This can be IID mask-len, not yet supported */
        lcaf_ptr->len   = htons(sizeof(lispd_pkt_lcaf_iid_t) +
                          get_addr_len(eid->afi));

        iid_ptr->iid = htonl(iid);
        iid_ptr->afi = htons(eid_afi);
    }

    if ((copy_addr(eid_ptr, eid, 0)) == 0) {
        syslog(LOG_DAEMON, "pkt_fill_eid: copy_addr failed");
        return NULL;
    }

    return CO(eid_ptr, get_addr_len(eid->afi));
}


extern void *pkt_fill_mapping_record(rec, locator_chain, opts)
    lispd_pkt_mapping_record_t              *rec;
    lispd_locator_chain_t                   *locator_chain;
    map_reply_opts                          *opts;
{
    int                                     cpy_len = 0;
    lispd_pkt_mapping_record_locator_t      *loc_ptr;
    lispd_db_entry_t                        *db_entry;
    lispd_locator_chain_elt_t               *locator_chain_elt;
#ifdef LISPMOBMH
    iface_list_elt *elt=NULL;
#endif

    if ((rec == NULL) || (locator_chain == NULL))
        return NULL;

    rec->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    rec->locator_count          = locator_chain->locator_count;
    rec->eid_prefix_length      = locator_chain->eid_prefix_length;
    rec->action                 = 0;
    rec->authoritative          = 1;
    rec->version_hi             = 0;
    rec->version_low            = 0;

    loc_ptr = (lispd_pkt_mapping_record_locator_t *)
              pkt_fill_eid_from_locator_chain(&(rec->eid_prefix_afi), locator_chain);

    if (loc_ptr == NULL)
        return NULL;

    locator_chain_elt = locator_chain->head;

    while (locator_chain_elt) {
        db_entry             = locator_chain_elt->db_entry;
#ifdef LISPMOBMH
        elt = search_iface_list(db_entry->locator_name);
        if(elt!=NULL && elt->ready){
#endif
        loc_ptr->priority    = db_entry->priority;
        loc_ptr->weight      = db_entry->weight;
        loc_ptr->mpriority   = db_entry->mpriority;
        loc_ptr->mweight     = db_entry->mweight;
        loc_ptr->local       = 1;
        if (opts && opts->rloc_probe)
            loc_ptr->probed  = 1;       /* XXX probed locator, should check addresses */
        loc_ptr->reachable   = 1;       /* XXX should be computed */
        loc_ptr->locator_afi = htons(get_lisp_afi(db_entry->locator.afi, NULL));

        if ((cpy_len = copy_addr((void *) CO(loc_ptr,
                sizeof(lispd_pkt_mapping_record_locator_t)), &(db_entry->locator), 0)) == 0) {
            syslog(LOG_DAEMON, "pkt_fill_mapping_record: copy_addr failed for locator %s",
                    db_entry->locator_name);
            return(NULL);
        }

        loc_ptr = (lispd_pkt_mapping_record_locator_t *)
            CO(loc_ptr, (sizeof(lispd_pkt_mapping_record_locator_t) + cpy_len));
#ifdef LISPMOBMH
        }
#endif
        locator_chain_elt = locator_chain_elt->next;
    }
    return (void *)loc_ptr;
}


/*
 * Packet parsing functions
 *
 * Return value is the offset where packet parsing should continue
 */

extern void *pkt_read_eid(offset, eid, eid_afi, iid)
    void                    *offset;
    lisp_addr_t            **eid;
    int                     *eid_afi;
    lispd_iid_t             *iid;
{
    void                    *cur_ptr;
    uint16_t                 lisp_afi;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;

    cur_ptr  = offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));

    if (lisp_afi == LISP_AFI_LCAF) {
        lcaf_ptr = (lispd_pkt_lcaf_t *)cur_ptr;
        cur_ptr  = CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));

        /* If the LCAF is IID, read data, else jump over it */
        if (lcaf_ptr->type == LCAF_IID) {
            iid_ptr  = (lispd_pkt_lcaf_iid_t *)cur_ptr;
            *iid     = ntohl(iid_ptr->iid);
            lisp_afi = ntohs(iid_ptr->afi);
            *eid_afi = lisp2inetafi(lisp_afi);
            cur_ptr  = (void *)CO(iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));
            *eid     = (lisp_addr_t *)cur_ptr;
            return CO(cur_ptr, get_addr_len(*eid_afi));
        } else {
            cur_ptr  = CO(cur_ptr, ntohs(lcaf_ptr->len));
            *eid     = NULL;
            *eid_afi = -1;
            *iid     = -1;
        }
    } else if (lisp_afi == 0) {
        *eid     = NULL;
        *eid_afi = -1;
        *iid     = -1;
    } else {
        *eid     = (lisp_addr_t *)cur_ptr;
        *eid_afi = lisp2inetafi(lisp_afi);
        *iid     = -1;
        return CO(cur_ptr, get_addr_len(*eid_afi));
    }

    return cur_ptr;
}

/* Temporary entries not to break existing code */
extern int get_record_length(lispd_locator_chain_t *locator_chain) {
    return pkt_get_mapping_record_length(locator_chain);
}
extern void *build_mapping_record(rec, locator_chain, opts)
    lispd_pkt_mapping_record_t              *rec;
    lispd_locator_chain_t                   *locator_chain;
    map_reply_opts                          *opts;
{
    return pkt_fill_mapping_record(rec, locator_chain, opts);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
