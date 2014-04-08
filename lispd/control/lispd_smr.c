/*
 * lispd_smr.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Write a message to /var/log/syslog
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
 *    Albert López       <alopez@ac.upc.edu>
 *
 */
#include "lispd_smr.h"
#include "defs.h"
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_register.h"
#include "lispd_external.h"
#include "lispd_log.h"
#include "lispd_control.h"

/*
 * smr_timer is used to avoid sending SMRs during transition period.
 */
timer *smr_timer = NULL;

//void smr_pitrs();

/*
 * Send a solicit map request for each rloc of all eids in the map cahce database
 */
void init_smr(
        timer *timer_elt,
        void  *arg)
{
    iface_list_elt        *iface_list         = NULL;
    iface_mappings_list   *mappings_list      = NULL;
    locators_list_t         *locators_lists[2]  = {NULL,NULL};
    mapping_t           *mapping            = NULL;
    uint64_t                    nonce               = 0;
    map_cache_entry_t       *map_cache_entry    = NULL;
    locators_list_t         *locator_iterator   = NULL;
    locator_t           *locator            = NULL;
    mapping_t           **mappings_to_smr   = NULL;
    lisp_addr_list_t           *pitr_elt           = NULL;
    lisp_addr_t                 *eid                = NULL;
    int                         mappings_ctr        = 0;
    int                         ctr=0,ctr1=0;


    lmlog(DBG_2,"*** Init SMR notification ***");

    /*
     * Check which mappings should be SMRed and put in a list without duplicate elements
     */

    iface_list = get_head_interface_list();

    if ((mappings_to_smr = (mapping_t **)malloc(total_mappings*sizeof(mapping_t *))) == NULL){
        lmlog(LWRN, "init_smr: Unable to allocate memory for lispd_mapping_elt **: %s", strerror(errno));
        return;
    }
    memset (mappings_to_smr,0,total_mappings*sizeof(mapping_t *));

    while (iface_list != NULL){
        if ( (iface_list->iface->status_changed == TRUE) ||
                (iface_list->iface->ipv4_changed == TRUE) ||
                (iface_list->iface->ipv6_changed == TRUE)){
            mappings_list = iface_list->iface->head_mappings_list;
            while(mappings_list != NULL && mappings_ctr<total_mappings){
                if (iface_list->iface->status_changed == TRUE ||
                        (iface_list->iface->ipv4_changed == TRUE && mappings_list->use_ipv4_address == TRUE) ||
                        (iface_list->iface->ipv6_changed == TRUE && mappings_list->use_ipv6_address == TRUE)){
                    mapping = mappings_list->mapping;
                    for ( ctr=0 ; ctr< mappings_ctr ; ctr++){
                        if ( mappings_to_smr[ctr]==mapping ){
                            break;
                        }
                    }
                    if (mappings_to_smr[ctr]!=mapping){
                        mappings_to_smr[mappings_ctr] = mapping;
                        mappings_ctr ++;
                    }
                }
                mappings_list = mappings_list->next;
            }
        }
        iface_list->iface->status_changed = FALSE;
        iface_list->iface->ipv4_changed = FALSE;
        iface_list->iface->ipv6_changed = FALSE;
        iface_list = iface_list->next;
    }

    /*
     * Send map register and SMR request for each affected mapping
     */


    for (ctr = 0 ; ctr < mappings_ctr ; ctr++){
        /* Send map register for the affected mapping */
        if (nat_aware == FALSE || nat_status == NO_NAT){
            build_and_send_map_register_msg(mappings_to_smr[ctr]);
        }else if (nat_status != UNKNOWN){
            // TODO : We suppose one EID and one interface. To be modified when multiple elements
            map_register_all_eids();
        }

        lmlog(DBG_1, "Start SMR for local EID %s",
                lisp_addr_to_char(mapping_eid(mappings_to_smr[ctr])));

        /* For each map cache entry with same afi as local EID mapping */

        eid = mapping_eid(mappings_to_smr[ctr]);
        if (lisp_addr_afi(eid) == LM_AFI_IP ) {
            lmlog(DBG_3, "init_smr: SMR request for %s. Shouldn't receive SMR for IP in mapping?!",
                    lisp_addr_to_char(eid));
        } else if (lisp_addr_afi(eid) != LM_AFI_IPPREF) {
            lmlog(DBG_3, "init_smr: SMR request for %s. SMR supported only for IP-prefixes for now!",
                    lisp_addr_to_char(eid));
            continue;
        }

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;


        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us traffic in the last minute
         * Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcache_foreach_active_entry_in_ip_eid_db(eid, map_cache_entry) {
            locators_lists[0] = map_cache_entry->mapping->head_v4_locators_list;
            locators_lists[1] = map_cache_entry->mapping->head_v6_locators_list;
            for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){ /*For each IPv4 and IPv6 locator*/

                if (locators_lists[ctr1] != NULL) {

                    locator_iterator = locators_lists[ctr1];

                    while (locator_iterator){
                        locator = locator_iterator->locator;
                        if (build_and_send_map_request_msg(map_cache_entry->mapping,
                                eid, locator->locator_addr,0,0,1,0,NULL, &nonce)==GOOD){
                            lmlog(DBG_1, "  SMR'ing RLOC %s from EID %s",
                                    lisp_addr_to_char(locator->locator_addr),
                                    lisp_addr_to_char(eid));
                        }

                        locator_iterator = locator_iterator->next;
                    }
                }
            }
        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        pitr_elt  = proxy_itrs;

        while (pitr_elt) {
            if (build_and_send_map_request_msg(mappings_to_smr[ctr],
                    mapping_eid(mappings_to_smr[ctr]),pitr_elt->address,0,0,1,0,NULL, &nonce)==GOOD){
                lmlog(DBG_1, "  SMR'ing Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(mapping_eid(mappings_to_smr[ctr])));
            }else {
                lmlog(DBG_1, "  Coudn't SMR Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(mapping_eid(mappings_to_smr[ctr])));
            }
            pitr_elt = pitr_elt->next;
        }

    }

    free (mappings_to_smr);
    lmlog(DBG_2,"*** Finish SMR notification ***");
}

static int
send_smr_invoked_map_request(map_cache_entry_t *mce) {
    struct lbuf *mr;
    void *mr_hdr;
    udpsock_t ssock;
    nonces_list *nonces;
    nonces = mcache_entry_nonces_list(mce);

    mr = lisp_msg_create(LISP_MAP_REQUEST);
    lisp_msg_put_mapping(mr, mce->mapping, NULL);

    mr_hdr = lisp_msg_hdr(mr);
    MREQ_SMR_INVOKED(mr) = 1;
    MREQ_NONCE(mr) = nonces->nonce[nonces->retransmits];

    return(send_map_request_to_mr(mr, ssock));
}

int smr_reply_cb(timer *t, void *arg)
{
    map_cache_entry_t *mce = (map_cache_entry_t *)arg;
    lisp_addr_t *dst_rloc = NULL;
    nonces_list *nonces;
    lisp_addr_t *eid;

    eid = mapping_eid(mce->mapping);

    /* Sanity Check */
    nonces = mcache_entry_nonces_list(mce);
    if (!nonces) {
        lmlog(LWRN, "SMR: no nonce list for entry %s. Aborting ...",
                lisp_addr_to_char(eid));
        return(BAD);
    }

    if (nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT) {
        lmlog(DBG_1,"SMR: Map-Request for EID: %s (%d retries)",
                lisp_addr_to_char(eid), nonces->retransmits);

        send_smr_invoked_map_request(mce);
        nonces->retransmits ++;

        start_timer(t, LISPD_INITIAL_SMR_TIMEOUT,
                (timer_callback)smr_reply_cb, (void *)mce);
    } else {
        free(nonces);
        free(mce->smr_inv_timer);
        lmlog(DBG_1,"SMR: No Map Reply for EID %s. Stopping ...",
                lisp_addr_to_char(eid));
    }
    return (GOOD);
}


