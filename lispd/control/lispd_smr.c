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
//timer *smr_timer = NULL;

//void smr_pitrs();

static int
build_and_send_smr_mreq(lisp_ctrl_dev_t *dev, mapping_t *m, lisp_addr_t *dst) {
    lbuf_t *b;
    void *hdr;
    uconn_t uc;
    int ret;

    b = lisp_msg_create(LISP_MAP_REQUEST);
    hdr = lisp_msg_hdr(b);

    MREQ_SMR(hdr) = 1;
    lisp_msg_put_mapping(b, m, NULL);
    lisp_addr_copy(&uc->ra, dst);
    lisp_addr_set_afi(&uc->la, LM_AFI_NO_ADDR); /* to be filled by ctrl */
    uc->rp = LISP_CONTROL_PORT;
    uc->lp = LISP_CONTROL_PORT;

    ret = send_msg(dev, b, &uc);
    lisp_msg_destroy(b);

    if (ret != GOOD) {
        return(BAD);
    }
    return(GOOD);
}

static int
send_smr_cb(timer *t, void *arg) {
    lisp_ctrl_dev_t *dev = arg;
    ctrl_dev_send_smr(dev);
    return(GOOD);
}

int
ctrl_dev_program_smr(lisp_ctrl_dev_t *dev) {
    void *arg;
    if (!dev->smr_timer && dev->mode != xTR_MODE && dev->mode != RTR_MODE) {
        return(GOOD);
    }

    if (!dev->smr_timer){
        dev->smr_timer = create_timer(SMR_TIMER);
    }

    arg = (void *)dev;
    start_timer(dev->smr_timer, LISPD_SMR_TIMEOUT, send_smr_cb, arg);
    return(GOOD);
}

/* Send a solicit map request for each rloc of all eids in the map cache
 * database */
void
ctrl_dev_send_smr(lisp_ctrl_dev_t *dev) {
    locators_list_t *loc_lists[2] = {NULL, NULL};
    map_cache_entry_t *mce = NULL;
    locators_list_t *lit = NULL;
    locator_t *loc = NULL;
    mapping_t **mlist = NULL;
    lisp_addr_list_t *pitr_elt = NULL;
    lisp_addr_t *eid = NULL;
    int mcount = 0;
    int i, j, nb_mappings;


    lmlog(DBG_2,"*** Init SMR notification ***");

    /* Get a list of mappings that require smrs */
    nb_mappings = local_map_db_n_mappings(local_mdb);
    if (!(mlist = calloc(1, nb_mappings*sizeof(mapping_t *)))) {
        lmlog(LWRN, "ctrl_dev_send_smr: Unable to allocate memory: %s",
                strerror(errno));
        return;
    }

    mlist = ctrl_get_mappings_to_smr(dev->ctrl, mlist, &mcount);

    /* Send map register and SMR request for each mapping */
    for (i = 0; i < mcount; i++) {
        /* Send map register for all mappings */
        if (nat_aware == FALSE || nat_status == NO_NAT) {
            build_and_send_map_register_msg(mlist[i]);
        }else if (nat_status != UNKNOWN){
            /* TODO : We suppose one EID and one interface.
             * To be modified when multiple elements */
            map_register_all_eids();
        }

        eid = mapping_eid(mlist[i]);

        lmlog(DBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

        /* For each map cache entry with same afi as local EID mapping */

        if (lisp_addr_afi(eid) == LM_AFI_IP ) {
            lmlog(DBG_3, "init_smr: SMR request for %s. Shouldn't receive SMR "
                    "for IP in mapping?!", lisp_addr_to_char(eid));
        } else if (lisp_addr_afi(eid) != LM_AFI_IPPREF) {
            lmlog(DBG_3, "init_smr: SMR request for %s. SMR supported only for "
                    "IP-prefixes for now!",  lisp_addr_to_char(eid));
            continue;
        }

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;


        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
         * traffic in the last minute. Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcache_foreach_active_entry_in_ip_eid_db(eid, mce) {
            loc_lists[0] = mce->mapping->head_v4_locators_list;
            loc_lists[1] = mce->mapping->head_v6_locators_list;
            for (j = 0; j < 2; j++) {
                if (loc_lists[j]) {
                    lit = loc_lists[j];
                    while (lit) {
                        loc = lit->locator;
                        if (build_and_send_smr_mreq(dev, mce->mapping,
                                locator_addr(loc)) == GOOD) {
                            lmlog(DBG_1, "  SMR'ing RLOC %s from EID %s",
                                    lisp_addr_to_char(locator_addr(loc)),
                                    lisp_addr_to_char(eid));
                        }

                        lit = lit->next;
                    }
                }
            }
        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        pitr_elt = proxy_itrs;

        while (pitr_elt) {
            if (build_and_send_smr_mreq(dev, mlist[i], pitr_elt->address)
                    == GOOD) {
                lmlog(DBG_1, "  SMR'ing Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(eid));
            } else {
                lmlog(DBG_1, "  Coudn't SMR Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(eid));
            }
            pitr_elt = pitr_elt->next;
        }

    }

    free (mlist);
    lmlog(DBG_2,"*** Finish SMR notification ***");
}

static int
send_smr_invoked_map_request(map_cache_entry_t *mce) {
    struct lbuf *mr;
    void *mr_hdr;
    uconn_t ssock;
    nonces_list *nonces;
    mapping_t *m;
    lisp_addr_t *eid;

    m = mcache_entry_mapping(mce);
    eid = mapping_eid(m);

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

        /* build Map-Request */
        mr = lisp_msg_create(LISP_MAP_REQUEST);
        lisp_msg_put_mapping(mr, m, NULL);

        mr_hdr = lisp_msg_hdr(mr);
        MREQ_SMR_INVOKED(mr) = 1;
        MREQ_NONCE(mr) = nonces->nonce[nonces->retransmits];

        if (send_map_request_to_mr(mr, ssock) != GOOD) {
            return(BAD);
        }

        nonces->retransmits ++;

        start_timer(mce->smr_inv_timer, LISPD_INITIAL_SMR_TIMEOUT,
                (timer_callback)smr_invoked_map_request_cb, (void *)mce);
    } else {
        free(nonces);
        free(mce->smr_inv_timer);
        lmlog(DBG_1,"SMR: No Map Reply for EID %s. Stopping ...",
                lisp_addr_to_char(eid));
    }
    return (GOOD);

}

int smr_invoked_map_request_cb(timer *t, void *arg)
{
    map_cache_entry_t *mce = (map_cache_entry_t *)arg;
    return(send_smr_invoked_map_request(mce));
}


