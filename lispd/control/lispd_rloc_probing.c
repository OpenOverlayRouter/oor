/*
 * lispd_rloc_probing.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#include "lispd_external.h"
#include "lispd_local_db.h"
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include "lispd_rloc_probing.h"
#include "lispd_control.h"

static timer_rloc_probe_argument *
new_timer_rloc_probe_argument(mapping_t *mapping, locator_t *locator)
{
    timer_rloc_probe_argument *timer_argument = NULL;

    if ((timer_argument = malloc(sizeof(timer_rloc_probe_argument))) == NULL) {
        lmlog(LWRN, "new_timer_rloc_probe_argument: Unable to allocate memory "
                "for timer_rloc_probe_argument: %s",  strerror(errno));
    } else {
        timer_argument->mapping = mapping;
        timer_argument->locator = locator;
    }

    return (timer_argument);
}


static int
rloc_probing_cb(timer *t, void *arg) {
    timer_arg_t *ta = arg;
    timer_rloc_probe_argument *rparg = ta->data;
    mapping_t *mapping = rparg->mapping;
    locator_t *locator = rparg->locator;

    return(rloc_probing(ta->dev, mapping, locator));
}

/* Send a Map-Request probe to check status of 'loc'. If the number of
 * retries without answer is higher than rloc_probe_retries. Change the status
 * of the 'loc' to down */
static int
rloc_probing(lisp_ctrl_dev_t *dev, mapping_t *m, locator_t *loc)
{

    mapping_t *mapping = NULL;
    locator_t *locator = NULL;
    rmt_locator_extended_info *locator_ext_inf = NULL;
    nonces_list_t *nonces = NULL;
    uint8_t have_control_iface = FALSE;
    lisp_addr_t *deid, empty, *drloc;
    lbuf_t *b;
    glist_t *rlocs;
    timer *t;
    timer_arg_t *arg;
    void *hdr;

    deid = mapping_eid(mapping);

    if (rloc_probe_interval == 0) {
        lmlog(DBG_2, "rloc_probing: No RLOC Probing for %s cache entry. "
                "RLOC Probing disabled",  lisp_addr_to_char(deid));
        return (GOOD);
    }

    drloc = locator_addr(locator);
    lisp_addr_set_afi(&empty, LM_AFI_NO_ADDR);
    locator_ext_inf = locator->extended_info;
    nonces = locator_ext_inf->rloc_probing_nonces;
    t = locator_ext_inf->probe_timer;
    arg = locator_ext_inf->probe_timer->cb_argument;


    /* Generate Nonce structure */
    if (!nonces) {
        nonces = nonces_list_new();
        if (!nonces) {
            lmlog(LWRN,"rloc_probing: Unable to allocate memory "
                    "for nonces. Reprogramming RLOC Probing");
            start_timer(t, rloc_probe_interval, rloc_probing_cb, arg);
            return(BAD);
        }
        locator_ext_inf->rloc_probing_nonces = nonces;
    }


    /* If the number of retransmits is less than rloc_probe_retries, then try
     * to send the Map Request Probe again */
    if (nonces->retransmits - 1 < rloc_probe_retries ) {
        if (nonces->retransmits > 0) {
            lmlog(DBG_1,"Retransmiting Map-Request Probe for locator %s and "
                    "EID: %s (%d retries)", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(deid), nonces->retransmits);
        }

        b = lisp_msg_create(LISP_MAP_REQUEST);
        rlocs = dev->tr_class->get_default_rlocs(dev);
        lisp_msg_mreq_init(b, empty, rlocs, deid);
        glist_destroy(rlocs);

        hdr = lisp_msg_hdr(b);
        MREQ_NONCE(hdr) = nonces->nonce[nonces->retransmits];
        MREQ_RLOC_PROBE(hdr) = 1;

        err = send_map_request(dev, b, NULL, locator_addr(locator));

        if (err != GOOD) {
            lmlog(DBG_1,"rloc_probing: Couldn't send Map-Request Probe for "
                    "locator %s and EID: %s", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(deid));
        }
        nonces->retransmits++;

        /* Reprogram time for next retry */
        start_timer(t, rloc_probe_retries_interval, rloc_probing_cb, arg);
    } else {
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */
        if (*(locator->state) == UP) {
            *(locator->state) = DOWN;
            lmlog(DBG_1,"rloc_probing: No Map-Reply Probe received for locator"
                    " %s and EID: %s -> Locator state changes to DOWN",
                    lisp_addr_to_char(drloc), lisp_addr_to_char(deid));

            /* [re]Calculate balancing loc vectors  if it has been a change
             * of status*/
            mapping_compute_balancing_vectors(mapping);
        }

        free(locator_ext_inf->rloc_probing_nonces);
        locator_ext_inf->rloc_probing_nonces = NULL;

        /* Reprogram time for next probe interval */
        start_timer(t, rloc_probe_interval, rloc_probing_cb, arg);
        lmlog(DBG_2,"Reprogramed RLOC probing of the locator %s of the EID %s "
                "in %d seconds", lisp_addr_to_char(drloc),
                lisp_addr_to_char(deid), rloc_probe_interval);
    }

    return (GOOD);
}

void
program_rloc_probing(lisp_ctrl_dev_t *dev, mapping_t *m,
        locator_t *loc, int time)
{
    rmt_locator_extended_info *locator_ext_inf = NULL;
    timer *t;
    timer_arg_t *arg;

    locator_ext_inf = loc->extended_info;

    /* create timer and arg if needed*/
    if (!locator_ext_inf->probe_timer) {
        locator_ext_inf->probe_timer = create_timer(RLOC_PROBING_TIMER);
        arg = calloc(1, sizeof(timer_arg_t));
        arg->dev = dev;
        arg->data = new_timer_rloc_probe_argument(m, loc);
    } else {
        t = locator_ext_inf->probe_timer;
        arg = locator_ext_inf->probe_timer->cb_argument;
    }

    lmlog(DBG_2,"Reprogrammed probing of EID's %s locator %s (%d seconds)",
                lisp_addr_to_char(mapping_eid(m)),
                lisp_addr_to_char(locator_addr(loc)),
                RLOC_PROBING_INTERVAL);

    start_timer(t, time, rloc_probing_cb, arg);
}

/* Program RLOC probing for each locator of the mapping */
void program_mapping_rloc_probing(lisp_ctrl_dev_t *dev, mapping_t *mapping)
{
    locators_list_t *locators_lists[2] = { NULL, NULL };
    locator_t *locator = NULL;
    timer_rloc_probe_argument *timer_arg = NULL;
    rmt_locator_extended_info *locator_ext_inf = NULL;
    int ctr = 0;

    if (rloc_probe_interval == 0) {
        return;
    }

    locators_lists[0] = mapping->head_v4_locators_list;
    locators_lists[1] = mapping->head_v6_locators_list;
    /* Start rloc probing for each locator of the mapping */
    for (ctr = 0; ctr < 2; ctr++) {
        while (locators_lists[ctr] != NULL) {
            locator = locators_lists[ctr]->locator;

            /* no RLOC probing for LCAF for now */
            if (lisp_addr_afi(locator_addr(locator)) == LM_AFI_LCAF) {
                locators_lists[ctr] = locators_lists[ctr]->next;
                continue;
            }

            program_rloc_probing(dev, mapping, locator, rloc_probe_interval);
            locators_lists[ctr] = locators_lists[ctr]->next;
        }
    }
}

/* Program RLOC probing for each proxy-ETR */
void
programming_petr_rloc_probing(lisp_ctrl_dev_t *dev, int time)
{
    locators_list_t *locators_lists[2] = { NULL, NULL };
    locator_t *locator = NULL;
    timer_rloc_probe_argument *timer_arg = NULL;
    rmt_locator_extended_info *locator_ext_inf = NULL;
    int ctr = 0;

    if (rloc_probe_interval == 0 || proxy_etrs == NULL) {
        return;
    }

    locators_lists[0] = proxy_etrs->mapping->head_v4_locators_list;
    locators_lists[1] = proxy_etrs->mapping->head_v6_locators_list;
    /* Start rloc probing for each locator of the mapping */
    for (ctr = 0; ctr < 2; ctr++) {
        while (locators_lists[ctr] != NULL) {
            locator = locators_lists[ctr]->locator;
            program_rloc_probing(dev, proxy_etrs->mapping, locator, time);
        }
    }
}


