/*
 * lispd_locator.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#include <errno.h>

#include "lisp_locator.h"
#include "lispd_lib.h"
#include "lmlog.h"


static lcl_locator_extended_info_t *new_lcl_locator_extended_info(int *);
static rmt_locator_extended_info_t *new_rmt_locator_extended_info();
static void free_lcl_locator_extended_info(lcl_locator_extended_info_t *);
static void free_rmt_locator_extended_info(rmt_locator_extended_info_t *);

static lcl_locator_extended_info_t *
new_lcl_locator_extended_info(int *out_socket)
{
    lcl_locator_extended_info_t *lcl_loc_ext_inf;
    lcl_loc_ext_inf = xmalloc(sizeof(lcl_locator_extended_info_t));

    lcl_loc_ext_inf->out_socket = out_socket;
    lcl_loc_ext_inf->rtr_locators_list = NULL;

    return lcl_loc_ext_inf;
}

static rmt_locator_extended_info_t *
new_rmt_locator_extended_info()
{
    rmt_locator_extended_info_t *rmt_loc_ext_inf;
    rmt_loc_ext_inf = xmalloc(sizeof(rmt_locator_extended_info_t));
    rmt_loc_ext_inf->rloc_probing_nonces = NULL;
    rmt_loc_ext_inf->probe_timer = NULL;

    return rmt_loc_ext_inf;
}

static void
free_lcl_locator_extended_info(lcl_locator_extended_info_t *extended_info)
{
    if (!extended_info) {
        return;
    }

    rtr_list_del(extended_info->rtr_locators_list);
    free(extended_info);
}

static void
free_rmt_locator_extended_info(rmt_locator_extended_info_t *extended_info)
{
    if (!extended_info) {
        return;
    }

    if (extended_info->probe_timer != NULL) {
        /* This is needed because in case of RLOC probing we allocate
         * a struct pointing to the mapping and the locator */
        free(extended_info->probe_timer->cb_argument);
        lmtimer_stop(extended_info->probe_timer);
        extended_info->probe_timer = NULL;
    }
    if (extended_info->rloc_probing_nonces != NULL) {
        free(extended_info->rloc_probing_nonces);
    }
    free(extended_info);
}

/* Clones of local locator extended info */
static lcl_locator_extended_info_t *
lcl_locator_extended_info_clone(lcl_locator_extended_info_t *einf)
{
    lcl_locator_extended_info_t *ei = NULL;

    ei = new_lcl_locator_extended_info(einf->out_socket);

    if (einf->rtr_locators_list != NULL) {
        ei->rtr_locators_list = rtr_locator_list_clone(einf->rtr_locators_list);
    }

    return (ei);
}

/* Clone remote locator extended info. Actually it just allocates memory for a
 * extended info and does't clone anything, THAT IS, probing nonces ARE NOT
 * copied */
static rmt_locator_extended_info_t *
rmt_locator_extended_info_clone(rmt_locator_extended_info_t *einf)
{
    rmt_locator_extended_info_t *ei = NULL;

    ei = new_rmt_locator_extended_info();

    return (ei);
}

locator_t *
locator_new()
{
    return (xzalloc(sizeof(locator_t)));
}

char *
locator_to_char(locator_t *l)
{
    static char buf[5][500];
    static int i=0;

    /* hack to allow more than one locator per line */
    i++; i = i % 5;
    *buf[i] = '\0';
    sprintf(buf[i], "%s, ", lisp_addr_to_char(locator_addr(l)));
    sprintf(buf[i] + strlen(buf[i]), "%s, ", l->state ? "Up" : "Down");
    sprintf(buf[i] + strlen(buf[i]), "%d/%-d, %d/%d", l->priority, l->weight,
            l->mpriority, l->mweight);
    return (buf[i]);
}

int locator_parse(void *ptr, locator_t *loc)
{
    locator_hdr_t *hdr;
    uint8_t status = UP;
    int len;

    hdr = ptr;
    if (!LOC_REACHABLE(hdr) && LOC_LOCAL(hdr)) {
        status = DOWN;
    }
    if (!loc->addr) {
        loc->addr = lisp_addr_new();
    }

    len = lisp_addr_parse(LOC_ADDR(hdr), loc->addr);
    if (len <= 0) {
        return (BAD);
    }

    loc->state = xzalloc(sizeof(uint8_t));
    *(loc->state) = status;
    loc->type = DYNAMIC_LOCATOR;
    loc->priority = LOC_PRIORITY(hdr);
    loc->weight = LOC_WEIGHT(hdr);
    loc->mpriority = LOC_MPRIORITY(hdr);
    loc->mweight = LOC_MWEIGHT(hdr);
    loc->extended_info = new_rmt_locator_extended_info();

    /* TODO: should we remove these? */
    loc->data_packets_in = 0;
    loc->data_packets_out = 0;

    return (sizeof(locator_hdr_t) + len);
}

int locator_cmp(locator_t *l1, locator_t *l2)
{
    int ret = 0;
    if ((ret = lisp_addr_cmp(locator_addr(l1), locator_addr(l2))) != 0) {
        return (1);
    }

    if (l1->priority != l2->priority)
        return (1);
    if (l1->weight != l2->weight)
        return (1);
    if (l1->mpriority != l2->mpriority)
        return (1);
    if (l1->mweight != l2->mweight)
        return (1);
    return (0);
}

locator_t *
locator_init_remote(lisp_addr_t *addr)
{
    if (!addr) {
        return (NULL);
    }

    locator_t *locator = locator_new();
    locator->addr = lisp_addr_clone(addr);
    locator->state = xmalloc(sizeof(uint8_t));
    locator->extended_info = new_rmt_locator_extended_info();
    locator->type = DYNAMIC_LOCATOR;

    return (locator);
}

/* Initializes a remote locator. 'addr' is cloned so it can be freed by the
 * caller*/
locator_t *
locator_init_remote_full(lisp_addr_t *addr, uint8_t state, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight)
{
    locator_t *locator = locator_init_remote(addr);
    if (!locator) {
        return (NULL);
    }

    *(locator->state) = state;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    return (locator);
}

/* For local locators address is NOT CLONED, since it is
 * linked to that of the associated interface */
locator_t *
locator_init_local(lisp_addr_t *addr)
{
    if (!addr) {
        return (NULL);
    }

    locator_t *locator = locator_new();
    /* Initialize locator */
    locator->addr = addr;
    locator->type = LOCAL_LOCATOR;

    return (locator);
}

/* Initializes a local locator. 'addr' should point to one of the
 * addresses of an interface thereby it is NOT cloned so it cannot be
 * freed by the caller */
locator_t *
locator_init_local_full(lisp_addr_t *addr, uint8_t *state, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight, int *out_socket)
{
    locator_t *locator = locator_init_local(addr);
    if (!locator) {
        return (NULL);
    }
    /* Initialize locator */
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;
    locator->state = state;
    locator->extended_info = (void *) new_lcl_locator_extended_info(out_socket);

    return (locator);
}

void
locator_del(locator_t *locator)
{
    if (!locator) {
        return;
    }

    if (locator->type != LOCAL_LOCATOR) {
        lisp_addr_del(locator->addr);
        free_rmt_locator_extended_info(locator->extended_info);
        free(locator->state);
    } else {
        free_lcl_locator_extended_info(locator->extended_info);
        /* DO NOT free the interface's address */
    }
    free(locator);
    locator = NULL;
}

locator_t *
locator_clone(locator_t *loc)
{
    locator_t *locator = NULL;

    if (loc->type != LOCAL_LOCATOR) {
        locator = locator_init_remote_full(loc->addr, *loc->state,
                loc->priority, loc->weight, loc->mpriority, loc->mweight);
    } else {
        /* For local locators, address and state are LINKED to the associated
         * interface. Socket is cloned with the extended info */
        locator = locator_init_local_full(loc->addr, loc->state, loc->priority,
                loc->weight, loc->mpriority, loc->mweight, NULL);
    }

    locator->type = loc->type;
    if (loc->extended_info != NULL){
        if (locator->type == LOCAL_LOCATOR){
            locator->extended_info =
                    lcl_locator_extended_info_clone(loc->extended_info);
        }else{
            locator->extended_info =
                    rmt_locator_extended_info_clone(loc->extended_info);
        }
    }

    return (locator);
}

int
locator_list_add(locator_list_t **list, locator_t *loc)
{
    locator_list_t *loc_list = NULL, *aux_llist_prev = NULL, *aux_llist_next =
            NULL;
    int cmp = 0;

    loc_list = xmalloc(sizeof(locator_list_t));
    loc_list->next = NULL;
    loc_list->locator = loc;

    if (loc->type == LOCAL_LOCATOR
        && !lisp_addr_is_no_addr(locator_addr(loc))) {
        /* If it's a local initialized locator, we should store it in order */

        if (*list == NULL) {
            *list = loc_list;
        } else {
            aux_llist_prev = NULL;
            aux_llist_next = *list;
            while (aux_llist_next != NULL) {
                cmp = lisp_addr_cmp(loc->addr, aux_llist_next->locator->addr);
                if (cmp < 0) {
                    break;
                } else if (cmp == 0) {
                    LMLOG(DBG_3,
                            "add_locator_to_list: The locator %s already exists.",
                            lisp_addr_to_char(locator_addr(loc)));
                    free(loc_list);
                    return (ERR_EXIST);
                }
                aux_llist_prev = aux_llist_next;
                aux_llist_next = aux_llist_next->next;
            }
            if (aux_llist_prev == NULL) {
                loc_list->next = aux_llist_next;
                *list = loc_list;
            } else {
                aux_llist_prev->next = loc_list;
                loc_list->next = aux_llist_next;
            }
        }
    } else { /* Remote locators and not initialized local locators */
        if (*list == NULL) {
            *list = loc_list;
        } else {
            aux_llist_prev = *list;
            while (aux_llist_prev->next != NULL) {
                aux_llist_prev = aux_llist_prev->next;
            }
            aux_llist_prev->next = loc_list;
        }
    }

    return (GOOD);
}

/* Extract the locator from a locators list that match with the address.
 * The locator is removed from the list */
locator_t *
locator_list_extract_locator(locator_list_t **head_locator_list,
        lisp_addr_t addr)
{
    locator_t *locator = NULL;
    locator_list_t *locator_list = NULL;
    locator_list_t *prev_locator_list_elt = NULL;

    locator_list = *head_locator_list;
    while (locator_list != NULL) {
        if (lisp_addr_cmp(locator_list->locator->addr, &addr) == 0) {
            locator = locator_list->locator;
            /* Extract the locator from the list */
            if (prev_locator_list_elt != NULL) {
                prev_locator_list_elt->next = locator_list->next;
            } else {
                *head_locator_list = locator_list->next;
            }
            free(locator_list);
            break;
        }
        prev_locator_list_elt = locator_list;
        locator_list = locator_list->next;
    }
    return (locator);
}

/* Return the locator from the list that contains the address passed as a
 * parameter */
locator_t *
locator_list_get_locator(locator_list_t *llist, lisp_addr_t *addr)
{
    locator_t *locator = NULL;
    int cmp = 0;

    while (llist != NULL) {
        cmp = lisp_addr_cmp(llist->locator->addr, addr);
        if (cmp == 0) {
            locator = llist->locator;
            break;
        } else if (cmp == 1) {
            break;
        }
        llist = llist->next;
    }
    return (locator);
}

void
locator_list_del(locator_list_t *locator_list)
{
    locator_list_t * next = NULL;
    while (locator_list) {
        next = locator_list->next;
        locator_del(locator_list->locator);
        free(locator_list);
        locator_list = next;
    }
}

/* Clones locators list BUT it DISCARDS probing nonces and timers! */
locator_list_t *
locator_list_clone(locator_list_t *llist)
{
    locator_list_t *llist_elt = NULL;
    locator_list_t *first = NULL;
    locator_list_t *last = NULL;

    while (llist != NULL){
        llist_elt = xzalloc(sizeof(locator_list_t));
        llist_elt->locator = locator_clone(llist->locator);

        if (first == NULL) {
            first = llist_elt;
        } else {
            last->next = llist_elt;
        }
        last = llist_elt;
        llist = llist->next;
    }

    return (first);
}

rtr_locator_t *
rtr_locator_new(lisp_addr_t address)
{
    rtr_locator_t *rtr_locator = NULL;

    rtr_locator = xmalloc(sizeof(rtr_locator));
    if (rtr_locator == NULL) {
        LMLOG(LWRN, "new_rtr_locator: Unable to allocate memory for "
                "lispd_rtr_locator: %s", strerror(errno));
        return (NULL);
    }
    rtr_locator->address = address;
    rtr_locator->latency = 0;
    rtr_locator->state = UP;

    return (rtr_locator);
}

rtr_locators_list_t*
rtr_locator_list_new()
{
    rtr_locators_list_t *rtr_list;
    rtr_list = xmalloc(sizeof(rtr_locators_list_t));
    return (rtr_list);
}

int rtr_list_add(rtr_locators_list_t **list, rtr_locator_t *locator)
{
    rtr_locators_list_t *loc_list_elt = NULL;
    rtr_locators_list_t *loc_list = *list;

    loc_list = rtr_locator_list_new();
    loc_list_elt->locator = locator;
    loc_list_elt->next = NULL;
    if (loc_list != NULL) {
        while (loc_list->next != NULL) {
            loc_list = loc_list->next;
        }
        loc_list->next = loc_list_elt;
    } else {
        *list = loc_list_elt;
    }

    return (GOOD);
}

void rtr_list_del(rtr_locators_list_t *rtr_list_elt)
{
    rtr_locators_list_t *aux_rtr_list_elt = NULL;

    while (rtr_list_elt != NULL) {
        aux_rtr_list_elt = rtr_list_elt->next;
        free(rtr_list_elt->locator);
        free(rtr_list_elt);
        rtr_list_elt = aux_rtr_list_elt;
    }
}

/* Leave in the list, rtr with afi equal to the afi passed as a parameter */
void
rtr_list_remove_locs_with_afi_different_to(rtr_locators_list_t **rtr_list,
        int afi)
{
    rtr_locators_list_t *rtr_list_elt = *rtr_list;
    rtr_locators_list_t *prev_rtr_list_elt = NULL;
    rtr_locators_list_t *aux_rtr_list_elt = NULL;

    while (rtr_list_elt != NULL) {
        if (rtr_list_elt->locator->address.afi == afi) {
            if (prev_rtr_list_elt == NULL) {
                prev_rtr_list_elt = rtr_list_elt;
                if (rtr_list_elt != *rtr_list) {
                    *rtr_list = rtr_list_elt;
                }
            } else {
                prev_rtr_list_elt->next = rtr_list_elt;
                prev_rtr_list_elt = prev_rtr_list_elt->next;
            }
            rtr_list_elt = rtr_list_elt->next;
        } else {
            aux_rtr_list_elt = rtr_list_elt;
            rtr_list_elt = rtr_list_elt->next;
            free(aux_rtr_list_elt->locator);
            free(aux_rtr_list_elt);
        }
    }
    /* Put the next element of the last rtr_locators_list found with afi X
     * to NULL*/
    if (prev_rtr_list_elt != NULL) {
        prev_rtr_list_elt->next = NULL;
    } else {
        *rtr_list = NULL;
    }
}

/* Clone RTR locator list */
rtr_locators_list_t *
rtr_locator_list_clone(rtr_locators_list_t *rtr_list)
{
    rtr_locators_list_t *rtr_locator_list = NULL;
    rtr_locator_t *rtr_locator = NULL;

    while (rtr_list != NULL){
        rtr_locator = rtr_locator_new(rtr_list->locator->address);
        rtr_list_add(&rtr_locator_list,rtr_locator);
        rtr_list = rtr_list->next;
    }
    return (rtr_locator_list);
}

