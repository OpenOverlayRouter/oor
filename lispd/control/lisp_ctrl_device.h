/*
 * lisp_ctrl_device.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 * All rights reserved.
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

#ifndef LISP_CTRL_DEVICE_H_
#define LISP_CTRL_DEVICE_H_

#include <defs.h>
#include <lisp_messages.h>
#include <lispd_types.h>
#include "lispd_map_cache_db.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_smr.h"
#include "lispd_rloc_probing.h"
#include "lispd_re.h"
//#include "lispd_map_notify.h"
#include "lispd_info_nat.h"

typedef enum {
    xTR_MODE = 1,
    MS_MODE,
    RTR_MODE
} lisp_device_mode;

struct lisp_ctrl_device_;
typedef struct lisp_ctrl_device_ lisp_ctrl_dev_t;

typedef struct ctrl_dev_class_t_ {
    int (*handle_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
    int (*send_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
    void (*start)(lisp_ctrl_dev_t *dev);
    void (*delete)(lisp_ctrl_dev_t *dev);
} ctrl_dev_class_t;

struct lisp_ctrl_device_ {
    ctrl_dev_class_t *vtable;
    lisp_device_mode mode;

    /* pointer to lisp ctrl */
    lisp_ctrl_t *ctrl;

    /* smr_timer is used to avoid sending SMRs during transition period. */
    timer_t *smr_timer;
};

int ctrl_dev_handle_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
void lisp_ctrl_dev_start(lisp_ctrl_dev_t *);
void lisp_ctrl_dev_del(lisp_ctrl_dev_t *);

/* interface to lisp_ctrl */
//int recv_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
int send_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);

int process_map_reply_msg(lisp_ctrl_dev_t *dev, lbuf_t *buf);
int process_map_request_msg(map_request_msg *, lisp_addr_t *,  uint16_t );
int process_map_notify(lisp_ctrl_dev_t *, lbuf_t *);

int send_map_request_to_mr(lbuf_t *b, uconn_t *ss);

int handle_map_cache_miss(lisp_addr_t *requested_eid, lisp_addr_t *src_eid);
int send_map_request_miss(timer *t, void *arg);
void timer_map_request_argument_del(void *);




/* Structure to set Map Reply options */
typedef struct _map_reply_opts {
    uint8_t send_rec;       // send a Map Reply record as well
    uint8_t rloc_probe;     // set RLOC probe bit
    uint8_t echo_nonce;     // set Echo-nonce bit
    mrsignaling_flags_t mrsig; // mrsignaling option bits
} map_reply_opts;


/* Struct used to pass the arguments to the call_back function of a map
 * request miss
 * TODO: make src_eid a pointer */
typedef struct _timer_map_request_argument {
    map_cache_entry_t *map_cache_entry;
    lisp_addr_t *src_eid;
    void (*arg_free_fct)(void *);
} timer_map_request_argument;

/* Put a wrapper around build_map_request_pkt and send_map_request */
int build_and_send_map_request_msg(mapping_t *requested_mapping,
        lisp_addr_t *src_eid, lisp_addr_t *dst_rloc_addr, uint8_t encap,
        uint8_t probe, uint8_t solicit_map_request, uint8_t smr_invoked,
        mrsignaling_flags_t *mrsig, uint64_t *nonce);

uint8_t *build_map_reply_pkt(mapping_t *mapping, lisp_addr_t *probed_rloc,
        map_reply_opts opts, uint64_t nonce, int *map_reply_msg_len);

int build_and_send_map_reply_msg(mapping_t *requested_mapping,
        lisp_addr_t *src_rloc_addr, lisp_addr_t *dst_rloc_addr, uint16_t dport,
        uint64_t nonce, map_reply_opts opts);

int mcache_update_entry(lisp_addr_t *eid, locators_list_t *locators,
        uint64_t nonce, uint8_t action, uint32_t ttl);
#endif /* LISP_CTRL_DEVICE_H_ */
