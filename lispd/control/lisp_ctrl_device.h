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
#include "lispd_rloc_probing.h"
#include "lispd_re.h"
#include "lispd_info_nat.h"
#include "lisp_proto.h"

typedef enum {
    xTR_MODE = 1,
    MS_MODE,
    RTR_MODE
} lisp_device_mode;

struct lisp_ctrl_device_;
typedef struct lisp_ctrl_device_ lisp_ctrl_dev_t;

/* functions to control lisp control devices*/
typedef struct ctrl_dev_class_t_ {
    int (*handle_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
    int (*send_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
    void (*start)(lisp_ctrl_dev_t *dev);
    void (*delete)(lisp_ctrl_dev_t *dev);
} ctrl_dev_class_t;


/* functions to interact with tunnel routers */
typedef struct tr_dev_class_t_ {
    /* timers */
    timer *(*map_register_timer)(lisp_ctrl_dev_t *);

    /* smr_timer is used to avoid sending SMRs during transition period. */
    timer *(*smr_timer)(lisp_ctrl_dev_t *);

    lispd_map_server_list_t *(*get_map_servers)(lisp_ctrl_dev_t *);
    lisp_addr_t *(*get_map_resolver)(lisp_ctrl_dev_t *);
    lisp_addr_t *(*get_default_rloc)(lisp_ctrl_dev_t *, int);
    glist_t *(*get_default_rlocs)(lisp_ctrl_dev_t *);
    lisp_addr_t *(*get_main_eid)(lisp_ctrl_dev_t *);

    /* NAT specific */
    int (*nat_aware)(lisp_ctrl_dev_t *);
    int (*nat_status)(lisp_ctrl_dev_t *);
    nonces_list_t *(*nat_emr_nonce)(lisp_ctrl_dev_t *);
} tr_dev_class_t;

struct lisp_ctrl_device_ {
    lisp_device_mode mode;

    ctrl_dev_class_t *ctrl_class;

    /* device type specific functions */
    union {
        tr_dev_class_t *tr_class;
        /* ms class */
        /* ddt class */
    };

    /* pointer to lisp ctrl */
    lisp_ctrl_t *ctrl;
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


int handle_map_cache_miss(lisp_addr_t *requested_eid, lisp_addr_t *src_eid);
int send_map_request_retry(timer *t, void *arg);

int mcache_update_entry(lisp_addr_t *eid, locators_list_t *locators,
        uint64_t nonce, uint8_t action, uint32_t ttl);
#endif /* LISP_CTRL_DEVICE_H_ */
