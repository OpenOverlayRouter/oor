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

#include "defs.h"
#include "liblisp.h"
#include "lisp_local_db.h"
#include "lisp_map_cache.h"
#include "lisp_control.h"

#include "lispd_info_nat.h"

typedef enum {
    xTR_MODE ,
    MS_MODE,
    RTR_MODE,
    MN_MODE
} lisp_dev_type_e;

typedef struct lisp_ctrl_dev lisp_ctrl_dev_t;

/* functions to control lisp control devices*/
typedef struct ctrl_dev_class_t {
    lisp_ctrl_dev_t *(*alloc)(void);
    int (*construct)(lisp_ctrl_dev_t *);
    void (*dealloc)(lisp_ctrl_dev_t *);
    void (*destruct)(lisp_ctrl_dev_t *);
    void (*init)(lisp_ctrl_dev_t *);

    void (*run)(lisp_ctrl_dev_t *dev);
    int (*recv_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
    int (*send_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);

    /* underlying system (interface) event */
    int (*if_event)(lisp_ctrl_dev_t *, char *, lisp_addr_t *, lisp_addr_t *, uint8_t );

    fwd_entry_t *(*get_fwd_entry)(lisp_ctrl_dev_t *, packet_tuple_t *);
} ctrl_dev_class_t;


struct lisp_ctrl_dev {
    lisp_dev_type_e mode;
    const ctrl_dev_class_t *ctrl_class;

    /* pointer to lisp ctrl */
    lisp_ctrl_t *ctrl;
};

extern ctrl_dev_class_t ms_ctrl_class;
extern ctrl_dev_class_t xtr_ctrl_class;



int ctrl_dev_create(lisp_dev_type_e , lisp_ctrl_dev_t **);
void ctrl_dev_destroy(lisp_ctrl_dev_t *);
int ctrl_dev_recv(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
void ctrl_dev_run(lisp_ctrl_dev_t *);
int ctrl_if_event(lisp_ctrl_dev_t *, char *iface_name, lisp_addr_t *old_addr, lisp_addr_t *new_addr, uint8_t status);
int ctrl_dev_set_ctrl(lisp_ctrl_dev_t *, lisp_ctrl_t *);
fwd_entry_t *ctrl_dev_get_fwd_entry(lisp_ctrl_dev_t *, packet_tuple_t *);


/* PRIVATE functions, used by xtr and ms */
int send_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);

char *
ctrl_dev_type_to_char(lisp_dev_type_e type);


#endif /* LISP_CTRL_DEVICE_H_ */
