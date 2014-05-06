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
#include <liblisp.h>
#include "lispd_map_cache_db.h"
#include "lispd_local_db.h"
#include "lispd_re.h"
#include "lispd_info_nat.h"

typedef enum {
    xTR_MODE = 1,
    MS_MODE,
    RTR_MODE
} lisp_dev_type;

struct lisp_ctrl_device_;
typedef struct lisp_ctrl_device_ lisp_ctrl_dev_t;

/* functions to control lisp control devices*/
typedef struct ctrl_dev_class_t_ {
    lisp_ctrl_dev_t *(*alloc)(void);
    int (*construct)(lisp_ctrl_dev_t *);
    void (*dealloc)(lisp_ctrl_dev_t *);
    void (*destruct)(lisp_ctrl_dev_t *);

    void (*run)(lisp_ctrl_dev_t *dev);
    int (*recv_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
    int (*send_msg)(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
} ctrl_dev_class_t;


struct lisp_ctrl_device_ {
    lisp_dev_type mode;
    ctrl_dev_class_t *ctrl_class;

    /* pointer to lisp ctrl */
    lisp_ctrl_t *ctrl;
};

extern ctrl_dev_class_t ms_ctrl_class;
extern ctrl_dev_class_t xtr_ctrl_class;

static ctrl_dev_class_t **reg_ctrl_dev_cls = {
        &xtr_ctrl_class,
        &ms_ctrl_class
};


/* Generic timer argument that includes the device as parameter. As a rule,
 * both 'dev' and 'data' should be pointers to existing data structure that
 * don't require the caller to free them */
typedef struct timer_arg_t_ {
    lisp_ctrl_dev_t *dev;
    void *data;
} timer_arg_t;

int ctrl_dev_create(lisp_dev_type , lisp_ctrl_dev_t **);
void ctrl_dev_destroy(lisp_ctrl_dev_t *);
int ctrl_dev_recv(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
void ctrl_dev_run(lisp_ctrl_dev_t *);

/* interface to lisp_ctrl */
//int recv_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
int send_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);


#endif /* LISP_CTRL_DEVICE_H_ */
