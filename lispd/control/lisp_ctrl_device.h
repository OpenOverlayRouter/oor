/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef LISP_CTRL_DEVICE_H_
#define LISP_CTRL_DEVICE_H_

#include "../defs.h"
#include "../liblisp/liblisp.h"
#include "lisp_local_db.h"
#include "lisp_map_cache.h"
#include "lisp_control.h"

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

    fwd_info_t *(*get_fwd_entry)(lisp_ctrl_dev_t *, packet_tuple_t *);
} ctrl_dev_class_t;


struct lisp_ctrl_dev {
    lisp_dev_type_e mode;
    const ctrl_dev_class_t *ctrl_class;
    /* pointer to lisp ctrl */
    lisp_ctrl_t *ctrl;
};

extern ctrl_dev_class_t ms_ctrl_class;
extern ctrl_dev_class_t xtr_ctrl_class;

inline lisp_dev_type_e lisp_ctrl_dev_mode(lisp_ctrl_dev_t *dev);
inline lisp_ctrl_t *lisp_ctrl_dev_get_ctrl_t(lisp_ctrl_dev_t *dev);


int ctrl_dev_create(lisp_dev_type_e , lisp_ctrl_dev_t **);
void ctrl_dev_destroy(lisp_ctrl_dev_t *);
int ctrl_dev_recv(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
void ctrl_dev_run(lisp_ctrl_dev_t *);
int ctrl_if_event(lisp_ctrl_dev_t *, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status);
inline lisp_dev_type_e ctrl_dev_mode(lisp_ctrl_dev_t *dev);
inline lisp_ctrl_t * ctrl_dev_ctrl(lisp_ctrl_dev_t *dev);
int ctrl_dev_set_ctrl(lisp_ctrl_dev_t *, lisp_ctrl_t *);
fwd_info_t *ctrl_dev_get_fwd_entry(lisp_ctrl_dev_t *, packet_tuple_t *);


/* PRIVATE functions, used by xtr and ms */
int send_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);

char *
ctrl_dev_type_to_char(lisp_dev_type_e type);


#endif /* LISP_CTRL_DEVICE_H_ */
