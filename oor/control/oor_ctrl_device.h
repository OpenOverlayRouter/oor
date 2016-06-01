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

#ifndef OOR_CTRL_DEVICE_H_
#define OOR_CTRL_DEVICE_H_

#include "../defs.h"
#include "../liblisp/liblisp.h"
#include "oor_local_db.h"
#include "oor_map_cache.h"
#include "oor_control.h"

typedef struct oor_ctrl_dev oor_ctrl_dev_t;

/* functions to control lisp control devices*/
typedef struct ctrl_dev_class_t {
    oor_ctrl_dev_t *(*alloc)(void);
    int (*construct)(oor_ctrl_dev_t *);
    void (*dealloc)(oor_ctrl_dev_t *);
    void (*destruct)(oor_ctrl_dev_t *);
    void (*init)(oor_ctrl_dev_t *);

    void (*run)(oor_ctrl_dev_t *dev);
    int (*recv_msg)(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
    int (*send_msg)(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);

    int (*if_link_update)(oor_ctrl_dev_t *, char *, uint8_t );
    int (*if_addr_update)(oor_ctrl_dev_t *, char *, lisp_addr_t *,lisp_addr_t *, uint8_t);
    int (*route_update)(oor_ctrl_dev_t *, int , char *,lisp_addr_t *,
            lisp_addr_t *, lisp_addr_t *);

    fwd_info_t *(*get_fwd_entry)(oor_ctrl_dev_t *, packet_tuple_t *);
} ctrl_dev_class_t;


struct oor_ctrl_dev {
    oor_dev_type_e mode;
    const ctrl_dev_class_t *ctrl_class;
    /* pointer to lisp ctrl */
    oor_ctrl_t *ctrl;
};

extern ctrl_dev_class_t ms_ctrl_class;
extern ctrl_dev_class_t xtr_ctrl_class;

inline oor_dev_type_e lisp_ctrl_dev_mode(oor_ctrl_dev_t *dev);
inline oor_ctrl_t *lisp_ctrl_dev_get_ctrl_t(oor_ctrl_dev_t *dev);


int ctrl_dev_create(oor_dev_type_e , oor_ctrl_dev_t **);
void ctrl_dev_destroy(oor_ctrl_dev_t *);
int ctrl_dev_recv(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
void ctrl_dev_run(oor_ctrl_dev_t *);
int ctrl_dev_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status);
int ctrl_dev_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name,
        lisp_addr_t *old_addr, lisp_addr_t *new_addr, uint8_t status);
int ctrl_dev_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name,
        lisp_addr_t *src, lisp_addr_t *dst_pref, lisp_addr_t *gateway);


inline oor_dev_type_e ctrl_dev_mode(oor_ctrl_dev_t *dev);
inline oor_ctrl_t * ctrl_dev_ctrl(oor_ctrl_dev_t *dev);
int ctrl_dev_set_ctrl(oor_ctrl_dev_t *, oor_ctrl_t *);
fwd_info_t *ctrl_dev_get_fwd_entry(oor_ctrl_dev_t *, packet_tuple_t *);


/* PRIVATE functions, used by xtr and ms */
int send_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);

char *
ctrl_dev_type_to_char(oor_dev_type_e type);


#endif /* OOR_CTRL_DEVICE_H_ */
