/*
 * lisp_ctrl_device.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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


#include "lisp_ctrl_device.h"
//#include <lispd_external.h>
#include <lispd_sockets.h>
#include <packets.h>
#include <lispd_lib.h>

static ctrl_dev_class_t *
ctrl_dev_class_find(lisp_dev_type type)
{
    return(reg_ctrl_dev_cls[type]);
}

int
ctrl_dev_recv(lisp_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc)
{
    return(dev->ctrl_class->recv_msg(dev, b, uc));
}

void
ctrl_dev_run(lisp_ctrl_dev_t *dev)
{
    dev->ctrl_class->run(dev);
}

int
ctrl_dev_create(lisp_dev_type type, lisp_ctrl_dev_t **devp)
{
    lisp_ctrl_dev_t *dev;
    ctrl_dev_class_t *class;

    *devp = NULL;

    /* find type of device */
    class = ctrl_dev_class_find(type);
    dev = class->alloc();
    dev->mode =type;
    dev->ctrl_class = class;
    dev->ctrl_class->construct(dev);

    *devp = dev;
    return(GOOD);
}

void
ctrl_dev_destroy(lisp_ctrl_dev_t *dev)
{
    if (!dev) {
        return;
    }

    dev->ctrl_class->destruct(dev);
    dev->ctrl_class->dealloc(dev);
}

int
send_msg(lisp_ctrl_dev_t *dev, lisp_msg *msg, uconn_t *uc)
{
    ctrl_send_msg(dev->ctrl, msg, uc);
    return(GOOD);
}


int
ctrl_dev_program_smr(lisp_ctrl_dev_t *dev)
{
    void *arg;
    timer *t;

    /* used only with tunnel routers */
    if (dev->mode != xTR_MODE && dev->mode != RTR_MODE) {
        return(GOOD);
    }

    return(program_smr(dev, LISPD_SMR_TIMEOUT));
}

