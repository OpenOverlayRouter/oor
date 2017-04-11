/*
 *  Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#ifndef INTERFACES_LIB_H_
#define INTERFACES_LIB_H_

#include "../liblisp/lisp_address.h"

typedef enum {
    TUN,
    TAP
} iface_type_t;

#ifdef ANDROID
#define CLONEDEV                "/dev/tun"
#else
#define CLONEDEV                "/dev/net/tun"
#endif

int create_tun_tap(iface_type_t type, const char *iface_name, int mtu);
int bring_up_iface(const char *iface_name);
int add_addr_to_iface(const char *iface_name, lisp_addr_t *addr);
int del_addr_from_iface(const char *iface_name, lisp_addr_t *addr);

#endif /* INTERFACES_LIB_H_ */
