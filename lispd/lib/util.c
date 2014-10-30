/*
 * util.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 * As the name goes, this is a set of useful macros and functions. An
 * important source of inspiration was util.c in the ovs project
 * http://openvswitch.org/
 *
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "util.h"
//#include "defs.h"
#include "lmlog.h"
#include "sockets.h"


static inline lisp_addr_t *get_network_address(lisp_addr_t *address);
static inline lisp_addr_t *get_network_address_v4(lisp_addr_t *address);
static inline lisp_addr_t *get_network_address_v6(lisp_addr_t *address);


static void
out_of_memory(void)
{
    LMLOG(LCRIT, "virtual memory exhausted");
    abort();
}

void *
xcalloc(size_t count, size_t size)
{
    void *p = count && size ? calloc(count, size) : malloc(1);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xzalloc(size_t size)
{
    return xcalloc(1, size);
}

void *
xmalloc(size_t size)
{
    void *p = malloc(size ? size : 1);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xrealloc(void *p, size_t size)
{
    p = realloc(p, size ? size : 1);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xmemdup(const void *p_, size_t size)
{
    void *p = xmalloc(size);
    memcpy(p, p_, size);
    return p;
}

char *
xmemdup0(const char *p_, size_t length)
{
    char *p = xmalloc(length + 1);
    memcpy(p, p_, length);
    p[length] = '\0';
    return p;
}

char *
xstrdup(const char *s)
{
    return xmemdup0(s, strlen(s));
}

void
lm_assert_failure(const char *where, const char *function,
                   const char *condition)
{
    /* Prevent an infinite loop (or stack overflow) in case VLOG_ABORT happens
     * to trigger an assertion failure of its own. */
    static int reentry = 0;

    switch (reentry++) {
    case 0:
        LMLOG(LCRIT, "%s: assertion %s failed in %s()",
                where, condition, function);
        abort();

    case 1:
        fprintf(stderr, "%s: assertion %s failed in %s()",
                where, condition, function);
        abort();

    default:
        abort();
    }
}

static inline int
convert_hex_char_to_byte (char val)
{
    val = (char)toupper (val);

    switch (val){
    case '0':
        return (0);
    case '1':
        return (1);
    case '2':
        return (2);
    case '3':
        return (3);
    case '4':
        return (4);
    case '5':
        return (5);
    case '6':
        return (6);
    case '7':
        return (7);
    case '8':
        return (8);
    case '9':
        return (9);
    case 'A':
        return (10);
    case 'B':
        return (11);
    case 'C':
        return (12);
    case 'D':
        return (13);
    case 'E':
        return (14);
    case 'F':
        return (15);
    default:
        return (-1);
    }
}

int
convert_hex_string_to_bytes(char *hex, uint8_t *bytes, int bytes_len)
{
    int         ctr = 0;
    char        hex_digit[2];
    int         partial_byte[2] = {0,0};

    while (hex[ctr] != '\0' && ctr <= bytes_len * 2) {
        ctr++;
    }
    if (hex[ctr] != '\0' && ctr != bytes_len * 2) {
        return (BAD);
    }

    for (ctr = 0; ctr < bytes_len; ctr++) {
        hex_digit[0] = hex[ctr * 2];
        hex_digit[1] = hex[ctr * 2 + 1];
        partial_byte[0] = convert_hex_char_to_byte(hex_digit[0]);
        partial_byte[1] = convert_hex_char_to_byte(hex_digit[1]);
        if (partial_byte[0] == -1 || partial_byte[1] == -1) {
            LMLOG(DBG_2, "convert_hex_string_to_bytes: Invalid hexadecimal"
                    " number");
            return (BAD);
        }
        bytes[ctr] = partial_byte[0] * 16 + partial_byte[1];
    }
    return (GOOD);
}

/*
 * If prefix b is contained in prefix a, then return TRUE. Otherwise return FALSE.
 * If both prefixs are the same it also returns TRUE
 */
int is_prefix_b_part_of_a (
        lisp_addr_t *a_prefix,
        lisp_addr_t *b_prefix)
{
    lisp_addr_t *a_network_addr;
    lisp_addr_t *b_network_addr_prefix_a;
    int a_prefix_length = 0;
    int b_prefix_length = 0;
    int res = FALSE;

    if (lisp_addr_is_ip_pref(a_prefix) == FALSE ||
            lisp_addr_is_ip_pref(b_prefix) == FALSE){
        return (FALSE);
    }

    a_prefix_length = lisp_addr_ip_get_plen(a_prefix);
    b_prefix_length = lisp_addr_ip_get_plen(b_prefix);

    if (lisp_addr_ip_afi(a_prefix) != lisp_addr_ip_afi(b_prefix)){
        return FALSE;
    }

    if (a_prefix_length > b_prefix_length){
        return FALSE;
    }

    a_network_addr = get_network_address(a_prefix);
    lisp_addr_set_plen(b_prefix,a_prefix_length);
    b_network_addr_prefix_a = get_network_address(b_prefix);
    lisp_addr_set_plen(b_prefix,b_prefix_length);

    if (lisp_addr_cmp (a_network_addr, b_network_addr_prefix_a) == 0){
        res = TRUE;
    }

    lisp_addr_del(a_network_addr);
    lisp_addr_del(b_network_addr_prefix_a);

    return (res);
}

static inline lisp_addr_t *get_network_address(lisp_addr_t *address)
{
    lisp_addr_t *network_address = NULL;

    switch (lisp_addr_ip_afi(address)){
    case AF_INET:
        network_address = get_network_address_v4(address);
        break;
    case AF_INET6:
        network_address = get_network_address_v6(address);
        break;
    default:
        LMLOG(DBG_1, "get_network_address: Afi not supported (%d). It should never "
                "reach this point", lisp_addr_ip_afi(address));
        break;
    }

    return (network_address);
}

static inline lisp_addr_t *get_network_address_v4(lisp_addr_t *address)
{
    lisp_addr_t *network_address = lisp_addr_new_afi(LM_AFI_IP);
    int prefix_length = lisp_addr_ip_get_plen(address);
    ip_addr_t   *ip_addr = lisp_addr_ip(address);
    ip_addr_t   *net_ip_addr = lisp_addr_ip(network_address);

    uint32_t mask = 0xFFFFFFFF;
    uint32_t addr = ntohl((ip_addr_get_v4(ip_addr))->s_addr);
    if (prefix_length != 0){
        mask = mask << (32 - prefix_length);
    }else{
        mask = 0;
    }
    addr = htonl(addr & mask);

    ip_addr_set_afi(net_ip_addr,AF_INET);
    ip_addr_set_v4(net_ip_addr,&addr);

    return network_address;
}

static inline lisp_addr_t *get_network_address_v6(lisp_addr_t *address)
{
    lisp_addr_t *network_address = lisp_addr_new_afi(LM_AFI_IP);
    ip_addr_t   *net_ip_addr = lisp_addr_ip(network_address);
    ip_addr_t   *ip_addr = lisp_addr_ip(address);
    struct in6_addr  *i6_addr = ip_addr_get_v6(ip_addr);
    struct in6_addr  net_i6_addr;
    int prefix_length = lisp_addr_ip_get_plen(address);
    uint32_t mask[4] = {0,0,0,0};
    int ctr = 0;
    int a,b;


    a = (prefix_length) / 32;
    b = (prefix_length) % 32;

    for (ctr = 0; ctr<a ; ctr++){
        mask[ctr] = 0xFFFFFFFF;
    }
    if (b != 0){
        mask[a] = 0xFFFFFFFF<<(32-b);
    }

    for (ctr = 0 ; ctr < 4 ; ctr++){
        net_i6_addr.s6_addr32[ctr] = htonl(ntohl(i6_addr->s6_addr32[ctr]) & mask[ctr]);
    }

    ip_addr_set_afi(net_ip_addr,AF_INET6);
    ip_addr_set_v6(net_ip_addr,&net_i6_addr);

    return network_address;
}

