/*
 * lispd_addr.c
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

#include "lisp_address.h"
#include "util.h"
#include "lmlog.h"


static inline lm_afi_t get_afi_(lisp_addr_t *laddr);
static inline void set_afi_(lisp_addr_t *laddr, lm_afi_t lafi);
static inline lisp_addr_t *new_ip_();
static inline lisp_addr_t *new_ippref_();
static inline lisp_addr_t *new_lcaf_();
static inline lisp_addr_t *new_afi_(lm_afi_t afi);
static inline ip_addr_t *get_ip_(lisp_addr_t *addr);
static inline ip_prefix_t *get_ippref_(lisp_addr_t *addr);
static inline lcaf_addr_t *get_lcaf_(lisp_addr_t *addr);



static inline lm_afi_t
get_afi_(lisp_addr_t *laddr)
{
    return (laddr->lafi);
}

static inline void
set_afi_(lisp_addr_t *laddr, lm_afi_t lafi)
{
    laddr->lafi = lafi;
}

static inline lisp_addr_t *
new_ip_()
{
    lisp_addr_t *laddr = lisp_addr_new();
    set_afi_(laddr, LM_AFI_IP);
    ip_addr_set_afi(get_ip_(laddr), AF_UNSPEC);
    return (laddr);
}

static inline lisp_addr_t *
new_ippref_()
{
    lisp_addr_t *laddr = lisp_addr_new();
    set_afi_(laddr, LM_AFI_IPPREF);
    return (laddr);
}

static inline lisp_addr_t *
new_lcaf_()
{
    lisp_addr_t *laddr;

    laddr = lisp_addr_new();
    set_afi_(laddr, LM_AFI_LCAF);
    return (laddr);
}

static inline lisp_addr_t *
new_afi_(lm_afi_t afi)
{
    switch (afi) {
    case LM_AFI_IP:
        return (new_ip_());
    case LM_AFI_IPPREF:
        return (new_ippref_());
    case LM_AFI_LCAF:
        return (new_lcaf_());
    default:
        lmlog(LWRN, "lisp_addr_new_afi: unknown lisp addr afi %d", afi);
        break;
    }
    return (NULL);
}

static inline ip_addr_t *
get_ip_(lisp_addr_t *addr)
{
    return (&addr->ip);
}

static inline ip_prefix_t *
get_ippref_(lisp_addr_t *addr)
{
    return (&addr->ippref);
}

static inline lcaf_addr_t *
get_lcaf_(lisp_addr_t *addr)
{
    return (&addr->lcaf);
}

inline lisp_addr_t *
lisp_addr_new_afi(uint8_t afi)
{
    return (new_afi_(afi));
}

inline lisp_addr_t *
lisp_addr_new()
{
    return (xzalloc(sizeof(lisp_addr_t)));
}

inline void
lisp_addr_del(lisp_addr_t *laddr)
{
    if (!laddr) {
        return;
    }

    switch (lisp_addr_afi(laddr)) {
    case LM_AFI_IP:
    case LM_AFI_IP6:
    case LM_AFI_IPPREF:
    case LM_AFI_NO_ADDR:
        free(laddr);
        break;
    case LM_AFI_LCAF:
        lcaf_addr_del_addr(get_lcaf_(laddr));
        free(laddr);
        break;
    default:
        lmlog(LWRN, "lisp_addr_delete: unknown lisp addr afi %d",
                lisp_addr_afi(laddr));
        return;
    }
}

inline lm_afi_t
lisp_addr_afi(lisp_addr_t *addr)
{
    return (addr->lafi);
}

inline ip_addr_t *
lisp_addr_ip(lisp_addr_t *addr)
{
    return (get_ip_(addr));
}

inline ip_prefix_t *
lisp_addr_get_ippref(lisp_addr_t *addr)
{
    return (get_ippref_(addr));
}

inline lcaf_addr_t *
lisp_addr_get_lcaf(lisp_addr_t *addr)
{
    return (get_lcaf_(addr));
}

inline uint16_t
lisp_addr_get_iana_afi(lisp_addr_t *laddr)
{

    switch (lisp_addr_afi(laddr)) {
    case LM_AFI_IP:
        return (ip_addr_get_iana_afi(get_ip_(laddr)));
        break;
    case LM_AFI_IPPREF:
        return (ip_addr_get_iana_afi(ip_prefix_addr(get_ippref_(laddr))));
        break;
    case LM_AFI_LCAF:
        return (LISP_AFI_LCAF);
    case LM_AFI_NO_ADDR:
        return (LISP_AFI_NO_ADDR);
    default:
        lmlog(DBG_2, "lisp_addr_get_iana_afi: unknown AFI (%d)",
                lisp_addr_afi(laddr));
        return (BAD);
    }
}

inline uint32_t
lisp_addr_size_to_write(lisp_addr_t *laddr)
{
    switch (lisp_addr_afi(laddr)) {
    case LM_AFI_NO_ADDR:
        return (sizeof(uint16_t));
    case LM_AFI_IP:
        return (ip_addr_get_size_to_write(get_ip_(laddr)));
        break;
    case LM_AFI_IPPREF:
        return (ip_addr_get_size_to_write(
                ip_prefix_addr(get_ippref_(laddr))));
        break;
    case LM_AFI_LCAF:
        return (lcaf_addr_get_size_to_write(get_lcaf_(laddr)));
    default:
        lmlog(DBG_3, "lisp_addr_get_size_in_pkt: not defined for afi %d",
                lisp_addr_afi(laddr));
        break;
    }
    return (0);
}

inline uint16_t
lisp_addr_get_plen(lisp_addr_t *laddr)
{
    switch (lisp_addr_afi(laddr)) {
    case LM_AFI_IP:
        return (ip_addr_afi_to_default_mask(get_ip_(laddr)));
    case LM_AFI_IPPREF:
        return (ip_prefix_get_plen(get_ippref_(laddr)));
    default:
//        lispd_log_msg(DBG_2, "lisp_addr_get_plen: not defined for afi %d",
//                lisp_addr_get_afi(laddr));
        break;
    }
    return (0);
}

char *
lisp_addr_to_char(lisp_addr_t *addr)
{
    if (!addr) {
        return("_NULL_");
    }

    switch (lisp_addr_afi(addr)) {
    case LM_AFI_IP:
    case LM_AFI_IP6:
        return (ip_addr_to_char(get_ip_(addr)));
    case LM_AFI_IPPREF:
        return (ip_prefix_to_char(get_ippref_(addr)));
        break;
    case LM_AFI_LCAF:
        return (lcaf_addr_to_char(get_lcaf_(addr)));
        break;
    case LM_AFI_NO_ADDR:
        return ("_EMPTY_ADDR_");
    default:
        lmlog(DBG_3, "lisp_addr_to_char: Trying to convert"
                " to string unknown LISP AFI %d", lisp_addr_afi(addr));
        break;
    }

    return (NULL);
}

inline void
lisp_addr_set_afi(lisp_addr_t *addr, lm_afi_t afi)
{
    set_afi_(addr, afi);
}

inline void
lisp_addr_ip_to_ippref(lisp_addr_t *laddr)
{
    if (lisp_addr_afi(laddr) != LM_AFI_IP
            && lisp_addr_afi(laddr) != LM_AFI_IPPREF) {
        lmlog(DBG_3, "lisp_addr_ip_to_ippref: called, but addr has afi (%d)",
                lisp_addr_afi(laddr));
        return;
    }
    set_afi_(laddr, LM_AFI_IPPREF);
    ip_prefix_set_plen(get_ippref_(laddr),
            ip_addr_afi_to_default_mask(lisp_addr_ip(laddr)));
}

inline uint16_t
lisp_addr_ip_afi(lisp_addr_t *addr)
{
    switch (get_afi_(addr)) {
    case LM_AFI_IP:
        return (ip_addr_afi(get_ip_(addr)));
    case LM_AFI_IPPREF:
        return (ip_prefix_afi(get_ippref_(addr)));
    default:
        lmlog(LWRN, "lisp_addr_ip_get_afi: not supported for afi %d",
                get_afi_(addr));
        return (0);
    }
}

void
lisp_addr_set_ip_afi(lisp_addr_t *la, int afi)
{
    switch (get_afi_(la)) {
    case LM_AFI_IP:
        ip_addr_set_afi(get_ip_(la), afi);
        break;
    case LM_AFI_IPPREF:
        ip_prefix_set_afi(get_ippref_(la), afi);
        break;
    default:
        lmlog(LWRN, "lisp_addr_ip_get_afi: not supported for afi %d",
                get_afi_(la));
        return;
    }
}

inline ip_addr_t *
lisp_addr_ip_get_addr(lisp_addr_t *laddr)
{
    if (get_afi_(laddr) != LM_AFI_IP && get_afi_(laddr) != LM_AFI_IPPREF) {
        lmlog(DBG_3, "lisp_addr_ip_get_addr: called, but addr has afi (%d)",
                get_afi_(laddr));
        return (NULL);
    }
    switch (get_afi_(laddr)) {
    case LM_AFI_IP:
        return (get_ip_(laddr));
    case LM_AFI_IPPREF:
        return (ip_prefix_addr(get_ippref_(laddr)));
    case LM_AFI_NO_ADDR:
    case LM_AFI_LCAF:
        lmlog(DBG_3, "lisp_addr_ip_get_addr: AFI (%s) not of IP type",
                get_afi_(laddr));
        break;
    default:
        lmlog(DBG_3, "lisp_addr_ip_get_addr: AFI (%s) not supported",
                get_afi_(laddr));
    }
    return (NULL);
}

inline uint8_t
lisp_addr_ip_get_plen(lisp_addr_t *laddr)
{
    switch (get_afi_(laddr)) {
    case LM_AFI_IP:
        if (ip_addr_afi(get_ip_(laddr)) == AF_UNSPEC) {
            lmlog(LWRN, "lisp_addr_ip_get_plen: called with AF_UNSPEC");
            return (0);
        }
        return ((ip_addr_afi(get_ip_(laddr)) == AF_INET) ? 32 : 128);
    case LM_AFI_IPPREF:
        return (ip_prefix_get_plen(get_ippref_(laddr)));
    default:
        lmlog(DBG_3, "lisp_addr_ip_get_plen: called with AFI not IP or IPPREF");
    }

    return (0);
}

inline void
lisp_addr_ip_set_afi(lisp_addr_t *laddr, int afi)
{
    switch (get_afi_(laddr)) {
    case LM_AFI_IP:
        ip_addr_set_afi(get_ip_(laddr), afi);
        break;
    case LM_AFI_IPPREF:
        ip_prefix_set_afi(get_ippref_(laddr), afi);
        break;
    default:
        lmlog(DBG_3, "lisp_addr_ip_set_afi: called with LM AFI %d",
                get_afi_(laddr));
        break;
    }
}

int
lisp_addr_is_ip(lisp_addr_t *addr)
{
    return (get_afi_(addr) == LM_AFI_IP);
}

inline void
lisp_addr_set_plen(lisp_addr_t *laddr, uint8_t plen)
{
    switch (get_afi_(laddr)) {
    case LM_AFI_IP:
        set_afi_(laddr, LM_AFI_IPPREF);
        ip_prefix_set_plen(get_ippref_(laddr), plen);
        break;
    case LM_AFI_IPPREF:
        ip_prefix_set_plen(get_ippref_(laddr), plen);
        break;
    default:
        lmlog(DBG_2, "lisp_addr_set_plen: not supported for afi %d",
                lisp_addr_afi(laddr));
        break;
    }
}

/**
 * lisp_addr_copy - copies src to dst. Still works if they have different internal
 * structures. Note that dst MUST be allocated prior to calling the function
 */
void
lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src)
{
    set_afi_(dst, lisp_addr_afi(src));
    switch (lisp_addr_afi(dst)) {
    case LM_AFI_IP:
        ip_addr_copy(get_ip_(dst), get_ip_(src));
        break;
    case LM_AFI_IPPREF:
        ip_prefix_copy(get_ippref_(dst), get_ippref_(src));
        break;
    case LM_AFI_LCAF:
        lcaf_addr_copy(get_lcaf_(dst), get_lcaf_(src));
        break;
    default:
        lmlog(DBG_2, "lisp_addr_copy:  Unknown AFI type %d in EID",
                lisp_addr_afi(dst));
        break;
    }
}

lisp_addr_t *
lisp_addr_clone(lisp_addr_t *src)
{
    lisp_addr_t *dst;

    dst = lisp_addr_new();
    lisp_addr_copy(dst, src);
    return (dst);
}

inline uint32_t
lisp_addr_copy_to(void *dst, lisp_addr_t *src)
{
    switch (lisp_addr_afi(src)) {
    case LM_AFI_IP:
        ip_addr_copy_to(dst, get_ip_(src));
        return (ip_addr_get_size(get_ip_(src)));
    case LM_AFI_IPPREF:
        ip_addr_copy_to(dst, ip_prefix_addr(get_ippref_(src)));
        return (ip_addr_get_size(ip_prefix_addr(get_ippref_(src))));
    case LM_AFI_LCAF:
        lmlog(DBG_3,
                "lisp_addr_copy_to: requeste for %s Not implemented for LCAF.",
                lisp_addr_to_char(src));
        break;
    default:
        lmlog(DBG_3, "lisp_addr_copy_to:  Unknown AFI type %d in EID",
                lisp_addr_afi(src));
        break;
    }
    return (0);
}

/** lisp_addr_write
 *
 * @offset:     memory location
 * @laddr:      the lisp address to be copied
 * Description: The function copies what is *CONTAINED* in a lisp address
 * to a certain memory location, NOT the whole structure!
 */
inline int
lisp_addr_write(void *offset, lisp_addr_t *laddr)
{
    switch (lisp_addr_afi(laddr)) {
    case LM_AFI_IP:
        return (ip_addr_write_to_pkt(offset, get_ip_(laddr), 0));
    case LM_AFI_IPPREF:
        return (ip_addr_write_to_pkt(offset,
                ip_prefix_addr(get_ippref_(laddr)), 0));
    case LM_AFI_LCAF:
        return (lcaf_addr_write(offset, get_lcaf_(laddr)));
    case LM_AFI_NO_ADDR:
        memset(offset, 0, sizeof(uint16_t));
        return (sizeof(uint16_t));
    default:
        lmlog(DBG_3, "lisp_addr_write_to_pkt: Unkown afi %d",
                lisp_addr_afi(laddr));
        break;
    }
    return (0);
}

int
lisp_addr_parse(uint8_t *offset, lisp_addr_t *laddr)
{
    lisp_afi_t afi;
    int len = 0;

    if (!laddr) {
        lmlog(DBG_3, "lisp_addr_parse: Called with unallocated address!");
        return (BAD);
    }

    afi = ntohs(*((uint16_t *) offset));

    switch (afi) {
    case LISP_AFI_IP:
    case LISP_AFI_IPV6:
        len = ip_addr_parse((void *) offset, afi, get_ip_(laddr));
        set_afi_(laddr, LM_AFI_IP);
        break;
    case LISP_AFI_LCAF:
//        laddr->lcaf = lcaf_addr_new();
        len = lcaf_addr_parse(offset, get_lcaf_(laddr));
        set_afi_(laddr, LM_AFI_LCAF);
        break;
    case LISP_AFI_NO_ADDR:
        len = sizeof(uint16_t);
        set_afi_(laddr, LM_AFI_NO_ADDR);
        break;
    default:
        lmlog(DBG_2, "lisp_addr_read_from_pkt:  Unknown AFI type %d in EID",
                afi);
        return (BAD);
        break;
    }

    return (len);
}

/*
 * Compare two lisp_addr_t.
 * Returns:
 *          -1: If they are from different afi
 *           0: Both address are the same
 *           1: Addr1 is bigger than addr2
 *           2: Addr2 is bigger than addr1
 */

inline int
lisp_addr_cmp(lisp_addr_t *addr1, lisp_addr_t *addr2)
{
    int cmp;
    if (!addr1 || !addr2) {
        return (-1);
    }
    if (lisp_addr_afi(addr1) != lisp_addr_afi(addr2)) {
        return (-1);
    }

    switch (lisp_addr_afi(addr1)) {
    case LM_AFI_IP:
        cmp = ip_addr_cmp(get_ip_(addr1), get_ip_(addr2));
        break;
    case LM_AFI_IPPREF:
        cmp = ip_addr_cmp(ip_prefix_addr(get_ippref_(addr1)),
                ip_prefix_addr(get_ippref_(addr2)));
        break;
    case LM_AFI_LCAF:
        cmp = lcaf_addr_cmp(get_lcaf_(addr1), get_lcaf_(addr2));
        break;
    default:
        break;
    }

    if (cmp == 0) {
        return (0);
    } else if (cmp > 0) {
        return (1);
    } else {
        return (2);
    }
}

inline int
lisp_addr_is_lcaf(lisp_addr_t *laddr)
{
    return (get_afi_(laddr) == LM_AFI_LCAF);
}

inline void
lisp_addr_lcaf_set_addr(lisp_addr_t *laddr, void *addr)
{
    laddr->lcaf.addr = addr;
}

inline void *
lisp_addr_lcaf_get_addr(lisp_addr_t *laddr)
{
    return (laddr->lcaf.addr);
}

inline lcaf_type
lisp_addr_lcaf_get_type(lisp_addr_t *laddr)
{
    return (laddr->lcaf.type);
}

inline void
lisp_addr_lcaf_set_type(lisp_addr_t *laddr, int type)
{
    laddr->lcaf.type = type;
}

inline void
lisp_addr_ip_init(lisp_addr_t *addr, void *data, int afi)
{
    set_afi_(addr, LM_AFI_IP);
    ip_addr_init(get_ip_(addr), data, afi);
}

inline int
lisp_addr_init_from_ip(lisp_addr_t *laddr, ip_addr_t *ip)
{
    set_afi_(laddr, LM_AFI_IP);
    ip_addr_copy(get_ip_(laddr), ip);
    return (GOOD);
}

inline int
lisp_addr_init_from_ippref(lisp_addr_t *laddr, ip_addr_t *ip, uint8_t plen)
{
    set_afi_(laddr, LM_AFI_IPPREF);
    ip_prefix_set(get_ippref_(laddr), ip, plen);
    return (GOOD);
}

inline int
lisp_addr_init_from_lcaf(lisp_addr_t *laddr, lcaf_addr_t *lcaf)
{
    set_afi_(laddr, LM_AFI_LCAF);
    lcaf_addr_copy(get_lcaf_(laddr), lcaf);
    return (GOOD);
}

inline uint16_t
lisp_addr_iana_afi_to_lm_afi(uint16_t afi)
{
    switch (afi) {
    case LISP_AFI_IP:
    case LISP_AFI_IPV6:
        return (LM_AFI_IP);
    case LISP_AFI_LCAF:
        return (LM_AFI_LCAF);
    default:
        lmlog(LWRN, "lisp_addr_iana_afi_to_sock_afi: unknown IP AFI (%d)", afi);
        return (0);
    }

}

inline int
lisp_addr_is_mc(lisp_addr_t *addr)
{
    if (!addr)
        return (0);
    if (lisp_addr_is_lcaf(addr) && lcaf_addr_is_mc(get_lcaf_(addr)))
        return (1);
    else
        return (0);
}

lisp_addr_t *
lisp_addr_to_ip_addr(lisp_addr_t *addr)
{
    switch (lisp_addr_afi(addr)) {
    case LM_AFI_IP:
    case LM_AFI_IPPREF:
        return (addr);
    case LM_AFI_LCAF:
        return (lcaf_eid_get_ip_addr(get_lcaf_(addr)));
    default:
        return (NULL);
    }
    return (NULL);
}

/* deallocates the lcaf's address or does nothing for other AFIs*/
void
lisp_addr_dealloc(lisp_addr_t *addr)
{
    switch (get_afi_(addr)) {
    case LM_AFI_IP:
    case LM_AFI_IPPREF:
    case LM_AFI_NO_ADDR:
        break;
    case LM_AFI_LCAF:
        lcaf_addr_del_addr(get_lcaf_(addr));
        break;
    default:
        break;
    }
}

void
lisp_addr_list_to_char(lisp_addr_list_t *list, const char *list_name,
        int log_level)
{
    lisp_addr_list_t *iterator = 0;

    if (!list)
        return;

    lmlog(log_level, "************* %13s ***************", list_name);
    lmlog(log_level, "|               Locator (RLOC)            |");

    iterator = list;
    while (iterator) {
        lmlog(log_level, "| %39s |", lisp_addr_to_char(iterator->address));
        iterator = iterator->next;
    }
}

/* Fill lisp_addr with the address.
 * Return GOOD if no error has been found */
int
lisp_addr_ip_from_char(char *addr, lisp_addr_t *laddr)
{
    if (ip_addr_from_char(addr, lisp_addr_ip(laddr)) == GOOD) {
        lisp_addr_set_afi(laddr, LM_AFI_IP);
        return(GOOD);
    } else {
        lisp_addr_set_afi(laddr, LM_AFI_NO_ADDR);
        return(BAD);
    }
}


/* Parse address and fill lisp_addr and mask.
 * Return GOOD if no error */
int
lisp_addr_ippref_from_char(char *addr, lisp_addr_t *laddr)
{
    if (ip_prefix_from_char(addr, get_ippref_(laddr)) == GOOD) {
        lisp_addr_set_afi(laddr, LM_AFI_IPPREF);
        return(GOOD);
    } else {
        lisp_addr_set_afi(laddr, LM_AFI_NO_ADDR);
        return(BAD);
    }
}
