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

#include "lisp_address.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"


static inline lm_afi_t get_lafi_(lisp_addr_t *laddr);
static inline void set_lafi_(lisp_addr_t *laddr, lm_afi_t lafi);
static inline lisp_addr_t *new_no_addr_();
static inline lisp_addr_t *new_ip_();
static inline lisp_addr_t *new_ippref_();
static inline lisp_addr_t *new_lcaf_();
static inline lisp_addr_t *new_lafi_(lm_afi_t afi);
static inline ip_addr_t *get_ip_(lisp_addr_t *addr);
static inline ip_prefix_t *get_ippref_(lisp_addr_t *addr);
static inline lcaf_addr_t *get_lcaf_(lisp_addr_t *addr);



static inline lm_afi_t
get_lafi_(lisp_addr_t *laddr)
{
    return (laddr->lafi);
}

static inline void
set_lafi_(lisp_addr_t *laddr, lm_afi_t lafi)
{
    laddr->lafi = lafi;
}

static inline lisp_addr_t *
new_no_addr_()
{
    lisp_addr_t *laddr = lisp_addr_new();
    set_lafi_(laddr, LM_AFI_NO_ADDR);
    return (laddr);
}

static inline lisp_addr_t *
new_ip_()
{
    lisp_addr_t *laddr = lisp_addr_new();
    set_lafi_(laddr, LM_AFI_IP);
    ip_addr_set_afi(get_ip_(laddr), AF_UNSPEC);
    return (laddr);
}

static inline lisp_addr_t *
new_ippref_()
{
    lisp_addr_t *laddr = lisp_addr_new();
    set_lafi_(laddr, LM_AFI_IPPREF);
    return (laddr);
}

static inline lisp_addr_t *
new_lcaf_()
{
    lisp_addr_t *laddr;

    laddr = lisp_addr_new();
    set_lafi_(laddr, LM_AFI_LCAF);
    return (laddr);
}

static inline lisp_addr_t *
new_lafi_(lm_afi_t afi)
{
    switch (afi) {
    case LM_AFI_NO_ADDR:
        return (new_no_addr_());
    case LM_AFI_IP:
        return (new_ip_());
    case LM_AFI_IPPREF:
        return (new_ippref_());
    case LM_AFI_LCAF:
        return (new_lcaf_());
    default:
        OOR_LOG(LWRN, "lisp_addr_new_afi: unknown lisp addr afi %d", afi);
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
lisp_addr_new_lafi(uint8_t lafi)
{
    return (new_lafi_(lafi));
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

    switch (lisp_addr_lafi(laddr)) {
    case LM_AFI_IP:
    case LM_AFI_IPPREF:
    case LM_AFI_NO_ADDR:
        free(laddr);
        break;
    case LM_AFI_LCAF:
        lcaf_addr_del_addr(get_lcaf_(laddr));
        free(laddr);
        break;
    default:
        OOR_LOG(LWRN, "lisp_addr_delete: unknown lisp addr afi %d",
                lisp_addr_lafi(laddr));
        return;
    }
    laddr = NULL;

}

inline uint16_t
lisp_addr_get_iana_afi(lisp_addr_t *laddr)
{

    switch (lisp_addr_lafi(laddr)) {
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
        OOR_LOG(LDBG_2, "lisp_addr_get_iana_afi: unknown AFI (%d)",
                lisp_addr_lafi(laddr));
        return (BAD);
    }
}

inline uint32_t
lisp_addr_size_to_write(lisp_addr_t *laddr)
{
    switch (lisp_addr_lafi(laddr)) {
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
        OOR_LOG(LDBG_3, "lisp_addr_get_size_in_pkt: not defined for afi %d",
                lisp_addr_lafi(laddr));
        break;
    }
    return (0);
}

inline uint16_t
lisp_addr_get_plen(lisp_addr_t *laddr)
{
    lisp_addr_t *pref_addr;
    switch (lisp_addr_lafi(laddr)) {
    case LM_AFI_IP:
        return (ip_addr_afi_to_default_mask(get_ip_(laddr)));
    case LM_AFI_IPPREF:
        return (ip_prefix_get_plen(get_ippref_(laddr)));
    case LM_AFI_LCAF:
        pref_addr = lisp_addr_get_ip_pref_addr(laddr);
        if (pref_addr){
            return (ip_prefix_get_plen(get_ippref_(pref_addr)));
        }
        break;
    default:
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

    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
        return (ip_addr_to_char(get_ip_(addr)));
    case LM_AFI_IPPREF:
        return (ip_prefix_to_char(get_ippref_(addr)));
        break;
    case LM_AFI_LCAF:
        return (lcaf_addr_to_char(get_lcaf_(addr)));
        break;
    case LM_AFI_NO_ADDR:
        return ("_NO_ADDR_");
    default:
        OOR_LOG(LDBG_3, "lisp_addr_to_char: Trying to convert"
                " to string unknown LISP AFI %d", lisp_addr_lafi(addr));
        break;
    }

    return (NULL);
}

inline void
lisp_addr_set_lafi(lisp_addr_t *addr, lm_afi_t afi)
{
    set_lafi_(addr, afi);
}

inline void
lisp_addr_ip_to_ippref(lisp_addr_t *laddr)
{
    if (lisp_addr_lafi(laddr) != LM_AFI_IP
            && lisp_addr_lafi(laddr) != LM_AFI_IPPREF) {
        OOR_LOG(LDBG_3, "lisp_addr_ip_to_ippref: called, but addr has afi (%d)",
                lisp_addr_lafi(laddr));
        return;
    }
    set_lafi_(laddr, LM_AFI_IPPREF);
    ip_prefix_set_plen(get_ippref_(laddr),
            ip_addr_afi_to_default_mask(lisp_addr_ip(laddr)));
}

inline uint16_t
lisp_addr_ip_afi(lisp_addr_t *addr)
{
    switch (get_lafi_(addr)) {
    case LM_AFI_IP:
        return (ip_addr_afi(get_ip_(addr)));
    case LM_AFI_IPPREF:
        return (ip_prefix_afi(get_ippref_(addr)));
    default:
        OOR_LOG(LDBG_1, "lisp_addr_ip_afi: not supported for afi %d",
                get_lafi_(addr));
        return (0);
    }
}

void
lisp_addr_set_ip_afi(lisp_addr_t *la, int afi)
{
    switch (get_lafi_(la)) {
    case LM_AFI_IP:
        ip_addr_set_afi(get_ip_(la), afi);
        break;
    case LM_AFI_IPPREF:
        ip_prefix_set_afi(get_ippref_(la), afi);
        break;
    default:
        OOR_LOG(LWRN, "lisp_addr_ip_get_afi: not supported for afi %d",
                get_lafi_(la));
        return;
    }
}

inline ip_addr_t *
lisp_addr_ip_get_addr(lisp_addr_t *laddr)
{
    if (get_lafi_(laddr) != LM_AFI_IP && get_lafi_(laddr) != LM_AFI_IPPREF) {
        OOR_LOG(LDBG_3, "lisp_addr_ip_get_addr: called, but addr has afi (%d)",
                get_lafi_(laddr));
        return (NULL);
    }
    switch (get_lafi_(laddr)) {
    case LM_AFI_IP:
        return (get_ip_(laddr));
    case LM_AFI_IPPREF:
        return (ip_prefix_addr(get_ippref_(laddr)));
    case LM_AFI_NO_ADDR:
    case LM_AFI_LCAF:
        OOR_LOG(LDBG_3, "lisp_addr_ip_get_addr: AFI (%s) not of IP type",
                get_lafi_(laddr));
        break;
    default:
        OOR_LOG(LDBG_3, "lisp_addr_ip_get_addr: AFI (%s) not supported",
                get_lafi_(laddr));
    }
    return (NULL);
}

inline uint8_t
lisp_addr_ip_get_plen(lisp_addr_t *laddr)
{
    switch (get_lafi_(laddr)) {
    case LM_AFI_IP:
        if (ip_addr_afi(get_ip_(laddr)) == AF_UNSPEC) {
            OOR_LOG(LWRN, "lisp_addr_ip_get_plen: called with AF_UNSPEC");
            return (0);
        }
        return ((ip_addr_afi(get_ip_(laddr)) == AF_INET) ? 32 : 128);
    case LM_AFI_IPPREF:
        return (ip_prefix_get_plen(get_ippref_(laddr)));
    default:
        OOR_LOG(LDBG_3, "lisp_addr_ip_get_plen: called with AFI not IP or IPPREF");
    }

    return (0);
}

inline void
lisp_addr_ip_set_afi(lisp_addr_t *laddr, int afi)
{
    switch (get_lafi_(laddr)) {
    case LM_AFI_IP:
        ip_addr_set_afi(get_ip_(laddr), afi);
        break;
    case LM_AFI_IPPREF:
        ip_prefix_set_afi(get_ippref_(laddr), afi);
        break;
    default:
        OOR_LOG(LDBG_3, "lisp_addr_ip_set_afi: called with LM AFI %d",
                get_lafi_(laddr));
        break;
    }
}

inline void
lisp_addr_set_plen(lisp_addr_t *laddr, uint8_t plen)
{
    lisp_addr_t *laddr_pref;
    switch (get_lafi_(laddr)) {
    case LM_AFI_IP:
        set_lafi_(laddr, LM_AFI_IPPREF);
        ip_prefix_set_plen(get_ippref_(laddr), plen);
        break;
    case LM_AFI_IPPREF:
        ip_prefix_set_plen(get_ippref_(laddr), plen);
        break;
    case LM_AFI_LCAF:
        laddr_pref  = lisp_addr_get_ip_pref_addr(laddr);
        if (!laddr_pref){
            laddr_pref  = lisp_addr_get_ip_addr(laddr);
            if (!laddr_pref){
                OOR_LOG(LDBG_2, "lisp_addr_set_plen: lcaf address without prefix address");
                return;
            }
        }
        lisp_addr_set_plen(laddr_pref,plen);
        break;
    default:
        OOR_LOG(LDBG_2, "lisp_addr_set_plen: not supported for afi %d",
                lisp_addr_lafi(laddr));
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
    set_lafi_(dst, lisp_addr_lafi(src));
    switch (lisp_addr_lafi(src)) {
    case LM_AFI_NO_ADDR:
        OOR_LOG(LDBG_3, "lisp_addr_copy:  No address element copied");
        break;
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
        OOR_LOG(LDBG_2, "lisp_addr_copy:  Unknown AFI type %d in EID",
                lisp_addr_lafi(dst));
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
    switch (lisp_addr_lafi(src)) {
    case LM_AFI_IP:
        ip_addr_copy_to(dst, get_ip_(src));
        return (ip_addr_get_size(get_ip_(src)));
    case LM_AFI_IPPREF:
        ip_addr_copy_to(dst, ip_prefix_addr(get_ippref_(src)));
        return (ip_addr_get_size(ip_prefix_addr(get_ippref_(src))));
    case LM_AFI_LCAF:
        OOR_LOG(LDBG_3,
                "lisp_addr_copy_to: requeste for %s Not implemented for LCAF.",
                lisp_addr_to_char(src));
        break;
    default:
        OOR_LOG(LDBG_3, "lisp_addr_copy_to:  Unknown AFI type %d in EID",
                lisp_addr_lafi(src));
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
    switch (lisp_addr_lafi(laddr)) {
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
        OOR_LOG(LDBG_3, "lisp_addr_write_to_pkt: Unkown afi %d",
                lisp_addr_lafi(laddr));
        break;
    }
    return (0);
}

/* Parses a LISP address and returns number of bytes read */
int
lisp_addr_parse(uint8_t *offset, lisp_addr_t *laddr)
{
    lisp_afi_e afi;
    int len = 0;

    if (!laddr) {
        OOR_LOG(LDBG_3, "lisp_addr_parse: Called with unallocated address!");
        return (0);
    }

    afi = ntohs(*((uint16_t *) offset));

    switch (afi) {
    case LISP_AFI_IP:
    case LISP_AFI_IPV6:
        len = ip_addr_parse((void *) offset, afi, get_ip_(laddr));
        set_lafi_(laddr, LM_AFI_IP);
        break;
    case LISP_AFI_LCAF:
        len = lcaf_addr_parse(offset, get_lcaf_(laddr));
        set_lafi_(laddr, LM_AFI_LCAF);
        break;
    case LISP_AFI_NO_ADDR:
        len = sizeof(uint16_t);
        set_lafi_(laddr, LM_AFI_NO_ADDR);
        break;
    default:
        OOR_LOG(LDBG_2, "lisp_addr_read_from_pkt:  Unknown AFI type %d in EID",
                afi);
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
        OOR_LOG(LDBG_3,"lisp_addr_cmp: One of the compared addresses is NULL");
        return (-1);
    }
    if (lisp_addr_lafi(addr1) != lisp_addr_lafi(addr2)) {
        OOR_LOG(LDBG_3,"lisp_addr_cmp: Addresses with different lafi: %d - %d",
                lisp_addr_lafi(addr1),lisp_addr_lafi(addr2));
        return (-1);
    }

    switch (lisp_addr_lafi(addr1)) {
    case LM_AFI_NO_ADDR:
        if (addr1 == addr2){
            cmp = 0;
        }else{
            cmp = 2;
        }
        break;
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
        cmp = -1;
        break;
    }

    return (cmp);
}


/*
 * Compare lafi and afit/type of two lisp_addr_t.
 * Returns:
 *           0: Both address has the same lafi and afi/type
 *           1: Addr1 is bigger than addr2
 *           2: Addr2 is bigger than addr1
 */

inline int
lisp_addr_cmp_afi(lisp_addr_t *addr1, lisp_addr_t *addr2)
{
    int             lafi_a;
    int             lafi_b;
    int             afi_a;
    int             afi_b;

    if (addr1 == NULL || addr2 == NULL){
        return (-2);
    }

    lafi_a = lisp_addr_lafi(addr1);
    lafi_b = lisp_addr_lafi(addr2);

    if (lafi_a > lafi_b){
        return (1);
    }
    if (lafi_a < lafi_b){
        return (2);
    }

    switch(lafi_a){
    case LM_AFI_NO_ADDR:
        return (0);
    case LM_AFI_IP:
        afi_a = lisp_addr_ip_afi(addr1);
        afi_b = lisp_addr_ip_afi(addr2);
        break;
    case LM_AFI_IPPREF:
        OOR_LOG(LDBG_1,"locator_list_cmp_afi: No locators of type prefix");
        return (-2);
    case LM_AFI_LCAF:
        afi_a = lisp_addr_lcaf_type(addr1);
        afi_b = lisp_addr_lcaf_type(addr2);
    }

    if (afi_a > afi_b){
        return (1);
    }
    if (afi_a < afi_b){
        return (2);
    }

    return (0);
}


inline void
lisp_addr_lcaf_set_addr(lisp_addr_t *laddr, void *addr)
{
    laddr->lcaf.addr = addr;
}

inline void *
lisp_addr_lcaf_addr(lisp_addr_t *laddr)
{
    return (laddr->lcaf.addr);
}

inline lcaf_type_e
lisp_addr_lcaf_type(lisp_addr_t *laddr)
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
    set_lafi_(addr, LM_AFI_IP);
    ip_addr_init(get_ip_(addr), data, afi);
}

inline int
lisp_addr_init_from_ip(lisp_addr_t *laddr, ip_addr_t *ip)
{
    set_lafi_(laddr, LM_AFI_IP);
    ip_addr_copy(get_ip_(laddr), ip);
    return (GOOD);
}

inline int
lisp_addr_init_from_ippref(lisp_addr_t *laddr, ip_addr_t *ip, uint8_t plen)
{
    set_lafi_(laddr, LM_AFI_IPPREF);
    ip_prefix_set(get_ippref_(laddr), ip, plen);
    return (GOOD);
}

inline int
lisp_addr_init_from_lcaf(lisp_addr_t *laddr, lcaf_addr_t *lcaf)
{
    set_lafi_(laddr, LM_AFI_LCAF);
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
        OOR_LOG(LWRN, "lisp_addr_iana_afi_to_sock_afi: unknown IP AFI (%d)", afi);
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
lisp_addr_get_ip_addr(lisp_addr_t *addr)
{
    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
    	return (addr);
    case LM_AFI_IPPREF:
    	OOR_LOG(LDBG_2, "lisp_addr_get_ip_addr: Not applicable to prefixes");
        return (NULL);
    case LM_AFI_LCAF:
        return (lcaf_get_ip_addr(get_lcaf_(addr)));
    default:
        return (NULL);
    }
    return (NULL);
}

lisp_addr_t *
lisp_addr_get_ip_pref_addr(lisp_addr_t *addr)
{
    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
        OOR_LOG(LDBG_2, "lisp_addr_get_ip_pref_addr: Not applicable to ip addressess");
        return (NULL);
    case LM_AFI_IPPREF:
        return (addr);
    case LM_AFI_LCAF:
        return (lcaf_get_ip_pref_addr(get_lcaf_(addr)));
    default:
        return (NULL);
    }
    return (NULL);
}



/* Deallocates the address for LCAFs. Does nothing for other AFIs*/
void
lisp_addr_dealloc(lisp_addr_t *addr)
{
    switch (get_lafi_(addr)) {
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

/* Fill lisp_addr with the address.
 * Return GOOD if no error has been found */
int
lisp_addr_ip_from_char(char *addr, lisp_addr_t *laddr)
{
    if (ip_addr_from_char(addr, lisp_addr_ip(laddr)) == GOOD) {
        lisp_addr_set_lafi(laddr, LM_AFI_IP);
        return(GOOD);
    } else {
        lisp_addr_set_lafi(laddr, LM_AFI_NO_ADDR);
        return(BAD);
    }
}


/* Parse address and fill lisp_addr and mask.
 * Return GOOD if no error */
int
lisp_addr_ippref_from_char(char *addr, lisp_addr_t *laddr)
{
    if (ip_prefix_from_char(addr, get_ippref_(laddr)) == GOOD) {
        lisp_addr_set_lafi(laddr, LM_AFI_IPPREF);
        return(GOOD);
    } else {
        lisp_addr_set_lafi(laddr, LM_AFI_NO_ADDR);
        return(BAD);
    }
}


inline int
lisp_addr_ip_afi_lcaf_type(lisp_addr_t *addr)
{
    switch (addr->lafi){
    case LM_AFI_NO_ADDR:
        return (0);
    case LM_AFI_IP:
        return (addr->ip.afi);
    case LM_AFI_IPPREF:
        return (addr->ippref.prefix.afi);
    case LM_AFI_LCAF:
        return (addr->lcaf.type);
    }
    return (-1);
}
