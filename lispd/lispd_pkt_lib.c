/*
 * lispd_pkt_lib.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 * Written or modified by:
 *    Lorand Jakab  <ljakab@ac.upc.edu>
 *
 */

#include "lispd_pkt_lib.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_external.h"

/*
 *  get_locator_chain_length
 *
 *  Compute the sum of the lengths of the locators
 *  so we can allocate  memory for the packet....
 */
int get_locator_length(lispd_locators_list *locators_list);

/*
 *  get_identifier_length
 *
 *  Compute the lengths of the identifier to be use in a record
 *  so we can allocate  memory for the packet....
 */

int get_identifier_length(lispd_identifier_elt *identifier);




int pkt_get_mapping_record_length(lispd_identifier_elt *identifier) {
    lispd_locators_list *locators_list[2] = {
            identifier->head_v4_locators_list,
            identifier->head_v6_locators_list};
    int length          = 0;
    int loc_length      = 0;
    int eid_length      = 0;
    int ctr;

    for (ctr = 0 ; ctr < 2 ; ctr ++){
        if (locators_list[ctr] == NULL)
            continue;
        loc_length += get_locator_length(locators_list[ctr]);
    }
    eid_length = get_identifier_length(identifier);
    length = sizeof(lispd_pkt_mapping_record_t) + eid_length +
            (identifier->locator_count * sizeof(lispd_pkt_mapping_record_locator_t)) +
            loc_length;

    return length;
}

/*
 *  get_locator_chain_length
 *
 *  Compute the sum of the lengths of the locators
 *  so we can allocate  memory for the packet....
 */

int get_locator_length(lispd_locators_list *locators_list)
{
    int sum = 0;
    while (locators_list) {
        switch (locators_list->locator->locator_addr->afi) {
        case AF_INET:
            sum += sizeof(struct in_addr);
            break;
        case AF_INET6:
            sum += sizeof(struct in6_addr);
            break;
        default:
            /* It should never happen*/
            syslog(LOG_ERR, "get_locator_length: Uknown AFI (%d) - It should never happen",
               locators_list->locator->locator_addr->afi);
            break;
        }
        locators_list = locators_list->next;
    }
    return(sum);
}

/*
 *  get_identifier_length
 *
 *  Compute the lengths of the identifier to be use in a record
 *  so we can allocate  memory for the packet....
 */


int get_identifier_length(lispd_identifier_elt *identifier)
{
    int ident_len = 0;
    switch (identifier->eid_prefix.afi) {
    case AF_INET:
        ident_len += sizeof(struct in_addr);
        break;
    case AF_INET6:
        ident_len += sizeof(struct in6_addr);
        break;
    default:
        break;
    }

    if (identifier->iid >= 0)
        ident_len += sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_lcaf_iid_t);

    return ident_len;
}

void *pkt_fill_eid(void         *offset,
        lispd_identifier_elt    *identifier)
{
    uint16_t                *afi_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;
    void                    *eid_ptr;
    int                     eid_addr_len;

    afi_ptr = (uint16_t *)offset;
    eid_addr_len = get_addr_len(identifier->eid_prefix.afi);

    /* For negative IID values, we skip LCAF/IID field */
    if (identifier->iid < 0) {
        *afi_ptr = htons(get_lisp_afi(identifier->eid_prefix.afi, NULL));
        eid_ptr  = CO(offset, sizeof(uint16_t));
    } else {
        *afi_ptr = htons(LISP_AFI_LCAF);
        lcaf_ptr = (lispd_pkt_lcaf_t *) CO(offset, sizeof(uint16_t));
        iid_ptr  = (lispd_pkt_lcaf_iid_t *) CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        eid_ptr  = (void *) CO(iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));

        lcaf_ptr->rsvd1 = 0;
        lcaf_ptr->flags = 0;
        lcaf_ptr->type  = 2;
        lcaf_ptr->rsvd2 = 0;    /* This can be IID mask-len, not yet supported */
        lcaf_ptr->len   = htons(sizeof(lispd_pkt_lcaf_iid_t) + eid_addr_len);

        iid_ptr->iid = htonl(identifier->iid);
        iid_ptr->afi = htons(identifier->eid_prefix.afi);
    }

    if ((copy_addr(eid_ptr,&(identifier->eid_prefix), 0)) == 0) {
        syslog(LOG_DAEMON, "pkt_fill_eid: copy_addr failed");
        return NULL;
    }

    return CO(eid_ptr, eid_addr_len);
}


void *pkt_fill_mapping_record(rec, identifier, probed_rloc)
    lispd_pkt_mapping_record_t              *rec;
    lispd_identifier_elt                    *identifier;
    lisp_addr_t                             *probed_rloc;
{
    int                                     cpy_len = 0;
    lispd_pkt_mapping_record_locator_t      *loc_ptr;
    lispd_locators_list                     *locators_list[2];
    lispd_locator_elt                       *locator;
    int                                     ctr = 0;
#ifdef LISPMOBMH
    iface_list_elt *elt=NULL;
#endif

    if ((rec == NULL) || (identifier == NULL))
        return NULL;

    rec->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    rec->locator_count          = identifier->locator_count;
    rec->eid_prefix_length      = identifier->eid_prefix_length;
    rec->action                 = 0;
    rec->authoritative          = 1;
    rec->version_hi             = 0;
    rec->version_low            = 0;

    loc_ptr = (lispd_pkt_mapping_record_locator_t *)
                pkt_fill_eid(&(rec->eid_prefix_afi), identifier);

    if (loc_ptr == NULL)
        return NULL;

    locators_list[0] = identifier->head_v4_locators_list;
    locators_list[1] = identifier->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (locators_list[ctr]) {
            locator             = locators_list[ctr]->locator;
#ifdef LISPMOBMH
            elt = search_iface_list(db_entry->locator_name);
            if(elt!=NULL && elt->ready){
#endif
                loc_ptr->priority    = locator->priority;
                loc_ptr->weight      = locator->weight;
                loc_ptr->mpriority   = locator->mpriority;
                loc_ptr->mweight     = locator->mweight;
                loc_ptr->local       = 1;
                if (probed_rloc && compare_lisp_addr_t(locator->locator_addr,probed_rloc)==0)
                    loc_ptr->probed  = 1;       /* XXX probed locator, should check addresses */
                loc_ptr->reachable   = locator->state && 1;
                loc_ptr->locator_afi = htons(get_lisp_afi(locator->locator_addr->afi,NULL));

                if ((cpy_len = copy_addr((void *) CO(loc_ptr,
                        sizeof(lispd_pkt_mapping_record_locator_t)), locator->locator_addr, 0)) == 0) {
                    syslog(LOG_DAEMON, "pkt_fill_mapping_record: copy_addr failed for locator %s",
                            get_char_from_lisp_addr_t(*(locator->locator_addr)));
                    return(NULL);
                }

                loc_ptr = (lispd_pkt_mapping_record_locator_t *)
                    CO(loc_ptr, (sizeof(lispd_pkt_mapping_record_locator_t) + cpy_len));
#ifdef LISPMOBMH
            }
#endif
            locators_list[ctr] = locators_list[ctr]->next;
        }
    }
    return (void *)loc_ptr;
}


/*
 * Packet parsing functions
 *
 * Return value is the offset where packet parsing should continue
 */

void *pkt_read_eid(offset, eid, eid_afi, iid)
    void                    *offset;
    lisp_addr_t            **eid;
    int                     *eid_afi;
    lispd_iid_t             *iid;
{
    void                    *cur_ptr;
    uint16_t                 lisp_afi;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;

    cur_ptr  = offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));

    if (lisp_afi == LISP_AFI_LCAF) {
        lcaf_ptr = (lispd_pkt_lcaf_t *)cur_ptr;
        cur_ptr  = CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));

        /* If the LCAF is IID, read data, else jump over it */
        if (lcaf_ptr->type == LCAF_IID) {
            iid_ptr  = (lispd_pkt_lcaf_iid_t *)cur_ptr;
            *iid     = ntohl(iid_ptr->iid);
            lisp_afi = ntohs(iid_ptr->afi);
            *eid_afi = lisp2inetafi(lisp_afi);
            cur_ptr  = (void *)CO(iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));
            *eid     = (lisp_addr_t *)cur_ptr;
            return CO(cur_ptr, get_addr_len(*eid_afi));
        } else {
            cur_ptr  = CO(cur_ptr, ntohs(lcaf_ptr->len));
            *eid     = NULL;
            *eid_afi = -1;
            *iid     = -1;
        }
    } else if (lisp_afi == 0) {
        *eid     = NULL;
        *eid_afi = -1;
        *iid     = -1;
    } else {
        *eid     = (lisp_addr_t *)cur_ptr;
        *eid_afi = lisp2inetafi(lisp_afi);
        *iid     = -1;
        return CO(cur_ptr, get_addr_len(*eid_afi));
    }

    return cur_ptr;
}

int send_ctrl_ipv4_packet(lisp_addr_t *destination, uint16_t src_port, uint16_t dst_port, void *packet, int packet_len)
{
    int                 s;      /*socket */
    int                 nbytes;
    struct sockaddr_in  dst;
    struct sockaddr_in  src;


    if ((s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0) {
        syslog(LOG_ERR, "socket (send_ctrl_ipv4_packet): %s", strerror(errno));
        return(BAD);
    }

    /*
     * PN: Bind the UDP socket to a valid rloc on the ctrl_iface
     */
    if (!(ctrl_iface)) {
        /* No physical interface available for control messages */
        syslog(LOG_ERR, "(send_ctrl_ipv4_packet): Unable to find valid physical interface\n");
        return (BAD);
    }
    else if (!(ctrl_iface->ipv4_address)){
        syslog(LOG_ERR, "(send_ctrl_ipv4_packet): Control interface doesn't have an IPv4 address\n");
        return (BAD);
    }
    memset((char *) &src, 0, sizeof(struct sockaddr_in));
    src.sin_family       = AF_INET;
    if (src_port == 0)
    	src.sin_port         = htons(INADDR_ANY);
    else
    	src.sin_port         = htons(src_port);
    src.sin_addr.s_addr  = ctrl_iface->ipv4_address->address.ip.s_addr;

    if (bind(s, (struct sockaddr *)&src, sizeof(struct sockaddr_in)) < 0) {
        syslog(LOG_ERR, "bind (send_ctrl_ipv4_packet): %s", strerror(errno));
        close(s);
        return(BAD);
    }

    memset((char *) &dst, 0, sizeof(struct sockaddr_in));

    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = destination->address.ip.s_addr;
    if (dst_port == 0)
    	dst.sin_port         = htons(INADDR_ANY);
    else
    	dst.sin_port         = htons(dst_port);
    if ((nbytes = sendto(s,
            (const void *) packet,
            packet_len,
            0,
            (struct sockaddr *)&dst,
            sizeof(struct sockaddr))) < 0) {
        syslog(LOG_ERR,"sendto (send_ctrl_ipv4_packet): %s", strerror(errno));
        close(s);
        return(BAD);
    }

    if (nbytes != packet_len) {
        syslog(LOG_ERR,
                "send_ctrl_ipv4_packet: nbytes (%d) != packet (%d)\n",
                nbytes, packet_len);
        close(s);
        return(BAD);
    }

    close(s);
    return (GOOD);
}


int send_ctrl_ipv6_packet(lisp_addr_t *destination, uint16_t src_port, uint16_t dst_port, void *packet, int packet_len)
{
    int                 s;      /*socket */
    int                 nbytes;
    struct sockaddr_in6  dst;
    struct sockaddr_in6  src;


    if ((s = socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP)) < 0) {
        syslog(LOG_ERR, "socket (send_ctrl_ipv6_packet): %s", strerror(errno));
        return(BAD);
    }

    /*
     * PN: Bind the UDP socket to a valid rloc on the ctrl_iface
     */
    if (!(ctrl_iface)) {
        /* No physical interface available for control messages */
        syslog(LOG_ERR, "(send_ctrl_ipv6_packet): Unable to find valid physical interface\n");
        return (BAD);
    }
    else if (!(ctrl_iface->ipv6_address)){
        syslog(LOG_ERR, "(send_ctrl_ipv6_packet): Control interface doesn't have an IPv4 address\n");
        return (BAD);
    }
    memset((char *) &src, 0, sizeof(struct sockaddr_in));
    src.sin6_family       = AF_INET6;
    if (src_port == 0)
    	src.sin6_port         = htons(INADDR_ANY);
    else
    	src.sin6_port         = htons(src_port);
    memcpy(&src.sin6_addr,&(ctrl_iface->ipv6_address->address.ipv6),sizeof(struct in6_addr));

    if (bind(s, (struct sockaddr *)&src, sizeof(struct sockaddr_in)) < 0) {
        syslog(LOG_ERR, "bind (send_ctrl_ipv6_packet): %s", strerror(errno));
        close(s);
        return(BAD);
    }

    memset((char *) &dst, 0, sizeof(struct sockaddr_in));

    dst.sin6_family      = AF_INET6;
    if (dst_port == 0)
    	dst.sin6_port         = htons(INADDR_ANY);
    else
    	dst.sin6_port         = htons(dst_port);
    memcpy(&dst.sin6_addr,&(destination->address.ipv6),sizeof(struct in6_addr));


    if ((nbytes = sendto(s,
            (const void *) packet,
            packet_len,
            0,
            (struct sockaddr *)&dst,
            sizeof(struct sockaddr))) < 0) {
        syslog(LOG_ERR,"sendto (send_ctrl_ipv6_packet): %s", strerror(errno));
        close(s);
        return(BAD);
    }

    if (nbytes != packet_len) {
        syslog(LOG_ERR,
                "send_ctrl_ipv6_packet: nbytes (%d) != packet_len (%d)\n",
                nbytes, packet_len);
        close(s);
        return(BAD);
    }

    close(s);
    return (GOOD);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
