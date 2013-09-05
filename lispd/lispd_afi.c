/*
 * lispd_afi.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#include "lispd_afi.h"
#include "lispd_lib.h"


int pkt_process_eid_afi(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping)
{

    uint8_t                 *cur_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    uint16_t                 lisp_afi;


    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        memcpy(&(mapping->eid_prefix.address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
        mapping->eid_prefix.afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(mapping->eid_prefix.address.ipv6),cur_ptr,sizeof(struct in6_addr));
        mapping->eid_prefix.afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        lcaf_ptr = (lispd_pkt_lcaf_t *)cur_ptr;
        cur_ptr  = CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        switch(lcaf_ptr->type) {
        case LCAF_IID:
            mapping->iid = ntohl(*(uint32_t *)cur_ptr);
            cur_ptr = CO(lcaf_ptr, sizeof(mapping->iid));
            if (!pkt_process_eid_afi (&cur_ptr, mapping))
                return (BAD);
            break;
        default:
            mapping->eid_prefix.afi = -1;
            lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_eid_afi:  Unknown LCAF type %d in EID", lcaf_ptr->type);
            return (BAD);
        }
        break;
    case LISP_AFI_NO_ADDR:
        mapping->eid_prefix.afi = 0;
        break;
    default:
        mapping->eid_prefix.afi = -1;
        lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_eid_afi:  Unknown AFI type %d in EID", lisp_afi);
        return (BAD);
    }
    *offset = cur_ptr;
    return (GOOD);
}

/*
 * Reads the address information from the packet and fill the lisp_addr_t
 */

int pkt_process_rloc_afi(
        uint8_t             **offset,
        lispd_locator_elt   *locator)
{
    uint8_t                  *cur_ptr;
    uint16_t                 lisp_afi;

    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        memcpy(&(locator->locator_addr->address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
        locator->locator_addr->afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(locator->locator_addr->address.ipv6),cur_ptr,sizeof(struct in6_addr));
        locator->locator_addr->afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_rloc_afi: LCAF address is not supported in locators");
        return (BAD);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_rloc_afi: Unknown AFI type %d in locator", lisp_afi);
        return (BAD);
    }
    *offset = cur_ptr;
    return (GOOD);
}


int extract_nat_lcaf_data(
        uint8_t                         *offset,
        uint16_t                        *ms_udp_port,
        uint16_t                        *etr_udp_port,
        lisp_addr_t                     *global_etr_rloc,
        lisp_addr_t                     *ms_rloc,
        lisp_addr_t                     *private_etr_rloc,
        lispd_rtr_locators_list         **rtr_list,
        uint32_t                        *length)
{
    lispd_pkt_lcaf_t         *pkt_lcaf               = NULL;
    lispd_pkt_nat_lcaf_t     *pkt_nat_lcaf           = NULL;
    lispd_rtr_locators_list  *rtr_locator_list       = NULL;
    lispd_rtr_locator        *rtr_locator            = NULL;
    lisp_addr_t              rtr_address             = {.afi=AF_UNSPEC};
    uint8_t                  *ptr                    = offset;
    uint32_t                 lcaf_length             = 0;
    uint32_t                 cumulative_add_length   = 0;


    pkt_lcaf = (lispd_pkt_lcaf_t *)ptr;

    if (pkt_lcaf->type != LCAF_NATT){
        lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Packet doesn't have NAT LCAF address");
        return (BAD);
    }

    lcaf_length = ntohs(pkt_lcaf->len);

    ptr = CO(ptr,sizeof(lispd_pkt_lcaf_t));
    pkt_nat_lcaf = (lispd_pkt_nat_lcaf_t *)ptr;

    *ms_udp_port = ntohs(pkt_nat_lcaf->ms_udp_port);
    *etr_udp_port = ntohs(pkt_nat_lcaf->etr_udp_port);

    cumulative_add_length = FIELD_PORT_LEN * 2; /* 2 UDP ports */

    ptr = CO(ptr,sizeof(lispd_pkt_nat_lcaf_t));

    /* Extract the Global ETR RLOC */


    if ((extract_lisp_address(ptr, global_etr_rloc)) != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Couldn't process Global ETR RLOC");
        return (BAD);
    }

    cumulative_add_length += get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN);

    /* Extract the MS RLOC */

    if ((extract_lisp_address(ptr, ms_rloc)) != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Couldn't process MS RLOC");
        return (BAD);
    }

    cumulative_add_length += get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN);

    /* Extract the Private ETR RLOC */

    if (extract_lisp_address(ptr, private_etr_rloc) != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Couldn't process private ETR RLOC");
        return (BAD);
    }

    cumulative_add_length += get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN);


    /* Extract the list of RTR RLOCs */


    while (cumulative_add_length < lcaf_length) {
        if ((extract_lisp_address(ptr, &rtr_address))!= GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Coudln't process rtr address");
            return (BAD);
        }
        rtr_locator = new_rtr_locator (rtr_address);
        if (rtr_locator == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Error malloc lispd_rtr_locator");
            return (BAD);
        }
        if ((add_rtr_locator_to_list(&rtr_locator_list,rtr_locator))!=GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_2, "extract_nat_lcaf_data: Error adding rtr_locator");
            return (BAD);
        }
        // Return the first element of the list
        if (*rtr_list == NULL){
            *rtr_list = rtr_locator_list;
        }

        lispd_log_msg(LISP_LOG_DEBUG_3, "Added RTR with RLOC %s to the list of RTRs",
                get_char_from_lisp_addr_t(rtr_locator->address));

        cumulative_add_length += get_addr_len(rtr_locator->address.afi) + FIELD_AFI_LEN;

        ptr = CO(ptr, get_addr_len(rtr_locator->address.afi) + FIELD_AFI_LEN);

    }

    *length = sizeof(lispd_pkt_lcaf_t) + lcaf_length;

    return (GOOD);
}
