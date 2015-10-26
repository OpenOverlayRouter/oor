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

#include <errno.h>

#include "lispd_afi.h"
#include "lisp_lcaf.h"
#include "lmlog.h"

int
pkt_process_eid_afi(uint8_t **offset, mapping_t *mapping)
{

    uint8_t *cur_ptr;
    lcaf_hdr_t *lcaf_ptr;
    uint16_t lisp_afi;

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
        lcaf_ptr = (lcaf_hdr_t *)cur_ptr;
        switch(ntohs(lcaf_ptr->type)) {
        case LCAF_IID:
            cur_ptr  = CO(lcaf_ptr, sizeof(lcaf_hdr_t));
            mapping->iid = ntohl(*(uint32_t *)cur_ptr);
            cur_ptr = CO(lcaf_ptr, sizeof(mapping->iid));
            if (pkt_process_eid_afi (&cur_ptr, mapping)!=GOOD)
                return (BAD);
            break;
        case LCAF_MCAST_INFO:
            if (extract_mcast_info_lcaf_data (&cur_ptr, mapping) != GOOD)
                return (BAD);
            break;
        default:
            mapping->eid_prefix.afi = -1;
            LMLOG(LDBG_2,"pkt_process_eid_afi:  Unknown LCAF type %d in EID", lcaf_ptr->type);
            return (BAD);
        }
        break;
    case LISP_AFI_NO_ADDR:
        mapping->eid_prefix.afi = 0;
        break;
    default:
        mapping->eid_prefix.afi = -1;
        LMLOG(LDBG_2,"pkt_process_eid_afi:  Unknown AFI type %d in EID", lisp_afi);
        return (BAD);
    }
    *offset = cur_ptr;
    return (GOOD);
}

/*
 * Reads the address information from the packet and fill the lisp_addr_t
 */

int
pkt_process_rloc_afi(uint8_t **offset, locator_t *locator)
{
    uint8_t *cur_ptr;
    uint16_t lisp_afi;

    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        memcpy(&(locator->addr->address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
        locator->addr->afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(locator->addr->address.ipv6),cur_ptr,sizeof(struct in6_addr));
        locator->addr->afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        LMLOG(LDBG_2,"pkt_process_rloc_afi: LCAF address is not supported in locators");
        return (BAD);
    default:
        LMLOG(LDBG_2,"pkt_process_rloc_afi: Unknown AFI type %d in locator", lisp_afi);
        return (BAD);
    }
    *offset = cur_ptr;
    return (GOOD);
}

int
extract_nat_lcaf_data(uint8_t *offset, uint16_t *ms_udp_port,
        uint16_t *etr_udp_port, lisp_addr_t *global_etr_rloc,
        lisp_addr_t *ms_rloc, lisp_addr_t *private_etr_rloc,
        rtr_locators_list_t **rtr_list, uint32_t *length)
{
    lcaf_hdr_t *pkt_lcaf;
    lispd_pkt_nat_lcaf_t *pkt_nat_lcaf;
    rtr_locators_list_t *rtr_locator_list = NULL;
    rtr_locator_t *rtr_locator;
    lisp_addr_t rtr_address = {.afi=LM_AFI_NO_ADDR};
    uint8_t *ptr = offset;
    uint32_t lcaf_length;
    uint32_t cumulative_add_length;


    pkt_lcaf = (lcaf_hdr_t *)ptr;

    if (pkt_lcaf->type != LCAF_NATT){
        LMLOG(LDBG_2, "extract_nat_lcaf_data: Packet doesn't have NAT LCAF address");
        return (BAD);
    }

    lcaf_length = ntohs(pkt_lcaf->len);

    ptr = CO(ptr,sizeof(lcaf_hdr_t));
    pkt_nat_lcaf = (lispd_pkt_nat_lcaf_t *)ptr;

    *ms_udp_port = ntohs(pkt_nat_lcaf->ms_udp_port);
    *etr_udp_port = ntohs(pkt_nat_lcaf->etr_udp_port);

    cumulative_add_length = FIELD_PORT_LEN * 2; /* 2 UDP ports */

    ptr = CO(ptr,sizeof(lispd_pkt_nat_lcaf_t));

    /* Extract the Global ETR RLOC */


    if ((extract_lisp_address(ptr, global_etr_rloc)) != GOOD){
        LMLOG(LDBG_2, "extract_nat_lcaf_data: Couldn't process Global ETR RLOC");
        return (BAD);
    }

    cumulative_add_length += get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN);

    /* Extract the MS RLOC */

    if ((extract_lisp_address(ptr, ms_rloc)) != GOOD){
        LMLOG(LDBG_2, "extract_nat_lcaf_data: Couldn't process MS RLOC");
        return (BAD);
    }

    cumulative_add_length += get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN);

    /* Extract the Private ETR RLOC */

    if (extract_lisp_address(ptr, private_etr_rloc) != GOOD){
        LMLOG(LDBG_2, "extract_nat_lcaf_data: Couldn't process private ETR RLOC");
        return (BAD);
    }

    cumulative_add_length += get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN);


    /* Extract the list of RTR RLOCs */


    while (cumulative_add_length < lcaf_length) {
        if ((extract_lisp_address(ptr, &rtr_address))!= GOOD){
            LMLOG(LDBG_2, "extract_nat_lcaf_data: Coudln't process rtr address");
            return (BAD);
        }
        rtr_locator = rtr_locator_new (rtr_address);
        if (rtr_locator == NULL){
            LMLOG(LDBG_2, "extract_nat_lcaf_data: Error malloc lispd_rtr_locator");
            return (BAD);
        }
        if ((rtr_list_add(&rtr_locator_list,rtr_locator))!=GOOD){
            LMLOG(LDBG_2, "extract_nat_lcaf_data: Error adding rtr_locator");
            return (BAD);
        }
        // Return the first element of the list
        if (*rtr_list == NULL){
            *rtr_list = rtr_locator_list;
        }

        LMLOG(LDBG_3, "Added RTR with RLOC %s to the list of RTRs",
                get_char_from_lisp_addr_t(rtr_locator->address));

        cumulative_add_length += get_addr_len(rtr_locator->address.afi) + FIELD_AFI_LEN;

        ptr = CO(ptr, get_addr_len(rtr_locator->address.afi) + FIELD_AFI_LEN);

    }

    *length = sizeof(lcaf_hdr_t) + lcaf_length;

    return (GOOD);
}



