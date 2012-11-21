/*
 * lispd_map_request.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send a map request.
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
 *    David Meyer       <dmm@cisco.com>
 *    Vina Ermagan      <vermagan@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Pranathi Mamidi   <pranathi.3961@gmail.com>
 *
 */

/*
 *  Send this packet on UDP 4342
 *
 *
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |                   Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *  Next is the inner IP header, either struct ip6_hdr or struct
 *  iphdr. 
 *
 *  This is follwed by a UDP header, random source port, 4342 
 *  dest port.
 *
 *  Followed by a struct lisp_pkt_map_request_t:
 *
 * Map-Request Message Format
 *   
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|      Reserved       |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |    Source EID Address  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                        EID-prefix ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                      Mappping Record ...                      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *	<source EID address>
 *	IRC = 0 --> one source rloc
 *      lisp_pkt_map_request_eid_prefix_record_t
 *      EID
 *
 */

#include "cksum.h"
#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_reply.h"
#include "lispd_map_request.h"
#include "lispd_nonce.h"
#include "lispd_pkt_lib.h"
#include "lispd_smr.h"
#include "patricia/patricia.h"
#include <time.h>


/*
 * Process record and send Map Reply
 */

int process_map_request_record(
        char **cur_ptr,
        lisp_addr_t src_rloc,
        lisp_addr_t dst_rloc,
        uint16_t dst_port,
        uint8_t rloc_probe,
        uint64_t nonce);


uint8_t *build_map_request_pkt(
		lisp_addr_t 	*dest,
		lisp_addr_t 	*eid_prefix,
		uint8_t 		eid_prefix_length,
		int 			*len, /* return length here */
		uint64_t        *nonce,            /* return nonce here */
		uint8_t 		encap,
		uint8_t 		probe,
		uint8_t 		solicit_map_request, /* boolean really */
		uint8_t 		smr_invoked)
{

    struct udphdr                               *udph;
    lisp_addr_t                                 *my_addr;
    uint8_t                                     *packet;
    lispd_pkt_map_request_t                     *mrp;
    lispd_pkt_encapsulated_control_t            *ecm;
    lispd_pkt_map_request_itr_rloc_t            *itr_rloc;
    lispd_pkt_map_request_eid_prefix_record_t   *eid;
    patricia_node_t                             *node;
    lispd_locator_chain_t                       *locator_chain = NULL;
    void                                        *cur_ptr;
    void                                        *iphptr;    /* v4 or v6 */

    uint16_t                udpsum              = 0;
    uint16_t                eid_afi             = 0;
    int                     packet_len          = 0;
    int                     eid_len             = 0;
    int                     ip_len              = 0;
    int                     udp_len             = 0;
    int                     map_request_msg_len = 0;
    int                     ip_header_len       = 0;
    //Pranathi : Changed the variable my_addr_len to my_itr_addr_len
    int                     my_itr_addr_len     = 0;
    int                     alen                = 0;

    eid_afi = get_lisp_afi(eid_prefix->afi, &eid_len);



    /*
    if (!(ctrl_iface)) {
        syslog(LOG_DAEMON, "(build_map_request_pkt): Unable to find valid physical interface\n");
        return (ERR_CTR_IFACE);
    }*/

    if (!encap) {
        if ((my_addr = get_my_addr(ctrl_iface->iface_name, dest->afi)) == NULL) {
            syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                    ctrl_iface->iface_name, dest->afi);
            return(ERR_SRC_ADDR);
        }
    } else {

        //Pranathi : my_addr -> This is for the source address in the inner header of the encapsulated Map-request msg
        // For v4eid over v4 rloc , Inner header: v4 src rloc , v4 dest eid
        // For v6eid over v4 rloc , Inner header: v6 src eid , v6 dest eid
        // For v4eid over v6 rloc , Inner header: v4 src eid , v4 dest eid
        // For v6eid over v6 rloc , Inner header: v6 src rloc , v6 dest eid
        if(ctrl_iface->ipv4_address && ctrl_iface->head_v4_identifiers_list)
        {
            switch(eid_prefix->afi) {
            case AF_INET:
                if ((my_addr = get_my_addr(ctrl_iface->iface_name,lisp2inetafi(eid_afi))) == NULL) {
                    syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                            ctrl_iface->iface_name,lisp2inetafi(eid_afi));
                    return(ERR_SRC_ADDR);
                }
                break;

            case AF_INET6:
                if ((my_addr = get_my_addr("lmn0",lisp2inetafi(eid_afi))) == NULL) {
                    syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                            "lmn0",lisp2inetafi(eid_afi));
                    return(ERR_SRC_ADDR);
                }
                break;

            default:
                syslog(LOG_DAEMON, "Unknown EID address family:%d in build_map_request_pkt()",eid_prefix->afi);
                return(ERR_AFI);
            }

        }

        else if(ctrl_iface->ipv6_address && ctrl_iface->head_v6_identifiers_list)
        {
            switch(eid_prefix->afi) {
            case AF_INET:
                if ((my_addr = get_my_addr("lmn0",lisp2inetafi(eid_afi))) == NULL) {
                    syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                            "lmn0",lisp2inetafi(eid_afi));
                    return(ERR_SRC_ADDR);
                }
                break;

            case AF_INET6:
                if ((my_addr = get_my_addr(ctrl_iface->iface_name,lisp2inetafi(eid_afi))) == NULL) {
                    syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                            ctrl_iface->iface_name,lisp2inetafi(eid_afi));
                    return(ERR_SRC_ADDR);
                }
                break;

            default:
                syslog(LOG_DAEMON,"Unknown EID address family:%d in build_map_request_pkt()",eid_prefix->afi);
                return(ERR_AFI);
            }
        }
        else
        {
            syslog(LOG_DAEMON,"Ctrl_iface : No v4/v6 locators");
            return(ERR_CTR_IFACE);

        }
    }

    //Pranathi : since this is for obtaining itr rloc length , not eid
    if(ctrl_iface->ipv4_address && ctrl_iface->head_v4_identifiers_list)
    {
        if ((my_itr_addr_len = get_addr_len(AF_INET)) < GOOD) {
            err = my_itr_addr_len;
            free(my_addr);
            return (NULL);
        }
    }
    else if(ctrl_iface->ipv6_address && ctrl_iface->head_v6_identifiers_list)
    {
        if ((my_itr_addr_len = get_addr_len(AF_INET6)) < GOOD) {
            err = my_itr_addr_len;
            free(my_addr);
            return (NULL);
        }
    }

    if ((ip_header_len = get_ip_header_len(my_addr->afi)) < GOOD) {
        err = ip_header_len;
        free(my_addr);
        return (NULL);
    }

    /* 
     * caclulate sizes of interest
     */

    map_request_msg_len = sizeof(lispd_pkt_map_request_t) + /* map request */
            eid_len                                           + /* source eid */
            sizeof(lispd_pkt_map_request_itr_rloc_t)          + /* IRC = 1 */
            my_itr_addr_len                                      + /* ITR RLOC */
            sizeof(lispd_pkt_map_request_eid_prefix_record_t) +
            eid_len;                                            /* EID prefix */


    /*
     * Get the Source EID early on, to see if have Instance ID,
     * which influences packet length
     */
    switch (eid_prefix->afi) {
    case AF_INET:
        PATRICIA_WALK(AF4_database->head, node) {
            locator_chain = ((lispd_locator_chain_t *)(node->data));
        } PATRICIA_WALK_END;
        break;
    case AF_INET6:
        PATRICIA_WALK(AF6_database->head, node) {
            locator_chain = ((lispd_locator_chain_t *)(node->data));
        } PATRICIA_WALK_END;
        break;
    default:
        free(my_addr);
        return(ERR_AFI);
    }

    if (!locator_chain) {
        syslog(LOG_DAEMON, "build_map_request_pkt: can't get source EID");
        free(my_addr);
        return(0);
    }

    /* We add 2x the IID LCAF size, once for source EID, once for request */
    if (locator_chain->iid >= 0)
        map_request_msg_len += 2 * sizeof(lispd_pkt_lcaf_t) +
        2 * sizeof(lispd_pkt_lcaf_iid_t);

    udp_len = sizeof(struct udphdr) + map_request_msg_len;  /* udp header */

    //pranathi
    if(eid_prefix->afi ==AF_INET)  // since total length
    {
        ip_len  = ip_header_len + udp_len;
        if (encap) {
            packet_len = sizeof(lispd_pkt_encapsulated_control_t) + ip_len;
        } else {
            packet_len = ip_len;
        }
    }
    if(eid_prefix->afi ==AF_INET6) // since payload length
    {
        ip_len  = udp_len;
        if (encap) {
            packet_len = sizeof(lispd_pkt_encapsulated_control_t) + ip_header_len + udp_len ;
        } else {
            packet_len = ip_header_len + udp_len;
        }

    }



    *len       = packet_len;                    /* return this */

    if ((packet = malloc(packet_len)) == NULL) {
        syslog(LOG_DAEMON, "malloc(packet_len): %s", strerror(errno));
        return (0);
    }
    memset(packet, 0, packet_len);

    /*
     *  build the encapsulated control message header
     */
    if (encap) {
        ecm       = (lispd_pkt_encapsulated_control_t *) packet;
        ecm->type = LISP_ENCAP_CONTROL_TYPE;

        /*
         * point cur_ptr at the start of the IP header
         */
        cur_ptr = CO(ecm, sizeof(lispd_pkt_encapsulated_control_t));
        iphptr = cur_ptr;					/* save for ip checksum */
    } else {
        iphptr = (void *) packet;
    }

    /*
     * build IPvX header
     */

    if (encap) {
        if ((udph = build_ip_header(iphptr, my_addr, eid_prefix, ip_len)) == 0) {
            syslog(LOG_DAEMON, "Can't build IP header (unknown AFI %d)",
                    my_addr->afi);
            free(my_addr);
            return (0);
        }
    } else {
        if ((udph = build_ip_header(iphptr, my_addr, dest, ip_len)) == 0) {
            syslog(LOG_DAEMON, "Can't build IP header (unknown AFI %d)",
                    my_addr->afi);
            free(my_addr);
            return (0);
        }
    }

    /*
     * fill in the UDP header. checksum\ later.
     *
     * Note src port == dest port == LISP_CONTROL_PORT (4342)
     */

#ifdef BSD
    udph->uh_sport = htons(LISP_CONTROL_PORT);
    udph->uh_dport = htons(LISP_CONTROL_PORT);
    udph->uh_ulen  = htons(udp_len);
    udph->uh_sum   = 0;
#else
    udph->source = htons(LISP_CONTROL_PORT);
    udph->dest   = htons(LISP_CONTROL_PORT);
    udph->len    = htons(udp_len);
    udph->check  = 0;
#endif

    /*
     * build the map request
     */

    mrp = (lispd_pkt_map_request_t *) CO(udph, sizeof(struct udphdr));

    mrp->type                      = LISP_MAP_REQUEST;
    mrp->authoritative             = 0;
    mrp->map_data_present          = 0;

    if (probe)
        mrp->rloc_probe            = 1;
    else
        mrp->rloc_probe            = 0;

    if (solicit_map_request)
        mrp->solicit_map_request   = 1;
    else
        mrp->solicit_map_request   = 0;

    if (smr_invoked)
        mrp->smr_invoked           = 1;
    else
        mrp->smr_invoked           = 0;

    mrp->additional_itr_rloc_count = 0;     /* 0 --> 1 */
    mrp->record_count              = 1;     /* XXX: assume 1 record */
    mrp->nonce = build_nonce((unsigned int) time(NULL));
    *nonce                         = mrp->nonce;

    /*
     * Source-EID address goes here.
     *
     *  point cur_ptr at where the variable length Source-EID 
     *  address goes
     */    

    // XXX alopez
    //cur_ptr = pkt_fill_eid_from_locator_chain(&(mrp->source_eid_afi), locator_chain);
    if (cur_ptr == NULL) {
        syslog(LOG_DAEMON, "build_map_request_pkt: could not add Source EID");
        return (0);
    }

    /*
     * now the ITR-RLOC (XXX: assumes only one)
     */
    //Pranathi
    if(ctrl_iface->ipv4_address && ctrl_iface->head_v4_identifiers_list)  /* v4 RLOC*/
    {
        itr_rloc = (lispd_pkt_map_request_itr_rloc_t *) CO(cur_ptr, alen);
        itr_rloc->afi = htons(get_lisp_afi(AF_INET, NULL));
        cur_ptr = CO(itr_rloc, sizeof(lispd_pkt_map_request_itr_rloc_t));
        if ((alen = copy_addr(cur_ptr, ctrl_iface->ipv4_address, 0)) == 0) {
            free(packet);
            return (0);
        }

    }

    if(ctrl_iface->ipv6_address && ctrl_iface->head_v6_identifiers_list)  /*v6 RLOC*/
    {
        itr_rloc = (lispd_pkt_map_request_itr_rloc_t *) CO(cur_ptr, alen);
        itr_rloc->afi = htons(get_lisp_afi(AF_INET6, NULL));
        cur_ptr = CO(itr_rloc, sizeof(lispd_pkt_map_request_itr_rloc_t));
        if ((alen = copy_addr(cur_ptr, ctrl_iface->ipv6_address, 0)) == 0) {

            free(packet);
            return (0);
        }

    }

    /* 
     *  finally, the requested EID prefix
     */

    eid = (lispd_pkt_map_request_eid_prefix_record_t *) CO(cur_ptr, alen);
    eid->eid_prefix_mask_length = eid_prefix_length;
    // XXX to be done
    //cur_ptr = pkt_fill_eid(&(eid->eid_prefix_afi), eid_prefix, locator_chain->iid);
    if (cur_ptr == NULL) {
        free(packet);
        return (0);
    }

    /*
     * now compute the checksums
     */

    if (my_addr->afi == AF_INET)
        ((struct ip *) iphptr)->ip_sum = ip_checksum(iphptr, ip_header_len);
    if ((udpsum = udp_checksum(udph, udp_len, iphptr, my_addr->afi)) == -1) {
        return (0);
    }
    udpsum(udph) = udpsum;
    free(my_addr);
    return (packet);
}

/*
 *  send_map_request
 *
 */

int send_map_request(packet, packet_len, resolver)
uint8_t *packet;
int packet_len;
lisp_addr_t *resolver;
{

    struct sockaddr_in   map_resolver;
    int         s;      /*socket */
    int         nbytes = 0;
    struct sockaddr_in  ctrl_saddr;

    /* XXX: assume v4 transport */

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        syslog(LOG_DAEMON, "socket (send_map_request): %s", strerror(errno));
        return (0);
    }

    /*
     * PN: Bind the UDP socket to a valid rloc on the ctrl_iface
     * (assume v4 transport)
     */
    if (!(ctrl_iface)) {
        /* 
         * No physical interface available for control messages
         */
        syslog(LOG_DAEMON, "(send_map_request): Unable to find valid physical interface\n");
        close(s);
        return (0);
    }
    memset((char *) &ctrl_saddr, 0, sizeof(struct sockaddr_in));
    ctrl_saddr.sin_family       = AF_INET;
    ctrl_saddr.sin_port         = htons(INADDR_ANY);
    ctrl_saddr.sin_addr.s_addr  = ctrl_iface->ipv4_address->address.ip.s_addr;

    if (bind(s, (struct sockaddr *)&ctrl_saddr, sizeof(struct sockaddr_in)) < 0) {
        syslog(LOG_DAEMON, "bind (send_map_request): %s", strerror(errno));
        close(s);
        return(0);
    }

    memset((char *) &map_resolver, 0, sizeof(map_resolver));

    map_resolver.sin_family      = AF_INET; /* XXX: assume v4 transport */
    map_resolver.sin_addr.s_addr = resolver->address.ip.s_addr;
    map_resolver.sin_port        = htons(LISP_CONTROL_PORT);

    if ((nbytes = sendto(s, 
            (const void *) packet, packet_len, 0,
            (struct sockaddr *) &map_resolver, sizeof(struct sockaddr))) < 0) {
        syslog(LOG_DAEMON, "sendto (send_map_request): %s", strerror(errno));
        close(s);
        return (0);
    }

    if (nbytes != packet_len) {
        syslog(LOG_DAEMON,
                "send_map_request: nbytes (%d) != packet_len (%d)\n", 
                nbytes, packet_len);
        close(s);
        return (0);
    }

    close(s);
    free(packet);
    return (1);
}

/*
 *  build_and_send_map_request --
 *
 *  Put a wrapper around build_map_request_pkt and send_map_request
 *
 */

int build_and_send_map_request_msg(
        lisp_addr_t     *eid_prefix,
        uint8_t         eid_prefix_length,
        lisp_addr_t     *dst_rloc_addr,
        uint8_t         encap,
        uint8_t         probe,
        uint8_t         solicit_map_request,
        uint8_t         smr_invoked,
        uint64_t        *nonce)
{

    uint8_t *packet;
    int      mrp_len;               /* return the length here */
    //struct sockaddr_storage rloc;


    packet = build_map_request_pkt(dst_rloc_addr,
            eid_prefix,
            eid_prefix_length,
            &len, nonce, encap, probe, solicit_map_request,
            smr_invoked);

    if (!packet) {
        syslog(LOG_DAEMON, "Could not build map-request packet for %s/%d",
                get_char_from_lisp_addr_t(*eid_prefix),
                eid_prefix_length);
        return (BAD);
    }

    if (encap) {
        if (!send_map_request(packet, len, dst_rloc_addr)) {
            syslog(LOG_DAEMON, "Could not send encapsulated map-request for %s/%d",
                    get_char_from_lisp_addr_t(*eid_prefix),
                    eid_prefix_length);
            return (BAD);
        }
    }
    else {
        if (!inaddr2sockaddr(dst_rloc_addr, (struct sockaddr *)&rloc, LISP_CONTROL_PORT)) {
            syslog(LOG_DAEMON, "inaddr2sockaddr: conversion failed");
            return(BAD);
        }
        if (!send_raw_udp((struct sockaddr *)&rloc, packet, len)) {
            syslog(LOG_DAEMON, "Could not send map-request to %s",
                    get_char_from_lisp_addr_t(*dst_rloc_addr));
            return (BAD);
        }
    }
    return (GOOD);
}

/*
 *  process Map_Request Message
 *  Receive a Map_request message and process based on control bits
 *
 *  For first phase just accept (encapsulated) SMR. Proxy bit is set to avoid receiving ecm, and all other types are ignored.
 */

int process_map_request_msg(uint8_t *packet, int s, struct sockaddr *from, int afi) {

    lispd_identifier_elt source_identifier;
    lispd_map_cache_entry *map_cache_entry;
    lisp_addr_t itr_rloc[32];
    int itr_rloc_count = 0;
    int itr_rloc_afi;
    char *cur_ptr;
    int ip_header_len = 0;
    int len = 0;
    lispd_pkt_map_request_t *msg;
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;
    int encap_afi;
    uint16_t udpsum = 0;
    uint16_t ipsum = 0;
    int udp_len = 0;
    uint16_t sport;
    int i;

    /* If the packet is an Encapsulated Map Request, verify checksum and remove the inner IP header */

    if (((lispd_pkt_encapsulated_control_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {

        /*
         * Read IP header.source_identifier
         */

        iph = (struct ip *) CO(packet, sizeof(lispd_pkt_encapsulated_control_t));

        switch (iph->ip_v) {
        case IPVERSION:
            ip_header_len = sizeof(struct ip);
            udph = (struct udphdr *) CO(iph, ip_header_len);
            encap_afi = AF_INET;
            break;
        case IP6VERSION:
            ip6h = (struct ip6_hdr *) CO(packet, sizeof(lispd_pkt_encapsulated_control_t));
            ip_header_len = sizeof(struct ip6_hdr);
            udph = (struct udphdr *) CO(ip6h, ip_header_len);
            encap_afi = AF_INET6;
            break;
        default:
            syslog(LOG_DAEMON, "process_map_request_msg: couldn't read incoming Encapsulated Map-Request: IP header corrupted.");
            return(BAD);
        }

#ifdef BSD
        udp_len = ntohs(udph->uh_ulen);
        sport   = ntohs(udph->uh_sport);
#else
        udp_len = ntohs(udph->len);
        sport   = ntohs(udph->source);
#endif

        /*
         * Verify the checksums.
         */
        if (iph->ip_v == IPVERSION) {
            ipsum = ip_checksum((uint16_t *)iph, ip_header_len);
            if (ipsum != 0) {
                syslog(LOG_DAEMON, " Map-Request: IP checksum failed.");
            }
            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                return(BAD);
            }
            if (udpsum != 0) {
                syslog(LOG_DAEMON, " Map-Request: UDP checksum failed.");
                return(BAD);
            }
        }

        //Pranathi: Added this
        if (iph->ip_v == IP6VERSION) {

            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                return(BAD);
            }
            if (udpsum != 0) {
                syslog(LOG_DAEMON, " Map-Request:v6 UDP checksum failed.");
                return(BAD);
            }
        }

        /*
         * Point msg at the start of the Map-Request payload
         */

        len = ip_header_len + sizeof(struct udphdr);
        msg = (lispd_pkt_map_request_t *) CO(iph, len);

    } else if (((lispd_pkt_map_request_t *) packet)->type == LISP_MAP_REQUEST) {
        msg = (lispd_pkt_map_request_t *) packet;
    } else
        return(BAD); //we should never reach this return()

    /* Source EID is optional in general, but required for SMRs */
    init_identifier(&source_identifier);
    cur_ptr = (char *)&(msg->source_eid_afi);
    if (pkt_process_eid_afi(&cur_ptr, &source_identifier)==BAD){
        if (source_identifier.eid_prefix.afi == -1)
            return BAD;
    }

    /* If packet is a Solicit Map Request, process it */

    if (source_identifier.eid_prefix.afi != 0 && msg->solicit_map_request) {
        /*
         * Lookup the map cache entry that match with the source identifier of the message
         */
        if ((err = lookup_eid_cache(source_identifier.eid_prefix, &map_cache_entry)) != GOOD)
            return BAD;
        /*
         * Check IID of the received Solicit Map Request match the IID of the map cache
         */
        if (map_cache_entry->identifier->iid != source_identifier.iid){
        	syslog(LOG_INFO,"The IID of the received Solicit Map Request doesn't match the IID of "
        			"the entry in the map cache");
        	return BAD;
        }

        /*
         * Only accept a solicit map request for an identifier ->If node which generates the message
         * has more than one locator, it probably will generate a solicit map request for each one.
         * Only the first one is considered.
         * If map_cache_entry->nonces is different of null, we have already received a solicit map request
         */
        if (map_cache_entry->nonces == NULL)
            solicit_map_request_reply(NULL,(void *)map_cache_entry);

        /* Return here only if RLOC probe bit is not set */
        if (!msg->rloc_probe)
            return(GOOD);
    }

    /* Get the array of ITR-RLOCs */
    itr_rloc_count = msg->additional_itr_rloc_count + 1;
    for (i = 0; i < itr_rloc_count; i++) {
        itr_rloc_afi = lisp2inetafi(ntohs(*(uint16_t *)cur_ptr));
        cur_ptr = CO(cur_ptr, sizeof(uint16_t));
        memcpy(&(itr_rloc[i].address), cur_ptr, get_addr_len(itr_rloc_afi));
        itr_rloc[i].afi = itr_rloc_afi;
        cur_ptr = CO(cur_ptr, get_addr_len(itr_rloc_afi));
    }
    /* TODO alopez: We send first RLOC. We should check ip version and reachability */
    /* Process record and send Map Reply for each one */
    for (i = 0; i < msg->record_count; i++) {
    	process_map_request_record(&cur_ptr, itr_rloc[0], sport, msg->rloc_probe, msg->nonce);
    }
    return(GOOD);
}

/*
 * Process record and send Map Reply
 */

int process_map_request_record(
        char **cur_ptr,
        lisp_addr_t src_rloc,
        lisp_addr_t dst_rloc,
        uint16_t dst_port,
        uint8_t rloc_probe,
        uint64_t nonce)
{
	lispd_pkt_request_record_t *record;
	lispd_identifier_elt requested_identifier;
	lispd_identifier_elt *identifier;
	map_reply_opts opts;

	/* Get the requested EID prefix */
	record = (lispd_pkt_request_record_t *)*cur_ptr;
	init_identifier(&requested_identifier);
	*cur_ptr = (char *)&(record->eid_prefix_afi);
	if ((err=pkt_process_eid_afi(cur_ptr, &requested_identifier))!=GOOD){
		syslog(LOG_WARNING,"WARNING: Requested EID could not be processed");
		return (err);
	}
	requested_identifier.eid_prefix_length = record->eid_prefix_length;

	/* Check the existence of the requested EID */
	/* XXX aloepz: We don't use prefix mask and use by default 32 or 128*/
	if (!lookup_eid_in_db(requested_identifier.eid_prefix, &identifier)){
		syslog(LOG_WARNING,"The requested EID doesn't belong to this node: %s/%d",
				get_char_from_lisp_addr_t(requested_identifier.eid_prefix),
				requested_identifier.eid_prefix_length);
		return (BAD);
	}


	/* Set flags for Map-Reply */
	opts.send_rec   = 1;
	opts.echo_nonce = 0;
	opts.rloc_probe = rloc_probe;


	/*
	 *  lispd_identifier_elt *requested_identifier,
        lisp_addr_t *dst_rloc,
        uint16_t dport,
        uint64_t nonce,
        map_reply_opts opts);
	 *
	 */


	if (rloc_probe) {
		if(!build_and_send_map_reply_msg(identifier, &dst_rloc, dst_port, nonce, opts)) {
			syslog(LOG_ERR, "process_map_request_msg: couldn't build/send RLOC-probe reply");
			return(BAD);
		}
		syslog(LOG_INFO, "Sent RLOC-probe reply");
		return(GOOD);
	}

	if(!build_and_send_map_reply_msg(&source_rloc, &(itr_rloc[0]), sport,
			NULL, 0, eid_prefix, msg->nonce, opts)) {
		syslog(LOG_ERR, "process_map_request_msg: couldn't build/send map-reply");
		return(BAD);
	}
	syslog(LOG_DAEMON, "Sent Map-Reply to %s", get_char_from_lisp_addr_t(dst_rloc));

	return (GOOD);
}


void send_map_request_miss(timer *t, void *arg)
{
    lispd_map_cache_entry *map_cache_entry = (lispd_map_cache_entry *)arg;
    nonces_list *nonces = map_cache_entry->nonces;
    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces==NULL){
            syslog (LOG_ERR,"Send_map_request_miss: Coudn't allocate memory for nonces");
            return;
        }
        map_cache_entry->nonces = nonces;
    }

    if (nonces->retransmits - 1 < LISPD_MAX_MR_RETRANSMIT ){

        if (build_and_send_map_request_msg(&(map_cache_entry->identifier->eid_prefix),
                map_cache_entry->identifier->eid_prefix_length,
                map_resolvers->address, 1, 0, 0, 0, &nonces->nonce[nonces->retransmits])== BAD){
            start_timer(map_cache_entry->request_retry_timer, LISPD_INITIAL_MRQ_TIMEOUT,
                    send_map_request_miss, (void *)map_cache_entry);
        }


        nonces->retransmits ++;
        if (map_cache_entry->request_retry_timer == NULL)
            map_cache_entry->request_retry_timer = create_timer ("MAP REQUEST RETRY");
        start_timer(map_cache_entry->request_retry_timer, LISPD_INITIAL_MRQ_TIMEOUT,
                send_map_request_miss, (void *)map_cache_entry);

    }else{
        del_eid_cache_entry(map_cache_entry->identifier->eid_prefix,
                map_cache_entry->identifier->eid_prefix_length);

        syslog (LOG_DEBUG,"No Map Reply fot EID %s/%d. Removing map cache entry ...",
                get_char_from_lisp_addr_t(map_cache_entry->identifier->eid_prefix),
                map_cache_entry->identifier->eid_prefix_length);
    }
}



/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
