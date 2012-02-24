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

#include "lispd_external.h"

uint8_t *build_map_request_pkt(dest, eid_prefix, eid_prefix_length,
        len, nonce, encap, probe, solicit_map_request, smr_invoked, islocal)
    lisp_addr_t *dest;
    lisp_addr_t *eid_prefix;
    uint8_t eid_prefix_length;
    int *len; /* return length here */
    uint64_t                 *nonce;            /* return nonce here */
    uint8_t encap;
    uint8_t probe;
    uint8_t solicit_map_request; /* boolean really */
    uint8_t smr_invoked;
    uint8_t                islocal;

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

    /* my_addr must have same afi as requested EID */
    if (!(ctrl_iface) || !(ctrl_iface->AF4_locators->head)) {
        /* 
         * No physical interface available for control messages
         */
        syslog(LOG_DAEMON, "(build_map_request_pkt): Unable to find valid physical interface\n");
        return (0);
    }

    if (!encap) {
        if ((my_addr = get_my_addr(ctrl_iface->iface_name, dest->afi)) == 0) {
            syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                   ctrl_iface->iface_name, dest->afi);
            return(0);
        }
    } else {

  //Pranathi : my_addr -> This is for the source address in the inner header of the encapsulated Map-request msg
  // For v4eid over v4 rloc , Inner header: v4 src rloc , v4 dest eid
  // For v6eid over v4 rloc , Inner header: v6 src eid , v6 dest eid
  // For v4eid over v6 rloc , Inner header: v4 src eid , v4 dest eid
  // For v6eid over v6 rloc , Inner header: v6 src rloc , v6 dest eid
 if(ctrl_iface->AF4_locators->head)
 {
   switch(eid_prefix->afi) {
    case AF_INET:
            if ((my_addr = get_my_addr(ctrl_iface->iface_name,lisp2inetafi(eid_afi))) == 0) { 
               syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                      ctrl_iface->iface_name,lisp2inetafi(eid_afi));
            return(0);
           }
           break;

    case AF_INET6:
          if ((my_addr = get_my_addr("lmn0",lisp2inetafi(eid_afi))) == 0) {
              syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                     "lmn0",lisp2inetafi(eid_afi));
          return(0);
        }
        break;
    
    default:
       syslog(LOG_DAEMON, "Unknown EID address family:%d in build_map_request_pkt()",eid_prefix->afi);
       return(0);
   }

 }

 else if(ctrl_iface->AF6_locators->head)
 {
   switch(eid_prefix->afi) {
    case AF_INET:
          if ((my_addr = get_my_addr("lmn0",lisp2inetafi(eid_afi))) == 0) {
              syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                     "lmn0",lisp2inetafi(eid_afi));
          return(0);
        }
        break;

    case AF_INET6:
         if ((my_addr = get_my_addr(ctrl_iface->iface_name,lisp2inetafi(eid_afi))) == 0) { 
               syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
                      ctrl_iface->iface_name,lisp2inetafi(eid_afi));
            return(0);
           }
           break;

    default:
        syslog(LOG_DAEMON,"Unknown EID address family:%d in build_map_request_pkt()",eid_prefix->afi);
       return(0);
   }
 }
else
{
 syslog(LOG_DAEMON,"Ctrl_iface : No v4/v6 locators");
 return(0);

}
}

 

/*

    if ((my_addr_len = get_addr_len(my_addr->afi)) == 0) { 
	free(my_addr);
	return (0);
    }

*/
//Pranathi : since this is for obtaining itr rloc length , not eid
	if(ctrl_iface->AF4_locators->head)
	{
	  if ((my_itr_addr_len = get_addr_len(AF_INET)) == 0) { 
	  free(my_addr);
	  return (0);
         }
        }
        else if(ctrl_iface->AF6_locators->head)
	{
	  if ((my_itr_addr_len = get_addr_len(AF_INET6)) == 0) { 
	  free(my_addr);
	  return (0);
         }
        }

    if ((ip_header_len = get_ip_header_len(my_addr->afi)) == 0) {
	free(my_addr);
	return (0);
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
    mrp->source_eid_afi = htons(get_lisp_afi(eid_prefix->afi, NULL));

    /*
     * Source-EID address goes here.
     *
     *  point cur_ptr at where the variable length Source-EID 
     *  address goes, namely, CO(mrp,sizeof(lispd_pkt_map_request_t))
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
    }

    cur_ptr = CO(mrp, sizeof(lispd_pkt_map_request_t));
    if (locator_chain) {
        if ((alen = copy_addr(cur_ptr, &(locator_chain->eid_prefix), 0)) == 0) {
            free(packet);
            return (0);
        }
    } else {
        /* XXX: Something went wrong before, we put the destination here for now */
        if ((alen = copy_addr(cur_ptr, eid_prefix, 0)) == 0) {
            free(packet);
            return (0);
        }
    }

    /*
     * now the ITR-RLOC (XXX: assumes only one)
     */
//Pranathi
 if(ctrl_iface->AF4_locators->head)  /* v4 RLOC*/
 {
    itr_rloc = (lispd_pkt_map_request_itr_rloc_t *) CO(cur_ptr, alen);
    itr_rloc->afi = htons(get_lisp_afi(AF_INET, NULL));
    cur_ptr = CO(itr_rloc, sizeof(lispd_pkt_map_request_itr_rloc_t));
      if ((alen = copy_addr(cur_ptr, (lisp_addr_t *)
                      &((ctrl_iface->AF4_locators->head->db_entry->locator).address), 0)) == 0) {

    free(packet);
    return (0);
      } 
 
 }

 if(ctrl_iface->AF6_locators->head)  /*v6 RLOC*/
  {
    itr_rloc = (lispd_pkt_map_request_itr_rloc_t *) CO(cur_ptr, alen);
   itr_rloc->afi = htons(get_lisp_afi(AF_INET6, NULL));
    cur_ptr = CO(itr_rloc, sizeof(lispd_pkt_map_request_itr_rloc_t));
   if ((alen = copy_addr(cur_ptr, (lisp_addr_t *)
                   &((ctrl_iface->AF6_locators->head->db_entry->locator).address), 0)) == 0) {

    free(packet);
    return (0);
    }

  }

    /* 
     *  finally, the requested EID prefix
     */

    eid = (lispd_pkt_map_request_eid_prefix_record_t *) CO(cur_ptr, alen);
    eid->eid_prefix_mask_length = eid_prefix_length;
    eid->eid_prefix_afi = htons(get_lisp_afi(eid_prefix->afi, NULL));
    cur_ptr = CO(eid, sizeof(lispd_pkt_map_request_eid_prefix_record_t));
    if (copy_addr(cur_ptr,              /* EID */
    eid_prefix, 0) == 0) {
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
    if (!(ctrl_iface) || !(ctrl_iface->AF4_locators->head)) {
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
    ctrl_saddr.sin_addr.s_addr  = (ctrl_iface->AF4_locators->head->db_entry->locator).address.ip.s_addr;

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

int build_and_send_map_request_msg(dest, eid_prefix,
        eid_prefix_length, eid_name, encap, probe, solicit_map_request,
        smr_invoked, islocal,retries,timeout,search)
    lisp_addr_t *dest;
    lisp_addr_t *eid_prefix;
    uint8_t eid_prefix_length;
    char *eid_name;
    uint8_t encap;                  /* "boolean" */
    uint8_t probe;                  /* "boolean" */
    uint8_t solicit_map_request;    /* "boolean" */
    uint8_t smr_invoked;            /* "boolean" */
    uint8_t islocal;                /* "boolean" */
    uint8_t retries;
    uint16_t timeout;
    uint8_t search;
{

    uint8_t *packet;
    uint64_t nonce;
    int      len;               /* return the length here */
    datacache_elt_t *res_elt = NULL;
    struct sockaddr_storage rloc;
    char rloc_name[128];

    if (search) {
        if (search_datacache_entry_eid(eid_prefix, res_elt)) {
            // We have already sent a Map-Request towards this destination
            // We should wait until the ongoing Map-Request expires to re-send
            // another one
            return (1);
        }
    }

    packet = build_map_request_pkt(dest, eid_prefix, eid_prefix_length,
            &len, &nonce, encap, probe, solicit_map_request,
            smr_invoked, islocal,retries);


    if (!packet) {
        syslog(LOG_DAEMON, "Could not build map-request packet for %s/%d",
                eid_name, eid_prefix_length);
        return (0);
    }

    if (encap) {
        if (!send_map_request(packet, len, dest)) {
            syslog(LOG_DAEMON, "Could not send encapsulated map-request for %s/%d", eid_name,
                    eid_prefix_length);
            return (0);
        }
    }
    else {
        if (!inaddr2sockaddr(dest, (struct sockaddr *)&rloc, LISP_CONTROL_PORT)) {
            syslog(LOG_DAEMON, "inaddr2sockaddr: conversion failed");
            return(0);
        }
        inet_ntop(dest->afi, &(dest->address), rloc_name, 128);
        if (!send_raw_udp((struct sockaddr *)&rloc, packet, len)) {
            syslog(LOG_DAEMON, "Could not send map-request to %s", rloc_name);
            return (0);
        }
    }

    /*
     * Add outstanding nonce to datacache, unless SMR
     */

    if (!solicit_map_request) {
        if (!build_datacache_entry(dest, eid_prefix, eid_prefix_length,
                    nonce, islocal, probe, smr_invoked, retries, timeout, encap)) {
            syslog(LOG_DAEMON, "Couldn't build datacache_entry");
            return (0);
        }
    }
    return (1);
}

/*
 *  process Map_Request Message
 *  Receive a Map_request message and process based on control bits
 *
 *  For first phase just accept (encapsulated) SMR. Proxy bit is set to avoid receiving ecm, and all other types are ignored.
 *
 *
 */

int process_map_request_msg(uint8_t *packet, int s, struct sockaddr *from, int afi) {

    lisp_addr_t src_eid_prefix;
    lisp_addr_t itr_rloc[32];
    prefix_t eid_prefix;
    int itr_rloc_count = 0;
    int src_eid_afi;
    int itr_rloc_afi;
    void *cur_ptr;
    int afi_len = 0;
    int ip_header_len = 0;
    int len = 0;
    char eid_name[128];
    char rloc_name[128];
    lispd_pkt_map_request_t *msg;
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;
    int encap_afi;
    uint16_t sport = LISP_CONTROL_PORT;
    uint16_t udpsum = 0;
    uint16_t ipsum = 0;
    int udp_len = 0;
    map_reply_opts opts;
    int i;

    if (((lispd_pkt_encapsulated_control_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {

        /*
         * Read IP header.
         */

        iph = (struct ip *) CO(packet, sizeof(lispd_pkt_encapsulated_control_t));

        switch (iph->ip_v) {
        case IPVERSION:
            ip_header_len = (iph->ip_hl) * 4;
            udph = (struct udphdr *) CO(iph, ip_header_len);
            encap_afi = AF_INET;
            break;
        case IP6VERSION:
            ip6h = (struct ip6_hdr *) CO(packet, sizeof(lispd_pkt_encapsulated_control_t));
            if ((ip_header_len = get_ip_header_len(AF_INET6)) == 0)
                return(0);
            udph = (struct udphdr *) CO(ip6h, ip_header_len);
            encap_afi = AF_INET6;
            break;
        default:
            syslog(LOG_DAEMON, "process_map_request_msg: couldn't read incoming Encapsulated Map-Request: IP header corrupted.");
            return(0);
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
            ipsum = ip_checksum(iph, ip_header_len);
            if (ipsum != 0) {
                syslog(LOG_DAEMON, " Map-Request: IP checksum failed.");
            }

            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                    return(0);
            }

            if (udpsum != 0) {
                    syslog(LOG_DAEMON, " Map-Request: UDP checksum failed.");
                    return(0);

            }
        }


                //Pranathi: Added this
        if (iph->ip_v == IP6VERSION) {
           
            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                    return(0);
            }

            if (udpsum != 0) {
                    syslog(LOG_DAEMON, " Map-Request:v6 UDP checksum failed.");
                    return(0);

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
        return(0); //we should never reach this return()

    /* Source EID is optional in general, but required for SMRs */
    src_eid_afi = lisp2inetafi(ntohs(msg->source_eid_afi));
    cur_ptr = CO((void *)msg, sizeof(lispd_pkt_map_request_t));
    if (src_eid_afi != 0) {
        memset(&src_eid_prefix, 0, sizeof(lisp_addr_t));
        memcpy(&(src_eid_prefix.address), cur_ptr, get_addr_len(src_eid_afi));
        src_eid_prefix.afi = src_eid_afi;
        inet_ntop(src_eid_afi, &(src_eid_prefix.address), eid_name, 128);
        afi_len = (get_prefix_len(src_eid_afi));
        cur_ptr = CO(cur_ptr, get_addr_len(src_eid_afi));

        if (msg->solicit_map_request) {
            if(!build_and_send_map_request_msg(map_resolvers->address,
                        &src_eid_prefix, afi_len, eid_name,
                        1, 0, 0, 1, 0, 0, LISPD_INITIAL_MRQ_TIMEOUT, 0)) {
                syslog(LOG_DAEMON, "process_map_request_msg: couldn't build/send SMR triggered Map-Request");
                return(0);
            }
            syslog(LOG_DAEMON, "Sent SMR triggered Map-Request for %s", eid_name);
            /* Return here only if RLOC probe bit is not set */
            if (!msg->rloc_probe)
                return(1);
        }
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

    /* LJ: The spec says the following:
     *         For this version of the protocol, a receiver MUST accept and
     *         process Map-Requests that contain one or more records, but a
     *         sender MUST only send Map-Requests containing one record.  Support
     *         for requesting multiple EIDs in a single Map-Request message will
     *         be specified in a future version of the protocol.
     *      Since currently a compliant implementation will always ask for a single
     *      record, we will implement support for more only when the protocol is
     *      updated.
     */

    /* Get the requested EID prefix */
    cur_ptr = CO(cur_ptr, sizeof(uint8_t));
    eid_prefix.ref_count = 0;
    eid_prefix.bitlen = *(uint8_t *)cur_ptr;
    cur_ptr = CO(cur_ptr, sizeof(uint8_t));
    eid_prefix.family = lisp2inetafi(ntohs(*(uint16_t *)cur_ptr));
    cur_ptr = CO(cur_ptr, sizeof(uint16_t));
    memcpy(&(eid_prefix.add), cur_ptr, get_addr_len(eid_prefix.family));

    /* Set flags for Map-Reply */
    opts.send_rec   = 1;
    opts.rloc_probe = 0;
    opts.echo_nonce = 0;

    if (msg->rloc_probe) {
        opts.rloc_probe = 1;
        if(!build_and_send_map_reply_msg(&source_rloc, NULL, 0,
                    from, s, eid_prefix, msg->nonce, opts)) {
            syslog(LOG_DAEMON, "process_map_request_msg: couldn't build/send RLOC-probe reply");
            return(0);
        }
        syslog(LOG_DAEMON, "Sent RLOC-probe reply");
        return(1);
    }

    if(!build_and_send_map_reply_msg(&source_rloc, &(itr_rloc[0]), sport,
                NULL, 0, eid_prefix, msg->nonce, opts)) {
        syslog(LOG_DAEMON, "process_map_request_msg: couldn't build/send map-reply");
        return(0);
    }
    inet_ntop(itr_rloc[0].afi, &(itr_rloc[0].address), rloc_name, 128);
    syslog(LOG_DAEMON, "Sent Map-Reply to %s", rloc_name);
    return(1);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
