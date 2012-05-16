/*
 * lispd_map_reply.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 *    Kari Okamoto	    <okamotok@stanford.edu>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

/*
 * Map-Reply Message Format from lisp draft-ietf-lisp-08
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|           Reserved                | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record  TTL                          |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                            Locator                            |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


#include "lispd_external.h"


int process_map_reply(packet)
    uint8_t *packet;

{
    lispd_pkt_map_reply_t                   *mrp;
    lispd_pkt_mapping_record_t              *record;
    lispd_pkt_mapping_record_locator_t      *loc_pkt;
    lisp_eid_map_msg_t                      *map_msg;
    int                                     map_msg_len;
    datacache_elt_t                         *elt = NULL;
    lisp_addr_t                             *eid;
    lisp_addr_t                             *loc;
    int                                     eid_afi;
    int                                     loc_afi;
    uint64_t                                nonce;
    int                                     loc_count;
    int                                     ret;
    int                                     i;

    mrp = (lispd_pkt_map_reply_t *)packet;
    nonce = mrp->nonce;

    /*
     * Advance ptrs to point to their corresponding locations
     * within the incoming packet
     *
     * VE:
     * Assumption is Map Reply has only one record
     */

    record = (lispd_pkt_mapping_record_t *)CO(mrp, sizeof(lispd_pkt_map_reply_t));
    eid = (lisp_addr_t *)CO(record, sizeof(lispd_pkt_mapping_record_t));
    eid_afi = lisp2inetafi(ntohs(record->eid_prefix_afi));

    if(record->locator_count > 0){
        switch (eid_afi) {
        case AF_INET: //ipv4: 4B
            loc_pkt = (lispd_pkt_mapping_record_locator_t *)CO(eid, sizeof(struct in_addr));
            break;
        case AF_INET6: //ipv6: 16B
            loc_pkt = (lispd_pkt_mapping_record_locator_t *)CO(eid, sizeof(struct in6_addr));
            break;
        default:
            syslog (LOG_DAEMON, "process_map_reply(), unknown AFI");
            return (0);
        }

        loc = (lisp_addr_t *)CO(loc_pkt, sizeof(lispd_pkt_mapping_record_locator_t));
    }

    /*
     * Search datacache for the corresponding entry
     */
    // Modified by acabello
    if (!search_datacache_entry_nonce(nonce,&elt)) {
    syslog(LOG_DAEMON,"Map-Reply: Datacache not found for nonce:\n");
    lispd_print_nonce(nonce);
        return 0;
    }
    if (!is_eid_included(elt,eid_afi,record->eid_prefix_length,eid)) {
    syslog(LOG_DAEMON,"Map-Reply: EID does not match for MRp with nonce:\n");
    lispd_print_nonce(nonce);
        return 0;
    }

    /*
     * Check for rloc probing bit?
     * Can calculate RTT if we want to know
     */
    if (mrp->rloc_probe) {
        syslog(LOG_DAEMON, "  RLOC probe reply, setting locator status UP");
        update_map_cache_entry_rloc_status(&elt->eid_prefix,
                elt->eid_prefix_length, &elt->dest, 1);
        delete_datacache_entry(elt);
        return 0;
    }

    delete_datacache_entry(elt);

    /*
     * Allocate memory for the new map cache entry, fill it in
     * If we have a negative reply and we also have a Proxy-ETR
     * configured, allocate memory for a locator
     */
    loc_count = record->locator_count;
    if ((loc_count == 0) && (proxy_etrs))
        loc_count = 1;
    map_msg_len = sizeof(lisp_eid_map_msg_t) +
                  sizeof(lisp_eid_map_msg_loc_t) * loc_count;
    if ((map_msg = malloc(map_msg_len)) == NULL) {
        syslog(LOG_DAEMON, "process_map_reply(), malloc (map-cache entry): %s", strerror(errno));
        return(0);
    }

    memset(map_msg, 0, sizeof(lisp_eid_map_msg_t));

    memcpy(&(map_msg->eid_prefix), eid, sizeof(lisp_addr_t));
    map_msg->eid_prefix.afi            = eid_afi;
    map_msg->eid_prefix_length  = record->eid_prefix_length;
    map_msg->count              = loc_count;
    map_msg->actions            = record->action;
    map_msg->how_learned        = DYNAMIC_MAP_CACHE_ENTRY;      
    map_msg->ttl                = ntohl(record->ttl);
    map_msg->sampling_interval  = RLOC_PROBING_INTERVAL;


    /*
     * VE:   If there are none -> negative map reply.
	 * LJ:   We add the first PETR in the list as locator
     * TODO: We should iterate list, and adjust weights accordingly
	 */
    if((record->locator_count) == 0) {
        if (proxy_etrs) {
            /* Don't RLOC probe PETRs */
            map_msg->sampling_interval = 0;
            /* Fill in locator data */
            memcpy(&(map_msg->locators[0].locator.address), &(proxy_etrs->address->address), sizeof(lisp_addr_t));
            map_msg->locators[0].locator.afi = proxy_etrs->address->afi;
            map_msg->locators[0].priority = 1;
            map_msg->locators[0].weight = 100;
            map_msg->locators[0].mpriority = 255;
            map_msg->locators[0].mweight = 100;

            ret = send_eid_map_msg(map_msg, map_msg_len);
#ifdef     DEBUG
            syslog (LOG_DAEMON, "Installed 'negative' map cache entry using PETR as the locator");
#endif
            if (ret < 0) {
                syslog (LOG_DAEMON, "Installing 'negative' map cache entry failed; ret=%d", ret);
            }

            free(map_msg);
            map_msg = NULL;
            return(0);
        }
    }

    /*
     * Loop through locators if there is more than one provided.
     */
    for(i = 0; i < record->locator_count; i++) {
        memcpy(&(map_msg->locators[i].locator.address), loc, sizeof(struct in6_addr));
        map_msg->locators[i].locator.afi = lisp2inetafi(ntohs(loc_pkt->locator_afi));
        map_msg->locators[i].priority = loc_pkt->priority;
        map_msg->locators[i].weight = loc_pkt->weight;
        map_msg->locators[i].mpriority = loc_pkt->mpriority;
        map_msg->locators[i].mweight = loc_pkt->mweight;

        /*
         * Advance the ptrs for the next locator
         */
        if(i+1 < record->locator_count) {
            loc_afi = map_msg->locators[i].locator.afi;
            if(loc_afi == AF_INET) { //ipv4: 4B
                loc_pkt = (lispd_pkt_mapping_record_locator_t *)CO(loc, sizeof(struct in_addr));
            } else if(loc_afi == AF_INET6){ //ipv6: 16B
                loc_pkt = (lispd_pkt_mapping_record_locator_t *)CO(loc, sizeof(struct in6_addr));
            } else
                return(0);
            loc = (lisp_addr_t *)CO(loc_pkt, sizeof(lispd_pkt_mapping_record_locator_t));
        }
    }

    ret = send_eid_map_msg(map_msg, map_msg_len);

#ifdef DEBUG
    syslog(LOG_DAEMON, "Installed map cache entry");
#endif
    if (ret < 0) {
        syslog(LOG_DAEMON, "Installing map cache entry failed; ret=%d", ret);
    }

    free(map_msg);
    map_msg = NULL;
    return(0);
}

int get_record_length(lispd_locator_chain_t *locator_chain) {
    lispd_locator_chain_elt_t *locator_chain_elt;
    int afi_len = 0;
    int loc_len = 0;
#ifdef LISPMOBMH
    /*We have the loop here as it counts two vars*/
    int loc_count = 0;
    iface_list_elt *elt=NULL;

    get_lisp_afi(locator_chain->eid_prefix.afi, &afi_len);
    locator_chain_elt = locator_chain->head;

    while (locator_chain_elt) {
    	elt = search_iface_list(locator_chain_elt->db_entry->locator_name);
    	if(elt!=NULL && elt->ready){
    		switch (locator_chain_elt->db_entry->locator.afi) {
    		case AF_INET:
    			loc_len += sizeof(struct in_addr);
    			loc_count++;
    			break;
    		case AF_INET6:
    			loc_len += sizeof(struct in6_addr);
    			loc_count++;
    			break;
    		default:
    			syslog(LOG_DAEMON, "Uknown AFI (%d) for %s",
    					locator_chain_elt->db_entry->locator.afi,
    					locator_chain_elt->db_entry->locator_name);
    			break;
    		}
    	}
    	locator_chain_elt = locator_chain_elt->next;
    }
#else
    locator_chain_elt = locator_chain->head;
    loc_len = get_locator_length(locator_chain_elt);
    get_lisp_afi(locator_chain->eid_prefix.afi, &afi_len);

#endif

#ifdef LISPMOBMH
    return sizeof(lispd_pkt_mapping_record_t) + afi_len +
           (loc_count * sizeof(lispd_pkt_mapping_record_locator_t)) +
           loc_len;
#else
    return sizeof(lispd_pkt_mapping_record_t) + afi_len +
           (locator_chain->locator_count * sizeof(lispd_pkt_mapping_record_locator_t)) +
           loc_len;
#endif
}

void *build_mapping_record(rec, locator_chain, opts)
    lispd_pkt_mapping_record_t              *rec;
    lispd_locator_chain_t                   *locator_chain;
    map_reply_opts                          *opts;
{
    int                                     eid_afi = 0;
    int                                     cpy_len = 0;
    lispd_pkt_mapping_record_locator_t      *loc_ptr;
    lispd_db_entry_t                        *db_entry;
    lispd_locator_chain_elt_t               *locator_chain_elt;
#ifdef LISPMOBMH
    iface_list_elt *elt=NULL;
#endif

    if ((rec == NULL) || (locator_chain == NULL))
        return NULL;

    eid_afi = get_lisp_afi(locator_chain->eid_prefix.afi, NULL);

    rec->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    rec->locator_count          = locator_chain->locator_count;
    rec->eid_prefix_length      = locator_chain->eid_prefix_length;
    rec->action                 = 0;
    rec->authoritative          = 1;
    rec->version_hi             = 0;
    rec->version_low            = 0;
    rec->eid_prefix_afi         = htons(eid_afi);

    if ((cpy_len = copy_addr((void *) CO(rec,
            sizeof(lispd_pkt_mapping_record_t)),
            &(locator_chain->eid_prefix), 0)) == 0) {
        syslog(LOG_DAEMON, "build_mapping_record: copy_addr failed");
        return(NULL);
    }

    loc_ptr = (lispd_pkt_mapping_record_locator_t *) CO(rec,
         sizeof(lispd_pkt_mapping_record_t) + cpy_len);

    locator_chain_elt = locator_chain->head;

    while (locator_chain_elt) {
        db_entry             = locator_chain_elt->db_entry;
#ifdef LISPMOBMH
        elt = search_iface_list(db_entry->locator_name);
        if(elt!=NULL && elt->ready){
#endif
        loc_ptr->priority    = db_entry->priority;
        loc_ptr->weight      = db_entry->weight;
        loc_ptr->mpriority   = db_entry->mpriority;
        loc_ptr->mweight     = db_entry->mweight;
        loc_ptr->local       = 1;
        if (opts && opts->rloc_probe)
            loc_ptr->probed  = 1;       /* XXX probed locator, should check addresses */
        loc_ptr->reachable   = 1;       /* XXX should be computed */
        loc_ptr->locator_afi = htons(get_lisp_afi(db_entry->locator.afi, NULL));

        if ((cpy_len = copy_addr((void *) CO(loc_ptr,
                sizeof(lispd_pkt_mapping_record_locator_t)), &(db_entry->locator), 0)) == 0) {
            syslog(LOG_DAEMON, "build_mapping_record: copy_addr failed for locator %s",
                    db_entry->locator_name);
            return(NULL);
        }

        loc_ptr = (lispd_pkt_mapping_record_locator_t *)
            CO(loc_ptr, (sizeof(lispd_pkt_mapping_record_locator_t) + cpy_len));
#ifdef LISPMOBMH
        }
#endif
        locator_chain_elt = locator_chain_elt->next;
    }
    return (void *)loc_ptr;
}


uint8_t *build_map_reply_pkt(lisp_addr_t *src, lisp_addr_t *dst, uint16_t dport,
        prefix_t eid_prefix, uint64_t nonce, map_reply_opts opts, int *len) {
    uint8_t *packet;
    int packet_len = 0;
    int iph_len = 0;
    struct udphdr *udph;
    int udpsum = 0;
    lispd_pkt_map_reply_t *map_reply_msg;
    int map_reply_msg_len = 0;
    lispd_pkt_mapping_record_t *mr_msg_eid, *next_rec;
    patricia_node_t *node = NULL;
    lispd_locator_chain_t *locator_chain_eid4 = NULL;
    lispd_locator_chain_t *locator_chain_eid6 = NULL;

    map_reply_msg_len = sizeof(lispd_pkt_map_reply_t);
    if ((iph_len = get_ip_header_len(src->afi)) == 0)
        return(0);

    /* If the options ask for a mapping record, calculate addtional length */
    if (opts.send_rec) {
        switch (eid_prefix.family) {
        case AF_INET:
            node = patricia_search_best(AF4_database, &eid_prefix);
            if (node != NULL)
                locator_chain_eid4 = ((lispd_locator_chain_t *)(node->data));
            if (locator_chain_eid4 != NULL)
                map_reply_msg_len += get_record_length(locator_chain_eid4);
            break;
        case AF_INET6:
            node = patricia_search_best(AF6_database, &eid_prefix);
            if (node != NULL)
                locator_chain_eid6 = ((lispd_locator_chain_t *)(node->data));
            if (locator_chain_eid6 != NULL)
                map_reply_msg_len += get_record_length(locator_chain_eid6);
            break;
        default:
            syslog(LOG_DAEMON, "build_map_reply_pkt: Unsupported EID prefix AFI: %d",
                    eid_prefix.family);
            return(0);
        }
    }

    packet_len = iph_len + sizeof(struct udphdr) + map_reply_msg_len;

    if ((packet = malloc(packet_len)) == NULL) {
        syslog(LOG_DAEMON, "build_map_reply_pkt: malloc(%d) %s",
                map_reply_msg_len, strerror(errno));
        return(0);
    }
    memset(packet, 0, packet_len);

    udph = build_ip_header((void *)packet, src, dst, iph_len);

#ifdef BSD
    udph->uh_sport = htons(LISP_CONTROL_PORT);
    udph->uh_dport = htons(dport);
    udph->uh_ulen  = htons(sizeof(struct udphdr) + map_reply_msg_len);
    udph->uh_sum   = 0;
#else
    udph->source = htons(LISP_CONTROL_PORT);
    udph->dest   = htons(dport);
    udph->len    = htons(sizeof(struct udphdr) + map_reply_msg_len);
    udph->check  = 0;
#endif

    map_reply_msg = (lispd_pkt_map_reply_t *) CO(udph, sizeof(struct udphdr));

    map_reply_msg->type = 2;
    if (opts.rloc_probe)
        map_reply_msg->rloc_probe = 1;
    if (opts.echo_nonce)
        map_reply_msg->echo_nonce = 1;
    map_reply_msg->record_count = 0;
    map_reply_msg->nonce = nonce;

    if (opts.send_rec) {
        /*
         * Optionally, we send Map Reply records. For RLOC Probing,
         * the language in the spec is SHOULD
         */
        mr_msg_eid = (lispd_pkt_mapping_record_t *)
                     CO(map_reply_msg, sizeof(lispd_pkt_map_reply_t));

        if (locator_chain_eid4) {
            next_rec = build_mapping_record(mr_msg_eid, locator_chain_eid4, &opts);
            if (next_rec) {
                map_reply_msg->record_count++;
                mr_msg_eid = next_rec;
            }
        }

        if (locator_chain_eid6) {
            if (build_mapping_record(mr_msg_eid, locator_chain_eid6, &opts))
                map_reply_msg->record_count++;
        }
    }

    /* Compute checksums */
    if (src->afi == AF_INET)
        ((struct ip *) packet)->ip_sum = ip_checksum(packet, iph_len);
    if ((udpsum = udp_checksum(udph, packet_len - iph_len, packet, src->afi)) == -1) {
        return (0);
    }
    udpsum(udph) = udpsum;
    *len = packet_len;
    return(packet);
}

int send_raw_udp(struct sockaddr *dst, uint8_t *packet, int packet_len) {
    struct ifreq ifr;
    int s, nbytes, one = 1;

    if ((s = socket(dst->sa_family, SOCK_RAW, IPPROTO_UDP)) < 0) {
        syslog(LOG_DAEMON, "send_raw_udp: socket: %s", strerror(errno));
        syslog(LOG_DAEMON, "AFI: %d", dst->sa_family);
        return(0);
    }

    /*
     * By default, raw sockets create the IP header automatically, with operating
     * system defaults and the protocol number specified in the socket() function
     * call. If IP header values need to be customized, the socket option
     * IP_HDRINCL must be set and the header built manually.
     */
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        syslog(LOG_DAEMON, "send_raw_udp: setsockopt IP_HDRINCL: %s", strerror(errno));
        close(s);
        return(0);
    }

    /* XXX (LJ): Even with source routing set up, the packet leaves on lmn0, unless
     *           we specificly ask for the output device to be the control interface
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ctrl_iface->iface_name);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) == -1) {
        syslog(LOG_DAEMON, "send_raw_udp: setsockopt SO_BINDTODEVICE: %s", strerror(errno));
        close(s);
        return(0);
    }

    if ((nbytes = sendto(s, (const void *) packet, packet_len, 0,
                    dst, sizeof(struct sockaddr))) < 0) {
        syslog(LOG_DAEMON, "send_raw_udp: sendto: %s", strerror(errno));
        close(s);
        return (0);
    }

    if (nbytes != packet_len) {
        syslog(LOG_DAEMON, "send_raw_udp: nbytes (%d) != packet_len (%d)\n",
                nbytes, packet_len);
        close(s);
        return (0);
    }

    close(s);
    free(packet);
    return (1);
}

/*
 * build_and_send_map_reply_msg()
 *
 */

int build_and_send_map_reply_msg(lisp_addr_t *src, lisp_addr_t *dst, uint16_t dport,
        struct sockaddr *dst_sa, int s, prefix_t eid_prefix,
        uint64_t nonce, map_reply_opts opts) {
    lisp_addr_t destination;
    struct sockaddr_storage destination_sa;
    uint8_t *packet;
    int len = 0;

    if (src == NULL) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: no source address");
        return(0);
    }

    if (dst == NULL && dst_sa == NULL) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: no destination address");
        return(0);
    }

    if (dst == NULL) {
        if (sockaddr2lisp(dst_sa, &destination) < 0) {
            syslog(LOG_DAEMON, "build_and_send_map_reply_msg: sockaddr2lisp failed");
            return(0);
        }
    } else {
        memcpy(&destination, dst, sizeof(lisp_addr_t));
    }

    if (dst_sa == NULL) {
        if (!inaddr2sockaddr(dst, (struct sockaddr *)&destination_sa, dport)) {
            syslog(LOG_DAEMON, "build_and_send_map_reply_msg: inaddr2sockaddr failed");
            return(0);
        }
    } else {
        memcpy((void *)&destination_sa, dst_sa, get_sockaddr_len(dst_sa->sa_family));
        switch (dst_sa->sa_family) {
        case AF_INET:
            dport = ntohs(((struct sockaddr_in *)dst_sa)->sin_port);
            break;
        case AF_INET6:
            dport = ntohs(((struct sockaddr_in6 *)dst_sa)->sin6_port);
            break;
        default:
            dport = LISP_CONTROL_PORT;
            break;
        }
    }

    packet = build_map_reply_pkt(src, &destination, dport, eid_prefix, nonce, opts, &len);

    /* Send the packet over a raw socket */
    if (!send_raw_udp((struct sockaddr *)&destination_sa, packet, len)) {
        syslog(LOG_DAEMON, "Could not send Map-Reply!");
        free(packet);
        return (0);
    }

    /* LJ: The code below is for the case when we reuse the receiving socket.
     *     However, since it is bound to INADDR_ANY, it selects source
     *     address based on exit interface, and because of that it will
     *     use our EID on lmn0. Because we want source port 4342, and it is
     *     already bound, we need to use raw sockets in send_map_reply()
     */
/*
    if ((nbytes = sendto(s, (const void *) packet, map_reply_msg_len, 0,
                    dst, sizeof(struct sockaddr))) < 0) {
        syslog(LOG_DAEMON, "send_map_reply: sendto: %s", strerror(errno));
        free(packet);
        return (0);
    }

    if (nbytes != map_reply_msg_len) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: nbytes (%d) != map_reply_msg_len (%d)\n",
                nbytes, map_reply_msg_len);
        return (0);
    }
    free(packet);
*/

    return(1);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
