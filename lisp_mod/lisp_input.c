/*
 * lisp_input.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implements packet input path for LISP module.
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
 *    Chris White       <chris@logicalelegance.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#include "lisp_mod.h"
#include "linux/ip.h"
#include "linux/udp.h"
#include "linux/in_route.h"
#include "linux/if_arp.h"
#include "net/route.h"
#include "net/ip.h"
#include "net/ipv6.h"
#include "net/ip6_route.h"
#include "linux/ipv6.h"
#include "net/icmp.h"
#include "net/inet_ecn.h"
#include "lisp_input.h"
#include "packettypes.h"

extern lisp_globals globals;
const char echo_signature = 0x78; // First byte past udp header if lisp echo reply

#define DEBUG
//#define DEBUG_PACKETS

/*
 * PN: LISP EID Interface
 * Currently supports 1 interface, name hard-coded
 */
#define LISP_EID_INTERFACE    "lmn0"

/*
 * check_locator_bits()
 *
 * Verify that the locator status bits in the data packet
 * match our view. If not update it. We have to do a cache
 * lookup for every input packet to do this.
 */
void check_locator_bits(struct lisphdr *lisp_hdr,
                        void *iph, int afi, int source)
{
    int i, bitval, retval;
    lisp_map_cache_t *eid_entry;
    int packet_lsbs;
    struct iphdr *ipheader;
    struct ipv6hdr *ip6header;
    lisp_addr_t src_addr;

    // Lookup the source in the map cache
    if ( afi == AF_INET){
    	ipheader = (struct iphdr*)iph;
    	retval = lookup_eid_cache_v4(ipheader->saddr, &eid_entry);
    }
    else {
    	ip6header = (struct ipv6hdr*)iph;
    	memcpy(src_addr.address.ipv6.s6_addr, ip6header->saddr.s6_addr, sizeof(lisp_addr_t));
    	retval = lookup_eid_cache_v6(src_addr, &eid_entry);
    }

    // No entry, what to do?? XXX
    if (retval == 0) {
        printk(KERN_INFO "   Odd, no cache entry for incoming packet.");
        return;
    }

    // Source must be using LSB's for us to care...
    if (lisp_hdr->lsb) {

        /*
         * Check our lsb's against theirs, first extract them from packet
         */
        if (lisp_hdr->instance_id) {
            packet_lsbs = ntohl(lisp_hdr->lsb_bits) & 0x000000FF;
        } else {
            packet_lsbs = ntohl(lisp_hdr->lsb_bits);
        }

        // Go through our list and mark the entries
        // with their current status.
        if (packet_lsbs != eid_entry->lsb) {
            printk(KERN_INFO "     LSB change, was 0x%x, now 0x%x",
                   eid_entry->lsb, packet_lsbs);
            eid_entry->lsb = packet_lsbs;
            bitval = 1;
            for (i = 0; i < eid_entry->count; i++) {
                eid_entry->locator_list[i]->state = !!(bitval & packet_lsbs);
                bitval = bitval << 1;
            }
            // Update the hash table
            update_locator_hash_table(eid_entry);
        }
    }

    // Update the input stats
    eid_entry->active_within_period = 1;
    for (i = 0; i < MAX_LOCATORS; i++) {
        if (!eid_entry->locator_list[i]) {
            break;
        }
        if (source == eid_entry->locator_list[i]->locator.address.ip.s_addr) {
            eid_entry->locator_list[i]->data_packets_in++;
            break;
        }
    }
}

/*
 * lisp_input()
 *
 * Packet entry point into LISP processing. Since all packets
 * will come here, we must be efficient at disposing of non-LISP
 * destined datagrams.
 */
unsigned int lisp_input(unsigned int hooknum, struct sk_buff *packet_buf,
			const struct net_device *input_dev,
			const struct net_device *output_dev,
			int (*okfunc)(struct sk_buff*))
{
  struct iphdr *iph;
  struct ipv6hdr *ip6;
  struct udphdr *udh;
  struct lisphdr *lisp_hdr;
  char   first_byte;
  int source_locator;
  /*
   * PN: net_device corresponding to LISP_EID_INTERFACE
   */
  struct net_device *eid_int = NULL;

  /*
   * Get the IP header
   */
  iph = ip_hdr(packet_buf);

  if (!iph) {
    printk(KERN_INFO "Odd, no IP header\n");
    return NF_ACCEPT;
  }

  source_locator = iph->saddr;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "In LISP Input with packet from %pI4 for %pI4\n",
         &(source_locator), &(iph->daddr));
#endif

  /*
   * Certain things should never be LISP examined:
   * locally loopback sourced.
   */
  if (packet_buf->pkt_type == PACKET_LOOPBACK) {
      return NF_ACCEPT;
  }

  /*
   * Check for UDP
   */
  if (iph->protocol == IPPROTO_UDP) {

    // Move past the ip header
    skb_pull(packet_buf, sizeof(struct iphdr));
    skb_reset_transport_header(packet_buf);

    udh = udp_hdr(packet_buf); 
    first_byte= *((char *)udh + sizeof(struct udphdr));

#ifdef DEBUG_PACKETS
    printk(KERN_INFO "  Proto is UDP, src port: %d dest port: %d\n",
	   ntohs(udh->source), ntohs(udh->dest));
    printk(KERN_INFO "  First byte: 0x%x", first_byte);
#endif

    // Detect non-encapsulated lisp control messages
    if (ntohs(udh->dest) == globals.udp_encap_port &&
        ntohs(udh->source) != LISP_CONTROL_PORT &&
        (first_byte != echo_signature)) {

      // LISP header
      lisp_hdr = (struct lisphdr *)skb_pull(packet_buf, sizeof(struct udphdr));
      skb_reset_transport_header(packet_buf);

#ifdef DEBUG_PACKETS
      printk(KERN_INFO "   LISP packet received: dest %d, len: %d\n", ntohs(udh->dest),
	     ntohs(udh->len));
      printk(KERN_INFO "       rflags: %d, e: %d, l: %d, n: %d, lsb: 0x%x",
             lisp_hdr->rflags, lisp_hdr->echo_nonce, lisp_hdr->lsb,
             lisp_hdr->nonce_present, lisp_hdr->lsb_bits);
#endif

      // Decapsulate
      skb_pull(packet_buf, sizeof(struct lisphdr));
      skb_reset_transport_header(packet_buf);
      skb_reset_network_header(packet_buf);
      iph = ip_hdr(packet_buf);

      if (iph->version == 4) {
#ifdef DEBUG_PACKETS
      printk(KERN_INFO "   Inner packet src:%pI4 dst:%pI4, type: %d\n", &(iph->saddr),
             &(iph->daddr), iph->protocol);
#endif

      // Check the LSB's.
      check_locator_bits(lisp_hdr, iph, AF_INET, source_locator);

      eid_int = dev_get_by_name (&init_net, LISP_EID_INTERFACE);
      if (eid_int) {
          dev_put (eid_int);
          packet_buf->dev = eid_int;
          skb_dst_drop (packet_buf);
          nf_reset(packet_buf);
      }
      else {
          printk (KERN_INFO "Couldn't get input interface %s\n",
                  LISP_EID_INTERFACE);
      }
      return NF_ACCEPT;
      } else if (iph->version == 6) {
          ip6 = ipv6_hdr(packet_buf);
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "   Inner packet src:%pI6 dst:%pI6, nexthdr: 0x%x\n",
                 ip6->saddr.s6_addr, ip6->daddr.s6_addr, ip6->nexthdr);
#endif

	  // Check the LSB's.
          check_locator_bits(lisp_hdr, ip6, AF_INET6, source_locator);

          IPCB(packet_buf)->flags = 0;
          packet_buf->protocol = htons(ETH_P_IPV6);
          packet_buf->pkt_type = PACKET_HOST;

          packet_buf->dev = input_dev;
          nf_reset(packet_buf);
          netif_rx(packet_buf);

          return NF_STOLEN;
      } else {
          return NF_ACCEPT; // Don't know what it is, let ip deal with it.
      }
    }

#ifdef DEBUG_PACKETS
    printk(KERN_INFO "  Non-LISP UDP Packet received\n");

    if (first_byte == echo_signature) {
        printk(KERN_INFO "    LISP-echo reply to data port");
    }
#endif

    // Undo the pull, the next layer expects a pristine skb
    skb_push(packet_buf, sizeof(struct iphdr));
    skb_reset_transport_header(packet_buf);
  }

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "  Punting to IP\n");
#endif
  return NF_ACCEPT;
}

