/*
 * lisp_output.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implements handler routines for locally sourced packets destined
 * for LISP encapsulation.
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
 *    Vina Ermagan      <vermagan@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include "linux/version.h"
#include "linux/ip.h"
#include "linux/udp.h"
#include "linux/in_route.h"
#include "net/route.h"
#include "net/ip.h"
#include "net/ipv6.h"
#include "net/ip6_route.h"
#include "net/inet_ecn.h"
#include "net/dst.h"
#include "lisp_mod.h"
#include "lisp_output.h"
#include "packettypes.h"

#define DEBUG 
//#define DEBUG_PACKETS

/* PN 
 * define NEW_KERNEL to handle differences in struct sk_buff
 * between android and newer kernels
 */
#define NEW_KERNEL

extern lisp_globals globals;

static inline uint16_t src_port_hash(struct iphdr *iph)
{
  uint16_t result = 0;
  
  // Simple rotated XOR hash of src and dst
  result = (iph->saddr << 4) ^ (iph->saddr >> 28) ^ iph->saddr ^ iph->daddr;
  return result;
}

static inline unsigned char output_hash_v4(unsigned int src_eid, unsigned int dst_eid)
{
	uint32_t hash, aux_addr, i;
	uint8_t byte;

	aux_addr = src_eid ^ dst_eid;
	for(hash = i = 0; i < 4; ++i)
	{
		byte = aux_addr & 0xFF;
		aux_addr = aux_addr >> 8;
		hash += byte;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return ( hash % LOC_HASH_SIZE);
}

static inline unsigned char output_hash_v6(struct in6_addr src_eid, struct in6_addr dst_eid)
{
	uint32_t hash, i;

	for(hash = i = 0; i < 4; ++i)
	{
		hash += src_eid.in6_u.u6_addr8[i] ^ dst_eid.in6_u.u6_addr8[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return ( hash % LOC_HASH_SIZE);
}

void lisp_encap4(struct sk_buff *skb, int locator_addr,
		 ushort inner_afi)
{
  struct udphdr *udh;
  struct iphdr *iph;
  struct iphdr *old_iph = ip_hdr(skb);
  struct lisphdr *lisph;
  struct sk_buff *new_skb = NULL;
  uint32_t orig_length = skb->len;
  uint32_t pkt_len, err;
  uint32_t max_headroom;
  struct net_device *tdev; // Output device
  struct rtable *rt; // route to RLOC

  /*
   * Painful: we have to do a routing check on our
   * proposed RLOC dstadr to determine the output
   * device. This is so that we can be assured
   * of having the proper space available in the 
   * skb to add our headers. This is modelled after
   * the ipip.c code.
   */
   /*
    * PN: Set correct saddr for route lookup
    */
    printk(KERN_INFO "lisp_encap4: saddr for route lookup: %pI4\n",
                      &globals.my_rloc.address.ip.s_addr);
  {
    struct flowi fl = { .oif = 0,
			.nl_u = { .ip4_u = 
				  { .daddr = locator_addr,
				    .saddr = globals.my_rloc.address.ip.s_addr,
				    .tos = RT_TOS(old_iph->tos) } },
			.proto = IPPROTO_UDP };
    if (ip_route_output_key(&init_net, &rt, &fl)) {
      printk(KERN_INFO "Route lookup for locator %pI4 failed\n", &locator_addr);
      /*
       * PN: Fix skb memory leaks
       */
      dev_kfree_skb(skb);
      return;
    }
  }
  
  /*
   * Get the output device 
   */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
  tdev = rt->dst.dev;
#else
  tdev = rt->u.dst.dev;
#endif
  
  /*
   * PN: What did route lookup return?
   */
#ifdef DEBUG_PACKETS
  printk(KERN_INFO "   Got route for RLOC; tdev: %s\n", tdev->name);
#endif

  /*
   * Handle fragmentation XXX 
   */
  
  /* 
   * Determine if we have enough space.
   */
  max_headroom = (LL_RESERVED_SPACE(tdev) + sizeof(struct iphdr) +
		  sizeof(struct udphdr) + sizeof(struct lisphdr));
#ifdef DEBUG_PACKETS
  printk(KERN_INFO "    Max headroom is %d\n", max_headroom);
#endif

  /*
   * If not, gotta make some more.
   */
  if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
      (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
#ifdef DEBUG_PACKETS
    printk(KERN_INFO "    Forced to allocate new sk_buff\n");
#endif
    new_skb = skb_realloc_headroom(skb, max_headroom);
    if (!new_skb) {
      ip_rt_put(rt);
      printk(KERN_INFO "Failed to allocate new skb for packet encap\n");
      /*
       * PN: Fix skb memory leaks
       */
      dev_kfree_skb(skb);
      return;
    }

    /*
     * Repoint socket if necessary
     */
    if (skb->sk) 
      skb_set_owner_w(new_skb, skb->sk);

    dev_kfree_skb(skb);
    skb = new_skb;
    old_iph = ip_hdr(skb);
  }

  /* 
   * Construct and add the LISP header
   */
  skb->transport_header = skb->network_header;
  lisph = (struct lisphdr *)(skb_push(skb, sizeof(struct lisphdr)));
  skb_reset_transport_header(skb);

  memset((char *)lisph, 0, sizeof(struct lisphdr));

  // Single LSB for now, and set it to ON
  lisph->lsb = 1;
  lisph->lsb_bits = htonl(0x1);
  lisph->nonce_present = 1;
  lisph->nonce[0] = net_random() & 0xFF;
  lisph->nonce[1] = net_random() & 0xFF;
  lisph->nonce[2] = net_random() & 0xFF;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "          rflags: %d, e: %d, l: %d, n: %d, lsb: 0x%x",
             lisph->rflags, lisph->echo_nonce, lisph->lsb,
             lisph->nonce_present, lisph->lsb_bits);
#endif

  /* 
   * Construct and add the udp header
   */ 
  skb->transport_header = skb->network_header;
  udh = (struct udphdr *)(skb_push(skb, sizeof(struct udphdr)));
  skb_reset_transport_header(skb);

  /*
   * Hash of inner header source/dest addr. This needs thought.
   */
  udh->source = htons(globals.udp_encap_port);
  udh->dest =  htons(LISP_ENCAP_PORT);
  udh->len = htons(sizeof(struct udphdr) + orig_length +
		   sizeof(struct lisphdr));
  udh->check = 0; // SHOULD be 0 as in LISP ID

  /*
   * Construct and add the outer ip header
   */
  iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
  skb_reset_network_header(skb);
  memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
  skb_dst_drop(skb);
  skb_dst_set(skb, &rt->dst);
#elif defined NEW_KERNEL
  skb_dst_drop(skb);
  skb_dst_set(skb, &rt->u.dst);
#else
  dst_release(skb->dst);
  skb->dst = &rt->u.dst;
#endif
  iph           = ip_hdr(skb);
  iph->version  =    4;
  iph->ihl      =     sizeof(struct iphdr)>>2;
  iph->frag_off = 0;   // XXX recompute above, use method in 5.4.1 of draft
  iph->protocol = IPPROTO_UDP;
  iph->tos      = old_iph->tos; // Need something else too? XXX
  iph->daddr    = rt->rt_dst;
  iph->saddr    = globals.my_rloc.address.ip.s_addr;
  iph->ttl      = old_iph->ttl;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "     Packet encapsulated to %pI4 from %pI4\n",
	 &(iph->daddr), &(iph->saddr));
#endif
  nf_reset(skb);
  
  /* 
   * We must transmit the packet ourselves:
   * the skb has probably changed out from under
   * the upper layers that have a reference to it.
   * 
   * This is the same work that the tunnel code does
   */
  pkt_len = skb->len - skb_transport_offset(skb);
  
  skb->ip_summed = CHECKSUM_NONE;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
  ip_select_ident(iph, &rt->dst, NULL);
#else
  ip_select_ident(iph, &rt->u.dst, NULL);
#endif

  /*
   * We want the equivalent of ip_local_output, but
   * without taking a pass through the NF_HOOK again.
   * We'd just come right back here. May be wary of
   * all this does too: fragmentation, etc.... XXX
   */
  iph->tot_len = htons(skb->len);
  ip_send_check(iph);

  err = dst_output(skb);
  if (net_xmit_eval(err) != 0) {
    printk(KERN_INFO "     ip_local_out() reported an error: %d\n", err);
    /*
     * PN: Fix skb memory leaks
     */
    dev_kfree_skb(skb);
  }

  return;
}

void lisp_encap6(struct sk_buff *skb, lisp_addr_t locator_addr,
		 ushort inner_afi)
{
  struct udphdr *udh;
  struct ipv6hdr *iph;
  struct ipv6hdr *old_iph = ipv6_hdr(skb);
  struct lisphdr *lisph;
  struct sk_buff *new_skb = NULL;
  uint32_t orig_length = skb->len;
  uint32_t pkt_len, err;
  uint32_t max_headroom;
  struct net_device *tdev; // Output device
  struct dst_entry *dst;
  int    mtu;
  uint8_t dsfield;
  struct flowi fl;
  
  /*
   * We have to do a routing check on our
   * proposed RLOC dstadr to determine the output
   * device. This is so that we can be assured
   * of having the proper space available in the 
   * skb to add our headers. This is modelled after
   * the iptunnel6.c code.
   */
  {
    ipv6_addr_copy(&fl.fl6_dst, &locator_addr.address.ipv6);
    if (globals.my_rloc_af != AF_INET6) {
      printk(KERN_INFO "No AF_INET6 source rloc available\n");
      return;
    }
    ipv6_addr_copy(&fl.fl6_src, &globals.my_rloc.address.ipv6);
    fl.oif = 0;

    fl.fl6_flowlabel = 0;
    fl.proto = IPPROTO_UDP;
  }

  dst = ip6_route_output(&init_net, NULL, &fl);

  if (dst->error) {
    printk(KERN_INFO "  Failed v6 route lookup for RLOC\n");
    
    // Error fail cleanup XXX
    return;
  }
     
  /*
   * Get the output device 
   */
  tdev = dst->dev;
  
  printk(KERN_INFO "   Got route for RLOC\n");

  /*
   * Handle fragmentation XXX 
   */
  mtu = dst_mtu(dst) - (sizeof(*iph) + sizeof(*lisph));
  if (mtu < IPV6_MIN_MTU) {
    mtu = IPV6_MIN_MTU;
  };

#ifdef NEW_KERNEL
  /*
   * Do we really want to do this? XXX
   */
  if (skb_dst(skb))
    skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);
  if (skb->len > mtu) {
    printk(KERN_INFO "   skb does not fit in MTU");
    return; // Cleanup XXX
  }
#else
  if (skb->dst)
      skb->dst->ops->update_pmtu(skb->dst, mtu);
  if (skb->len > mtu) {
      printk(KERN_INFO "   skb does not fit in MTU\n");
      return; // Cleanup XXX
  }
#endif
  
  /* 
   * Determine if we have enough space.
   */
  max_headroom = (LL_RESERVED_SPACE(tdev) + sizeof(struct ipv6hdr) +
		  sizeof(struct udphdr) + sizeof(struct lisphdr));
  printk(KERN_INFO "  Max headroom is %d\n", max_headroom);

  /*
   * If not, gotta make some more.
   */
  if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
      (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
      printk(KERN_INFO "  Forced to allocate new sk_buff\n");
      new_skb = skb_realloc_headroom(skb, max_headroom);
      if (!new_skb) {
          printk(KERN_INFO "Failed to allocate new skb for packet encap\n");
          return;
      }

      /*
     * Repoint socket if necessary
     */
      if (skb->sk)
          skb_set_owner_w(new_skb, skb->sk);

      dev_kfree_skb(skb);
      skb = new_skb;
      old_iph = ipv6_hdr(skb); // Err.. what if its v6 encaped v4? XXX
  }

#ifdef NEW_KERNEL
  skb_dst_drop(skb);
  skb_dst_set(skb, dst);
#else
  dst_release(skb->dst);
  skb->dst = dst_clone(dst);
#endif

  /* 
   * Construct and add the LISP header
   */
  skb->transport_header = skb->network_header;
  lisph = (struct lisphdr *)(skb_push(skb, sizeof(struct lisphdr)));
  skb_reset_transport_header(skb);

  // no flags XXX
  memset((char *)lisph, 0, sizeof(struct lisphdr));

   /* 
   * Construct and add the udp header
   */ 
  skb->transport_header = skb->network_header;
  udh = (struct udphdr *)(skb_push(skb, sizeof(struct udphdr)));
  skb_reset_transport_header(skb);
  
  /*
   * Hash of inner header source/dest addr. This needs thought.
   */
  udh->source = htons(globals.udp_encap_port);
  udh->dest =  LISP_ENCAP_PORT;
  udh->len = htons(sizeof(struct udphdr) + orig_length +
		   sizeof(struct lisphdr));
  udh->check = 0; // SHOULD be 0 as in LISP ID

  /*
   * Construct and add the outer ipv6 header
   */
  skb_push(skb, sizeof(struct ipv6hdr));
  skb_reset_network_header(skb);
  iph = ipv6_hdr(skb);
  *(__be32*)iph = htonl(0x60000000); // Flowlabel? XXX
  dsfield = INET_ECN_encapsulate(0, dsfield);
  ipv6_change_dsfield(iph, ~INET_ECN_MASK, dsfield);
  iph->hop_limit = 10; // XXX grab from inner header.
  iph->nexthdr = IPPROTO_UDP;
  ipv6_addr_copy(&iph->saddr, &fl.fl6_src);
  ipv6_addr_copy(&iph->daddr, &fl.fl6_dst);
  nf_reset(skb);

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "  Packet encapsulated to %pI6\n", iph->daddr.s6_addr);
#endif

  /* 
   * We must transmit the packet ourselves:
   * the skb has probably changed out from under
   * the upper layers that have a reference to it.
   * 
   * This is the same work that the tunnel code does
   */
  pkt_len = skb->len;
  err = ip6_local_out(skb);
  if (net_xmit_eval(err) != 0) {
    printk(KERN_INFO "ip_local_out() reported an error: %d\n", err);
  }

  return;
}

unsigned int lisp_output6(unsigned int hooknum,
			  struct sk_buff *packet_buf,
			  const struct net_device *input_dev,
			  const struct net_device *output_dev,
			  int (*okfunc)(struct sk_buff*))
{
  struct ipv6hdr *iph;
  lisp_map_cache_t *eid_entry;
  int retval;
  lisp_addr_t locator_addr;
  unsigned char loc_index;
  ushort      loc_afi;
  lisp_addr_t dst_addr;

  /* 
   * Extract the ip header
   */
  iph = ipv6_hdr(packet_buf);
  
#ifdef DEBUG
  printk(KERN_INFO "   Output packet originally destined for %pI6 from %pI6\n", iph->daddr.s6_addr,
         iph->saddr.s6_addr);
#endif

  /*
   * Sanity check the inner packet XXX
   */

  /*
   * Eventually, when supporting ipv6/ipv6 or v4 or v6, we
   * will need to escape LISP control messages, like in lisp_output4.
   * XXX
   */

  /*
   * Lookup the destination in the map-cache, this will
   * need to return the full entry in the future for all
   * the flags to be processed. TDB: Check for concurrency
   * issues with directly using the entry pointer here. May
   * need to lock it or make a copy (ick)
   */
  memcpy(dst_addr.address.ipv6.s6_addr, iph->daddr.s6_addr, sizeof(lisp_addr_t));
  retval = lookup_eid_cache_v6(dst_addr, &eid_entry);
  
  /*
   * Check status of returned entry XXX (requires extension
   * of above function).
   */
  if (retval == 0 || !eid_entry->count) {

    printk(KERN_INFO "No EID mapping found, notifying lispd...\n");
    send_cache_miss_notification(dst_addr, AF_INET6);
    return NF_ACCEPT;  // What's the right thing to do here? XXX
  }

  /*
   * Mark that traffic has been received.
   */
  eid_entry->active_within_period = 1;

  /*
   * Hash to find the correct locator based on weight, priority, etc.
   */
  loc_index = eid_entry->locator_hash_table[output_hash_v6(iph->saddr, iph->daddr)];
  if (!eid_entry->locator_list[loc_index]) {
    printk(KERN_INFO " No suitable locators.\n");
    return(NF_DROP);
  } else {
      loc_afi = eid_entry->locator_list[loc_index]->locator.afi;
      memcpy(&locator_addr, &eid_entry->locator_list[loc_index]->locator, sizeof(lisp_addr_t));
      printk(KERN_INFO " Locator found.\n");
  }
  
  /* 
   * Prepend UDP, LISP, outer IP header
   */
  if (loc_afi == AF_INET) {
      lisp_encap4(packet_buf, locator_addr.address.ip.s_addr,
                  AF_INET6);
      printk(KERN_INFO "   Using locator address: %pI4\n", &locator_addr);
  } else {
      if (loc_afi == AF_INET6) {
          lisp_encap6(packet_buf, locator_addr, AF_INET6);
          printk(KERN_INFO "   Using locator address: %pI6\n", locator_addr.address.ipv6.s6_addr);
      }
  }

  eid_entry->locator_list[0]->data_packets_out++;

  /* 
   * In all liklihood we've disposed of the orignal skb
   * for size reasons. We must transmit it ourselves, and
   * force the upper-layers to conside it gone.
   */
  return NF_STOLEN;
}

/*
 * is_v4addr_local
 *
 * Perform a route lookup to determine if this address
 * belongs to us. See arp.c for comparable check.
 */
bool is_v4addr_local(struct iphdr *iph, struct sk_buff *packet_buf)
{
    struct flowi fl;
    struct rtable *rt;
    struct net_device *dev;

    /*
     * XXX (LJ): Non-Android kernels seem to pass an sk_buff with a NULL dev member
     *           Return false for now if that happens to avoid oops
     */
#ifdef NEW_KERNEL
    if(packet_buf->dev == NULL) {
          printk(KERN_INFO "packet_buf->dev is null pointer!");
          return 0;
    }
#endif

    memset(&fl, 0, sizeof(fl));
    fl.fl4_dst = iph->daddr;
    fl.fl4_tos = RTO_ONLINK;
    if (ip_route_output_key(dev_net(packet_buf->dev), &rt, &fl))
        return 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
    dev = rt->dst.dev;
#else
    dev = rt->u.dst.dev;
#endif
    ip_rt_put(rt);
    if (!dev)
        return 0;

    // If we got anything, it's local
    return 1;
}

unsigned int lisp_output4(unsigned int hooknum,
			  struct sk_buff *packet_buf,
			  const struct net_device *input_dev,
			  const struct net_device *output_dev,
			  int (*okfunc)(struct sk_buff*))
{
  struct iphdr *iph;
  struct udphdr *udh;
  lisp_map_cache_t *eid_entry;
  int retval;
  int locator_addr;
  unsigned char loc_index;
  lisp_addr_t miss_addr;

  /* 
   * Extract the ip header
   */
  iph = ip_hdr(packet_buf);
  
#ifdef DEBUG_PACKETS
  printk(KERN_INFO "   Output packet destined for %pI4 from %pI4, proto: %d\n", &(iph->daddr),
         &(iph->saddr), iph->protocol);
#endif

  /*
   * Check for local destination, punt if so.
   */
  if (is_v4addr_local(iph, packet_buf)) {
#ifdef DEBUG_PACKETS
      printk(KERN_INFO "       Packet is locally destined.\n");
#endif
      return NF_ACCEPT;
  }

  /*
   * Don't encapsulate LISP control messages
   */
  if (iph->protocol == IPPROTO_UDP) {
      skb_pull(packet_buf, sizeof(struct iphdr));
      skb_reset_transport_header(packet_buf);
      udh = udp_hdr(packet_buf);

      /*
       * If either of the udp ports are the control port or data, allow
       * to go out natively. This is a quick way around the
       * route filter which rewrites the EID as the source address.
       */
      if ( (ntohs(udh->dest) == LISP_CONTROL_PORT) ||
          (ntohs(udh->source) == LISP_CONTROL_PORT) ||
          (ntohs(udh->source) == LISP_ENCAP_PORT) ||
          (ntohs(udh->dest) == LISP_ENCAP_PORT) ) {

          // Undo the pull
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "      Packet looks like lisp control: dstprt %d, srcprt %d\n",
                 ntohs(udh->dest), ntohs(udh->source));
#endif
          skb_push(packet_buf, sizeof(struct iphdr));
          skb_reset_transport_header(packet_buf);
          return NF_ACCEPT;
      } else {
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "       Packet not lisp control: dstprt %d, srcprt %d\n", ntohs(udh->dest),
                 ntohs(udh->source));
#endif
      }
       // Undo the pull
      skb_push(packet_buf, sizeof(struct iphdr));
      skb_reset_transport_header(packet_buf);
    }

  /*
   * Sanity check the inner packet XXX
   */

  /*
   * Lookup the destination in the map-cache, this will
   * need to return the full entry in the future for all
   * the flags to be processed. TDB: Check for concurrency
   * issues with directly using the entry pointer here. May
   * need to lock it or make a copy (ick)
   */
  retval = lookup_eid_cache_v4(iph->daddr, &eid_entry);
  
  /*
   * Check status of returned entry XXX (requires extension
   * of above function).
   */
  if (retval == 0 || !eid_entry->count) {

    printk(KERN_INFO "        No EID mapping found, notifying lispd...\n");
    miss_addr.address.ip.s_addr = iph->daddr;
    send_cache_miss_notification(miss_addr, AF_INET);
    return NF_ACCEPT;  // What's the right thing to do here? XXX
  }

  /*
   * Mark that traffic has been received.
   */
  eid_entry->active_within_period = 1;

  /*
   * Hash to find the correct locator based on weight, priority, etc.
   */
  loc_index = eid_entry->locator_hash_table[output_hash_v4(iph->saddr, iph->daddr)];
  if (eid_entry->locator_list[loc_index]) {
      locator_addr = eid_entry->locator_list[loc_index]->locator.address.ip.s_addr;
  } else {
      printk(KERN_INFO "    Invalid locator list!\n");
      return NF_ACCEPT;
  }

  /* 
   * Prepend UDP, LISP, outer IP header
   */
  lisp_encap4(packet_buf, locator_addr, AF_INET);

  eid_entry->locator_list[loc_index]->data_packets_out++;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "       Using locator address: %pI4\n", &locator_addr);
#endif

  /* 
   * In all liklihood we've disposed of the orignal skb
   * for size reasons. We must transmit it ourselves, and
   * force the upper-layers to conside it gone.
   */
  return NF_STOLEN;
}
