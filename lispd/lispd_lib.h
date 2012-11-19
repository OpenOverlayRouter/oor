/*
 * lispd_lib.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Various library routines.
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
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#ifndef LISPD_LIB_H_
#define LISPD_LIB_H_

#include "lispd.h"


/*
 *      build_receive_sockets
 *
 *      Set up the receive sockets. Note that if you use a
 *      a random port, which is used as  the source port used
 *      in the inner UDP header of the encapsulated
 *      map-request. If proxy-reply on, you will receive map-replies
 *      destined to this port (i.e., the destination port). e.g.,
 *
 *      No. Time     Source         Destination     Protocol Info
 *      97  5.704114 128.223.156.23 128.223.156.117 LISP     Map-Reply
 *      ...
 *      Internet Protocol, Src: 128.223.156.23 (128.223.156.23), Dst: 128.223.156.117 (128.223.156.117)
 *      User Datagram Protocol, Src Port: lisp-control (4342), Dst Port: 48849 (48849)
 *      Locator/ID Separation Protocol
 *
 *      In this case, 48849 was the random source port I put in the
 *      inner UDP header source port in the encapsulated map-request
 *      which was sent to to the map-server at 128.223.156.23.
 *
 *      So we'll just use src port == dest port == 4342. Note that you
 *      need to setsockopt SO_REUSEADDR or you'll get bind: address in use.
 *
 */

int build_receive_sockets(void);


int send_raw_udp(struct sockaddr *dst, uint8_t *packet, int packet_len);


/*
 *      Assume if there's a colon in str that its an IPv6
 *      address. Otherwise its v4.
 */

int get_afi(char *str);

/*
 *      Copy a lisp_addr_t, converting it using convert
 *      if supplied
 */

int copy_lisp_addr_t(lisp_addr_t *a1, lisp_addr_t *a2, int convert);

/*
 *      Copy a lisp_addr_t to a memory location, htonl'ing it
 *      it convert != 0. Return the length or 0;
 */
int copy_addr(void *a1, lisp_addr_t *a2, int convert);

/*
 *      find a useable source address with AFI = afi
 */

/* TODO (LJ): To avoid memory leaks, the lisp_addr_t should be allocated
 *            by caller and a pointer passed as parameter. Update calls! */
lisp_addr_t *get_my_addr(char *if_name, int afi);

/*
 *      return GOOD if addr contain a  lisp_addr_t for host/FQDN or BAD if none
 */
int lispd_get_address(char *host, lisp_addr_t *addr, unsigned int *flags);

/*
 *  return lisp_addr_t for the interface, 0 if none
 */
lisp_addr_t *lispd_get_iface_address(char *ifacename, lisp_addr_t *addr, int afi);

void dump_database(patricia_tree_t *tree,int afi);

void dump_servers(lispd_addr_list_t *list, const char *list_name);

void dump_map_server(lispd_map_server_list_t *ms);

void dump_map_servers(void);


void dump_tree(int afi, patricia_tree_t *tree);

/*
 *  connect up the locator_chain and locator_chain_elt sorted by RLOC
 */
int add_locator_chain_elt(
    lispd_locator_chain_t       *locator_chain,
    lispd_locator_chain_elt_t   *locator_chain_elt);

void debug_installed_database_entry(lispd_db_entry_t *db_entry, lispd_locator_chain_t *locator_chain);

/*
 *      Map from Internet AFI -> LISP_AFI
 *
 *      Get the length while your at it
 */
uint16_t get_lisp_afi(int afi, int *len);

/*
 *      Map from Internet LISP AFI -> INET AFI
 */
int lisp2inetafi(uint16_t afi);

/*
 *      given afi, get the IP header length
 */

int get_ip_header_len(int afi);

/*
 *      given afi, get sockaddr len
 */
int get_sockaddr_len(int afi);

/*
 *      given afi, get addr len
 */

int get_addr_len(int afi);

/*
 *      given afi, get prefix len
 */
int get_prefix_len(int afi);

struct udphdr *build_ip_header(
        void                  *cur_ptr,
        lisp_addr_t           *my_addr,
        lisp_addr_t           *eid_prefix,
        int                   ip_len);


/*
 * Return lisp_addr_t in a char format;
 */

char *get_char_from_lisp_addr_t (lisp_addr_t addr);

/*
 * Fill lisp_addr with the address.
 * Return GOOD if no error has been found
 */

int get_lisp_addr_from_char (char *address, lisp_addr_t *lisp_addr);

/*
 * Compare two lisp_addr_t.
 * Returns:
 * 			-1: If they are from different afi
 * 			 0: Both address are the same
 * 			 1: Addr1 is bigger than addr2
 * 			 2: Addr2 is bigger than addr1
 */
int compare_lisp_addr_t (lisp_addr_t *addr1, lisp_addr_t *addr2);
/*
 * Parse address and fill lisp_addr and mask.
 * Return GOOD if no error has been found
 */

int get_lisp_addr_and_mask_from_char (char *address, lisp_addr_t *lisp_addr, int *mask);


/*
 *      API functions of datacache entries (updated acabello)
 */

/*
 * Build new datacache entry and insert timer into ordered list of timers
 */
int build_datacache_entry(
        lisp_addr_t  *dest,
        lisp_addr_t  *eid_prefix,
        uint8_t      eid_prefix_length,
        uint64_t     nonce,
        uint8_t      islocal,
        uint8_t      probe,
        uint8_t      smr_invoked,
        uint8_t      retries,
        uint16_t     timeout,
        uint8_t      encap);

/*
 * Timeout expired entries and trigger appropriate actions
 */
void expire_datacache();

/*
 *  Deletes a datacache entry
 */
void delete_datacache_entry(datacache_elt_t *elt);

/*
 * Check if address is included into another address
 */
int is_eid_included(
    datacache_elt_t* elt,
    int eid_prefix_mask_length,
    lisp_addr_t *eid);

/*
 * Search a datacache entry based on EID prefix and returns it in res_elt
 */
int search_datacache_entry_eid(lisp_addr_t* eid_prefix, datacache_elt_t **res_elt);


/*
 *  Auxiliary definitions
 */
uint16_t min_timeout(uint16_t a,uint16_t b);

/*
 *  select from among readfds, the largest of which
 *  is max_fd.
 */
int have_input(int max_fd,fd_set *readfds);

/*
 *  Process a LISP protocol message sitting on
 *  socket s with address family afi
 */
int process_lisp_msg(int s, int afi);

/*
 *  Retrieve a mesage from socket s
 */
int retrieve_lisp_msg(int s, uint8_t *packet, void *from, int afi);


int inaddr2sockaddr(lisp_addr_t *inaddr, struct sockaddr *sockaddr, uint16_t port);

int sockaddr2lisp(struct sockaddr *src, lisp_addr_t *dst);


#endif /*LISPD_LIB_H_*/

