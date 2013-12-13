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
#include "lispd_locator.h"


/**
 * Add an address (lisp_addr_t *) into a list of addresses (lispd_addr_list_t **)
 * @param addr Pointer to the address to be added into the list
 * @param list Pointer to the pointer of the first element of the list where the address should be added
 * @return GOOD if finish correctly or an error code otherwise
 */
int add_lisp_addr_to_list(
        lisp_addr_t         *addr,
        lispd_addr_list_t   **list );

/**
 *  Converts the hostname into IPs which are added to a list of lisp_addr_t
 *  @param addr_str String conating fqdn address or de IP address
 *  @param preferred_afi Indicates the afi of the IPs to be added in the list
 *  @return List of addresses (lispd_addr_list_t *)
 */
lispd_addr_list_t *lispd_get_address(
        char        *addr_str,
        const int   preferred_afi);


int copy_addr_from_sockaddr( struct sockaddr   *addr, lisp_addr_t    *);


/*
 *      Assume if there's a colon in str that its an IPv6
 *      address. Otherwise its v4.
 */

int get_afi(char *str);


/*
 * Return TRUE if the address belongs to:
 *          IPv4: 169.254.0.0/16
 *          IPv6: fe80::/10
 */

int is_link_local_addr (lisp_addr_t addr);


/*
 *      Copy a lisp_addr_t to a memory location, htonl'ing it
 *      it convert != 0. Return the length or 0;
 */
int copy_addr(void *a1, lisp_addr_t *a2, int convert);

/*
 *  Fill the parameter addr with the lisp_addr_t of the interface with afi.
 *  Return BAD if no address is present in the interface.
 */
int lispd_get_iface_address(char *ifacename, lisp_addr_t *addr, int afi);


void dump_servers(lispd_addr_list_t *list, const char *list_name, int log_level);

void dump_proxy_etrs(int log_level);

void dump_map_servers(int log_level);


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
 *      Map from Internet INET AFI -> LISP AFI
 */

int inet2lispafi(int afi);

/*
 *      given afi, get the IP header length
 */

int get_ip_header_len(int afi);


/*
 *      given afi, get addr len
 */

int get_addr_len(int afi);

/*
 *      given afi, get prefix len
 */
int get_prefix_len(int afi);

/*
 * Return the first Map Resolver with the correct AFI
 */

lisp_addr_t *get_map_resolver();

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
 *  select from among readfds, the largest of which
 *  is max_fd.
 */
int have_input(int max_fd,fd_set *readfds);

/*
 *  Process a LISP protocol message sitting on
 *  socket s with address family afi
 */
int process_lisp_ctr_msg(int sock, int afi);

/*
 *  Retrieve a mesage from socket s
 */
int retrieve_lisp_msg(int s, uint8_t *packet, void *from, int afi);


int inaddr2sockaddr(lisp_addr_t *inaddr, struct sockaddr *sockaddr, uint16_t port);


inline void copy_lisp_addr_V4(lisp_addr_t *dest,
                              lisp_addr_t *orig);

inline void copy_lisp_addr_V6(lisp_addr_t *dest,
                              lisp_addr_t *orig);

/**
 * Copy address from orig to dest. The memory for dest must be allocated outside this function
 * @param dest Destination of the copied address
 * @return orig Address to be copied
 */
void copy_lisp_addr(
        lisp_addr_t *dest,
        lisp_addr_t *orig);

/**
 * Copy address into a new generated lisp_addr_t structure
 * @param addr Address to be copied
 * @return New allocated address
 */
lisp_addr_t *clone_lisp_addr(lisp_addr_t *addr);

inline void memcopy_lisp_addr_V4(void *dest,
                                 lisp_addr_t *orig);

inline void memcopy_lisp_addr_V6(void *dest,
                                 lisp_addr_t *orig);

void memcopy_lisp_addr(void *dest,
                       lisp_addr_t *orig);

int extract_lisp_address(
        uint8_t         *ptr,
        lisp_addr_t     *addr);

void free_lisp_addr_list(lispd_addr_list_t * list);

int convert_hex_string_to_bytes(
        char        *hex,
        uint8_t     *bytes,
        int         bytes_len);

int is_prefix_b_part_of_a (
        lisp_addr_t a_prefix,
        int a_prefix_length,
        lisp_addr_t b_prefix,
        int b_prefix_length);

lisp_addr_t get_network_address(
        lisp_addr_t address,
        int prefix_length);


#endif /*LISPD_LIB_H_*/

