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

#include "defs.h"






/*
 * Return TRUE if the address belongs to:
 *          IPv4: 169.254.0.0/16
 *          IPv6: fe80::/10
 */

int is_link_local_addr(lisp_addr_t *addr);


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


/*
 *      return GOOD if addr contain a  lisp_addr_t for host/FQDN or BAD if none
 */
int lispd_get_address(char *host, lisp_addr_t *addr);





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



/*
 *  select from among readfds, the largest of which
 *  is max_fd.
 */
int have_input(int max_fd,fd_set *readfds);


/*
 *  Retrieve a mesage from socket s
 */
int retrieve_lisp_msg(int s, uint8_t *packet, void *from, int afi);


int inaddr2sockaddr(lisp_addr_t *inaddr, struct sockaddr *sockaddr, uint16_t port);


inline void copy_lisp_addr_V4(lisp_addr_t *dest,
                              lisp_addr_t *orig);

inline void copy_lisp_addr_V6(lisp_addr_t *dest,
                              lisp_addr_t *orig);

void copy_lisp_addr(lisp_addr_t *dest,
                    lisp_addr_t *orig);

inline void memcopy_lisp_addr_V4(void *dest,
                                 lisp_addr_t *orig);

inline void memcopy_lisp_addr_V6(void *dest,
                                 lisp_addr_t *orig);

void memcopy_lisp_addr(void *dest,
                       lisp_addr_t *orig);

int extract_lisp_address(
        uint8_t         *ptr,
        lisp_addr_t     *addr);




#endif /*LISPD_LIB_H_*/

