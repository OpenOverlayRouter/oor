/*
 * lispd_nat_lib.c
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
 *    Alberto Rodríguez Natal <arnatal@ac.upc.edu>
 *
 */


#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

//#define _BSD_SOURCE             // needed?
#include <endian.h>

#include "linux/netlink.h"
#include "lispd_external.h"

#include "lispd_nat_lib.h"
#include "cksum.h"
#include "lispd_afi.h"
#include "lispd_info_request.h"
#include "lispd_lib.h"
#include "patricia/patricia.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_sockets.h"
/*
 * 
 * void parameter function just to avoid to write the default values of
 * build_and_send_info_request function
 */

void nat_info_request(void)
{

    lispd_mapping_elt *mapping_elt;
    lisp_addr_t eid_address;
    uint8_t eid_prefix_length;
    patricia_node_t *node;


    /*arnatal XXX TODO There should be some generic function to get the db EID */
    
    PATRICIA_WALK(get_local_db(AF_INET)->head, node) {

        mapping_elt = ((lispd_mapping_elt *) (node->data));
        eid_prefix_length = mapping_elt->eid_prefix_length;
        eid_address = mapping_elt->eid_prefix;
        eid_address.afi = mapping_elt->eid_prefix.afi;

    } PATRICIA_WALK_END;

    lispd_log_msg(LISP_LOG_DEBUG_2, "Sending Info-Request packet");

    build_and_send_info_request(build_nonce((unsigned int) time(NULL)),
                                map_servers->key_type,
                                map_servers->key,
                                DEFAULT_INFO_REQUEST_TIMEOUT,
                                eid_prefix_length,
                                &eid_address,
                                default_ctrl_iface_v4->ipv4_address,
                                LISP_CONTROL_PORT,
                                map_servers->address,
                                LISP_CONTROL_PORT);


}

/*
 * void parameter function just to avoid to write the default values of
 * build_and_send_ecm_map_register function
 */

/*
void ecm_map_register(void)
{

    lispd_locator_chain_t *locator_chain;
    patricia_node_t *node;

    lispd_db_entry_t db_entry;

    PATRICIA_WALK(AF4_database->head, node) {
        locator_chain = ((lispd_locator_chain_t *) (node->data));
        // Substitute the MN RLOC for the RTR RLOC in the Map Register
        db_entry = *(locator_chain->head->db_entry);
        db_entry.locator = rtr;
        locator_chain->head->db_entry = &db_entry;

    } PATRICIA_WALK_END;

#ifdef DEBUG
    lispd_log_msg(LISP_LOG_DEBUG_2, "Sending ECM Map-Register packet");
#endif

    build_and_send_ecm_map_register(locator_chain,
                                    map_servers->proxy_reply,
                                    &(ctrl_iface->AF4_locators->head->db_entry->locator),
                                    map_servers->address,
                                    LISP_CONTROL_PORT,
                                    LISP_CONTROL_PORT,
                                    &(ctrl_iface->AF4_locators->head->db_entry->locator),
                                    &(rtr),
                                    LISP_DATA_PORT,
                                    LISP_CONTROL_PORT,
                                    map_servers->key_type,
                                    map_servers->key);

}
*/

/* Returns the current locator of the MN */

lisp_addr_t *get_current_locator(void)
{
    return (default_out_iface_v4->ipv4_address);
}

/*
 * Returns the length of the auth data field based on the ket_id value
 */

int get_auth_data_len(int key_id)

{
    switch (key_id) {
    default:
        return (LISP_SHA1_AUTH_DATA_LEN);   //TODO support more auth algorithms
    }
}

/*
 * Compute and fill auth data field
 *
 * TODO Support more than SHA1
 */

int complete_auth_fields(int key_id,
                         uint16_t * key_id_pos,
                         char *key,
                         void *packet,
                         int pckt_len,
                         void *auth_data_pos)

{
    int auth_data_len;
    int err;

    auth_data_len = get_auth_data_len(key_id);

    *key_id_pos = htons(key_id);

    switch (key_id) {
    default:                   /* TODO support more auth algorithms */
        err =
            compute_sha1_hmac(key, packet, pckt_len, auth_data_pos,
                              auth_data_len);
        return (err);

    }


}

/*
 * Computes the HMAC using SHA1 of packet with length packt_len
 * using key and puting the output in auth_data
 *
 */
int compute_sha1_hmac(char *key,
                      void *packet,
                      int pckt_len,
                      void *auth_data_pos,
                      int auth_data_len)

{
    unsigned int md_len;    /* Length of the HMAC output.  */

    memset(auth_data_pos, 0, auth_data_len);    /* make sure */

    if (!HMAC((const EVP_MD *) EVP_sha1(),
              (const void *) key,
              strlen(key),
              (uchar *) packet,
              pckt_len, 
              (uchar *) auth_data_pos, 
              &md_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "HMAC failed");

        return (BAD);
    }
    return (GOOD);
}


int check_sha1_hmac(char *key,
                    void *packet,
                    int pckt_len,
                    void *auth_data_pos,
                    int auth_data_len)
{
    unsigned int md_len;    /* Length of the HMAC output.  */
   
    uint8_t* auth_data_copy;

    auth_data_copy = (uint8_t *) malloc(auth_data_len*sizeof(uint8_t));

    /* Copy the data to another location and put 0's on the auth data field of the packet */
    memcpy(auth_data_copy,auth_data_pos,auth_data_len);	
    memset(auth_data_pos,0,auth_data_len);
	
    if (!HMAC((const EVP_MD *) EVP_sha1(),
              (const void *) key,
              strlen(key),
              (uchar *) packet,
              pckt_len,
              (uchar *) auth_data_pos,
              &md_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "SHA1 HMAC failed");
        return(BAD);
    }
    if ((strncmp((char *)auth_data_pos, (char *)auth_data_copy, (size_t)auth_data_len)) == 0)
        return(GOOD);
    else
        return(BAD);
}
 
int check_auth_field(int key_id,
                     char *key,
                     void *packet,
                     int pckt_len,
                     void *auth_data_pos,
                     int auth_data_len)
                     
{
	
    switch (key_id){
        default:      /* Only sha1 hmac supported at the moment */
            return(check_sha1_hmac(key,
                                   packet,
                                   pckt_len,
                                   auth_data_pos,
                                   auth_data_len));

    }


}

/*
 * Extracts a lisp_addr_t from a memory position (if stored in Network Byte Order)
 */

lisp_addr_t extract_lisp_address(void *ptr)

{
    lisp_addr_t lisp_addr;

    lisp_addr.afi = lisp2inetafi(ntohs(*(uint16_t *) ptr));     /* 2 Byte AFI field */

    ptr = CO(ptr, sizeof(uint16_t));

    memcpy(&(lisp_addr.address), ptr, get_addr_len(lisp_addr.afi));

    return (lisp_addr);
}

/*
 * Loop to free all the members of a lispd_addr_list_t
 */

void free_lisp_addr_list(lispd_addr_list_t * list)

{

    lispd_addr_list_t *list_pre;

    while (list->next != NULL) {

        list_pre = list;

        list = list->next;

        free(list_pre->address);
        free(list_pre);
    }
}

/*
 * Generates an IP header and an UDP header
 * and copies the original packet at the end
 */

static uint8_t *build_ip_udp_encap_pkt(orig_pkt,orig_pkt_len,addr_from,addr_dest,
                                port_from,port_dest,encap_pkt_len)

uint8_t * orig_pkt;
unsigned int orig_pkt_len;
lisp_addr_t * addr_from;
lisp_addr_t * addr_dest;
unsigned int port_from;
unsigned int port_dest;
unsigned int *encap_pkt_len;

{

    uint8_t *cur_ptr;
    void *pkt_ptr;

    void *iph_ptr;
    struct udphdr *udph_ptr;

    unsigned int epkt_len;
    unsigned int ip_hdr_len;
    unsigned int udp_hdr_len;

    unsigned int ip_payload_len;
    unsigned int udp_hdr_and_payload_len;

    uint16_t udpsum = 0;


    if (addr_from->afi != addr_dest->afi) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "data_encap_pkt: Different AFI addresses");
        return (NULL);
    }

    if ((addr_from->afi != AF_INET) && (addr_from->afi != AF_INET6)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "data_encap_pkt: Unknown AFI %d",
               addr_from->afi);
        return (NULL);
    }

    /* Headers lengths */

    ip_hdr_len = get_ip_header_len(addr_from->afi);

    udp_hdr_len = sizeof(struct udphdr);


    /* Assign memory for the original packet plus the new headers */

    epkt_len = ip_hdr_len + udp_hdr_len + orig_pkt_len;

    if ((pkt_ptr = (void *) malloc(epkt_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "malloc(packet_len): %s", strerror(errno));
        return (NULL);
    }

    /* Make sure it's clean */

    memset(pkt_ptr, 0, epkt_len);


    /* IP header */

    iph_ptr = pkt_ptr;

    ip_payload_len = ip_hdr_len + udp_hdr_len + orig_pkt_len;

    udph_ptr = build_ip_header(iph_ptr,
                               addr_from,
                               addr_dest,
                               ip_payload_len);

    /* UDP header */


    udp_hdr_and_payload_len = udp_hdr_len + orig_pkt_len;

#ifdef BSD
    udph_ptr->uh_sport = htons(port_from);
    udph_ptr->uh_dport = htons(port_dest);
    udph_ptr->uh_ulen = htons(udp_payload_len);
    udph_ptr->uh_sum = 0;
#else
    udph_ptr->source = htons(port_from);
    udph_ptr->dest = htons(port_dest);
    udph_ptr->len = htons(udp_hdr_and_payload_len);
    udph_ptr->check = 0;
#endif

    /* Copy original packet after the headers */

    cur_ptr = (void *) CO(udph_ptr, udp_hdr_len);

    memcpy(cur_ptr, orig_pkt, orig_pkt_len);


    /*
     * Now compute the headers checksums
     */


    ((struct ip *) iph_ptr)->ip_sum = ip_checksum(iph_ptr, ip_hdr_len);

    if ((udpsum =
         udp_checksum(udph_ptr,
                      udp_hdr_and_payload_len,
                      iph_ptr,
                      addr_from->afi)) == -1) {
        return (NULL);
    }
    udpsum(udph_ptr) = udpsum;


    /* Return the encapsulated packet and its length */

    *encap_pkt_len = epkt_len;

    return (pkt_ptr);

}

/*
 * Generates a LISP data header and copies the original packet at the end
 *
 */

static uint8_t *build_data_encap_pkt(orig_pkt,orig_pkt_len,addr_from,addr_dest,
                              port_from,port_dest,data_encap_pkt_len)

uint8_t * orig_pkt;
unsigned int orig_pkt_len;
lisp_addr_t * addr_from;
lisp_addr_t * addr_dest;
unsigned int port_from;
unsigned int port_dest;
unsigned int *data_encap_pkt_len;

{

    uint8_t *encap_pkt_ptr;
    uint8_t *cur_ptr;
    void *d_encap_pkt_ptr;

    lisp_data_hdr_t *lisp_hdr_ptr;

    unsigned int encap_pkt_len;
    unsigned int d_encap_pkt_len;
    unsigned int lisp_hdr_len;


    encap_pkt_ptr = build_ip_udp_encap_pkt(orig_pkt,
                                           orig_pkt_len,
                                           addr_from,
                                           addr_dest,
                                           port_from,
                                           port_dest,
                                           &encap_pkt_len);


    /* Header length */

    lisp_hdr_len = sizeof(lisp_data_hdr_t);

    /* Assign memory for the original packet plus the new header */

    d_encap_pkt_len = lisp_hdr_len + encap_pkt_len;

    if ((d_encap_pkt_ptr = (void *) malloc(d_encap_pkt_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "malloc(packet_len): %s", strerror(errno));
        free(encap_pkt_ptr);
        return (NULL);
    }

    memset(d_encap_pkt_ptr, 0, d_encap_pkt_len);


    /* LISP data header */

    lisp_hdr_ptr = (lisp_data_hdr_t *) d_encap_pkt_ptr;

    lisp_hdr_ptr->instance_id = 1;

    lisp_hdr_ptr->lsb_bits = htonl(0xFFFFFF00); /* 4294967040 = 0xFFFFFF00 */


    /* Copy original packet after the LISP data header */

    cur_ptr = (void *) CO(lisp_hdr_ptr, lisp_hdr_len);

    memcpy(cur_ptr, encap_pkt_ptr, encap_pkt_len);


    /* Return the encapsulated packet and its length */

    *data_encap_pkt_len = d_encap_pkt_len;

    return (d_encap_pkt_ptr);

}

/* TODO merge control and data encap. Avoid duplicate code */

static uint8_t *build_control_encap_pkt(orig_pkt,orig_pkt_len,addr_from,addr_dest,
                                 port_from,port_dest,control_encap_pkt_len)

uint8_t * orig_pkt;
unsigned int orig_pkt_len;
lisp_addr_t * addr_from;
lisp_addr_t * addr_dest;
unsigned int port_from;
unsigned int port_dest;
unsigned int *control_encap_pkt_len;

{

    uint8_t *encap_pkt_ptr;
    uint8_t *cur_ptr;
    void *c_encap_pkt_ptr;

    lisp_encap_control_hdr_t *lisp_hdr_ptr;

    unsigned int encap_pkt_len;
    unsigned int c_encap_pkt_len;
    unsigned int lisp_hdr_len;


    encap_pkt_ptr = build_ip_udp_encap_pkt(orig_pkt,
                                           orig_pkt_len,
                                           addr_from,
                                           addr_dest,
                                           port_from,
                                           port_dest, &encap_pkt_len);


    /* Header length */

    lisp_hdr_len = sizeof(lisp_encap_control_hdr_t);

    /* Assign memory for the original packet plus the new header */

    c_encap_pkt_len = lisp_hdr_len + encap_pkt_len;

    if ((c_encap_pkt_ptr = (void *) malloc(c_encap_pkt_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "malloc(packet_len): %s", strerror(errno));
        free(encap_pkt_ptr);
        return (NULL);
    }

    memset(c_encap_pkt_ptr, 0, c_encap_pkt_len);

    /* LISP encap control header */

    lisp_hdr_ptr = (lisp_encap_control_hdr_t *) c_encap_pkt_ptr;

    lisp_hdr_ptr->type = 8;

    /* Copy original packet after the LISP control header */

    cur_ptr = (void *) CO(lisp_hdr_ptr, lisp_hdr_len);

    memcpy(cur_ptr, encap_pkt_ptr, encap_pkt_len);

    /* Return the encapsulated packet and its length */

    *control_encap_pkt_len = c_encap_pkt_len;

    return (c_encap_pkt_ptr);

}



int build_and_send_ecm_map_register(lispd_mapping_elt *mapping_elt,
                                    int proxy_reply,
                                    lisp_addr_t *inner_addr_from,
                                    lisp_addr_t *inner_addr_dest,
                                    unsigned int inner_port_from,
                                    unsigned int inner_port_dest,
                                    lisp_addr_t *outer_addr_from,
                                    lisp_addr_t *outer_addr_dest,
                                    unsigned int outer_port_from,
                                    unsigned int outer_port_dest,
                                    int key_id,
                                    char *key)

{

    lispd_pkt_map_register_t *map_register_pkt;
    lispd_pkt_map_register_t *map_register_pkt_tmp;
    uint8_t *ecm_map_register;
    lisp_addr_t *orig_rloc;

    int map_register_pkt_len;
    int ecm_map_register_len;
    
    /* Quick hack to put the RTR locator instead of ours in the ECM Map Register */

    orig_rloc = mapping_elt->head_v4_locators_list->locator->locator_addr; /* Switch RLOCs */
    mapping_elt->head_v4_locators_list->locator->locator_addr = &natt_rtr;
    
    map_register_pkt = (lispd_pkt_map_register_t *)build_map_register_pkt(mapping_elt,&map_register_pkt_len);

    mapping_elt->head_v4_locators_list->locator->locator_addr = orig_rloc; /* Undo switch */
    
    
    /* Map Server proxy reply */
    map_register_pkt->proxy_reply = 1; /* We have to let the Map Server to proxy reply.
                                          If not, we need to keep open a state in NAT via Info-Requests */

    /* R bit always 1 for Map Registers sent to the RTR */
    map_register_pkt->rbit = 1;

    /* xTR-ID must be set if RTR bit is 1 */
    map_register_pkt->ibit = 1;



    map_register_pkt->nonce = htobe64(1);

    
    map_register_pkt_tmp = map_register_pkt;
    
    map_register_pkt = (lispd_pkt_map_register_t *)malloc(map_register_pkt_len + 16 + 8); /* xTR-ID + site-ID */

    memset(map_register_pkt, 0,map_register_pkt_len + 16 + 8);

    memcpy(map_register_pkt,map_register_pkt_tmp,map_register_pkt_len);

//     memset(map_register_pkt + map_register_pkt_len + 15, 0x01,1);
//     memset(map_register_pkt + map_register_pkt_len + 16 + 7, 0x01,1);

    char *aux; // XXX TODO quick hardcoded xtr-ID and site-ID, TO BE FIXED
    
    aux = (char *)CO(map_register_pkt,map_register_pkt_len+15);
    *aux = 1;

    aux = (char *) CO(aux,8);
    *aux = 1;
    
    map_register_pkt_len = map_register_pkt_len + 16 + 8;



    
    
    complete_auth_fields(key_id,
                         &(map_register_pkt->key_id),
                         key,
                         (void *) (map_register_pkt),
                         map_register_pkt_len,
                         &(map_register_pkt->auth_data));

    ecm_map_register = build_control_encap_pkt((uint8_t *) map_register_pkt,
                                               map_register_pkt_len,
                                               inner_addr_from,
                                               inner_addr_dest,
                                               inner_port_from,
                                               inner_port_dest,
                                               &ecm_map_register_len);
    free(map_register_pkt);

    if (ecm_map_register == NULL) {
        return (BAD);
    }


    if (BAD == send_udp_ipv4_packet(outer_addr_from,
                                    outer_addr_dest,
                                    outer_port_from,
                                    outer_port_dest,
                                    ecm_map_register,
                                    ecm_map_register_len)){
                                    
        free(ecm_map_register);
        return (BAD);
    }


    free(ecm_map_register);

    return (GOOD);
}

/* Policy to select the best RTR from the RTR list retrived from the Info Reply */

lisp_addr_t *select_best_rtr_from_rtr_list(lispd_addr_list_t *rtr_rloc_list)

{
    /* No policy at the moment. Just use the first one. */
    return (rtr_rloc_list->address);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
