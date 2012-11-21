/* 
 * lispd_map_register.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
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

#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_external.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_pkt_lib.h"
#include "lispd_local_db.h"
#include "patricia/patricia.h"




lispd_pkt_map_register_t *build_map_register_pkt(lispd_identifier_elt *identifier, int *mrp_len);
int send_map_register(lisp_addr_t *ms_address, lispd_pkt_map_register_t *mrp, int mrp_len);


/*
 *  map_server_register (tree)
 *
 */

timer *map_register_timer = NULL;

/*
 * Timer and arg parameters are not used but must be defined to be consistent
 * with timer call back function.
 */
int map_register(timer *t, void *arg)
{
    patricia_tree_t           *dbs[2];
    patricia_tree_t           *tree = NULL;
    lispd_map_server_list_t   *ms;
    lispd_pkt_map_register_t  *map_register_pkt; 
    patricia_node_t           *node;
    lispd_identifier_elt      *identifier_elt;
    int                       mrp_len = 0;
    int                       ctr = 0;
    uint64_t                  *nonce;
    uint32_t                  md_len;

    dbs[0] = get_local_db(AF_INET);
    dbs[1] = get_local_db(AF_INET6);

    if (!map_servers) {
        syslog(LOG_CRIT, "No Map Servers conifgured!");
        return(BAD);
    }

    for (ctr = 0 ; ctr < 2 ; ctr++) {
        tree = dbs[ctr];
        if (!tree)
            continue;
        PATRICIA_WALK(tree->head, node) {
            identifier_elt = ((lispd_identifier_elt *)(node->data));
            if (identifier_elt) {
                if ((map_register_pkt =
                        build_map_register_pkt(identifier_elt, &mrp_len)) == NULL) {
                    syslog(LOG_DAEMON, "Couldn't build map register packet");
                    return(BAD);
                }

                 //  for each map server, send a register, and if verify
                 //  send a map-request for our eid prefix

                ms = map_servers;

                while (ms) {

                    /*
                     * Fill in proxy_reply and compute the HMAC with SHA-1.
                     */

                    map_register_pkt->proxy_reply = ms->proxy_reply;
                    memset(map_register_pkt->auth_data,0,LISP_SHA1_AUTH_DATA_LEN);   /* make sure */

                    if (!HMAC((const EVP_MD *) EVP_sha1(),
                            (const void *) ms->key,
                            strlen(ms->key),
                            (uchar *) map_register_pkt,
                            mrp_len,
                            (uchar *) map_register_pkt->auth_data,
                            &md_len)) {
                        syslog(LOG_DAEMON, "HMAC failed for map-register");
                        return(0);
                    }

                    /* Send the map register */

                    if (!send_map_register(ms->address,map_register_pkt,mrp_len)) {
                        syslog(LOG_DAEMON, "Couldn't send map-register for %s",
                                get_char_from_lisp_addr_t(identifier_elt->eid_prefix));
                    } else if (ms->verify) {
                        if (!build_and_send_map_request_msg(&(identifier_elt->eid_prefix),
                                identifier_elt->eid_prefix_length,
                                ms->address,1,1,0,0,nonce))
                            syslog(LOG_DAEMON,"map_register:couldn't build/send map_request");
                    }
                    ms = ms->next;
                }

                free(map_register_pkt);
            }
        } PATRICIA_WALK_END;
    }

    /*
     * Configure timer to send the next map register.
     */
    if (!map_register_timer) {
        map_register_timer = create_timer("Map register");
    }
    start_timer(map_register_timer, MAP_REGISTER_INTERVAL, map_register, NULL);

    return(GOOD);
}


/*
 *  build_map_register_pkt
 *
 *  Build the map-register
 *
 */

lispd_pkt_map_register_t *build_map_register_pkt(lispd_identifier_elt *identifier, int *mrp_len)
{
    lispd_pkt_map_register_t *mrp;
    lispd_pkt_mapping_record_t *mr;

    *mrp_len = sizeof(lispd_pkt_map_register_t) +
              pkt_get_mapping_record_length(identifier);

    if ((mrp = malloc(*mrp_len)) == NULL) {
        syslog(LOG_ERR, "build_map_register_pkt: malloc: %s", strerror(errno));
        return(NULL);
    }
    memset(mrp, 0, *mrp_len);

    /*
     *  build the packet
     *
     *  Fill in mrp->proxy_reply and compute the HMAC in 
     *  send_map_register()
     *
     */

    mrp->lisp_type        = LISP_MAP_REGISTER;
    mrp->map_notify       = 1;              /* TODO conf item */
    mrp->nonce            = 0;
    mrp->record_count     = 1;				/* XXX Just supported one record per map register */
    mrp->key_id           = htons(1);       /* XXX not sure */
    mrp->auth_data_len    = htons(LISP_SHA1_AUTH_DATA_LEN);


    /* skip over the fixed part,  assume one record (mr) */

    mr = (lispd_pkt_mapping_record_t *) CO(mrp, sizeof(lispd_pkt_map_register_t));

    if (pkt_fill_mapping_record(mr, identifier, NULL)) {
        return(mrp);
    } else {
        free(mrp);
        return(NULL);
    }
}


/*
 *  send_map_register
 */

int send_map_register(lisp_addr_t *ms_address, lispd_pkt_map_register_t *mrp, int mrp_len)
{
    int result;
    if (ms_address->afi == AF_INET)
        result = send_ctrl_ipv4_packet(ms_address,0,LISP_CONTROL_PORT,(void *)mrp,mrp_len);
    else
        result = send_ctrl_ipv6_packet(ms_address,0,LISP_CONTROL_PORT,(void *)mrp,mrp_len);

    free (mrp);
    return result;
}


#ifdef LISPMOBMH
/* Machinery to handle rate limited smrs when interfaces go up and down
 * in dynamic multihomed scenarios.
 */

void start_smr_timeout(void)
{
    struct itimerspec interval;

    if (timerfd_gettime(smr_timer_fd, &interval) == -1)
            syslog(LOG_INFO, "timerfd_gettime: %s", strerror(errno));

    if (interval.it_value.tv_sec == 0){
    	/*Timer is disarmed. Start it*/

    	interval.it_interval.tv_sec  = 0;
    	interval.it_interval.tv_nsec = 0;
    	interval.it_value.tv_sec     = DEFAULT_SMR_TIMEOUT;
    	interval.it_value.tv_nsec    = 0;

    	syslog(LOG_INFO, "Start timer to send an smr in %d seconds",
    			DEFAULT_SMR_TIMEOUT);

    	if (timerfd_settime(smr_timer_fd, 0, &interval, NULL) == -1)
    		syslog(LOG_INFO, "timerfd_settime: %s", strerror(errno));
    }
}


void stop_smr_timeout(void)
{
    struct itimerspec interval;

    interval.it_interval.tv_sec  = 0;
    interval.it_interval.tv_nsec = 0;
    interval.it_value.tv_sec     = 0;
    interval.it_value.tv_nsec    = 0;

    syslog(LOG_INFO, "Clear timer to send smrs");

    if (timerfd_settime(smr_timer_fd, 0, &interval, NULL) == -1)
        syslog(LOG_INFO, "timerfd_settime: %s", strerror(errno));
}


inline void smr_on_timeout(void)
{
    ssize_t s;
    uint64_t num_exp;

    if((s = read(smr_timer_fd, &num_exp, sizeof(num_exp))) != sizeof(num_exp))
        syslog(LOG_INFO, "read error (smr_on_timeout): %s", strerror(errno));
    /*
     * Trigger SMR to PITRs and the MN's peers
     */
    init_smr();
}
#endif





/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
