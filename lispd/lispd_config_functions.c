/*
 * lispd_config_functions.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *    Alberto López     <alopez@ac.upc.edu>
 *
 */

#include <netdb.h>

#include "lispd_config_functions.h"
#include "lmlog.h"

/***************************** FUNCTIONS DECLARATION *************************/

/********************************** FUNCTIONS ********************************/

void
validate_rloc_probing_parameters(
        int *interval,
        int *retries,
        int *retries_int)
{

    if (*interval < 0) {
        *interval = 0;
    }

    if (*interval > 0) {
        LMLOG(DBG_1, "RLOC Probing Interval: %d", *interval);
    } else {
        LMLOG(DBG_1, "RLOC Probing disabled");
    }

    if (*interval != 0) {
        if (*retries > LISPD_MAX_RETRANSMITS) {
            *retries = LISPD_MAX_RETRANSMITS;
            LMLOG(LWRN, "RLOC Probing retries should be between 0 and %d. "
                    "Using %d retries", LISPD_MAX_RETRANSMITS,
                    LISPD_MAX_RETRANSMITS);
        } else if (*retries < 0) {
            *retries = 0;
            LMLOG(LWRN, "RLOC Probing retries should be between 0 and %d. "
                    "Using 0 retries", LISPD_MAX_RETRANSMITS);
        }

        if (*retries > 0) {
            if (*retries_int < LISPD_MIN_RETRANSMIT_INTERVAL) {
                *retries_int = LISPD_MIN_RETRANSMIT_INTERVAL;
                LMLOG(LWRN, "RLOC Probing interval retries should be between "
                        "%d and RLOC Probing interval. Using %d seconds",
                        LISPD_MIN_RETRANSMIT_INTERVAL,
                        LISPD_MIN_RETRANSMIT_INTERVAL);
            } else if (*retries_int > *interval) {
                *retries_int = *interval;
                LMLOG(LWRN, "RLOC Probing interval retries should be between "
                        "%d and RLOC Probing interval. Using %d seconds",
                         LISPD_MIN_RETRANSMIT_INTERVAL, *interval);
            }
        }
    }
}

int
validate_priority_weight(int p, int w)
{
    /* Check the parameters */
    if (p < (MAX_PRIORITY - 1)|| p > UNUSED_RLOC_PRIORITY) {
        LMLOG(LERR, "Configuration file: Priority %d out of range [%d..%d]",
                p, MIN_PRIORITY, MAX_PRIORITY);
        return (BAD);
    }

    if (w > MAX_WEIGHT || w < MIN_WEIGHT) {
        LMLOG(LERR, "Configuration file: Weight %d out of range [%d..%d]",
                p, MIN_WEIGHT, MAX_WEIGHT);
        return (BAD);
    }
    return (GOOD);
}

/*
 *  add a map-resolver to the list
 */

int
add_server(char *server, lisp_addr_list_t **list)
{

    lisp_addr_t *addr;
    lisp_addr_list_t *list_elt;

    addr = lisp_addr_new();
    if (lisp_addr_ip_from_char(server, addr) != GOOD) {
        lisp_addr_del(addr);
        return(BAD);
    }


    /* Check that the afi of the map server matches with the default rloc afi
     * (if it's defined). */
    if (default_rloc_afi != -1 && default_rloc_afi != lisp_addr_ip_afi(addr)) {
        LMLOG(LWRN, "The server %s will not be added due to the selected "
                "default rloc afi", server);
        lisp_addr_del(addr);
        return (BAD);
    }

    list_elt = xzalloc(sizeof(lisp_addr_list_t));
    list_elt->address = addr;

    /* hook this one to the front of the list  */
    if (*list) {
        list_elt->next = *list;
        *list = list_elt;
    } else {
        *list = list_elt;
    }

    return(GOOD);
}


int
add_map_server(lisp_xtr_t *xtr, char *map_server, int key_type,
        char *key, uint8_t proxy_reply)
{
    lisp_addr_t *addr;
    map_server_list_t *list_elt;
    struct hostent *hptr;

    if (map_server == NULL || key_type == 0 || key == NULL){
        LMLOG(LERR, "Configuraton file: Wrong Map Server configuration. "
                "Check configuration file");
        exit_cleanup();
    }

    if (((hptr = gethostbyname2(map_server, AF_INET)) == NULL) && ((hptr =
            gethostbyname2(map_server, AF_INET6)) == NULL)) {
        LMLOG(LWRN, "can gethostbyname2 for map_server (%s)", map_server);
        return (BAD);
    }

    addr = lisp_addr_new_afi(LM_AFI_IP);
    lisp_addr_ip_init(addr, *(hptr->h_addr_list), hptr->h_addrtype);

    /* Check that the afi of the map server matches with the default rloc afi
     * (if it's defined). */
    if (default_rloc_afi != -1 && default_rloc_afi != addr->afi){
        LMLOG(LWRN, "The map server %s will not be added due to the selected "
                "default rloc afi", map_server);
        lisp_addr_del(addr);
        return(BAD);
    }

    list_elt = xzalloc(sizeof(map_server_list_t));

    list_elt->address     = addr;
    list_elt->key_type    = key_type;
    list_elt->key         = strdup(key);
    list_elt->proxy_reply = proxy_reply;

    /* hook this one to the front of the list */

    if (xtr->map_servers) {
        list_elt->next = xtr->map_servers;
        xtr->map_servers = list_elt;
    } else {
        xtr->map_servers = list_elt;
    }

    return(GOOD);
}


int
add_proxy_etr_entry(
        lisp_xtr_t *    xtr,
        char *          address,
        int             priority,
        int             weight)
{
    lisp_addr_t aux_addr;
    lisp_addr_t rloc;
    locator_t *locator = NULL;
    int ret;

    if (address == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for PETR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    /* Check that the afi of the map server matches with the default rloc afi
     * (if it's defined). */
    if (default_rloc_afi != -1
        && default_rloc_afi != ip_afi_from_char(address)) {
        LMLOG(LWRN, "The PETR %s will not be added due to the selected "
                "default rloc afi", address);
        return(BAD);
    }

    /* Create the proxy-etrs map cache structure if it doesn't exist */
    if (xtr->petrs == NULL) {
        xtr->petrs = mcache_entry_new();
        lisp_addr_ip_from_char("0.0.0.0", &aux_addr);
        mcache_entry_init_static(xtr->petrs, mapping_init_remote(&aux_addr));
    }

    if (lisp_addr_ip_from_char(address, &rloc) == BAD) {
        LMLOG(LERR, "Error parsing RLOC address. Ignoring proxy-ETR %s",
                address);
        return (BAD);
    }

    /* Create locator representing the proxy-etr and add it to the mapping */
    locator = locator_init_remote_full(&rloc, UP, priority, weight, 255, 0);

    if (locator) {
        ret =  mapping_add_locator(xtr->petrs->mapping, locator);
    } else {
        ret = BAD;
    }

    return(ret);
}

int
add_database_mapping(
        lisp_xtr_t  *xtr,
        char        *eid_str,
        int         iid,
        char        *iface_name,
        int         p4,
        int         w4,
        int         p6,
        int         w6)
{
    mapping_t       *m          = NULL;
    iface_t         *interface  = NULL;
    iface_locators  *if_loct    = NULL;
    lisp_addr_t     eid;



    /* XXX: Don't use IIDs with this method */

    /* ADD INTERFACE */
    if (iface_name == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for database"
                " mapping. Ignoring mapping");
        return (BAD);
    }

    /* Check if the interface already exists. If not, add it*/
    if ((interface = get_interface(iface_name)) == NULL) {
        interface = add_interface(iface_name);
        if (!interface) {
            LMLOG(LWRN, "add_database_mapping: Can't create interface %s",
                    iface_name);
            return(BAD);
        }
    }
    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    if (if_loct == NULL){
        if_loct = iface_locators_new(iface_name);
        shash_insert(xtr->iface_locators_table, iface_name, if_loct);
    }

    /* PARSE AND ADD MAPPING TO XTR*/
    if (iid > MAX_IID || iid < 0) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (validate_priority_weight(p4, w4) != GOOD
        || validate_priority_weight(p6, w6) != GOOD) {
        return(BAD);
    }

    if (lisp_addr_ippref_from_char(eid_str, &eid) != GOOD) {
        LMLOG(LERR, "Configuration file: Error parsing EID address");
        return (BAD);
    }

    if (iid > 0) {
        lisp_addr_set_afi(&eid, LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(&eid, iid_type_init(iid, &eid,
                ip_afi_to_default_mask(lisp_addr_ip_afi(&eid))));
    }

    /* Lookup if the mapping exists. If not, a new mapping is created. */
    m = local_map_db_lookup_eid_exact(xtr->local_mdb, &eid);

    if (!m) {
        m = mapping_init_local(&eid);
        if (!m) {
            LMLOG(LERR, "Configuration file: mapping %s could not be created",
                    eid_str);
            return(BAD);
        }
        mapping_set_ttl(m, DEFAULT_MAP_REGISTER_TIMEOUT);

        /* Add the mapping to the local database */
        if (local_map_db_add_mapping(xtr->local_mdb, m) != GOOD) {
            mapping_del(m);
            return(BAD);
        }
    } else {
        if (m->iid != iid) {
            LMLOG(LERR, "Same EID prefix with different iid. This configuration"
                    " is not supported...Ignoring EID prefix.");
            return(BAD);
        }
    }

    /* BIND MAPPING TO IFACE */
    if (link_iface_and_mapping(interface, if_loct, m, p4, w4, p6, w6) != GOOD) {
        return(BAD);
    }

    /* Recalculate the outgoing rloc vectors */
    mapping_compute_balancing_vectors(m);

    /* in case we converted it to an LCAF, need to free memory */
    lisp_addr_dealloc(&eid);
    return(GOOD);
}

int
add_static_map_cache_entry(
        lisp_xtr_t *        xtr,
        char *              eid,
        int                 iid,
        char *              rloc_addr,
        int                 priority,
        int                 weight,
        htable_t *          elp_hash)
{
    mapping_t *mapping;
    locator_t *locator;
    lisp_addr_t rloc;
    lisp_addr_t *lcaf_rloc;
    lisp_addr_t eid_prefix;
    int err;

    if (iid > MAX_IID) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d],"
                " disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid < 0) {
        iid = 0;
    }

    if (priority < MAX_PRIORITY || priority > UNUSED_RLOC_PRIORITY) {
        LMLOG(LERR, "Configuration file: Priority %d out of range [%d..%d], "
                "set minimum priority...", priority, MAX_PRIORITY,
                UNUSED_RLOC_PRIORITY);
        priority = MIN_PRIORITY;
    }

    if (lisp_addr_ippref_from_char(eid, &eid_prefix) !=GOOD) {
        LMLOG(LERR, "Configuration file: Error parsing EID address ..."
                "Ignoring static map cache entry");
        return (BAD);
    }

    if (iid != 0) {
        lisp_addr_set_afi(&eid_prefix, LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(&eid_prefix, iid_type_init(iid, &eid_prefix,
                ip_afi_to_default_mask(lisp_addr_ip_afi(&eid_prefix))));
    }


    if (!(mapping = mapping_init_static(&eid_prefix))) {
        return(BAD);
    }

    if (lisp_addr_ip_from_char(rloc_addr, &rloc) == BAD) {
        lcaf_rloc = htable_lookup(elp_hash, rloc_addr);
        if (!lcaf_rloc) {
            LMLOG(LERR, "Error parsing RLOC address ..."
                    " Ignoring static map cache entry");
            return (BAD);
        }
        locator = locator_init_remote_full(lcaf_rloc, UP, priority, weight, 255,
                0);
    } else {
        locator = locator_init_remote_full(&rloc, UP, priority, weight, 255, 0);

    }

    if (locator != NULL) {
        locator_set_type(locator, STATIC_LOCATOR);
        if ((err = mapping_add_locator(mapping, locator)) != GOOD) {
            return(BAD);
        }
    } else {
        return(BAD);
    }

    tr_mcache_add_static_mapping(xtr, mapping);
    /* if it was converted to IID LCAF */
    lisp_addr_dealloc(&eid_prefix);
    return(GOOD);
}

/*
 * Create the locators associated with the address of the iface and assign them
 * to the mapping_t and the iface_locators
 * @param iface Interface containing the rlocs associated to the mapping
 * @param if_loct Structure that associate iface with locators
 * @param m Mapping where to add the new locators
 * @param p4 priority of the IPv4 RLOC. 1..255 -1 the IPv4 address is not used
 * @param w4 weight of the IPv4 RLOC
 * @param p4 priority of the IPv6 RLOC. 1..255 -1 the IPv6 address is not used
 * @param w4 weight of the IPv6 RLOC
 * @return GOOD if finish correctly or an error code otherwise
 */
int
link_iface_and_mapping(
        iface_t *iface,
        iface_locators *if_loct,
        mapping_t *m,
        int p4,
        int w4,
        int p6,
        int w6)
{
    locator_t *locator = NULL;

    /* Add mapping to the list of mappings associated to the interface */
    if (glist_contain(m, if_loct->mappings) == FALSE){
        glist_add(m,if_loct->mappings);
    }

    /* Create IPv4 locator and assign to the mapping */
    if ((p4 >= 0) && (default_rloc_afi != AF_INET6)) {
        locator = locator_init_local_full(iface->ipv4_address,
                iface->status, p4, w4, 255, 0,
                &(iface->out_socket_v4));
        if (!locator) {
            return(BAD);
        }

        if (mapping_add_locator(m, locator) != GOOD) {
            return(BAD);
        }
        glist_add(locator,if_loct->ipv4_locators);
    }

    /* Create IPv6 locator and assign to the mapping  */
    if ((p6 >= 0) && (default_rloc_afi != AF_INET)) {

        locator = locator_init_local_full(iface->ipv6_address,
                iface->status, p6, w6, 255, 0,
                &(iface->out_socket_v6));

        if (!locator) {
            return(BAD);
        }

        if (mapping_add_locator(m, locator) != GOOD) {
            return(BAD);
        }
        glist_add(locator,if_loct->ipv6_locators);
    }

    return(GOOD);
}



int
add_rtr_iface(
        lisp_xtr_t  *xtr,
        char        *iface_name,
        int         p,
        int         w)
{
    iface_t         *iface   = NULL;
    iface_locators  *if_loct = NULL;
    lisp_addr_t     aux_address;

    if (iface_name == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for RTR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(p, w) != GOOD) {
        return(BAD);
    }

    /* Check if the interface already exists. If not, add it*/
    if ((iface = get_interface(iface_name)) == NULL) {
        iface = add_interface(iface_name);
        if (!iface) {
            LMLOG(LWRN, "add_rtr_iface: Can't create interface %s",
                    iface_name);
            return(BAD);
        }
    }

    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    if (if_loct == NULL){
        if_loct = iface_locators_new(iface_name);
        shash_insert(xtr->iface_locators_table, iface_name, if_loct);
    }

    if (!xtr->all_locs_map) {
        lisp_addr_ip_from_char("0.0.0.0", &aux_address);
        xtr->all_locs_map = mapping_init_local(&aux_address);
    }

    if (link_iface_and_mapping(iface, if_loct, xtr->all_locs_map, p, w, p, w)
            != GOOD) {
        return(BAD);
    }

    return(GOOD);
}


lisp_site_prefix_t *
build_lisp_site_prefix(
        lisp_ms_t *     ms,
        char *          eidstr,
        uint32_t        iid,
        int             key_type,
        char *          key,
        uint8_t         more_specifics,
        uint8_t         proxy_reply,
        uint8_t         merge,
        htable_t *      lcaf_ht)
{
    lisp_addr_t *eid_prefix = NULL;
    lisp_addr_t *ht_prefix = NULL;
    lisp_site_prefix_t *site = NULL;

    if (iid > MAX_IID) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid < 0) {
        iid = 0;
    }

    /* DON'T DELETE eid_prefix */
    eid_prefix = lisp_addr_new();
    if (lisp_addr_ippref_from_char(eidstr, eid_prefix) != GOOD) {
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        ht_prefix = htable_lookup(lcaf_ht, eidstr);
        if (!ht_prefix) {
            LMLOG(LERR, "Configuration file: Error parsing RLOC address %s",
                    eidstr);
            return (NULL);
        }
        eid_prefix = lisp_addr_clone(ht_prefix);
    }

    site = lisp_site_prefix_init(eid_prefix, iid, key_type, key,
            more_specifics, proxy_reply, merge);
    lisp_addr_del(eid_prefix);
    return(site);
}

char *
get_interface_name_from_address(lisp_addr_t *addr)
{
    char *iface  = NULL;

    if (lisp_addr_afi(addr) != LM_AFI_IP) {
        LMLOG(DBG_1, "get_interface_name_from_address: failed for %s. Function"
                " only supports IP syntax addresses!", lisp_addr_to_char(addr));
        return(NULL);
    }

    iface = shash_lookup(iface_addr_ht, lisp_addr_to_char(addr));
    if (iface) {
        return(iface);
    } else {
        return(NULL);
    }
}
