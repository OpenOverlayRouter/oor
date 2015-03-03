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
#include "lispd_lib.h"
#include "lib/lmlog.h"

/***************************** FUNCTIONS DECLARATION *************************/
glist_t *fqdn_to_addresses(
        char        *addr_str,
        const int   preferred_afi);
/********************************** FUNCTIONS ********************************/

char *conf_loc_dump(conf_loc_t * loc){
    static char buf[100];

    sprintf(buf,"Locator address: %s, Priority: %d, Weight: %d",
            loc->address,loc->priority,loc->weight);

    return (buf);
}

char *conf_loc_iface_dump(conf_loc_iface_t * loc_iface){
    static char buf[100];

    sprintf(buf,"Locator interface: %s, AFI: %d, Priority: %d, Weight: %d",
            loc_iface->interface,loc_iface->afi,loc_iface->priority,loc_iface->weight);

    return (buf);

}


no_addr_loct *
no_addr_loct_new_init(
        locator_t * loct,
        char *      iface,
        int         afi)
{
    no_addr_loct * nloct = NULL;

    nloct = (no_addr_loct *)xzalloc(sizeof(no_addr_loct));
    if (nloct == NULL){
        return (NULL);
    }
    nloct->locator = loct;
    nloct->iface_name = strdup(iface);
    nloct->afi = afi;
    return (nloct);
}

void
no_addr_loct_del(no_addr_loct * nloct)
{
    free(nloct->iface_name);
    free(nloct);
}

no_addr_loct *
get_no_addr_loct_from_list(
        glist_t     *list,
        locator_t   *locator)
{
    glist_entry_t * it      = NULL;
    no_addr_loct *  nloct   = NULL;

    glist_for_each_entry(it,list){
        nloct = (no_addr_loct *)glist_entry_data(it);
        /* Comparing memory position */
        if (nloct->locator == locator){
            return (nloct);
        }
    }

    return (NULL);
}
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
                p, MAX_PRIORITY, MIN_PRIORITY);
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
add_server(
        char                *str_addr,
        glist_t             *list)
{
    lisp_addr_t *       addr        = NULL;
    glist_t *           addr_list   = NULL;
    glist_entry_t *     it          = NULL;

    addr_list = parse_ip_addr(str_addr);

    if (addr_list == NULL){
        LMLOG(LERR, "Error parsing address. Ignoring server with address %s",
                        str_addr);
        return (BAD);
    }
    glist_for_each_entry(it, addr_list) {
        addr = glist_entry_data(it);

        /* Check that the afi of the map server matches with the default rloc afi
         * (if it's defined). */
        if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(addr)){
            LMLOG(LWRN, "The server %s will not be added due to the selected "
                    "default rloc afi (-a option)", str_addr);
            continue;
        }

        glist_add_tail(lisp_addr_clone(addr), list);
        LMLOG(DBG_3,"The server %s has been added to the list",lisp_addr_to_char(addr));
    }

    glist_destroy(addr_list);


    return(GOOD);
}


int
add_map_server(
        lisp_xtr_t *    xtr,
        char *          str_addr,
        int             key_type,
        char *          key,
        uint8_t         proxy_reply)
{
    lisp_addr_t *       addr        = NULL;
    map_server_elt *    ms          = NULL;
    glist_t *           addr_list   = NULL;
    glist_entry_t *     it          = NULL;

    if (str_addr == NULL || key_type == 0 || key == NULL){
        LMLOG(LERR, "Configuraton file: Wrong Map Server configuration. "
                "Check configuration file");
        exit_cleanup();
    }

    if (key_type != HMAC_SHA_1_96){
        LMLOG(LERR, "Configuraton file: Only SHA-1 (1) authentication is supported");
        exit_cleanup();
    }

    addr_list = parse_ip_addr(str_addr);

    if (addr_list == NULL){
        LMLOG(LERR, "Error parsing address. Ignoring Map Server %s",
                        str_addr);
        return (BAD);
    }
    glist_for_each_entry(it, addr_list) {
        addr = glist_entry_data(it);

        /* Check that the afi of the map server matches with the default rloc afi
         * (if it's defined). */
        if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(addr)){
            LMLOG(LWRN, "The map server %s will not be added due to the selected "
                    "default rloc afi (-a option)", str_addr);
            continue;
        }
        // XXX Create method to do it authomatically
        ms = xzalloc(sizeof(map_server_elt));

        ms->address     = lisp_addr_clone(addr);
        ms->key_type    = key_type;
        ms->key         = strdup(key);
        ms->proxy_reply = proxy_reply;

        glist_add(ms, xtr->map_servers);
    }

    glist_destroy(addr_list);

    return(GOOD);
}


int
add_proxy_etr_entry(
        lisp_xtr_t *    xtr,
        char *          str_addr,
        int             priority,
        int             weight)
{
    glist_t *           addr_list   = NULL;
    glist_entry_t *     it          = NULL;
    lisp_addr_t *       addr        = NULL;
    locator_t *         locator     = NULL;

    if (str_addr == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for PETR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    addr_list = parse_ip_addr(str_addr);
    if (addr_list == NULL){
        LMLOG(LERR, "Error parsing RLOC address. Ignoring proxy-ETR %s",
                        str_addr);
        return (BAD);
    }
    glist_for_each_entry(it, addr_list) {
        addr = glist_entry_data(it);
        if (default_rloc_afi != AF_UNSPEC
                && default_rloc_afi != lisp_addr_ip_afi(addr)) {
            LMLOG(LWRN, "The PETR %s will not be added due to the selected "
                    "default rloc afi", str_addr);
            continue;
        }

        /* Create locator representing the proxy-etr and add it to the mapping */
        locator = locator_init_remote_full(addr, UP, priority, weight, 255, 0);

        if (locator != NULL) {
            if (mapping_add_locator(mcache_entry_mapping(xtr->petrs), locator)!= GOOD){
                locator_del(locator);
                continue;
            }
        }
    }

    glist_destroy(addr_list);

    return(GOOD);
}

/*
 * Create the locators associated with the address of the iface and assign them
 * to the mapping_t and the iface_locators
 * @param iface Interface containing the rlocs associated to the mapping
 * @param if_loct Structure that associate iface with locators
 * @param map_loc_e Local mapping where to add the new locators
 * @param afi Afi of the address of the interface to be used
 * @param priority priority of the IPv4 RLOC. 1..255 -1 the IPv4 address is not used
 * @param weight weight of the IPv4 RLOC
 * @return GOOD if finish correctly or an error code otherwise
 */
int
link_iface_and_mapping(
        iface_t *iface,
        iface_locators *if_loct,
        map_local_entry_t * map_loc_e,
        int afi,
        int priority,
        int weight)
{
    mapping_t *     mapping = NULL;
    locator_t *     locator = NULL;

    mapping = map_local_entry_mapping(map_loc_e);

    /* Add mapping to the list of mappings associated to the interface */
    if (glist_contain(map_loc_e, if_loct->map_loc_entries) == FALSE){
        glist_add(map_loc_e,if_loct->map_loc_entries);
    }

    /* Create locator and assign to the mapping and  to iface_loct*/
    if (priority >= 0){
        if (afi == AF_INET){
            locator = locator_init_local_full(iface->ipv4_address,
                    iface->status, priority, weight, 255, 0,
                    &(iface->out_socket_v4));
            if (locator == NULL){
                return (BAD);
            }
            if (mapping_add_locator(mapping, locator) != GOOD) {
                locator_del(locator);
                return(BAD);
            }
            glist_add(locator,if_loct->ipv4_locators);
        }else{
            locator = locator_init_local_full(iface->ipv6_address,
                    iface->status, priority, weight, 255, 0,
                    &(iface->out_socket_v6));
            if (locator == NULL){
                return (BAD);
            }
            if (mapping_add_locator(mapping, locator) != GOOD) {
                locator_del(locator);
                return(BAD);
            }
            glist_add(locator,if_loct->ipv6_locators);
        }
    }

    return(GOOD);
}


int
add_rtr_iface(
        lisp_xtr_t  *xtr,
        char        *iface_name,
        int         afi,
        int         priority,
        int         weight)
{
    iface_t *       iface       = NULL;
    iface_locators *if_loct     = NULL;
    mapping_t *     mapping     = NULL;
    lisp_addr_t     aux_address;
    void *          fwd_map_inf = NULL;

    if (iface_name == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for RTR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    if (priority < 0){
        LMLOG(LERR, "Configuration file: Discarding the interface %s of the RTR with afi %d due to the assigned priority",
                iface_name, afi);
        return (GOOD);
    }

    if (afi != 4 && afi !=6){
        LMLOG(LERR, "Configuration file: The rtr-iface->afi of the locator should be \"4\" (IPv4)"
                " or \"6\" (IPv6)");
        return (BAD);
    }

    afi = (afi == 4) ? AF_INET : AF_INET6;

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
        mapping = mapping_new_init(&aux_address);
        if (mapping == NULL){
            LMLOG(DBG_1, "add_rtr_iface: Can't allocate mapping!");
            return (BAD);
        }
        xtr->all_locs_map = map_local_entry_new_init(mapping);
        if(xtr->all_locs_map == NULL){
            LMLOG(DBG_1, "add_rtr_iface: Can't allocate map_local_entry_t!");
            return (BAD);
        }
        fwd_map_inf = xtr->fwd_policy->new_map_loc_policy_inf(xtr->fwd_policy_dev_parm,mapping,NULL);
        if (fwd_map_inf == NULL){
            LMLOG(LERR, "Couldn't create forward information for rtr localtors.",
                    lisp_addr_to_char(mapping_eid(mapping)));
            map_local_entry_del(xtr->all_locs_map);
            return (BAD);
        }
        map_local_entry_set_fwd_info(xtr->all_locs_map, fwd_map_inf, xtr->fwd_policy->del_map_loc_policy_inf);
    }

    if (link_iface_and_mapping(iface, if_loct, xtr->all_locs_map, afi, priority, weight)
            != GOOD) {
        return(BAD);
    }
    /* Updated forwarding info */
    xtr->fwd_policy->updated_map_loc_inf(
            xtr->fwd_policy_dev_parm,
            map_local_entry_fwd_info(xtr->all_locs_map),
            map_local_entry_mapping(xtr->all_locs_map));

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


/* Parses an EID/RLOC (IP or LCAF) and returns a list of 'lisp_addr_t'.
 * Caller must free the returned value */
glist_t *
parse_lisp_addr(
        char *      addr_str,
        htable_t *  lcaf_ht)
{
    glist_t *       addr_list   = NULL;
    lisp_addr_t *   addr        = NULL;
    lisp_addr_t *   lcaf        = NULL;
    int             res         = 0;

    addr = lisp_addr_new();

    if (strstr(addr_str,"/") == NULL){
        // Address may be an IP
        res = lisp_addr_ip_from_char(addr_str, addr);
    }else{
        // Address may be a prefix
        res = lisp_addr_ippref_from_char(addr_str, addr);
    }

    if (res != GOOD){
        lisp_addr_del(addr);
        addr = NULL;
        /* if not found, try in the hash table */
        lcaf = htable_lookup(lcaf_ht, addr_str);
        if (lcaf != NULL) {
            addr = lisp_addr_clone(lcaf);
        }
    }

    if (addr != NULL){
        addr_list = glist_new_managed((glist_del_fct)lisp_addr_del);
        if (addr_list != NULL){
            glist_add (addr,addr_list);
        }
    }else{
        addr_list = fqdn_to_addresses(addr_str,default_rloc_afi);
    }

    if (addr_list == NULL || glist_size(addr_list) == 0){
        LMLOG(LERR, "Configuration file: Error parsing address %s",addr_str);
    }

    return(addr_list);
}


/* Parses a char (IP or FQDN) into a list of 'lisp_addr_t'.
 * Caller must free the returned value */
glist_t *
parse_ip_addr(char *addr_str)
{
    glist_t *       addr_list   = NULL;
    lisp_addr_t *   addr        = NULL;
    int             res         = 0;

    addr = lisp_addr_new();

    res = lisp_addr_ip_from_char(addr_str, addr);

    if (res == GOOD){
        addr_list = glist_new_managed((glist_del_fct)lisp_addr_del);
        if (addr_list != NULL){
            glist_add (addr,addr_list);
        }
    }else{
        lisp_addr_del(addr);
        addr_list = fqdn_to_addresses(addr_str,default_rloc_afi);
    }

    if (addr_list == NULL || glist_size(addr_list) == 0){
        LMLOG(LERR, "Configuration file: Error parsing address %s",addr_str);
    }

    return(addr_list);
}

locator_t*
clone_customize_locator(
        lisp_ctrl_dev_t     *dev,
        locator_t*          locator,
        glist_t*            no_addr_loct_l,
        uint8_t             type)
{
    char *              iface_name      = NULL;
    locator_t *         new_locator     = NULL;
    iface_t *           iface           = NULL;
    lisp_addr_t *       rloc            = NULL;
    lisp_addr_t *       aux_rloc        = NULL;
    int                 rloc_ip_afi     = AF_UNSPEC;
    int *               out_socket      = 0;
    no_addr_loct *      nloct           = NULL;
    lisp_xtr_t *        xtr             = NULL;
    shash_t *           iface_lctrs     = NULL;
    iface_locators *    if_loct         = NULL;

    rloc = locator_addr(locator);
    /* LOCAL locator */
    if (type == LOCAL_LOCATOR) {
        /* Decide IP address to be used to lookup the interface */
        if (lisp_addr_is_lcaf(rloc) == TRUE) {
            aux_rloc = lisp_addr_get_ip_addr(rloc);
            if (aux_rloc == NULL) {
                LMLOG(LERR, "Configuration file: Can't determine RLOC's IP "
                        "address %s", lisp_addr_to_char(rloc));
                lisp_addr_del(rloc);
                return(NULL);
            }
        } else if (lisp_addr_is_no_addr(rloc)){
            aux_rloc = rloc;
            nloct = get_no_addr_loct_from_list(no_addr_loct_l,locator);
            if (nloct == NULL){
                return (NULL);
            }
            iface_name = nloct->iface_name;
            rloc_ip_afi = nloct->afi;
        } else{
            aux_rloc = rloc;
            /* Find the interface name associated to the RLOC */
            if (!(iface_name = get_interface_name_from_address(aux_rloc))) {
                LMLOG(LERR, "Configuration file: Can't find interface for RLOC %s",
                        lisp_addr_to_char(aux_rloc));
                return(NULL);
            }
            rloc_ip_afi = lisp_addr_ip_afi(aux_rloc);
        }

        /* Find the interface */
        if (!(iface = get_interface(iface_name))) {
            if (!(iface = add_interface(iface_name))) {
                return(NULL);
            }
        }

        out_socket = (rloc_ip_afi == AF_INET) ? &(iface->out_socket_v4) : &(iface->out_socket_v6);

        new_locator = locator_init_local_full(rloc, iface->status,
                            locator_priority(locator), locator_weight(locator),
                            255, 0, out_socket);

        /* Associate locator with iface */
        if (dev->mode == xTR_MODE || dev->mode == MN_MODE){
            xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
            iface_lctrs = xtr->iface_locators_table;

            if_loct = (iface_locators *)shash_lookup(iface_lctrs, iface_name);

            if (if_loct == NULL){
                if_loct = iface_locators_new(iface_name);
                shash_insert(xtr->iface_locators_table, iface_name, if_loct);
            }

            if (rloc_ip_afi == AF_INET){
                glist_add(new_locator,if_loct->ipv4_locators);
            }else{
                glist_add(new_locator,if_loct->ipv6_locators);
            }
        }
    /* REMOTE locator */
    } else {
        new_locator = locator_init_remote_full(rloc, UP, locator_priority(locator), locator_weight(locator), 255, 0);
        if (new_locator != NULL) {
            locator_set_type(new_locator,type);
        }

    }

    return(new_locator);
}


/*
 *  Converts the hostname into IPs which are added to a list of lisp_addr_t
 *  @param addr_str String conating fqdn address or de IP address
 *  @param preferred_afi Indicates the afi of the IPs to be added in the list
 *  @return List of addresses (glist_t *)
 */
glist_t *fqdn_to_addresses(
        char        *addr_str,
        const int   preferred_afi)
{
    glist_t *           addr_list               = NULL;
    lisp_addr_t *       addr                    = NULL;
    struct addrinfo     hints;
    struct addrinfo *   servinfo                = NULL;
    struct addrinfo *   p                       = NULL;
    struct sockaddr *   s_addr                  = NULL;
    int err;

    addr_list = glist_new_managed((glist_del_fct)lisp_addr_del);

    memset(&hints, 0, sizeof hints);

    hints.ai_family = preferred_afi;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;    /* we are interested in UDP only */

    if ((err = getaddrinfo( addr_str, 0, &hints, &servinfo)) != 0) {
        LMLOG( LWRN, "fqdn_to_addresses: %s", gai_strerror(err));
        return( NULL );
    }
    /* iterate over addresses */
    for (p = servinfo; p != NULL; p = p->ai_next) {

        if ((addr = lisp_addr_new_lafi(LM_AFI_IP))== NULL){
            LMLOG( LWRN, "fqdn_to_addresses: Unable to allocate memory for lisp_addr_t");
            continue;
        }

        s_addr = p->ai_addr;

        switch(s_addr->sa_family){
        case AF_INET:
            ip_addr_init(lisp_addr_ip(addr),&(((struct sockaddr_in *)s_addr)->sin_addr),s_addr->sa_family);
            break;
        case AF_INET6:
            ip_addr_init(lisp_addr_ip(addr),&(((struct sockaddr_in6 *)s_addr)->sin6_addr),s_addr->sa_family);
            break;
        default:
            break;
        }

        LMLOG( DBG_1, "converted addr_str [%s] to address [%s]", addr_str, lisp_addr_to_char(addr));
        /* depending on callback return, we continue or not */

        glist_add(addr,addr_list);
    }
    freeaddrinfo(servinfo); /* free the linked list */
    return (addr_list);
}


static glist_t *
process_rloc_address(
        conf_loc_t *        conf_loc,
        lisp_ctrl_dev_t *   dev,
        htable_t *          lcaf_ht,
        uint8_t             type)
{
    glist_t *           loct_list       = NULL;
    locator_t *         locator         = NULL;
    glist_t *           addr_list       = NULL;
    glist_entry_t *     it              = NULL;
    lisp_addr_t *       address         = NULL;
    lisp_addr_t *       ip_addr        = NULL;
    iface_t*            iface           = NULL;
    int *               out_socket      = 0;
    char*               iface_name      = NULL;

    lisp_xtr_t *        xtr             = NULL;
    shash_t *           iface_lctrs     = NULL;
    iface_locators *    if_loct         = NULL;


    if (validate_priority_weight(conf_loc->priority, conf_loc->weight) != GOOD) {
        return (NULL);
    }

    addr_list = parse_lisp_addr(conf_loc->address, lcaf_ht);
    if (addr_list == NULL || glist_size(addr_list) == 0){
        return (NULL);
    }

    loct_list = glist_new();
    if (loct_list == NULL){
        return (NULL);
    }

    glist_for_each_entry(it,addr_list){
        address = (lisp_addr_t *)glist_entry_data(it);
        if (address == NULL){
            continue;
        }
        if (lisp_addr_lafi(address) == LM_AFI_IPPREF){
            LMLOG(LERR, "Configuration file: RLOC address can not be a prefix: %s ",
                    lisp_addr_to_char(address));
            continue;
        }

        if (type == LOCAL_LOCATOR){
            /* Decide IP address to be used to lookup the interface */
            if (lisp_addr_is_lcaf(address) == TRUE) {
                ip_addr = lisp_addr_get_ip_addr(address);
                if (ip_addr == NULL) {
                    LMLOG(LERR, "Configuration file: Can't determine RLOC's IP "
                            "address %s", lisp_addr_to_char(address));
                    return(NULL);
                }
            } else {
                ip_addr = address;
            }

            /* Find the interface name associated to the RLOC */
            if (!(iface_name = get_interface_name_from_address(ip_addr))) {
                LMLOG(LERR, "Configuration file: Can't find interface for RLOC %s",
                        lisp_addr_to_char(ip_addr));
                continue;
            }
            /* Find the interface */
            iface = get_interface(iface_name);
            if (iface == NULL){
                iface = add_interface(iface_name);
                if (iface == NULL){
                    LMLOG(LERR, "Configuration file: Can't add interface with name %s",
                                            lisp_addr_to_char(ip_addr));
                    continue;
                }
            }

            out_socket = (lisp_addr_ip_afi(ip_addr) == AF_INET) ? &(iface->out_socket_v4) : &(iface->out_socket_v6);

            locator = locator_init_local_full(address, iface->status,conf_loc->priority, conf_loc->weight,255, 0, out_socket);

            /* If the locator is for a local mapping, associate the locator with the interface */
            if (locator != NULL && (dev->mode == xTR_MODE || dev->mode == MN_MODE)){
                xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
                iface_lctrs = xtr->iface_locators_table;
                if_loct = (iface_locators *)shash_lookup(iface_lctrs, iface_name);
                if (if_loct == NULL){
                    if_loct = iface_locators_new(iface_name);
                    shash_insert(xtr->iface_locators_table, iface_name, if_loct);
                }
                if (lisp_addr_ip_afi(ip_addr) == AF_INET){
                    glist_add(locator,if_loct->ipv4_locators);
                }else{
                    glist_add(locator,if_loct->ipv6_locators);
                }
            }
        } else {
            locator = locator_init_remote_full(address, UP, conf_loc->priority, conf_loc->weight, 255, 0);
            if (locator != NULL) {
                locator_set_type(locator,type);
            }
        }
        if (locator != NULL){
            glist_add(locator,loct_list);
            LMLOG(DBG_2,"parse_rloc_address: Locator stucture created: \n %s",
                    locator_to_char(locator));
        }
    }
    glist_destroy(addr_list);

    return (loct_list);
}

static locator_t *
process_rloc_interface(
        conf_loc_iface_t *  conf_loc_iface,
        lisp_ctrl_dev_t *   dev)

{
    locator_t *         locator         = NULL;
    lisp_addr_t *       address         = NULL;
    iface_t*            iface           = NULL;
    int *               out_socket      = 0;


    lisp_xtr_t *        xtr             = NULL;
    shash_t *           iface_lctrs     = NULL;
    iface_locators *    if_loct         = NULL;

    if (conf_loc_iface == NULL){
        return (NULL);
    }

    if (validate_priority_weight(conf_loc_iface->priority, conf_loc_iface->weight) != GOOD) {
        return (NULL);
    }

    if (conf_loc_iface->afi != 4 && conf_loc_iface->afi !=6){
        LMLOG(LERR, "Configuration file: The conf_loc_iface->afi of the locator should be \"4\" (IPv4)"
                " or \"6\" (IPv6)");
        return (NULL);
    }

    /* Find the interface */
    if (!(iface = get_interface(conf_loc_iface->interface))) {
        if (!(iface = add_interface(conf_loc_iface->interface))) {
            return (BAD);
        }
    }

    if (conf_loc_iface->afi == 4){
        out_socket = &(iface->out_socket_v4);
        address = iface->ipv4_address;
        conf_loc_iface->afi = AF_INET;
    }else{
        out_socket = &(iface->out_socket_v4);
        address = iface->ipv6_address;
        conf_loc_iface->afi = AF_INET6;
    }

    locator = locator_init_local_full(address, iface->status,conf_loc_iface->priority, conf_loc_iface->weight,255, 0, out_socket);

    LMLOG(DBG_2,"parse_rloc_address: Locator stucture created: \n %s",
                        locator_to_char(locator));

    /* If the locator is for a local mapping, associate the locator with the interface */
    if (locator != NULL && (dev->mode == xTR_MODE || dev->mode == MN_MODE)){
        xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
        iface_lctrs = xtr->iface_locators_table;
        if_loct = (iface_locators *)shash_lookup(iface_lctrs, conf_loc_iface->interface);
        if (if_loct == NULL){
            if_loct = iface_locators_new(conf_loc_iface->interface);
            shash_insert(xtr->iface_locators_table, conf_loc_iface->interface, if_loct);
        }
        if (conf_loc_iface->afi == AF_INET){
            glist_add(locator,if_loct->ipv4_locators);
        }else{
            glist_add(locator,if_loct->ipv6_locators);
        }
    }

    return (locator);
}


mapping_t *
process_mapping_config(lisp_ctrl_dev_t * dev, htable_t * lcaf_ht,
        uint8_t type, conf_mapping_t * conf_mapping){

    mapping_t *         mapping         = NULL;
    glist_t *           loct_list       = NULL;
    glist_entry_t *     it              = NULL;
    locator_t *         locator         = NULL;
    glist_t *           addr_list       = NULL;
    lisp_addr_t *       eid_prefix      = NULL;
    lisp_xtr_t *        xtr             = NULL;
    conf_loc_t *        conf_loc        = NULL;
    conf_loc_iface_t *  conf_loc_iface  = NULL;
    glist_entry_t   *   conf_it         = NULL;

    switch (dev->mode){
        case xTR_MODE:
        case MN_MODE:
            xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
            break;
        default:
            break;
        }

    addr_list = parse_lisp_addr(conf_mapping->eid_prefix, lcaf_ht);

    if (addr_list == NULL || glist_size(addr_list) != 1){
        return NULL;
    }

    eid_prefix = (lisp_addr_t *)glist_first_data(addr_list);

    /* Create mapping */
    if ( type == LOCAL_LOCATOR){
        mapping = mapping_new_init(eid_prefix);
        if (mapping == NULL){
            return(NULL);
        }
        mapping_set_ttl(mapping, DEFAULT_MAP_REGISTER_TIMEOUT);
        mapping_set_auth(mapping, 1);
    }else{
        mapping = mapping_new_init(eid_prefix);
        if (mapping == NULL){
            return(NULL);
        }
    }

    /* no need for the prefix */
    glist_destroy(addr_list);


    if (mapping == NULL){
        return (NULL);
    }

    /* Create and add locators */
    glist_for_each_entry(conf_it,conf_mapping->conf_loc_list){
        conf_loc = (conf_loc_t *)glist_entry_data(conf_it);

        loct_list = process_rloc_address(conf_loc, dev, lcaf_ht, type);
        if (loct_list == NULL){
            continue;
        }
        glist_for_each_entry(it,loct_list){
            locator = (locator_t *)glist_entry_data(it);
            if (locator == NULL){
                continue;
            }
            /* Check that the locator is not already added */
            if (mapping_get_loct_with_addr(mapping, locator_addr(locator)) != NULL){
                LMLOG(LERR,"Configuration file: Duplicated RLOC with address %s "
                        "for EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL && type == LOCAL_LOCATOR){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
            if (mapping_add_locator(mapping, locator) != GOOD){
                LMLOG(DBG_1,"parse_mapping: Couldn't add RLOC with address %s "
                        "to the mapping with EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL && type == LOCAL_LOCATOR){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }

        }
        glist_destroy(loct_list);
    }


    if (type == LOCAL_LOCATOR){

        glist_for_each_entry(conf_it,conf_mapping->conf_loc_iface_list){
            conf_loc_iface = (conf_loc_iface_t *)glist_entry_data(conf_it);
            locator = process_rloc_interface(conf_loc_iface, dev);
            if (locator == NULL){
                continue;
            }
            /* Check that the locator is not already added */
            if (mapping_get_loct_with_addr(mapping, locator_addr(locator)) != NULL){
                LMLOG(LERR,"Configuration file: Duplicated RLOC with address %s "
                        "for EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
            if (mapping_add_locator(mapping, locator) != GOOD){
                LMLOG(DBG_1,"parse_mapping: Couldn't add RLOC with address %s "
                        "to the mapping with EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
        }
    }

    return (mapping);

}


int
add_local_db_map_local_entry(
		map_local_entry_t *map_loca_entry,
        lisp_xtr_t *    xtr)
{
	lisp_addr_t *eid = map_local_entry_eid(map_loca_entry);


    if (map_loca_entry == NULL){
        LMLOG(LERR, "Can't add mapping (NULL)");
        return (BAD);
    }

    if (local_map_db_lookup_eid_exact(xtr->local_mdb, eid) == NULL){
        if (local_map_db_add_entry(xtr->local_mdb, map_loca_entry) == GOOD){
            LMLOG(DBG_1, "Added EID prefix %s in the database.",
                    lisp_addr_to_char(eid));
            iface_locators_attach_map_local_entry(xtr->iface_locators_table,map_loca_entry);
        }else{
            LMLOG(LERR, "Can't add EID prefix %s. Discarded ...",
                    lisp_addr_to_char(eid));
            goto err;
        }
    }else{
        LMLOG(LERR, "Configuration file: Duplicated EID prefix %s. Discarded ...",
                lisp_addr_to_char(eid));
        goto err;
    }

    return(GOOD);
err:
    iface_locators_unattach_mapping_and_loct(
            xtr->iface_locators_table,
            map_loca_entry);

    return(BAD);
}
