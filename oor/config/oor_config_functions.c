/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <libgen.h>
#include <netdb.h>
#include <stdio.h>

#include "oor_config_functions.h"
#include "../data-plane/data-plane.h"
#include "../net_mgr/net_mgr.h"
#include "../lib/oor_log.h"
#include "../lib/prefixes.h"
#include "../lib/util.h"

/***************************** FUNCTIONS DECLARATION *************************/
glist_t *fqdn_to_addresses(
        char        *addr_str,
        const int   preferred_afi);
/********************************** FUNCTIONS ********************************/

inline conf_mapping_t *
conf_mapping_new()
{
    conf_mapping_t * conf_map = (conf_mapping_t *)xzalloc(sizeof(conf_mapping_t));
    if (conf_map == NULL){
        OOR_LOG(LWRN,"conf_mapping_new: Couldn't allocate memory for a conf_mapping_t structure");
        return (NULL);
    }
    conf_map->eid_prefix = NULL;
    conf_map->conf_loc_list = glist_new_managed((glist_del_fct) conf_loc_destroy);
    conf_map->conf_loc_iface_list = glist_new_managed((glist_del_fct) conf_loc_iface_destroy);
    return (conf_map);
}

inline void
conf_mapping_destroy(conf_mapping_t * conf_map)
{
    if (!conf_map){
        return;
    }
    glist_destroy(conf_map->conf_loc_list);
    glist_destroy(conf_map->conf_loc_iface_list);
    free(conf_map->eid_prefix);
    free(conf_map);
}


inline void
conf_mapping_dump(conf_mapping_t * conf_map, int log_level)
{
    char buf[2000];
    conf_loc_t *conf_loct;
    conf_loc_iface_t *conf_loct_iface;
    glist_entry_t *it_loct_addr;
    glist_entry_t *it_loct_iface;
    size_t buf_size = sizeof(buf);

    if (is_loggable(log_level) == FALSE){
        return;
    }

    snprintf(buf,buf_size,"EID: %s, ttl: %d\n", conf_map->eid_prefix, conf_map->ttl);

    glist_for_each_entry(it_loct_addr,conf_map->conf_loc_list){
        conf_loct = (conf_loc_t *)glist_entry_data(it_loct_addr);
        snprintf(buf+strlen(buf), buf_size - strlen(buf),"\n  %s",conf_loc_to_char(conf_loct));
    }
    glist_for_each_entry(it_loct_iface,conf_map->conf_loc_iface_list){
        conf_loct_iface = (conf_loc_iface_t *)glist_entry_data(it_loct_iface);
        snprintf(buf+strlen(buf), buf_size - strlen(buf),"\n  %s",conf_loc_iface_to_char(conf_loct_iface));
    }
    OOR_LOG(log_level,"%s\n",buf);
}

gconf_loc_t *
gconf_loc_new_init(conf_loct_type_e type, void *loct)
{
    gconf_loc_t *conf_loct;
    conf_loct = (gconf_loc_t *)xzalloc(sizeof(gconf_loc_t));
    if (!conf_loct){
        return (NULL);
    }
    conf_loct->type = type;
    conf_loct->conf_loct = loct;
    return (conf_loct);
}

void
gconf_loc_destroy(gconf_loc_t *gconf_loc)
{
    if(!gconf_loc){
        return;
    }
    switch (gconf_loc->type){
    case CONF_LOCT_ADDR:
        conf_loc_destroy(gconf_loc->conf_loct);
        break;
    case CONF_LOCT_IFACE:
        conf_loc_iface_destroy(gconf_loc->conf_loct);
        break;
    }
    free(gconf_loc);
}

inline conf_loc_t *
conf_loc_new_init(char *addr, uint8_t priority, uint8_t weight,
        uint8_t mpriority, uint8_t mweight)
{
    conf_loc_t * conf_loc;

    if (!addr){
        OOR_LOG(LERR,"Configuration file: No address assigned to rloc-address");
    }

    conf_loc = (conf_loc_t *)xzalloc(sizeof(conf_loc_t));
    if (conf_loc == NULL){
        OOR_LOG(LWRN,"conf_loc_new_init: Couldn't allocate memory for a conf_loc_t structure");
        return (NULL);
    }
    conf_loc->address = strdup(addr);
    conf_loc->priority = priority;
    conf_loc->weight = weight;
    conf_loc->mpriority = mpriority;
    conf_loc->mweight = mweight;

    return (conf_loc);
}

conf_loc_t *
conf_loc_clone(conf_loc_t *conf_loc)
{
    conf_loc_t * new_conf_loc;
    new_conf_loc = conf_loc_new_init(conf_loc->address, conf_loc->priority,
            conf_loc->weight, conf_loc->mpriority, conf_loc->mweight);
    return (new_conf_loc);
}

char *
conf_loc_to_char(conf_loc_t * loc)
{
    static char buf[100];

    *buf = '\0';
    snprintf(buf,sizeof(buf),"Locator address: %s, Priority: %d, Weight: %d",
            loc->address,loc->priority,loc->weight);
    return (buf);
}

inline conf_loc_iface_t *
conf_loc_iface_new_init(char *iface_name, int afi, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight)
{
    conf_loc_iface_t * conf_loc_iface;

    if (!iface_name){
        OOR_LOG(LERR,"Configuration file: An rloc-iface should have an interface selected");
        return (NULL);
    }

    if (afi == 4){
        afi = AF_INET;
    }else if (afi == 6){
        afi = AF_INET6;
    }else{
        OOR_LOG(LERR,"Configuration file: The ip_version of the rloc-iface should be 4 (IPv4) or 6 (IPv6): %d", afi);
        return (BAD);
    }

    conf_loc_iface = (conf_loc_iface_t *)xzalloc(sizeof(conf_loc_iface_t));
    if (conf_loc_iface == NULL){
        OOR_LOG(LWRN,"conf_loc_iface_new_init: Couldn't allocate memory for a conf_loc_iface_t structure");
        return (NULL);
    }
    conf_loc_iface->interface = strdup(iface_name);
    conf_loc_iface->afi = afi;
    conf_loc_iface->priority = priority;
    conf_loc_iface->weight = weight;
    conf_loc_iface->mpriority = mpriority;
    conf_loc_iface->mweight = mweight;

    return (conf_loc_iface);
}

conf_loc_iface_t *
conf_loc_iface_clone(conf_loc_iface_t * cli)
{
    conf_loc_iface_t * new_conf_loc_iface;
    int afi46;
    afi46 = cli->afi == AF_INET ? 4 : 6;
    new_conf_loc_iface = conf_loc_iface_new_init(cli->interface, afi46,
            cli->priority, cli->weight, cli->mpriority, cli->mweight);
    return (new_conf_loc_iface);
}

char *
conf_loc_iface_to_char(conf_loc_iface_t * loc_iface)
{
    static char buf[100];

    *buf = '\0';
    snprintf(buf,sizeof(buf),"Locator interface: %s, AFI: %d, Priority: %d, Weight: %d",
            loc_iface->interface,loc_iface->afi,loc_iface->priority,loc_iface->weight);
    return (buf);
}

no_addr_loct *
no_addr_loct_new_init(locator_t * loct, char *iface, int afi)
{
    no_addr_loct * nloct;

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
get_no_addr_loct_from_list(glist_t *list, locator_t *locator)
{
    glist_entry_t *it;
    no_addr_loct *nloct;

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
validate_rloc_probing_parameters(int *interval,int *retries,int *retries_int)
{
    if (*interval < 0) {
        *interval = 0;
    }

    if (*interval > 0) {
        OOR_LOG(LDBG_1, "RLOC Probing Interval: %d", *interval);
    } else {
        OOR_LOG(LDBG_1, "RLOC Probing disabled");
    }

    if (*interval != 0) {
        if (*retries > OOR_MAX_RETRANSMITS) {
            *retries = OOR_MAX_RETRANSMITS;
            OOR_LOG(LWRN, "RLOC Probing retries should be between 0 and %d. "
                    "Using %d retries", OOR_MAX_RETRANSMITS,
                    OOR_MAX_RETRANSMITS);
        } else if (*retries < 0) {
            *retries = 0;
            OOR_LOG(LWRN, "RLOC Probing retries should be between 0 and %d. "
                    "Using 0 retries", OOR_MAX_RETRANSMITS);
        }

        if (*retries > 0) {
            if (*retries_int < OOR_MIN_RETRANSMIT_INTERVAL) {
                *retries_int = OOR_MIN_RETRANSMIT_INTERVAL;
                OOR_LOG(LWRN, "RLOC Probing interval retries should be between "
                        "%d and RLOC Probing interval. Using %d seconds",
                        OOR_MIN_RETRANSMIT_INTERVAL,
                        OOR_MIN_RETRANSMIT_INTERVAL);
            } else if (*retries_int > *interval) {
                *retries_int = *interval;
                OOR_LOG(LWRN, "RLOC Probing interval retries should be between "
                        "%d and RLOC Probing interval. Using %d seconds",
                         OOR_MIN_RETRANSMIT_INTERVAL, *interval);
            }
        }
    }
}

int
validate_priority_weight(int p, int w)
{
    /* Check the parameters */
    if (p < (MAX_PRIORITY - 1)|| p > UNUSED_RLOC_PRIORITY) {
        OOR_LOG(LERR, "Configuration file: Priority %d out of range [%d..%d]",
                p, MAX_PRIORITY, MIN_PRIORITY);
        return (BAD);
    }

    if (w > MAX_WEIGHT || w < MIN_WEIGHT) {
        OOR_LOG(LERR, "Configuration file: Weight %d out of range [%d..%d]",
                p, MIN_WEIGHT, MAX_WEIGHT);
        return (BAD);
    }
    return (GOOD);
}

/*
 *  add a map-resolver to the list
 */

int
add_server(char *str_addr, glist_t *list)
{
    lisp_addr_t *       addr;
    glist_t *           addr_list;
    glist_entry_t *     it;

    addr_list = parse_ip_addr(str_addr);

    if (addr_list == NULL){
        OOR_LOG(LERR, "Error parsing address. Ignoring server with address %s",
                        str_addr);
        return (BAD);
    }
    glist_for_each_entry(it, addr_list) {
        addr = (lisp_addr_t *)glist_entry_data(it);

        /* Check that the afi of the map server matches with the default rloc afi
         * (if it's defined). */
        if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(addr)){
            OOR_LOG(LWRN, "The server %s will not be added due to the selected "
                    "default rloc afi (-a option)", str_addr);
            continue;
        }

        glist_add_tail(lisp_addr_clone(addr), list);
        OOR_LOG(LDBG_3,"The server %s has been added to the list",lisp_addr_to_char(addr));
    }

    glist_destroy(addr_list);

    return(GOOD);
}


int
add_map_server(glist_t *ms_list, char *str_addr, int key_type, char *key,
        uint8_t proxy_reply)
{
    lisp_addr_t *addr;
    map_server_elt *ms;
    glist_t *addr_list;
    glist_entry_t *it;

    if (str_addr == NULL || key_type == 0 || key == NULL){
        OOR_LOG(LERR, "Configuration file: Wrong Map Server configuration. "
                "Check configuration file");
        exit_cleanup();
    }

    if (key_type != HMAC_SHA_1_96){
        OOR_LOG(LERR, "Configuration file: Only SHA-1 (1) authentication is supported");
        exit_cleanup();
    }

    addr_list = parse_ip_addr(str_addr);

    if (addr_list == NULL){
        OOR_LOG(LERR, "Error parsing address. Ignoring Map Server %s",
                        str_addr);
        return (BAD);
    }
    glist_for_each_entry(it, addr_list) {
        addr = (lisp_addr_t *)glist_entry_data(it);

        /* Check that the afi of the map server matches with the default rloc afi
         * (if it's defined). */
        if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(addr)){
            OOR_LOG(LWRN, "The map server %s will not be added due to the selected "
                    "default rloc afi (-a option)", str_addr);
            continue;
        }

        ms = map_server_elt_new_init(addr,key_type,key,proxy_reply);
        if (ms == NULL){
            continue;
        }

        glist_add(ms, ms_list);
    }

    glist_destroy(addr_list);

    return(GOOD);
}


int
add_proxy_etr_entry(mcache_entry_t *petrs, char *str_addr, int priority,
        int weight)
{
    glist_t *addr_list;
    glist_entry_t *it;
    lisp_addr_t *addr;
    locator_t *locator;

    if (str_addr == NULL){
        OOR_LOG(LERR, "Configuration file: No interface specified for PETR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    addr_list = parse_ip_addr(str_addr);
    if (addr_list == NULL){
        OOR_LOG(LERR, "Error parsing RLOC address. Ignoring proxy-ETR %s",
                        str_addr);
        return (BAD);
    }
    glist_for_each_entry(it, addr_list) {
        addr = glist_entry_data(it);
        if (default_rloc_afi != AF_UNSPEC
                && default_rloc_afi != lisp_addr_ip_afi(addr)) {
            OOR_LOG(LWRN, "The PETR %s will not be added due to the selected "
                    "default rloc afi (-a)", str_addr);
            continue;
        }

        /* Create locator representing the proxy-etr and add it to the mapping */
        locator = locator_new_init(addr, UP, 0, 1, priority, weight, 255, 0);

        if (locator != NULL) {
            if (mapping_add_locator(mcache_entry_mapping(petrs), locator)!= GOOD){
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
link_iface_and_mapping(iface_t *iface, iface_locators *if_loct,
        map_local_entry_t *map_loc_e, int afi, int priority, int weight)
{
    mapping_t *mapping;
    locator_t *locator;

    mapping = map_local_entry_mapping(map_loc_e);

    /* Add mapping to the list of mappings associated to the interface */
    if (glist_contain(map_loc_e, if_loct->map_loc_entries) == FALSE){
        glist_add(map_loc_e,if_loct->map_loc_entries);
    }

    /* Create locator and assign to the mapping and  to iface_loct*/
    if (priority >= 0){
        if (afi == AF_INET){
            locator = locator_new_init(iface->ipv4_address,
                    iface->status,1,1, priority, weight, 255, 0);
            if (locator == NULL){
                return (BAD);
            }
            if (mapping_add_locator(mapping, locator) != GOOD) {
                locator_del(locator);
                return(BAD);
            }
            glist_add(locator,if_loct->ipv4_locators);
        }else{
            locator = locator_new_init(iface->ipv6_address,
                    iface->status,1,1, priority, weight, 255, 0);
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
add_rtr_iface(lisp_rtr_t *rtr, char *iface_name,int afi, int priority,
        int weight)
{
    iface_t *iface;
    iface_locators *if_loct;

    if (iface_name == NULL){
        OOR_LOG(LERR, "Configuration file: No interface specified for RTR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    if (priority < 0){
        OOR_LOG(LERR, "Configuration file: Discarding the interface %s of the RTR with afi %d due to the assigned priority",
                iface_name, afi);
        return (GOOD);
    }

    if (afi != 4 && afi !=6){
        OOR_LOG(LERR, "Configuration file: The rtr-iface->afi of the locator should be \"4\" (IPv4)"
                " or \"6\" (IPv6)");
        return (BAD);
    }

    afi = (afi == 4) ? AF_INET : AF_INET6;

    /* Check if the interface already exists. If not, add it*/
    if ((iface = get_interface(iface_name)) == NULL) {
        iface = add_interface(iface_name);
        if (!iface) {
            OOR_LOG(LWRN, "add_rtr_iface: Can't create interface %s",
                    iface_name);
            return(BAD);
        }
    }

    if (iface_configure (iface, afi)!= GOOD){
        OOR_LOG(LWRN, "add_rtr_iface: Can't configure addresses of interface %s",
                iface_name);
        return(BAD);
    }

    if_loct = (iface_locators *)shash_lookup(rtr->tr.iface_locators_table,iface_name);
    if (if_loct == NULL){
        if_loct = iface_locators_new(iface_name);
        shash_insert(rtr->tr.iface_locators_table, strdup(iface_name), if_loct);
    }

    if (!rtr->all_locs_map->fwd_policy_info) {
        if (rtr->tr.fwd_policy->init_map_loc_policy_inf(
                rtr->tr.fwd_policy_dev_parm,rtr->all_locs_map,NULL) != GOOD){
            OOR_LOG(LERR, "Couldn't initiate forward information for rtr localtors.");
            map_local_entry_del(rtr->all_locs_map);
            return (BAD);
        }
    }

    if (link_iface_and_mapping(iface, if_loct, rtr->all_locs_map, afi, priority, weight)
            != GOOD) {
        return(BAD);
    }
    /* Updated forwarding info */
    rtr->tr.fwd_policy->updated_map_loc_inf(rtr->tr.fwd_policy_dev_parm, rtr->all_locs_map);

    return(GOOD);
}

lisp_site_prefix_t *
build_lisp_site_prefix(lisp_ms_t *ms, char *eidstr, uint32_t iid, int key_type,
        char *key, uint8_t more_specifics, uint8_t proxy_reply, uint8_t merge,
        shash_t *lcaf_ht)
{
    lisp_addr_t *eid_prefix;
    lisp_addr_t *ht_prefix;
    lisp_site_prefix_t *site;

    if (iid > MAX_IID) {
        OOR_LOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = 0;
    }

    /* DON'T DELETE eid_prefix */
    eid_prefix = lisp_addr_new();
    if (lisp_addr_ippref_from_char(eidstr, eid_prefix) != GOOD) {
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        ht_prefix = shash_lookup(lcaf_ht, eidstr);
        if (!ht_prefix) {
            OOR_LOG(LERR, "Configuration file: Error parsing EID prefix %s",
                    eidstr);
            return (NULL);
        }
        eid_prefix = lisp_addr_clone(ht_prefix);
    }
    pref_conv_to_netw_pref(eid_prefix);
    site = lisp_site_prefix_init(eid_prefix, iid, key_type, key,
            more_specifics, proxy_reply, merge);
    lisp_addr_del(eid_prefix);
    return(site);
}




/* Parses an EID/RLOC (IP or LCAF) and returns a list of 'lisp_addr_t'.
 * Caller must free the returned value */
glist_t *
parse_lisp_addr(char *addr_str, shash_t *lcaf_ht)
{
    glist_t *addr_list;
    lisp_addr_t *addr;
    lisp_addr_t *lcaf;
    int res;

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
        lcaf = shash_lookup(lcaf_ht, addr_str);
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
        OOR_LOG(LERR, "Configuration file: Error parsing address %s",addr_str);
    }

    return(addr_list);
}


/* Parses a char (IP or FQDN) into a list of 'lisp_addr_t'.
 * Caller must free the returned value */
glist_t *
parse_ip_addr(char *addr_str)
{
    glist_t *addr_list;
    lisp_addr_t *addr;
    int res;

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
        OOR_LOG(LERR, "Configuration file: Error parsing the address %s",addr_str);
    }

    return(addr_list);
}

/*
 *  Converts the hostname into IPs which are added to a list of lisp_addr_t
 *  @param addr_str String conating fqdn address or de IP address
 *  @param preferred_afi Indicates the afi of the IPs to be added in the list
 *  @return List of addresses (glist_t *)
 */
glist_t *fqdn_to_addresses(char *addr_str, const int preferred_afi)
{
    glist_t *addr_list;
    lisp_addr_t *addr;
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    struct addrinfo *p;
    struct sockaddr *s_addr;
    int err;

    addr_list = glist_new_managed((glist_del_fct)lisp_addr_del);

    memset(&hints, 0, sizeof hints);

    hints.ai_family = preferred_afi;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;    /* we are interested in UDP only */

    if ((err = getaddrinfo( addr_str, 0, &hints, &servinfo)) != 0) {
        OOR_LOG( LWRN, "fqdn_to_addresses: %s", gai_strerror(err));
        return( NULL );
    }
    /* iterate over addresses */
    for (p = servinfo; p != NULL; p = p->ai_next) {

        if ((addr = lisp_addr_new_lafi(LM_AFI_IP))== NULL){
            OOR_LOG( LWRN, "fqdn_to_addresses: Unable to allocate memory for lisp_addr_t");
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

        OOR_LOG(LDBG_1, "converted addr_str [%s] to address [%s]", addr_str, lisp_addr_to_char(addr));
        /* depending on callback return, we continue or not */

        glist_add(addr,addr_list);
    }
    freeaddrinfo(servinfo); /* free the linked list */
    return (addr_list);
}


static glist_t *
process_rloc_address(conf_loc_t *conf_loc, oor_ctrl_dev_t *dev,
        shash_t *lcaf_ht, uint8_t is_local)
{
    glist_t *loct_list;
    locator_t *locator;
    glist_t *addr_list;
    glist_entry_t *it;
    lisp_addr_t *address;
    lisp_addr_t *ip_addr;
    iface_t *iface;
    char *iface_name;
    int ip_afi;
    lisp_xtr_t *xtr;
    shash_t *iface_lctrs;
    iface_locators *if_loct;


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
        /* Remove locators not compatibles with default RLOC */
        if (default_rloc_afi != AF_UNSPEC &&
                lisp_addr_ip_afi(lisp_addr_get_ip_addr(address)) != default_rloc_afi){

            OOR_LOG(LDBG_1, "Configuration file: RLOC address %s can not be added due to "
                    "the selected default rloc afi (-a option)", lisp_addr_to_char(address));
            continue;
        }
        if (lisp_addr_lafi(address) == LM_AFI_IPPREF){
            OOR_LOG(LERR, "Configuration file: RLOC address can not be a prefix: %s ",
                    lisp_addr_to_char(address));
            continue;
        }

        if (is_local){
            /* Decide IP address to be used to lookup the interface */
            if (lisp_addr_is_lcaf(address) == TRUE) {
                ip_addr = lisp_addr_get_ip_addr(address);
                if (ip_addr == NULL) {
                    OOR_LOG(LERR, "Configuration file: Can't determine RLOC's IP "
                            "address %s", lisp_addr_to_char(address));
                    return(NULL);
                }
            } else {
                ip_addr = address;
            }
            ip_afi = lisp_addr_ip_afi(ip_addr);

            if (ip_afi == AF_INET6){
                if (ipv6_scope == SCOPE_GLOBAL){
                    if (!IN6_IS_ADDR_GLOBAL(ip_addr_get_v6(lisp_addr_ip(ip_addr)))){
                        OOR_LOG(LERR, "Configuration file: Selected IPv6 address %s doesn't match the IPv6 global scope (2000::/3). Ignoring it...",
                                lisp_addr_to_char(ip_addr));
                        continue;
                    }
                }
                if (ipv6_scope == SCOPE_SITE_LOCAL){
                    if (!IN6_IS_ADDR_SITE_LOCAL(ip_addr_get_v6(lisp_addr_ip(ip_addr)))){
                        OOR_LOG(LERR, "Configuration file: Selected IPv6 address %s doesn't match the IPv6 local site scope (FEC0::/10).  Ignoring it...",
                                lisp_addr_to_char(ip_addr));
                        continue;
                    }
                }
            }

            /* Find the interface name associated to the RLOC */
            if (!(iface_name = get_interface_name_from_address(ip_addr))) {
                OOR_LOG(LERR, "Configuration file: Can't find interface for RLOC %s",
                        lisp_addr_to_char(ip_addr));
                continue;
            }
            /* Find the interface */
            iface = get_interface(iface_name);
            if (iface == NULL){
                iface = add_interface(iface_name);
                if (iface == NULL){
                    OOR_LOG(LERR, "Configuration file: Can't add interface with name %s",
                            iface_name);
                    continue;
                }
            }



            iface_configure (iface, ip_afi);

            if (lisp_addr_cmp(ip_addr, iface_address(iface, ip_afi))!=0){
                OOR_LOG(LERR, "Configuration file: Can't add address %s. The interface don't have "
                        " a gateway associated or the address is not default src address used to reach "
                        " the gateway of the interface", iface_name);
                continue;
            }

            locator = locator_new_init(address, iface->status,1,1,conf_loc->priority, conf_loc->weight,
                    conf_loc->mpriority, conf_loc->mweight);

            /* If the locator is for a local mapping, associate the locator with the interface */
            if (locator != NULL && (dev->mode == xTR_MODE || dev->mode == MN_MODE)){
                xtr  = lisp_xtr_cast(ctrl_dev);
                iface_lctrs = xtr->tr.iface_locators_table;
                if_loct = (iface_locators *)shash_lookup(iface_lctrs, iface_name);
                if (if_loct == NULL){
                    if_loct = iface_locators_new(iface_name);
                    shash_insert(xtr->tr.iface_locators_table, strdup(iface_name), if_loct);
                }
                if (lisp_addr_ip_afi(ip_addr) == AF_INET){
                    glist_add(locator,if_loct->ipv4_locators);
                }else{
                    glist_add(locator,if_loct->ipv6_locators);
                }
            }
        } else {
            locator = locator_new_init(address, UP, 1, 1, conf_loc->priority, conf_loc->weight, 255, 0);
        }
        if (locator != NULL){
            glist_add(locator,loct_list);
            OOR_LOG(LDBG_2,"parse_rloc_address: Locator structure created: \n %s",
                    locator_to_char(locator));
        }
    }
    glist_destroy(addr_list);

    return (loct_list);
}

static locator_t *
process_rloc_interface(conf_loc_iface_t * conf_loc_iface, oor_ctrl_dev_t * dev)
{
    locator_t *locator;
    lisp_addr_t *address;
    iface_t *iface;
    lisp_xtr_t *xtr;
    shash_t *iface_lctrs;
    iface_locators *if_loct;

    if (conf_loc_iface == NULL){
        return (NULL);
    }

    /* Remove locators not compatibles with default RLOC */
    if (default_rloc_afi != AF_UNSPEC && conf_loc_iface->afi != default_rloc_afi){
        OOR_LOG(LDBG_1, "Configuration file: RLOC of the interface %s can not be added due to "
                "the selected default rloc afi (-a option)", conf_loc_iface->interface);
        return (NULL);
    }

    if (validate_priority_weight(conf_loc_iface->priority, conf_loc_iface->weight) != GOOD) {
        return (NULL);
    }

    /* Find the interface */
    if (!(iface = get_interface(conf_loc_iface->interface))) {
        if (!(iface = add_interface(conf_loc_iface->interface))) {
            OOR_LOG(LDBG_1, "Configuration file: Couldn't add interface %s",conf_loc_iface->interface);
            return (BAD);
        }
    }

    iface_configure (iface, conf_loc_iface->afi);

    if (conf_loc_iface->afi == AF_INET){
        address = iface->ipv4_address;
    }else{
        address = iface->ipv6_address;
    }

    locator = locator_new_init(address, iface->status,1,1,conf_loc_iface->priority,
            conf_loc_iface->weight,conf_loc_iface->mpriority, conf_loc_iface->mweight);

    OOR_LOG(LDBG_2,"parse_rloc_address: Locator structure created: \n %s",
                        locator_to_char(locator));

    /* If the locator is for a local mapping, associate the locator with the interface */
    if (locator != NULL && (dev->mode == xTR_MODE || dev->mode == MN_MODE)){
        xtr  = lisp_xtr_cast(ctrl_dev);
        iface_lctrs = xtr->tr.iface_locators_table;
        if_loct = (iface_locators *)shash_lookup(iface_lctrs, conf_loc_iface->interface);
        if (if_loct == NULL){
            if_loct = iface_locators_new(conf_loc_iface->interface);
            shash_insert(xtr->tr.iface_locators_table, strdup(conf_loc_iface->interface), if_loct);
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
process_mapping_config(oor_ctrl_dev_t * dev, shash_t * lcaf_ht,
        conf_mapping_t * conf_mapping, uint8_t is_local)
{

    mapping_t *mapping;
    glist_t *loct_list;
    glist_entry_t *it;
    locator_t *locator;
    glist_t *addr_list;
    lisp_addr_t *eid_prefix, *ip_eid_prefix;
    lisp_xtr_t *xtr=NULL;
    conf_loc_t *conf_loc;
    conf_loc_iface_t *conf_loc_iface;
    glist_entry_t *conf_it;
    int iidmlen;
    switch (dev->mode){
        case xTR_MODE:
        case MN_MODE:
            xtr  = lisp_xtr_cast(ctrl_dev);
            break;
        default:
            break;
        }

    addr_list = parse_lisp_addr(conf_mapping->eid_prefix, lcaf_ht);

    if (addr_list == NULL || glist_size(addr_list) != 1){
        return NULL;
    }

    ip_eid_prefix = (lisp_addr_t *)glist_first_data(addr_list);
    pref_conv_to_netw_pref(ip_eid_prefix);

    if (conf_mapping->iid > MAX_IID || conf_mapping->iid < 0) {
        OOR_LOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "set ID to 0", conf_mapping->iid, MAX_IID);
        conf_mapping->iid = 0;
    }
    if (conf_mapping->iid > 0){
        iidmlen = 32;
        eid_prefix = lisp_addr_new_init_iid(conf_mapping->iid, ip_eid_prefix, iidmlen);
    }else{
        eid_prefix = lisp_addr_clone(ip_eid_prefix);
    }

    if (conf_mapping->ttl <1){
        conf_mapping->ttl = 1;
        OOR_LOG(LWRN,"Configuration file: Minimum TTL value is 1. Set TTL to 1");
    }

    /* Create mapping */
    mapping = mapping_new_init(eid_prefix);
    if (mapping == NULL){
        return(NULL);
    }

    mapping_set_ttl(mapping, conf_mapping->ttl);
    if (is_local){
        mapping_set_auth(mapping, 1);
    }

    /* no need for the prefix */
    lisp_addr_del(eid_prefix);
    glist_destroy(addr_list);

    /* Create and add locators */
    glist_for_each_entry(conf_it,conf_mapping->conf_loc_list){
        conf_loc = (conf_loc_t *)glist_entry_data(conf_it);
        loct_list = process_rloc_address(conf_loc, dev, lcaf_ht, is_local);
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
                OOR_LOG(LERR,"Configuration file: Duplicated RLOC with address %s "
                        "for EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL && is_local){
                    iface_locators_unattach_locator(xtr->tr.iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
            if (mapping_add_locator(mapping, locator) != GOOD){
                OOR_LOG(LDBG_1,"parse_mapping: Couldn't add RLOC with address %s "
                        "to the mapping with EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL && is_local){
                    iface_locators_unattach_locator(xtr->tr.iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }

        }
        glist_destroy(loct_list);
    }

    if (is_local){
        glist_for_each_entry(conf_it,conf_mapping->conf_loc_iface_list){
            conf_loc_iface = (conf_loc_iface_t *)glist_entry_data(conf_it);
            locator = process_rloc_interface(conf_loc_iface, dev);
            if (locator == NULL){
                continue;
            }
            /* Check that the locator is not already added */
            if (mapping_get_loct_with_addr(mapping, locator_addr(locator)) != NULL){
                OOR_LOG(LERR,"Configuration file: Duplicated RLOC with address %s "
                        "for EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL){
                    iface_locators_unattach_locator(xtr->tr.iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
            if (mapping_add_locator(mapping, locator) != GOOD){
                OOR_LOG(LDBG_1,"parse_mapping: Couldn't add RLOC with address %s "
                        "to the mapping with EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL){
                    iface_locators_unattach_locator(xtr->tr.iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
        }
    }

    return (mapping);
}


int
add_local_db_map_local_entry(map_local_entry_t *map_loca_entry, lisp_xtr_t *xtr)
{
	lisp_addr_t *eid = map_local_entry_eid(map_loca_entry);
    if (map_loca_entry == NULL){
        OOR_LOG(LERR, "Can't add mapping (NULL)");
        return (BAD);
    }

    if (local_map_db_lookup_eid_exact(xtr->local_mdb, eid) == NULL){
        if (local_map_db_add_entry(xtr->local_mdb, map_loca_entry) == GOOD){
            OOR_LOG(LDBG_1, "Added EID prefix %s in the database.",
                    lisp_addr_to_char(eid));
            iface_locators_attach_map_local_entry(xtr->tr.iface_locators_table,map_loca_entry);
        }else{
            OOR_LOG(LERR, "Can't add EID prefix %s. Discarded ...",
                    lisp_addr_to_char(eid));
            goto err;
        }
    }else{
        OOR_LOG(LERR, "Configuration file: Duplicated EID prefix %s. Discarded ...",
                lisp_addr_to_char(eid));
        goto err;
    }

    return(GOOD);
err:
    iface_locators_unattach_mapping_and_loct(
            xtr->tr.iface_locators_table,
            map_loca_entry);

    return(BAD);
}

int
ms_add_rtr_node(lisp_ms_t *ms, char *name, char *addr_str, char *key)
{
    ms_rtr_node_t *rtr;
    glist_t *addr_lst;
    lisp_addr_t *addr;

    if (!name || !addr_str || !key){
        OOR_LOG(LERR, "ms-rtr-node needs to have assigned a name, an address and a key");
        return (BAD);
    }
    if (shash_lookup(ms->rtrs_table_by_name,name) != NULL){
        OOR_LOG(LERR, "MS rtr node \"%s\" already exists",name);
        return (BAD);
    }


    addr_lst = parse_ip_addr(addr_str);
    if (!addr_lst || glist_size(addr_lst)==0){
        glist_destroy(addr_lst);
        return (BAD);
    }
    if (glist_size(addr_lst) >1){
        OOR_LOG(LERR, "ms-rtr-node hostname %s resolves to more than one IP. Use one rtr-node element"
                "for each IP", addr_str);
        glist_destroy(addr_lst);
        return (BAD);
    }
    addr = (lisp_addr_t *)glist_first_data(addr_lst);
    if (shash_lookup(ms->rtrs_table_by_ip,lisp_addr_to_char(addr)) != NULL){
        OOR_LOG(LERR, "MS rtr node with address \"%s\" already exists",lisp_addr_to_char(addr));
        return (BAD);
    }
    rtr = ms_rtr_node_new_init(name,addr,key);
    glist_destroy(addr_lst);
    if (!rtr){
        return (BAD);
    }

    shash_insert(ms->rtrs_table_by_name,strdup(rtr->id),rtr);
    shash_insert(ms->rtrs_table_by_ip,strdup(lisp_addr_to_char(rtr->addr)),rtr);
    OOR_LOG(LDBG_1,"New RTR node added -> name: \"%s\", addr: %s", rtr->id, lisp_addr_to_char(rtr->addr));

    return (GOOD);
}

int
ms_add_rtr_set(lisp_ms_t *ms, char *name, int ttl, glist_t *rtr_nodes)
{
    ms_rtr_set_t *rtr_set;
    glist_entry_t *rtr_it;
    char *rtr_id;
    ms_rtr_node_t *rtr;

    if (!name) {
        OOR_LOG(LERR, "ms-rtr-set name option required");
        return (BAD);
    }
    if(shash_lookup(ms->rtrs_set_table,name)!= NULL){
        OOR_LOG(LERR, "ms-rtr-set \"%s\" already exists",name);
        return (BAD);
    }
    if (glist_size (rtr_nodes) == 0){
        OOR_LOG(LERR, "ms-rtr-set \"%s\" doesn't have any rtr assigned", name);
        return (BAD);
    }
    if (ttl <1 ){
        OOR_LOG(LERR, "ms-rtr-set \"%s\" doesn't have a valid ttl value", name);
        return (BAD);
    }

    rtr_set = ms_rtr_set_new_init(name, ttl);
    if (!rtr_set){
        return (BAD);
    }

    glist_for_each_entry (rtr_it, rtr_nodes){
        rtr_id = (char *)glist_entry_data(rtr_it);
        rtr = (ms_rtr_node_t *)shash_lookup(ms->rtrs_table_by_name,rtr_id);
        if (!rtr){
            OOR_LOG(LERR, "rtr node \"%s\" assigned to the ms-rtr-set \"%s\" doesn't exist",
                    rtr_id, name);
            ms_rtr_set_del(rtr_set);
            return (BAD);
        }
        glist_add(rtr,rtr_set->rtr_list);
    }
    shash_insert(ms->rtrs_set_table,strdup(name),rtr_set);

    OOR_LOG(LDBG_1,"New RTR set added:");
    ms_rtr_set_dump(rtr_set, LDBG_1);

    return (GOOD);
}

int
ms_advertised_rtr_set(lisp_ms_t *ms, char *rtr_set_name)
{
    if (!rtr_set_name){
        ms->def_rtr_set = NULL;
        OOR_LOG(LDBG_1,"No RTR will be advertised");
        return(GOOD);
    }
    ms->def_rtr_set = (ms_rtr_set_t *)shash_lookup(ms->rtrs_set_table,rtr_set_name);
    if (!ms->def_rtr_set){
        OOR_LOG(LERR, "ms-rtr-set %s doesn't exist. It cannot be advertised", rtr_set_name);
        return (BAD);
    }

    return (GOOD);
}

int
rtr_add_rtr_ms_node(lisp_rtr_t *rtr, char *addr_str, char *key, char *draft_version)
{
    glist_t *addr_lst;
    lisp_addr_t *addr;
    nat_version nat_version;
    rtr_ms_node_t *ms_node;

    if (!addr_str || !key){
        OOR_LOG(LERR, "Configuration file: rtr-ms-node needs to have assigned an address and a key");
        return (BAD);
    }

    if (strcmp(draft_version,"OLD")==0){
        nat_version = NAT_PREV_DRAFT_4;
    }else if (strcmp(draft_version,"NEW")==0){
        nat_version = NAT_AFTER_DRAFT_4;
    }else{
        OOR_LOG(LERR, "Unknown nat draft-version type: %s",draft_version);
        return (BAD);
    }


    addr_lst = parse_ip_addr(addr_str);
    if (!addr_lst || glist_size(addr_lst)==0){
        glist_destroy(addr_lst);
        return (BAD);
    }
    if (glist_size(addr_lst) >1){
        OOR_LOG(LERR, "ms-rtr-node hostname %s resolves to more than one IP. Use one rtr-ms-node element"
                "for each IP", addr_str);
        glist_destroy(addr_lst);
        return (BAD);
    }
    addr = (lisp_addr_t *)glist_first_data(addr_lst);
    ms_node = rtr_ms_node_new_init(addr, key, nat_version);
    glist_destroy(addr_lst);
    if (!ms_node){
        return (BAD);
    }
    shash_insert(rtr->rtr_ms_table, strdup(lisp_addr_to_char(ms_node->addr)),ms_node);
    OOR_LOG(LDBG_1,"RTR: Added MS configuration for NAT use: %s", rtr_ms_node_to_char(ms_node));

    return (GOOD);
}

void
tr_set_site_ID(lisp_xtr_t *xtr, uint64_t site_id)
{
    xtr->site_id = site_id;
}
int
tr_set_xTR_ID(lisp_xtr_t *xtr)
{
	FILE *xtr_id_file;
	lisp_xtr_id *xtr_id = &(xtr->xtr_id);
	int ctr = 0;
	char *path;
	char file[200];
	char line[80];
	char part_xtr_id_str[3];

	path = dirname(config_file);
	if (snprintf(file,sizeof(file),"%s/%s",path, DEVICE_ID_FILE) >= sizeof(file)){
	    OOR_LOG(LERR,"File name path too long");
	    return (BAD);
	}
	xtr_id_file = fopen(file, "r");
	if (! xtr_id_file)
	{
		xtr_id_file = fopen(file, "w");
		if (!xtr_id_file){
			OOR_LOG(LERR,"Could not generate device id file \"%s\": %s",file , strerror(errno));
			return (BAD);
		}
		for (ctr=0; ctr<16; ctr++){
			xtr_id->byte[ctr] = (uint8_t)random();
		}
		fprintf(xtr_id_file,"%s", get_char_from_xTR_ID(xtr_id));
	}else{
		if (fgets(line, sizeof(line),xtr_id_file) == NULL || strlen(line) != 32){
			fclose(xtr_id_file);
			xtr_id_file = fopen(file, "w");
			if (!xtr_id_file){
				OOR_LOG(LERR,"%s file has wrong format and could not be regenerated: %s",file , strerror(errno));
				return (BAD);
			}
			for (ctr=0; ctr<16; ctr++){
				xtr_id->byte[ctr] = (uint8_t)random();
			}
			fprintf(xtr_id_file,"%s", get_char_from_xTR_ID(xtr_id));
		}else{
			part_xtr_id_str[2] = '\0';
			for (ctr=0; ctr<16; ctr++){
				part_xtr_id_str[0] = line[0+ctr*2];
				part_xtr_id_str[1] = line[1+ctr*2];
				xtr_id->byte[ctr] = (uint8_t)strtol(part_xtr_id_str, NULL, 16);
			}
		}
	}
	fclose(xtr_id_file);

	OOR_LOG(LDBG_2,"tr_set_xTR_ID: xTR_ID initialiazed with value: %s",
			get_char_from_xTR_ID(xtr_id));

	return(GOOD);
}
