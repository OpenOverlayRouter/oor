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

#include "oor_api_internals.h"
#include "oor_config_functions.h"
#include "../lib/oor_log.h"
#include "../liblisp/liblisp.h"
#include "../lib/mem_util.h"
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>


lisp_addr_t * lxml_lcaf_get_lisp_addr (xmlNodePtr xml_lcaf);

xmlNodePtr
get_inner_xmlNodePtr(xmlNodePtr parent, char *name)
{
    xmlNodePtr node;
    xmlChar *xmlName = xmlCharStrdup(name);

    node = xmlFirstElementChild(parent);

    while (node != NULL){
        if(xmlStrEqual(node->name,xmlName)){
            break;
        }
        node = xmlNextElementSibling(node);
    }
    free(xmlName);
    return (node);
}

inline xmlNodePtr
lxml_get_next_node(xmlNodePtr node)
{
    char * name = (char *)node->name;
    do {
        node = xmlNextElementSibling(node);
    }while(node != NULL && strcmp((char *)node->name,name) != 0);
    return (node);
}

lisp_addr_t *
lxml_get_lisp_addr(xmlNodePtr xml_address)
{
    lisp_addr_t *addr = NULL;
    char *str_afi;
    uint8_t mask;

    str_afi = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"afi"));


    if (strcmp(str_afi,"ipv4")==0){
        addr = lisp_addr_new();
        lisp_addr_ip_from_char((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"ipv4")),addr);
    }else if (strcmp(str_afi,"ipv6") == 0){
        addr = lisp_addr_new();
        lisp_addr_ip_from_char((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"ipv6")),addr);
    }else if (strcmp(str_afi,"lcaf") == 0){

    }else{
        OOR_LOG(LDBG_2,"OOR_API->lxml_get_lisp_addr: Afi not suppoted: %s",str_afi);
        return NULL;
    }

    if (get_inner_xmlNodePtr(xml_address,"mask") != NULL){
        mask = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"mask")));
        lisp_addr_ip_to_ippref(addr);
        ip_prefix_set_plen(lisp_addr_get_ippref(addr),mask);
    }

    return (addr);
}

char *
lxml_get_char_lisp_addr(xmlNodePtr xml_address, char *name, shash_t *lcaf_ht)
{
    char *lisp_address_str;
    char *addr;
    char *mask;
    char *str_afi;
    xmlNodePtr xml_lcaf;
    lisp_addr_t *laddr;

    str_afi = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"afi"));

    if (strcmp(str_afi,"ipv4")==0){
        addr = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"ipv4"));
    }else if (strcmp(str_afi,"ipv6") == 0){
        addr = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"ipv6"));
    }else if (strcmp(str_afi,"lcaf") == 0){
        free(str_afi);
        /* Process lcaf address */
        xml_lcaf = get_inner_xmlNodePtr(xml_address,"lcaf");
        laddr = lxml_lcaf_get_lisp_addr(xml_lcaf);
        if (laddr == NULL){
            OOR_LOG(LDBG_2,"OOR_API->lxml_get_char_lisp_addr: Error processing lcaf address");
            return (NULL);
        }
        shash_insert(lcaf_ht,strdup(name),laddr);
        return (strdup(name));
    }else{
        OOR_LOG(LDBG_2,"OOR_API->lxml_get_char_lisp_addr: Afi not suppoted: %s",str_afi);
        free(str_afi);
        return (NULL);
    }
    free(str_afi);

    /* Process a prefix */
    if (get_inner_xmlNodePtr(xml_address,"mask") != NULL){
        mask = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"mask"));
        lisp_address_str = xmalloc(strlen(addr)+strlen(mask)+1+1);
        sprintf(lisp_address_str,"%s/%s",addr,mask);
        free(addr);
        free(mask);
    }else{
        lisp_address_str = addr;
    }

    return lisp_address_str;
}

int
lxml_get_iid_lisp_addr(xmlNodePtr xml_address)
{
    int iid;

    if (get_inner_xmlNodePtr(xml_address,"instance-id") != NULL){
        iid = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_address,"instance-id")));
        return(iid);
    }
    return (0);
}



lisp_addr_t *
lxml_lcaf_get_lisp_addr (xmlNodePtr xml_lcaf)
{
    lisp_addr_t *lcaf_addr;
    lisp_addr_t *addr;
    char *str_addr;
    char *lcaf_type;
    char *elp_bits;
    uint8_t lookup_bit = FALSE;
    uint8_t rloc_probe_bit = FALSE;
    uint8_t strict_bit = FALSE;

    xmlNodePtr xml_elp;
    xmlNodePtr xml_elp_node;
    elp_t *elp;
    elp_node_t *enode;

    lcaf_type = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_lcaf,"lcaf-type"));

    if (strcmp (lcaf_type,"explicit-locator-path") == 0){
        lcaf_addr = lisp_addr_elp_new();
        elp = (elp_t *)lisp_addr_lcaf_addr(lcaf_addr);
        xml_elp = get_inner_xmlNodePtr(xml_lcaf,"explicit-locator-path");
        xml_elp_node = get_inner_xmlNodePtr(xml_elp,"hop");
        while (xml_elp_node != NULL){
            /* Process address */
            str_addr = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_elp_node,"address"));
            addr = lisp_addr_new();
            lisp_addr_ip_from_char(str_addr,addr);
            free(str_addr);
            /* Process bits */
            elp_bits = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_elp_node,"lrs-bits"));
            if (strstr(elp_bits,"lookup") != NULL){
                lookup_bit = TRUE;
            }
            if (strstr(elp_bits,"rloc-probe") != NULL){
                rloc_probe_bit = TRUE;
            }
            if (strstr(elp_bits,"strict") != NULL){
                strict_bit = TRUE;
            }
            free (elp_bits);
            enode = elp_node_new_init(addr, lookup_bit, rloc_probe_bit, strict_bit);
            if (enode != NULL){
                elp_add_node(elp, enode);
            }
            lisp_addr_del(addr);
            xml_elp_node = lxml_get_next_node(xml_elp_node);
        }
    }else {
        OOR_LOG(LDBG_2,"OOR_API->lxml_lcaf_get_lisp_addr: LCAF type not suppoted: %s",lcaf_type);
        return (NULL);
    }
    free(lcaf_type);

    return (lcaf_addr);
}

conf_mapping_t *
lxml_get_conf_mapping (xmlNodePtr xml_local_eid, shash_t * lcaf_ht)
{
    conf_mapping_t *conf_mapping;
    conf_loc_t *conf_loct;
    conf_loc_iface_t *conf_loct_iface;
    xmlNodePtr xml_rlocs;
    xmlNodePtr xml_rloc;
    xmlNodePtr xml_ifce_rloc;
    xmlNodePtr xml_addr_rloc;
    char *eid;
    char *rloc;
    char *eid_name;
    char *rloc_name;
    int ttl = 0;
    int prty = 255;
    int wght = 0;
    int mprty = 255;
    int mwght = 0;

    eid_name = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_local_eid,"id"));
    eid = lxml_get_char_lisp_addr(get_inner_xmlNodePtr(xml_local_eid,"eid-address"),eid_name,lcaf_ht);

    free(eid_name);
    if (eid == NULL){
        OOR_LOG(LDBG_1,"OOR_API->oor_api_nc_xtr_mapdb_add: Error processing EID");
        return NULL;
    }
    conf_mapping = conf_mapping_new();
    if (conf_mapping == NULL){
        free (eid);
        return NULL;
    }
    conf_mapping->eid_prefix = eid;
    conf_mapping->iid = lxml_get_iid_lisp_addr(get_inner_xmlNodePtr(xml_local_eid,"eid-address"));
    if (get_inner_xmlNodePtr(xml_local_eid,"record-ttl") != NULL){
        ttl = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_local_eid,"record-ttl")));
        conf_mapping->ttl = ttl;
    }

    /* Process locators */
    xml_rlocs = get_inner_xmlNodePtr(xml_local_eid,"rlocs");
    xml_rloc = get_inner_xmlNodePtr(xml_rlocs,"rloc");
    while (xml_rloc != NULL){
        if (get_inner_xmlNodePtr(xml_rloc,"priority") != NULL){
            prty = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"priority")));
        }
        if (get_inner_xmlNodePtr(xml_rloc,"weight") != NULL){
            wght = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"weight")));
        }
        if (get_inner_xmlNodePtr(xml_rloc,"mpriority") != NULL){
            mprty = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"multicast-priority")));
        }
        if (get_inner_xmlNodePtr(xml_rloc,"mweight") != NULL){
            mwght = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"multicast-weight")));
        }
        if (get_inner_xmlNodePtr(xml_rloc,"interface")!=NULL){
            xml_ifce_rloc = get_inner_xmlNodePtr(xml_rloc,"interface");
            conf_loct_iface = conf_loc_iface_new_init((char*)xmlNodeGetContent(xml_ifce_rloc),AF_INET,prty,wght,mprty,mwght);
            if (conf_loct_iface == NULL){
                conf_mapping_destroy(conf_mapping);
                return NULL;
            }
            glist_add(conf_loct_iface,conf_mapping->conf_loc_iface_list);
            conf_loct_iface = conf_loc_iface_new_init((char*)xmlNodeGetContent(xml_ifce_rloc),AF_INET6,prty,wght,mprty,mwght);
            if (conf_loct_iface == NULL){
                conf_mapping_destroy(conf_mapping);
                return NULL;
            }
            glist_add(conf_loct_iface,conf_mapping->conf_loc_iface_list);
        }else if (get_inner_xmlNodePtr(xml_rloc,"locator-address")!=NULL){
            rloc_name = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"name"));
            xml_addr_rloc = get_inner_xmlNodePtr(xml_rloc,"locator-address");
            rloc = lxml_get_char_lisp_addr(xml_addr_rloc, rloc_name, lcaf_ht);
            free(rloc_name);
            if (rloc == NULL){
                conf_mapping_destroy(conf_mapping);
                return NULL;
            }
            conf_loct = conf_loc_new_init(rloc,prty,wght,mprty,mwght);
            free(rloc);
            if (conf_loct == NULL){
                conf_mapping_destroy(conf_mapping);
                return NULL;
            }
            glist_add(conf_loct,conf_mapping->conf_loc_list);
        }else{
            conf_mapping_destroy(conf_mapping);
            OOR_LOG(LDBG_1,"OOR_API->oor_api_nc_xtr_mapdb_add: Error processing locator");
            return NULL;
        }
        xml_rloc = lxml_get_next_node(xml_rloc);
    }

    return (conf_mapping);
}

int
lxml_update_map_server_list(xmlNodePtr xml_map_servers, uint8_t proxy_reply,
        glist_t *map_servers_list)
{
    xmlNodePtr xml_map_sever;
    xmlNodePtr xml_address;
    xmlNodePtr xml_key_type;
    xmlNodePtr xml_key;
    map_server_elt *ms;
    char *str_addr;
    char *key_type_aux;
    int key_type;
    char *key;
    lisp_addr_t *ms_addr;
    glist_entry_t *ms_it;

    xml_map_sever = get_inner_xmlNodePtr(xml_map_servers,"map-server");
    while (xml_map_sever != NULL){
        /* Check parameters */
        xml_address = get_inner_xmlNodePtr(xml_map_sever,"address");
        if ((xml_address) == NULL){
            OOR_LOG (LWRN,"lxml_update_map_server_list: No map server address configured");
            return (BAD);
        }
        if ((xml_key_type = get_inner_xmlNodePtr(xml_map_sever,"auth-key-type")) == NULL){
            OOR_LOG (LWRN,"lxml_update_map_server_list: No authentication key type specified");
            return (BAD);
        }
        if ((xml_key = get_inner_xmlNodePtr(xml_map_sever,"auth-key")) == NULL){
            OOR_LOG (LWRN,"lxml_update_map_server_list: No authentication key specified");
            return (BAD);
        }
        str_addr = (char*)xmlNodeGetContent(xml_address);
        key = (char*)xmlNodeGetContent(xml_key);
        key_type_aux = (char*)xmlNodeGetContent(xml_key_type);
        if (strcmp(key_type_aux,"none")==0){
            key_type = NO_KEY;
        }else if (strcmp(key_type_aux,"hmac-sha-1-96")==0){
            key_type = HMAC_SHA_1_96;
        }else if (strcmp(key_type_aux,"hmac-sha-256-128")==0){
            key_type = HMAC_SHA_256_128;
        }
        free(key_type_aux);
        if (key_type != HMAC_SHA_1_96){
            OOR_LOG(LERR, "Configuraton file: Only SHA-1 (1) authentication is supported");
            free(str_addr);
            free(key);
            return (BAD);
        }

        ms_addr = lisp_addr_new();
        if (ms_addr == NULL){
            OOR_LOG(LWRN,"lxml_update_map_server_list: Couldn't allocate memory for a lisp_addr_t structure");
            free(str_addr);
            free(key);
            return (BAD);
        }
        if (lisp_addr_ip_from_char(str_addr,ms_addr) != GOOD){
            OOR_LOG(LWRN,"lxml_update_map_server_list: Error processing address: %s",str_addr);
            free(str_addr);
            free(key);
            return (BAD);
        }
        free(str_addr);

        /* Check if the Map Server is already in the list */
        glist_for_each_entry(ms_it, map_servers_list) {
            ms = (map_server_elt *)glist_entry_data(ms_it);
            if (lisp_addr_cmp(ms->address,ms_addr) == 0){
                lisp_addr_del(ms_addr);
                free(key);
                OOR_LOG(LDBG_2,"lxml_update_map_server_list: Map server %s already exist. Skipping it ...",
                        lisp_addr_to_char(ms_addr));
                xml_map_sever = lxml_get_next_node(xml_map_sever);
                continue;
            }
        }

        /* Check default afi */
        if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(ms_addr)){
            OOR_LOG(LWRN, "The map server %s will not be added due to the selected "
                    "default rloc afi (-a option)", str_addr);
            lisp_addr_del(ms_addr);
            free(key);
            xml_map_sever = lxml_get_next_node(xml_map_sever);
            continue;
        }
        /* Create map server structure and add to the list */
        ms = map_server_elt_new_init(ms_addr,key_type,key,proxy_reply);
        free(key);
        lisp_addr_del(ms_addr);
        if (ms == NULL){
            return (BAD);
        }
        glist_add(ms,map_servers_list);
        xml_map_sever = lxml_get_next_node(xml_map_sever);
    }

    return(GOOD);
}


int
oor_api_init_server(oor_api_connection_t *conn)
{

	int error;

    conn->context = zmq_ctx_new();
    OOR_LOG(LDBG_3,"OOR_API: zmq_ctx_new errno: %s\n",zmq_strerror (errno));

    //Request-Reply communication pattern (Server side)
    conn->socket = zmq_socket(conn->context, ZMQ_REP);
    OOR_LOG(LDBG_3,"OOR_API: zmq_socket: %s\n",zmq_strerror (errno));

    //Attachment point for other processes
    error = zmq_bind(conn->socket, IPC_FILE);

    if (error != 0){
        OOR_LOG(LDBG_2,"OOR_API: Error while ZMQ binding on server: %s\n",zmq_strerror (error));
    	goto err;
    }

    OOR_LOG(LDBG_2,"OOR_API: API server initiated using ZMQ\n");

    return (GOOD);

err:
    OOR_LOG(LERR,"OOR_API: The API server couldn't be initialized.\n");
    return (BAD);

}

int
oor_api_xtr_mr_create(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{

    lisp_xtr_t *xtr;
    uint8_t *result_msg;
    int result_msg_len;
    glist_t *list;
    xmlDocPtr doc;
    xmlNodePtr root_element;
    xmlNodePtr mr_list_xml;
    xmlNodePtr mr_addr_xml;
    lisp_addr_t *mr_addr;

    OOR_LOG(LDBG_1, "OOR_API: Creating new list of Map Resolvers");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
    list = glist_new_managed((glist_del_fct)lisp_addr_del);

    doc =  xmlReadMemory ((const char *)data, hdr->datalen, NULL, "UTF-8", XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    root_element = xmlDocGetRootElement(doc);

    mr_list_xml = get_inner_xmlNodePtr(root_element,"map-resolvers");
    mr_list_xml = get_inner_xmlNodePtr(mr_list_xml,"map-resolver");


    while (mr_list_xml != NULL){

        mr_addr_xml = get_inner_xmlNodePtr(mr_list_xml,"map-resolver-address");
        while (mr_addr_xml != NULL){;
            mr_addr = lisp_addr_new();
            if (lisp_addr_ip_from_char((char*)xmlNodeGetContent(mr_addr_xml),mr_addr) != GOOD){
                OOR_LOG(LDBG_1,"oor_api_xtr_mr_create: Could not parse Map Resolver: %s", (char*)xmlNodeGetContent(mr_addr_xml));
                goto err;
            }

            if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(mr_addr)){
                OOR_LOG(LWRN, "oor_api_xtr_mr_create: The Map Resolver %s will not be added due to the selected "
                        "default rloc afi (-a option)", lisp_addr_to_char(mr_addr));
                goto err;
            }

            if (glist_contain_using_cmp_fct(mr_addr, list, (glist_cmp_fct)lisp_addr_cmp)){
                OOR_LOG(LWRN, "oor_api_xtr_mr_create: The Map Resolver %s is duplicated. Descarding all the list.",
                        lisp_addr_to_char(mr_addr));
                goto err;
            }
            glist_add_tail(lisp_addr_clone(mr_addr), list);

            mr_addr_xml = lxml_get_next_node(mr_addr_xml);
        }
        mr_list_xml = lxml_get_next_node(mr_list_xml);
    }

    xmlFreeDoc(doc);
    doc = NULL;

    //Everything fine. We replace the old list with the new one
    glist_destroy(xtr->map_resolvers);
    xtr->map_resolvers = list;

    OOR_LOG(LDBG_1, "OOR_API: List of Map Resolvers successfully created");
    OOR_LOG(LDBG_2, "************* %13s ***************", "Map Resolvers");
    glist_dump(xtr->map_resolvers, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);


    return (GOOD);
err:
    OOR_LOG(LERR, "OOR_API: Error while creating Map Resolver list");

    glist_destroy(list);
    if (doc != NULL){
        xmlFreeDoc(doc);
    }

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_ERR);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    return (BAD);

}

int
oor_api_xtr_mr_delete(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{

	lisp_xtr_t *xtr;
	uint8_t *result_msg;
	int result_msg_len;

	OOR_LOG(LDBG_2, "OOR_API: Deleting Map Resolver list");
	xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

	if (glist_size(xtr->map_resolvers) == 0){
		result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_ERR);
		oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);
		OOR_LOG(LWRN, "OOR_API: Trying to remove Map Resolver list, but list was already empty");
		return BAD;
	}

	glist_remove_all(xtr->map_resolvers);

	result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
	oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

	OOR_LOG(LDBG_1, "OOR_API: Map Resolver list deleted");

	return (GOOD);
}

int
oor_api_xtr_ms_create(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{
    lisp_xtr_t *xtr;
    xmlDocPtr doc;
    xmlNodePtr root_element;
    xmlNodePtr xml_map_servers;
    xmlNodePtr xml_ms_proxy_reply;
    int result_msg_len;
    uint8_t *result_msg;
    glist_t * map_servers_list;
    char * str_proxy_reply;
    uint8_t proxy_reply = FALSE;

    OOR_LOG(LDBG_1, "OOR_API: Creating new map servers list");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    doc =  xmlReadMemory ((const char *)data, hdr->datalen, NULL,
            "UTF-8", XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    root_element = xmlDocGetRootElement(doc);

    xml_map_servers = xmlFirstElementChild(root_element);
    xml_ms_proxy_reply = get_inner_xmlNodePtr(xml_map_servers,"proxy-reply");
    if (xml_ms_proxy_reply != NULL){
        str_proxy_reply = (char *)xmlNodeGetContent(xml_ms_proxy_reply);
        if (strcmp(str_proxy_reply,"true") == 0){
            proxy_reply = TRUE;
        }
    }

    map_servers_list = glist_new_managed((glist_del_fct)map_server_elt_del);
    if (lxml_update_map_server_list(xml_map_servers,proxy_reply, map_servers_list)!=GOOD){
        OOR_LOG(LDBG_1,"oor_api_xtr_ms_create: Error adding map servers");
        goto err;
    }
    xmlFreeDoc(doc);
    doc = NULL;

    /* Everything fine. We replace the old list with the new one */
    glist_destroy(xtr->map_servers);
    xtr->map_servers = map_servers_list;

    /* Reprogram Map Register for local EIDs */
    program_map_register(xtr);

    OOR_LOG(LDBG_1, "OOR_API: List of Map Servers successfully created");
    map_servers_dump(xtr, LDBG_1);

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    return (GOOD);

    err:
     glist_destroy(map_servers_list);

     if (doc != NULL){
         xmlFreeDoc(doc);
     }

     result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_ERR);
     oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);
     OOR_LOG(LWRN, "OOR_API: Error while setting new Map Servers list");

     return (BAD);
}


int
oor_api_xtr_ms_delete(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{
    lisp_xtr_t *xtr;
    uint8_t *result_msg;
    int result_msg_len;

    OOR_LOG(LDBG_2, "OOR_API: Deleting Map Servers list");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    if (glist_size(xtr->map_servers) == 0){
        //ERROR: Already NULL
        result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_ERR);
        oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);
        OOR_LOG(LWRN, "OOR_API: Trying to remove Map Resolver list, but list was already empty");
        return (BAD);
    }

    glist_remove_all(xtr->map_servers);

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    OOR_LOG(LDBG_1, "OOR_API: Map Servers list deleted");

    return (GOOD);
}


int
oor_api_xtr_mapdb_create(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{
    lisp_xtr_t *xtr;
    mapping_t *processed_mapping;
    map_local_entry_t *map_loc_e;
    shash_t *lcaf_ht;
    void *it;
    xmlDocPtr doc;
    xmlNodePtr root_element;
    xmlNodePtr xml_local_eids;
    xmlNodePtr xml_local_eid;
    conf_mapping_t *conf_mapping;
    glist_t *conf_mapping_list;
    glist_entry_t *conf_map_it;
    int result_msg_len;
    uint8_t *result_msg;
    int ipv4_mapings = 0;
    int ipv6_mapings = 0;
    int eid_ip_afi;

    OOR_LOG(LDBG_1, "OOR_API: Creating new local data base");
    lcaf_ht = shash_new_managed((free_value_fn_t)lisp_addr_del);
    conf_mapping_list = glist_new_managed((glist_del_fct)conf_mapping_destroy);

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    doc =  xmlReadMemory ((const char *)data, hdr->datalen, NULL, "UTF-8", XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    root_element = xmlDocGetRootElement(doc);

    xml_local_eids = xmlFirstElementChild(root_element);
    xml_local_eid = xmlFirstElementChild(xml_local_eids);
    while (xml_local_eid != NULL){
        conf_mapping = lxml_get_conf_mapping (xml_local_eid, lcaf_ht);
        if (conf_mapping == NULL){
            goto err;
        }
        glist_add(conf_mapping,conf_mapping_list);
        xml_local_eid = lxml_get_next_node(xml_local_eid);
    }
    xmlFreeDoc(doc);
    doc = NULL;

    /*
     * Empty previous local database
     */
    /* Remove routing configuration for the eids */
    local_map_db_foreach_entry(xtr->local_mdb, it) {
        map_loc_e = (map_local_entry_t *)it;
        ctrl_unregister_eid_prefix(ctrl_dev, map_local_entry_eid(map_loc_e));
    } local_map_db_foreach_end;

    /* Empty local database */
    local_map_db_del(xtr->local_mdb);
    xtr->local_mdb = local_map_db_new();

    /* We leverage on the OOR configuration subsystem to introduce
     * and process the configuration mappings into the system */
    glist_for_each_entry(conf_map_it, conf_mapping_list){
        conf_mapping = (conf_mapping_t *) glist_entry_data(conf_map_it);

        //XXX Beware the NULL in lcaf_ht. No LCAF support yet
        processed_mapping = process_mapping_config(&(xtr->super),lcaf_ht,conf_mapping, TRUE);

        if (processed_mapping == NULL){
            OOR_LOG(LDBG_2, "OOR_API: Couldn't process mapping %s",conf_mapping->eid_prefix);
            goto err;
        }
        /* If dev is a mobile node, we can only have one IPv4 and one IPv6 mapping */
        if (lisp_ctrl_dev_mode(ctrl_dev) == MN_MODE){
            eid_ip_afi = lisp_addr_ip_afi((lisp_addr_get_ip_pref_addr(mapping_eid(processed_mapping))));;
            if (eid_ip_afi == AF_INET){
                ipv4_mapings ++;
            }else if (eid_ip_afi == AF_INET6){
                ipv6_mapings ++;
            }
            if (ipv4_mapings >1 || ipv6_mapings >1){
                OOR_LOG(LWRN, "OOR_API: LISP Mobile Node only supports one IPv4 and one IPv6 EID prefix");
                break;
            }
        }

        mapping_set_auth(processed_mapping, 1);

        map_loc_e = map_local_entry_new_init(processed_mapping);
        if (map_loc_e == NULL){
            OOR_LOG(LDBG_2, "OOR_API: Couldn't allocate map_local_entry_t %s",conf_mapping->eid_prefix);
            goto err;
        }
        if (xtr->fwd_policy->init_map_loc_policy_inf(
                xtr->fwd_policy_dev_parm, map_loc_e, NULL,
                xtr->fwd_policy->del_map_loc_policy_inf) != GOOD){
            OOR_LOG(LDBG_2, "OOR_API: Couldn't initiate forward information for mapping with EID: %s",conf_mapping->eid_prefix);
            goto err;
        }

        if (add_local_db_map_local_entry(map_loc_e,xtr) != GOOD){
            OOR_LOG(LDBG_2, "OOR_API: Couldn't add mapping %s to local database",
                    lisp_addr_to_char(&(processed_mapping->eid_prefix)));
            goto err;
        }

        OOR_LOG(LDBG_1, "OOR_API: Updating data-plane for EID prefix %s",
                lisp_addr_to_char(&(processed_mapping->eid_prefix)));

        /* Update the routing rules for the new EID */
        if (ctrl_register_eid_prefix(ctrl_dev,mapping_eid(processed_mapping))!=GOOD){
            OOR_LOG(LERR, "OOR_API: Unable to update data-plane for mapping %s",
                    lisp_addr_to_char(&(processed_mapping->eid_prefix)));
            goto err;
        }
    }

    /* Update control with new added interfaces */
    ctrl_update_iface_info(ctrl_dev->ctrl);

    glist_destroy(conf_mapping_list);
    shash_destroy(lcaf_ht);

    OOR_LOG(LDBG_1, "OOR_API: New local data base created");
    OOR_LOG(LDBG_2, "************* %20s ***************", "Local EID Database");
    local_map_db_dump(xtr->local_mdb, LDBG_1);


    /* Reprogram Map Register for local EIDs */
    program_map_register(xtr);


    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    return (GOOD);

    err:
    //XXX if error, destroy mappings added to local mapdb? deattach locators from ifaces?
    glist_destroy(conf_mapping_list);
    shash_destroy(lcaf_ht);

    if (doc != NULL){
        xmlFreeDoc(doc);
    }

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_ERR);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);
    OOR_LOG(LWRN, "OOR_API: Error while setting new Mapping Database content");

    return (BAD);
}


int
oor_api_xtr_mapdb_delete(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{
    lisp_xtr_t *xtr;
    map_local_entry_t *map_loc_e;
    void *it;
    uint8_t *result_msg;
    int result_msg_len;

    OOR_LOG(LDBG_2, "OOR_API: Deleting local Mapping Database list");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    /* Remove routing configuration for the eids */
    local_map_db_foreach_entry(xtr->local_mdb, it) {
        map_loc_e = (map_local_entry_t *)it;
        ctrl_unregister_eid_prefix(ctrl_dev, map_local_entry_eid(map_loc_e));
    } local_map_db_foreach_end;

    /* Empty local database */
    local_map_db_del(xtr->local_mdb);
    xtr->local_mdb = local_map_db_new();

    /* Send confirmation message to the API server */
    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    OOR_LOG(LDBG_1, "OOR_API: Local Mapping Database deleted");

    return (GOOD);
}

int
oor_api_xtr_petrs_create(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{
    lisp_xtr_t *xtr;
    uint8_t *result_msg;
    int result_msg_len;
    glist_t *str_addr_list;
    char *str_addr;
    xmlDocPtr doc;
    xmlNodePtr root_element;
    xmlNodePtr petr_list_xml;
    xmlNodePtr petr_addr_xml;
    lisp_addr_t *petr_addr;
    glist_entry_t *addr_it;

    OOR_LOG(LDBG_1, "OOR_API: Creating new list of Proxy ETRs");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
    str_addr_list = glist_new_managed(free);

    doc =  xmlReadMemory ((const char *)data, hdr->datalen, NULL, "UTF-8", XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    root_element = xmlDocGetRootElement(doc);

    petr_list_xml = get_inner_xmlNodePtr(root_element,"proxy-etrs");
    petr_list_xml = get_inner_xmlNodePtr(petr_list_xml,"proxy-etr");

    while (petr_list_xml != NULL){

        petr_addr_xml = get_inner_xmlNodePtr(petr_list_xml,"proxy-etr-address");
        while (petr_addr_xml != NULL){
            str_addr = (char*)xmlNodeGetContent(petr_addr_xml);
            /* We do some checks before adding the address to the aux list */
            petr_addr = lisp_addr_new();
            if (lisp_addr_ip_from_char(str_addr,petr_addr) != GOOD){
                OOR_LOG(LDBG_1,"oor_api_xtr_mr_create: Could not parse Proxy ETR address: %s", str_addr);
                goto err;
            }
            if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(petr_addr)){
                OOR_LOG(LWRN, "oor_api_xtr_mr_create: The Proxy ETR %s will not be added due to the selected "
                        "default rloc afi (-a option)", str_addr);
                goto err;
            }

            if (glist_contain_using_cmp_fct(str_addr, str_addr_list, (glist_cmp_fct)strcmp)){
                OOR_LOG(LWRN, "oor_api_xtr_petr_create: The Proxy ETR %s is duplicated. Descarding all the list.",
                        str_addr);
                goto err;
            }
            glist_add_tail(str_addr, str_addr_list);
            lisp_addr_del(petr_addr);
            petr_addr_xml = lxml_get_next_node(petr_addr_xml);
        }
        petr_list_xml = lxml_get_next_node(petr_list_xml);
    }

    xmlFreeDoc(doc);
    doc = NULL;

    //Everything fine. We replace the old list with the new one
    glist_remove_all(mapping_locators_lists(mcache_entry_mapping(xtr->petrs)));
    glist_for_each_entry(addr_it,str_addr_list){
        str_addr = (char *)glist_entry_data(addr_it);
        add_proxy_etr_entry(xtr->petrs,str_addr,1,100);
    }

    xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,xtr->petrs);

    OOR_LOG(LDBG_1, "OOR_API: List of Proxy ETRs successfully created");
    OOR_LOG(LDBG_1, "************************* Proxy ETRs List ****************************");
    mapping_to_char(mcache_entry_mapping(xtr->petrs));

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    return (GOOD);

err:
    lisp_addr_del(petr_addr);
    free(str_addr);
    xmlFreeDoc(doc);
    OOR_LOG(LERR, "OOR_API: Error while creating Map Resolver list");
    glist_destroy(str_addr_list);
    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_ERR);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    return (BAD);
}

int
oor_api_xtr_petrs_delete(oor_api_connection_t *conn, oor_api_msg_hdr_t *hdr,
        uint8_t *data)
{
    lisp_xtr_t *xtr;
    uint8_t *result_msg;
    int result_msg_len;

    OOR_LOG(LDBG_2, "OOR_API: Deleting Proxy ETRs list");


    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    glist_remove_all(mapping_locators_lists(mcache_entry_mapping(xtr->petrs)));

    result_msg_len = oor_api_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,OOR_API_RES_OK);
    oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);

    return (GOOD);
}


int
(*oor_api_get_proc_func(oor_api_msg_hdr_t* hdr))(oor_api_connection_t *,
        oor_api_msg_hdr_t *, uint8_t *)
{

    int (*process_func)(oor_api_connection_t *, oor_api_msg_hdr_t *, uint8_t *) = NULL;

    oor_dev_type_e device = hdr->device;
    oor_api_msg_target_e target = hdr->target;
    oor_api_msg_opr_e operation = hdr->operation;


    switch (device){
    case OOR_API_DEV_XTR:
        if (lisp_ctrl_dev_mode(ctrl_dev) != xTR_MODE && lisp_ctrl_dev_mode(ctrl_dev) != MN_MODE){
            OOR_LOG(LDBG_1, "OOR_API call = Call API from wrong device");
            break;
        }
        switch (target){
        case OOR_API_TRGT_MRLIST:
            switch (operation){
                case OOR_API_OPR_CREATE:
                    OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: MR list | Operation: Create)");
                    process_func = oor_api_xtr_mr_create;
                    break;
                case OOR_API_OPR_DELETE:
                    OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: MR list | Operation: Delete)");
                	process_func = oor_api_xtr_mr_delete;
                	break;
                default:
                	OOR_LOG(LWRN, "OOR_API call = (Device: xTR | Target: MR list | Operation: Unsupported)");
                    break;
                }
            break;
        case OOR_API_TRGT_MSLIST:
            switch (operation){
                case OOR_API_OPR_CREATE:
                    OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: MS list | Operation: Create)");
                    process_func = oor_api_xtr_ms_create;
                    break;
                case OOR_API_OPR_DELETE:
                    OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: MS list | Operation: Delete)");
                    process_func = oor_api_xtr_ms_delete;
                    break;
                default:
                    OOR_LOG(LWRN, "OOR_API call = (Device: xTR | Target: MS list | Operation: Unsupported)");
                    break;
            }
            break;
        case OOR_API_TRGT_MAPDB:
            switch (operation){
                case OOR_API_OPR_CREATE:
                    OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: Mapping DB | Operation: Create)");
                    process_func = oor_api_xtr_mapdb_create;
                    break;
                case OOR_API_OPR_DELETE:
                    OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: Mapping DB | Operation: Delete)");
                    process_func = oor_api_xtr_mapdb_delete;
                    break;
                default:
                    OOR_LOG(LWRN, "OOR_API call = (Device: xTR | Target: Mapping DB | Operation: Unsupported)");
                    break;
            }
            break;
         case OOR_API_TRGT_PETRLIST:
            switch (operation){
            case OOR_API_OPR_CREATE:
                OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: Proxy ETRs | Operation: Create)");
                process_func = oor_api_xtr_petrs_create;
                break;
            case OOR_API_OPR_DELETE:
                OOR_LOG(LDBG_2, "OOR_API call = (Device: xTR | Target: Proxy ETRs | Operation: Delete)");
                process_func = oor_api_xtr_petrs_delete;
                break;
            default:
                OOR_LOG(LWRN, "OOR_API call = (Device: xTR | Target: Mapping DB | Operation: Unsupported)");
                break;
            }
            break;
        default:
        	OOR_LOG(LWRN, "OOR_API call = (Device: xTR | Target: Unsupported)");
            break;
        }
        break;
    case OOR_API_DEV_RTR:
        if (lisp_ctrl_dev_mode(ctrl_dev) != RTR_MODE){
            OOR_LOG(LDBG_1, "OOR_API call = Call API from wrong device");
            break;
        }
        switch (target){
        case OOR_API_TRGT_MRLIST:
            switch (operation){
            case OOR_API_OPR_CREATE:
                OOR_LOG(LDBG_2, "OOR_API call = (Device: RTR | Target: MR list | Operation: Create)");
                process_func = oor_api_xtr_mr_create;
                break;
            case OOR_API_OPR_DELETE:
                OOR_LOG(LDBG_2, "OOR_API call = (Device: RTR | Target: MR list | Operation: Delete)");
                process_func = oor_api_xtr_mr_delete;
                break;
            default:
                OOR_LOG(LWRN, "OOR_API call = (Device: RTR | Target: MR list | Operation: Unsupported)");
                break;
            }
            break;
        default:
            OOR_LOG(LWRN, "OOR_API call = (Device: RTR | Target: Unsupported)");
            break;
        }
        break;
    default:
    	OOR_LOG(LWRN, "OOR_API call = (Device: Unsupported)");
        break;
    }

    return (process_func);
}

void
oor_api_loop(oor_api_connection_t *conn)
{
    uint8_t *buffer;
    uint8_t *data;
    int nbytes;
    int datalen;
    oor_api_msg_hdr_t *header;
    int (*process_func)(oor_api_connection_t *, oor_api_msg_hdr_t *, uint8_t *) = NULL;
    uint8_t *result_msg;
    int result_msg_len;

    buffer = xzalloc(MAX_API_PKT_LEN);

    nbytes = oor_api_recv(conn,buffer,OOR_API_DONTWAIT);

    if (nbytes == OOR_API_NOTHINGTOREAD){
    	goto end;
    }

    if (nbytes == OOR_API_ERROR){
    	OOR_LOG(LERR, "oor_api_loop: Error while trying to retrieve API packet\n");
    	goto end;
    }

    header = (oor_api_msg_hdr_t *)buffer;

    data = CO(buffer,sizeof(oor_api_msg_hdr_t));
    datalen = nbytes - sizeof(oor_api_msg_hdr_t);

    if (header->datalen < datalen){
        OOR_LOG(LWRN, "oor_api_loop: API packet longer than expected\n");
    }
    else if (header->datalen > datalen){
        OOR_LOG(LERR, "oor_api_loop: API packet shorter than expected\n");
        goto end;
    }

    process_func = oor_api_get_proc_func(header);

    if (process_func != NULL){
    	(*process_func)(conn,header,data);
    }else {
        result_msg_len = oor_api_result_msg_new(&result_msg,header->device,header->target,header->operation,OOR_API_RES_ERR);
        oor_api_send(conn,result_msg,result_msg_len,OOR_API_NOFLAGS);
    }

end:
    free(buffer);

    return;
}


