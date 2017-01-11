/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef LISPD_LCAF_H_
#define LISPD_LCAF_H_

#include "lisp_ip.h"
#include "../lib/generic_list.h"
#include "lisp_messages.h"


#define MAX_LCAFS 16

typedef struct _lisp_addr_t lisp_addr_t;


typedef struct _lcaf_addr_t {
    lcaf_type_e type;
    void *addr;
} lcaf_addr_t;

#define MAX_IID 16777215

/*
 * Abstract representation of LCAFs
 */

typedef struct afi_list {
    glist_t *list_addr;
} afi_list_t;


typedef struct _iid_t {
    uint32_t iid;
    uint8_t mlen;
    lisp_addr_t *iidaddr;
} iid_t;

/* GEO */
typedef struct {
    uint8_t dir;
    uint16_t deg;
    uint8_t min;
    uint8_t sec;
} geo_coordinates;

typedef struct {
    geo_coordinates latitude;
    geo_coordinates longitude;
    uint32_t altitude;
    lisp_addr_t *addr;
} geo_t;

/* NAT */
typedef struct {
    uint16_t etr_pub_port;
    lisp_addr_t *etr_pub_addr;
    uint16_t ms_port;
    lisp_addr_t *ms_addr;
    lisp_addr_t *etr_prv_addr;
    glist_t *rtr_addr_lst;
} nat_t;

typedef struct {
    uint8_t src_plen;
    uint8_t grp_plen;
    uint32_t iid;
    lisp_addr_t *src;
    lisp_addr_t *grp;
} mc_t;

/* ELP */
typedef struct elp_node {
    uint8_t L:1;
    uint8_t P:1;
    uint8_t S:1;
    lisp_addr_t *addr;
} elp_node_t;

typedef struct _elp_t {
    glist_t *nodes;
} elp_t;

/* RLE */
typedef struct _rle_node_t {
    lisp_addr_t *addr;
    uint8_t level;
} rle_node_t;

typedef struct _rle_t {
    glist_t *nodes;
} rle_t;


lcaf_addr_t *lcaf_addr_new();
lcaf_addr_t *lcaf_addr_new_type(uint8_t type);
void lcaf_addr_del_addr(lcaf_addr_t *lcaf);

lcaf_type_e lcaf_addr_get_type(lcaf_addr_t *lcaf);
void *lcaf_addr_get_addr(lcaf_addr_t *lcaf);
mc_t *lcaf_addr_get_mc(lcaf_addr_t *lcaf);
geo_t *lcaf_addr_get_geo(lcaf_addr_t *lcaf);
iid_t *lcaf_addr_get_iid(lcaf_addr_t *lcaf);
nat_t *lcaf_addr_get_nat(lcaf_addr_t *lcaf);

int lcaf_addr_is_mc(lcaf_addr_t *lcaf);
int lcaf_addr_is_iid(lcaf_addr_t *lcaf);

void lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type);
void lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr);
void lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type);
int lcaf_addr_parse(uint8_t *offset, lcaf_addr_t *lcaf_addr);

char *lcaf_addr_to_char(lcaf_addr_t *lcaf);

uint32_t lcaf_addr_get_size_to_write(lcaf_addr_t *lcaf);
int lcaf_addr_copy(lcaf_addr_t *dst, lcaf_addr_t *src);
int lcaf_addr_write(void *offset, lcaf_addr_t *lcaf);
int lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2);
uint8_t lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2);


/*
 * mc type functions
 */

lisp_addr_t *lcaf_mc_get_src(lcaf_addr_t *mc);
lisp_addr_t *lcaf_mc_get_grp(lcaf_addr_t *mc);
uint32_t lcaf_mc_get_iid(lcaf_addr_t *mc);
uint8_t lcaf_mc_get_src_plen(lcaf_addr_t *mc);
uint8_t lcaf_mc_get_grp_plen(lcaf_addr_t *mc);
uint8_t lcaf_mc_get_afi(lcaf_addr_t *mc);

mc_t *mc_type_new();
void mc_type_del(void *mc);
mc_t *mc_type_init(lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
void mc_type_set_src_plen(mc_t *mc, uint8_t plen);
void mc_type_set_grp_plen(mc_t *mc, uint8_t plen);
void mc_type_set_iid(mc_t *mc, uint32_t iid);
void mc_type_set_src(void *mc, lisp_addr_t *src);
void mc_type_set_grp(mc_t *mc, lisp_addr_t *grp);

lisp_addr_t *mc_type_get_src(mc_t *mc);
lisp_addr_t *mc_type_get_grp(mc_t *mc);
uint8_t mc_type_get_afi(mc_t *mc);
uint32_t mc_type_get_iid(void *mc);
uint8_t mc_type_get_src_plen(mc_t *mc);
uint8_t mc_type_get_grp_plen(mc_t *mc);

char *mc_type_to_char (void *mc);
int mc_type_get_size_to_write(void *mc);
int mc_type_write_to_pkt(uint8_t *offset, void *mc);
void mc_type_copy(void **dst, void *src);
int mc_type_cmp(void *mc1, void *mc2);
void mc_type_set(mc_t *dst, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
int mc_type_parse(uint8_t *offset, void **mc);
lisp_addr_t *			mc_type_get_ip_addr (void *mc);
lisp_addr_t * mc_type_get_ip_pref_addr (void *mc);
int lcaf_addr_set_mc(lcaf_addr_t *lcaf, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
lisp_addr_t *lisp_addr_build_mc(lisp_addr_t *src, lisp_addr_t *grp);
int lisp_addr_is_mcinfo(lisp_addr_t *addr);

/*
 * iid type functions
 */

iid_t *iid_type_new();
iid_t * iid_type_new_init(int iid, lisp_addr_t *addr, uint8_t mlen);
void iid_type_del(void *iid);
uint8_t iid_type_get_mlen(iid_t *iid);
uint32_t lcaf_iid_get_iid(lcaf_addr_t *iid);
uint32_t iid_type_get_iid(iid_t *iid);
lisp_addr_t *iid_type_get_addr(void *iid);
void iid_type_set_iid(iid_t *addr, uint32_t iid);
void iid_type_set_addr(iid_t *addr, lisp_addr_t *iidaddr);
void iid_type_set_mlen(iid_t *addr, uint8_t mlen);
int iid_type_cmp(void *iid1, void *iid2);
int iid_type_get_size_to_write(void *iid);
int iid_type_write_to_pkt(uint8_t *offset, void *iid);
int iid_type_parse(uint8_t *offset, void **iid);
char *iid_type_to_char(void *iid);
void iid_type_copy(void **dst, void *src);
lisp_addr_t *				iid_type_get_ip_addr(void *iid);
lisp_addr_t * iid_type_get_ip_pref_addr(void *iid);
void lcaf_iid_init(lcaf_addr_t *iidaddr, int iid, lisp_addr_t *addr, uint8_t mlen);
int lisp_addr_is_iid(lisp_addr_t *addr);
lisp_addr_t * lisp_addr_new_init_iid(int iid, lisp_addr_t *addr, uint8_t mlen);

/*
 * geo type functions
 */
geo_t * geo_type_new();
void geo_type_del(void *geo);
void geo_type_set_addr(geo_t *geo, lisp_addr_t *addr);
void geo_type_set_lat(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
void geo_type_set_long(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
void geo_type_set_lat_from_coord(geo_t *geo, geo_coordinates *coord);
void geo_type_set_long_from_coord(geo_t *geo, geo_coordinates *coord);
void geo_type_set_altitude(geo_t *geo, uint32_t altitude);

lisp_addr_t *geo_type_get_addr(geo_t *geo);
geo_coordinates *geo_type_get_lat(geo_t *geo);
geo_coordinates *geo_type_get_long(geo_t *geo);
uint32_t geo_type_get_altitude(geo_t *geo);
int geo_type_parse(uint8_t *offset, void **geo);

char *geo_type_to_char(void *geo);
void geo_type_copy(void **dst, void *src);
char *geo_coord_to_char(geo_coordinates *coord);

/*
 * NAT type functions
 */

nat_t * nat_type_new();
nat_t * nat_type_new_init(uint16_t ms_port, lisp_addr_t *ms_addr, uint16_t etr_pub_port,
        lisp_addr_t *etr_pub_addr, lisp_addr_t *etr_prv_addr, glist_t *rtr_addr_lst);
void nat_type_del(void *nat);
uint16_t nat_type_get_ms_port(nat_t *nat);
uint16_t nat_type_get_etr_pub_port(nat_t *nat);
lisp_addr_t * nat_type_get_ms_addr(nat_t *nat);
lisp_addr_t * nat_type_get_etr_pub_addr(nat_t *nat);
lisp_addr_t * nat_type_get_etr_priv_addr(nat_t *nat);
glist_t * nat_type_get_rtr_addr_lst(nat_t *nat);
void nat_type_set_ms_port(nat_t *nat, uint16_t ms_port);
void nat_type_set_etr_pub_port(nat_t *nat, uint16_t etr_pub_port);
void nat_type_set_ms_addr(nat_t *nat, lisp_addr_t * ms_addr);
void nat_type_set_etr_pub_addr(nat_t *nat, lisp_addr_t * etr_pub_addr);
void nat_type_set_etr_priv_addr(nat_t *nat, lisp_addr_t * etr_prv_addr);
void nat_type_set_rtr_addr_lst(nat_t *nat, glist_t * rtr_addr_lst);
int nat_type_cmp(void *nat1, void *nat2);
int nat_type_get_size_to_write(void *nat);
int nat_type_write_to_pkt(uint8_t *offset, void *nat);
int nat_type_parse(uint8_t *offset, void **nat);
char *nat_type_to_char(void *nat);
void nat_type_copy(void **dst, void *src);
lisp_addr_t * nat_type_get_ip_addr(void *nat);
lisp_addr_t * nat_type_get_ip_pref_addr(void *nat);
void lcaf_nat_init(lcaf_addr_t *nat_addr, uint16_t ms_port, lisp_addr_t *ms_addr,
        uint16_t etr_pub_port, lisp_addr_t *etr_pub_addr, lisp_addr_t *etr_prv_addr,
        glist_t *rtr_addr_lst);
int lisp_addr_is_nat(lisp_addr_t *addr);
lisp_addr_t * lisp_addr_new_init_nat(uint16_t ms_port, lisp_addr_t *ms_addr,
        uint16_t etr_pub_port, lisp_addr_t *etr_pub_addr, lisp_addr_t *etr_prv_addr,
        glist_t *rtr_addr_lst);

/*
 * RLE type functions
 */

rle_t * rle_type_new();
void rle_type_del(void *rleaddr);
int rle_type_parse(uint8_t *offset, void **rle);
int rle_type_write_to_pkt(uint8_t *offset, void *rle);
int rle_type_get_size_to_write(void *elp);
char * rle_type_to_char(void *rle);
void rle_type_copy(void **dst, void *src);
int rle_type_cmp(void *elp1, void *elp2);

rle_node_t * rle_node_clone(rle_node_t *srn);
rle_node_t * rle_node_new();
void rle_node_del(rle_node_t *rnode);
glist_t * lcaf_rle_node_list(lcaf_addr_t *lcaf);

/*
 * ELP type functions
 */

lisp_addr_t * lisp_addr_elp_new();
elp_t * lcaf_elp_get_elp(lcaf_addr_t *elp);
elp_t *elp_type_new();
void elp_type_del(void *elp);
int elp_type_get_size_to_write(void *elp);
int elp_type_write_to_pkt(uint8_t *offset, void *elp);
int elp_type_parse(uint8_t *offset, void **elp);
char *elp_type_to_char(void *elp);
void elp_type_copy(void **dst, void *src);
int elp_type_cmp(void *elp1, void *elp2);
lisp_addr_t * elp_type_get_ip_addr(void *elp);

elp_node_t * elp_node_new_init(lisp_addr_t *addr, uint8_t lookup, uint8_t rloc_probe, uint8_t strict);
lisp_addr_t * elp_node_addr(elp_node_t *enode);
void elp_node_del(elp_node_t *enode);
void elp_add_node(elp_t *elp, elp_node_t *enode);
glist_t * lcaf_elp_node_list(lcaf_addr_t *lcaf);

int lisp_addr_is_elp(lisp_addr_t *addr);

/*
 * AFI-list type functions
 */

afi_list_t *afi_list_type_new();
void afi_list_type_del(void *afil);
int afi_list_type_get_size_to_write(void *afil);
int afi_list_type_write_to_pkt(uint8_t *offset, void *afil);
int afi_list_type_parse(uint8_t *offset, void **afil);
char *afi_list_type_to_char(void *afil);
void afi_list_type_copy(void **dst, void *src);
int afi_list_type_cmp(void *afil1, void *afil2);
lisp_addr_t * afi_list_type_get_ip_addr(void *afi_list);
lisp_addr_t * afi_list_type_get_ip_pref_addr(void *afi_list);

lisp_addr_t * lcaf_get_ip_addr(lcaf_addr_t *lcaf);
lisp_addr_t * lcaf_get_ip_pref_addr(lcaf_addr_t *lcaf);

int lcaf_rloc_set_ip_addr(lisp_addr_t *, lisp_addr_t *if_addr);
#endif /* LISPD_LCAF_H_ */
