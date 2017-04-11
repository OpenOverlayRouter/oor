/*
 * vpp_balancing.h
 *
 *  Created on: Sep 14, 2016
 *      Author: alopez
 */

#ifndef OOR_FWD_POLICIES_VPP_BALANCING_VPP_BALANCING_H_
#define OOR_FWD_POLICIES_VPP_BALANCING_VPP_BALANCING_H_


#include "../../lib/generic_list.h"

typedef struct vpp_dev_parm_ {
    oor_dev_type_e     dev_type;
    glist_t *          loc_loct;
}vpp_dev_parm;


typedef struct vpp_map_policy_inf_ {
    glist_t *ipv4_loct_lst;
    glist_t *ipv6_loct_lst;
    int priority4;
    int priority6;
    int sum_weight4;
    int sum_weight6;
}vpp_map_policy_inf;

#endif /* OOR_FWD_POLICIES_VPP_BALANCING_VPP_BALANCING_H_ */
