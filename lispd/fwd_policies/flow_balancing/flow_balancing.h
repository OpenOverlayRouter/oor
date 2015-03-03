/*
 * flow_balancing.h
 *
 *  Created on: 29/01/2015
 *      Author: albert
 */

#ifndef FLOW_BALANCING_H_
#define FLOW_BALANCING_H_

#include "../fwd_policy.h"
#include "../../control/lisp_ctrl_device.h"


typedef struct fb_dev_parm_ {
    lisp_dev_type_e     dev_type;
    glist_t *           loc_loct;
}fb_dev_parm;


/*
 * Used to select the locator to be used for an identifier according to locators' priority and weight.
 *  v4_balancing_locators_vec: If we just have IPv4 RLOCs
 *  v6_balancing_locators_vec: If we just hace IPv6 RLOCs
 *  balancing_locators_vec: If we have IPv4 & IPv6 RLOCs
 *  For each packet, a hash of its tuppla is calculaed. The result of this hash is one position of the array.
 */

typedef struct balancing_locators_vecs_ {
    locator_t **v4_balancing_locators_vec;
    locator_t **v6_balancing_locators_vec;
    locator_t **balancing_locators_vec;
    int v4_locators_vec_length;
    int v6_locators_vec_length;
    int locators_vec_length;
} balancing_locators_vecs;



#endif /* FLOW_BALANCING_H_ */
