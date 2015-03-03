/*
 * fb_lisp_addr.h
 *
 *  Created on: 17/02/2015
 *      Author: albert
 */

#ifndef FB_LISP_ADDR_H_
#define FB_LISP_ADDR_H_

#include "../../liblisp/liblisp.h"


lisp_addr_t *
fb_lisp_addr_get_fwd_ip_addr(lisp_addr_t *addr, glist_t *locl_rlocs_addr);

lisp_addr_t *
fb_lcaf_get_fwd_ip_addr(lcaf_addr_t *lcaf, glist_t *locl_rlocs_addr);

#endif /* FB_LISP_ADDR_H_ */
