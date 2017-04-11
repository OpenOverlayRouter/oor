
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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>

#include "../../defs.h"
#include "../../lib/oor_log.h"

/* Declare message IDs */
#include <oor_ctrl/oor_ctrl_msg_enum.h>
#include "vpp_api_requests.h"

/* define message structures */
#define vl_typedefs
#include <oor_ctrl/oor_ctrl_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <oor_ctrl/oor_ctrl_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <oor_ctrl/oor_ctrl_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 oor_ctrl_api_version=(v);
#include <oor_ctrl/oor_ctrl_all_api_h.h>
#undef vl_api_version

uint16_t ctr_msg_id_base = ~0;

#define foreach_standard_reply_retval_handler   \
_(oor_ctrl_enable_disable_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vpp_api_main_t * vam = vpp_api_main_get();      \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _


/* M: construct, but don't yet send a message */

#define M(T,t)                                      \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + ctr_msg_id_base);          \
    mp->client_index = vam->my_client_index;                    \
} while(0);


/* S: send a message */
#define S (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))


int
vpp_oor_ctrl_enable_disable (char *iface_name, uint8_t enable_disable)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_oor_ctrl_enable_disable_t * mp;

    /* Construct the API message */
    M(OOR_CTRL_ENABLE_DISABLE, oor_ctrl_enable_disable);
    memcpy (mp->host_if_name, iface_name, strlen(iface_name));
    mp->enable_disable = enable_disable;

    /* send it... */
    S;

    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not enable OOR control plugin");
        return (BAD);
    }
    return (GOOD);
}

clib_error_t *
ctrl_plugin_register (vpp_api_main_t * vam)
{
    u8 * name;

    /* Ask the vpp engine for the first assigned message-id */
    name = format (0, "oor_ctrl_%08x%c", oor_ctrl_api_version, 0);
    ctr_msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);
    vec_free(name);

    if (ctr_msg_id_base != (uint16_t) ~0){
        vl_msg_api_set_handlers((VL_API_OOR_CTRL_ENABLE_DISABLE_REPLY + ctr_msg_id_base),     \
                "oor_ctrl_enable_disable_reply",                             \
                vl_api_oor_ctrl_enable_disable_reply_t_handler,              \
                vl_noop_handler,                                             \
                vl_api_oor_ctrl_enable_disable_reply_t_endian,               \
                vl_api_oor_ctrl_enable_disable_reply_t_print,                \
                sizeof(vl_api_oor_ctrl_enable_disable_reply_t), 1);
    }

    return 0;
}
