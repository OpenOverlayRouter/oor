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

#include "vpp_api_requests.h"
#include "../oor_log.h"
#include "../../defs.h"

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/byte_order.h>

vpp_api_main_t vpp_api_main;
vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

int
vpp_is_enabled()
{
    FILE *fp;
    char output[100];

    fp = popen("pidof vpp", "r");
    if (fp == NULL) {
        OOR_LOG(LDBG_1,"vpp_is_enabled: Couldn't check vpp status");
        return (FALSE);
    }
    if (fgets(output, sizeof(output)-1, fp) == NULL){
        OOR_LOG(LERR,"VPP is not running. Start VPP before starting OOR");
        return (FALSE);
    }

    pclose(fp);
    return (TRUE);
}

int
connect_to_vpe (char *name)
{
    vpp_api_main_t *vam = &vpp_api_main;
    api_main_t *am = &api_main;

    if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0){
        return (BAD);
    }
    vam->vl_input_queue = am->shmem_hdr->vl_input_queue;
    vam->my_client_index = am->my_client_index;

    return 0;
}

int
vpp_init_api()
{
    vpp_api_main_t *vam = &vpp_api_main;
    uint8_t *heap;
    mheap_t *h;

    clib_mem_init (0, 128 << 20);
    heap = clib_mem_get_per_cpu_heap ();
    h = mheap_header (heap);

    /* make the main heap thread-safe */
    h->flags |= MHEAP_FLAG_THREAD_SAFE;

    clib_time_init (&vam->clib_time);

    vat_api_hookup (vam);

    if (connect_to_vpe ("vpp_api_oor") < 0)
    {
        svm_region_exit ();
        OOR_LOG(LERR, "Couldn't connect to vpe, exiting...\n");
        return(BAD);
    }

    ctrl_plugin_register(vam);
    pkt_miss_plugin_register(vam);
    return (GOOD);
}

inline int
vpp_uninit_api()
{
    vpp_api_main_t *vam = &vpp_api_main;
    glist_destroy(vam->ip_addr_lst);
    glist_destroy(vam->iface_list);
    vl_client_disconnect_from_vlib ();
    return (GOOD);
}
