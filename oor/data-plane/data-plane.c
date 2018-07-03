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


#include "data-plane.h"

data_plane_struct_t *data_plane = NULL;

void data_plane_select()
{
#ifdef VPNAPI
    data_plane = &dplane_vpnapi;
#elif VPP
    data_plane = &dplane_vpp;
#elif __APPLE__
    data_plane = &dplane_apple;
#else
    data_plane = &dplane_tun;
#endif
}
