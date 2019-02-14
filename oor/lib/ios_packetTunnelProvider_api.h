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

#ifndef ios_packetTunnelProvider_api_h
#define ios_packetTunnelProvider_api_h

typedef struct iOS_CLibCallbacks iOS_CLibCallbacks;

struct  iOS_CLibCallbacks	{
    const void * _Nonnull packetTunnelProviderPtr;
    void (* _Nonnull ptp_write_to_tun)(char * _Nonnull buffer,  int length, int afi, void * _Nonnull ptp);
};

extern void iOS_init_out_packet_buffer();
extern void iOS_init_semaphore();
extern void iOS_end_semaphore();

extern void iOS_CLibCallbacks_setup(const iOS_CLibCallbacks * _Nonnull callbacks);


extern void oor_ptp_read_from_tun (const void * _Nonnull buffer, int length);


#endif /* ios_packetTunnelProvider_api_h */
