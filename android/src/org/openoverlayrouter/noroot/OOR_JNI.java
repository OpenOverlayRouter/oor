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

package org.openoverlayrouter.noroot;

public class OOR_JNI {
	
	static {
		System.loadLibrary("oor");
	}
	
	public OORVPNService lm_vpn_service = null;
	
	public OOR_JNI (OORVPNService vpn_service){
		this.lm_vpn_service = vpn_service;
	}
	
	public native int oor_start(int tunFD, String storage_path);
	
	public native void oor_loop();
	
	public native void oor_exit();
	
	public void jni_protect_socket(int socket)
	{
		boolean sock_protect = false;
		
		if (socket >= 0){
			int retry = 0;
			while (!sock_protect && retry < 30){		
				if (!lm_vpn_service.protect(socket)) {
					retry++;
					try {
						Thread.sleep(200);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}else{
					sock_protect = true;
					System.out.println("OOR: The socket "+socket+" has been protected (VPN Service)");
				}
			}
		}
		if (sock_protect == false){
			System.out.println("OOR: Couldn't protect the socket "+socket);
		}
	}

}
