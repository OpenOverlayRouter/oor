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

package org.lispmob.noroot;

import java.io.IOException;
import java.lang.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import org.apache.http.util.EncodingUtils;
import org.json.JSONObject;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.res.Resources;

public class IPC implements Runnable {
	
	private LISPmobVPNService vpn_service = null;
	private Notifications notifications = null;
	private boolean isRunning	= false;
	private Thread ipc_thread;
	private DatagramChannel ipc_channel;
	private static final String ipc_addr  = "127.0.1.1";
	private static final int ipc_dst_port = 10000;
	private static final int ipc_src_port = 10001;
	
	
	private static final int IPC_LOG_MSG = 6;
	private static final int IPC_PROTECT_SOCKS 	= 7;

	
	public IPC(LISPmobVPNService vpn_service){
		this.vpn_service = vpn_service;
		notifications = new Notifications(this.vpn_service);
		try {
			ipc_channel = DatagramChannel.open();
			ipc_channel.socket().bind(new InetSocketAddress(ipc_addr, ipc_src_port));
			ipc_channel.connect(new InetSocketAddress(ipc_addr, ipc_dst_port));
		} catch (Exception e) {
			e.printStackTrace();
		}
		ipc_thread =  new Thread(this, "IPC");
	}
	
	public void start(){
		ipc_thread.start();
		isRunning = true;
	}
	
	public void stop(){
		ipc_thread.interrupt();
		try {
			if (ipc_channel.isOpen()){
				ipc_channel.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		isRunning = false;
	}
	
	public void run()
	{
		int len = 0;
		ByteBuffer buf = ByteBuffer.allocate(9000);
		while (!ipc_thread.isInterrupted()){
			buf.clear();
			try {
				len = ipc_channel.read(buf);
				if (len == 0){
					continue;
				}
				buf.flip();
				String json_str = EncodingUtils.getString(buf.array(), "utf8");
				JSONObject jObj = new JSONObject(json_str);
				int ipc_type = jObj.getInt("type");
				System.out.println("LISPmob: Received IPC message: "+ipc_type);
				switch (ipc_type){
				case IPC_LOG_MSG:
					LISPmobVPNService.err_msg_code = jObj.getInt("err_msg_code");
					Thread.sleep(1000);
					if (LISPmobVPNService.err_msg_code != 0){
						/* If LISPmob is not the active windows, the error msg code is not clean
						 * and we send a notification of the error */
						Resources res = vpn_service.getResources();
						String[] err_msg = res.getStringArray(R.array.ErrMsgArray);
						String msg =  err_msg[LISPmobVPNService.err_msg_code];
						//notifications.notify_msg( msg);
					}	
					break;
				case IPC_PROTECT_SOCKS:
					int socket = jObj.getInt("socket");
					if (socket != -1){
						boolean sock_protect = false;
						int retry = 0;
						while (!sock_protect && retry < 30){		
							if (!vpn_service.protect(socket)) {
								retry++;
								Thread.sleep(200);
							}else{
								sock_protect = true;
								System.out.println("LISPmob: The socket "+socket+" has been protected (VPN Service)");
							}
						}
					}
					break;
				default:
					System.out.println("***** Unknown IPC message: "+ipc_type);
					break;
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	public boolean is_IPC_running(){
		return (isRunning);
	}
}