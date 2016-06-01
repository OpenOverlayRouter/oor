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

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;

import android.content.Intent;
import android.net.VpnService;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import java.io.FileNotFoundException;
import java.util.Iterator;
import java.util.List;




public class OORVPNService extends VpnService implements Handler.Callback, Runnable {
	private static final String TAG = "OORVPNService";

	private PendingIntent mConfigureIntent = null;

	private static Thread mThread	= null;

	private static ParcelFileDescriptor mInterface = null;

	public static boolean   vpn_running	  = false;
	public static int       err_msg_code     = 0;
	
	public OOR_JNI 		jni = null;
	


	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {

		String prefix = getPackageName();
		boolean start;
		
		if (intent != null){
			start = intent.getBooleanExtra(prefix + ".START",true);
		}else{
			Log.i(TAG, "OOR VPN service stopped and it has been reestarted");
			start 				= true;
		}
		
		
		if (start == true){
			if (mThread != null){
				if (mInterface == null){
					Log.i(TAG, "Error");
				}
				Log.i(TAG, "Service already running");
				//return (START_STICKY);
				vpn_running = true;
			}else{
				mThread = new Thread(this, "OORVpnThread");
				mThread.start();
				
			}
		}else{
			this.onDestroy();
		}
		
		/*
		 * START_STICKY tells the OS to recreate the service after it has enough memory and call 
		 * onStartCommand() again with a null intent. START_NOT_STICKY tells the OS to not bother 
		 * recreating the service again
		 */
		if (start == true){
			//return (START_STICKY);
			return (START_NOT_STICKY);
		}else{
			return (START_NOT_STICKY);
		}
	}

	@Override
	public void onDestroy() {
		if (vpn_running == true){
			vpn_running = false;
			jni.oor_exit();
		}
		Log.d(TAG, "Destroying VPN Service thread");
		if (mThread != null) {
			try {
				mThread.interrupt();
			}catch (Exception e){
				e.printStackTrace();
			}
		}
		mInterface = null;
		mThread = null;
		
	}

	@Override
	public boolean handleMessage(Message message) {
		if (message != null) {
			Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
		}
		return true;
	}

	public synchronized void run(){
		
		String storage_path = Environment.getExternalStorageDirectory().getAbsolutePath()+"/";
		jni = new OOR_JNI(this);
	
		try {
			// Create a DatagramChannel as the VPN tunnel.
			this.configure();			
			int tunfd = mInterface.detachFd();

			vpn_running = true;
			
			if (jni.oor_start(tunfd, storage_path) != 1){
				Log.e(TAG, "OOR error, check configuration file");
				this.onDestroy();
				return;
			}	

			System.out.println("====> Starting OOR event loop ");
			jni.oor_loop();

			System.out.println(" ************************** END ************************** ");

		}catch(IllegalArgumentException e){
			Log.e(TAG, e.getMessage());
		}catch (Exception e) {
			e.printStackTrace();
		}finally{
			if (vpn_running == true){
				vpn_running = false;
				jni.oor_exit();
			}
			mThread = null;
			vpn_running = false;
		}
		
		return;
	}

	private void configure() throws Exception {
		Iterator <String> 	eids 			= null;
		String 				eid 			= null;
		List<String>		dns_list		= null;
		Iterator <String> 	dns_servers		= null;
		String 				dns 			= null;
		boolean 			ipv4_eids		= false;
		boolean 			ipv6_eids		= false;
		
		// Configure a builder while parsing the parameters.
		Builder builder = new Builder();


		try {
			eids = ConfigTools.getEIDs().iterator();
			while(eids.hasNext()){
				eid = eids.next();
				Log.i(TAG, "Assigning EID "+eid+" to the TUN interface");
				if (eid.contains(":")){
					if (ipv6_eids == false){
						builder.addAddress(eid, 128);
						ipv6_eids = true;
					}
				}else{
					if (ipv4_eids == false){
						builder.addAddress(eid, 32);
						ipv4_eids = true;
					}
				}
			}
			if (ipv4_eids == false && ipv6_eids == false){
				throw new Exception("At least one EID is required");
			}
			dns_list = ConfigTools.getDNS();
			if (dns_list != null){
				dns_servers = dns_list.iterator();
				while(dns_servers.hasNext()){
					dns = dns_servers.next();
					builder.addDnsServer(dns);
				}
			}
			
			if (ipv4_eids){
				Log.i(TAG, "ADD IPV4 ROUTES");
				builder.addRoute("0.0.0.0",1);
				builder.addRoute("128.0.0.0",1);
			}
			if (ipv6_eids){
				Log.i(TAG, "ADD IPV6 ROUTES");
				builder.addRoute("::",1);
				builder.addRoute("8000::",1);
			}
			builder.setMtu(1440);
		}catch (FileNotFoundException e){ 
			OORVPNService.err_msg_code = 1;
			throw new IllegalArgumentException("Configuration file not exist");
		}catch (Exception e) {
			OORVPNService.err_msg_code = 2;
			throw new IllegalArgumentException("Wrong configuration");
		}

		// Create a new interface using the builder and save the parameters.
		mInterface = builder.setSession("OOR")
				.setConfigureIntent(mConfigureIntent)
				.establish();
		Log.i(TAG, "Tun interface configured");
	}

	
	public void notify_msg(String log_msg)
	{
		NotificationManager notificationManager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
		Intent startIntent = new Intent(this, OOR.class);
		PendingIntent contentIntent = PendingIntent.getActivity(this,0,startIntent,PendingIntent.FLAG_CANCEL_CURRENT);

		// Allways overwriting same notification.
		int notification_id = 1;
		
		Notification.Builder notify_b = new Notification.Builder(this);
		notify_b.setContentTitle("OOR Alert");
		notify_b.setContentText(log_msg);
		notify_b.setSmallIcon(R.drawable.oor_logo_small);
		notify_b.setWhen(System.currentTimeMillis());
		notify_b.setContentIntent(contentIntent);
		notify_b.setAutoCancel(true);
		
		Notification notify_msg = notify_b.getNotification();
		notificationManager.notify(notification_id,notify_msg);

	}
}