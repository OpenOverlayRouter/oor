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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Timer;
import java.util.TimerTask;

import org.openoverlayrouter.noroot.R;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlertDialog;
import android.location.Location;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.Color;
import android.widget.CheckBox;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;

@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class OOR extends Activity implements OnClickListener {

	public static String oor_path = null;
	private static String system_dns[] = new String[2];
	private boolean oorWasRunning = false;
	private static boolean oorRunning = false;
	private static boolean err_msg_detected = false;
	private static boolean startVPN = false;
	private Intent vpn_intent	= null;
	private static final int CONF_ACT = 1;
	private static final int VPN_SER = 2;
	
	private Handler handler;
	private Runnable doUpdateView;

	
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		
		//shell = new SuShell();
		
		/* Get the directory of the executable */
		
		try{
			oor_path =  getPackageManager().getApplicationInfo("org.openoverlayrouter.noroot", 0).nativeLibraryDir;
			
		}catch(Exception e)
		{
			e.printStackTrace();
		};

		/*
		 * Set up the button handlers
		 */
		CheckBox oorCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);
		oorCheckBox.setOnClickListener(this);
		handler = new Handler(); 
		doUpdateView = new Runnable() { 
			public void run() { 
				updateStatus();
			} 
		};

		Button log = (Button) findViewById(R.id.showLogButton);
		log.setOnClickListener(new View.OnClickListener() {
			public void onClick(View view) {
				Intent myIntent = new Intent(view.getContext(), logActivity.class);
				startActivity(myIntent);
			}
		}
				);
		Button conf = (Button) findViewById(R.id.showConfButton);
		conf.setOnClickListener(new View.OnClickListener() {
			public void onClick(View view) {
				Intent myIntent = new Intent(view.getContext(), confActivity.class);
				startActivity(myIntent);
			}
		}
				);

		Button updateconf = (Button) findViewById(R.id.updateConfButton);
		updateconf.setOnClickListener(new View.OnClickListener() {
			public void onClick(View view) {
				Intent myIntent = new Intent(view.getContext(), updateConfActivity.class);
				startActivityForResult(myIntent, CONF_ACT);
				
			}
		}
				);
		
		//system_dns = get_dns_servers();
		
	}


	Location lastLocation;

	Timer mUpdateTimer = null;
	@Override
	protected void onPause() {
		Log.v("OOR", "Pausing..");
		super.onPause();

		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onStop() {
		Log.v("OOR", "Stopping...");
		super.onStop();
		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onResume() {
		Log.v("OOR", "Resuming...");
		super.onResume();

		// Rebuild the timer
		if (mUpdateTimer != null) {
			mUpdateTimer.cancel();
		}
		mUpdateTimer = new Timer();
		mUpdateTimer.scheduleAtFixedRate(new statusTask(), 0, 1000);
	}

	static public String runTask(String command, String args, boolean ignoreOutput) {
		StringBuffer output = new StringBuffer();
		Process process = null;
		try {
			process = new ProcessBuilder()
			.command(command, args)
			.redirectErrorStream(true)
			.start();
			InputStream in = process.getInputStream();
			BufferedReader reader = new BufferedReader(new InputStreamReader(in));
			String line;
			process.waitFor();
			if (!ignoreOutput) {
				while ((line = reader.readLine()) != null) {
					output.append(line);
					output.append('\n');
				}
			}
		} catch (IOException e1) {
			System.out.println("OOR: Command Failed.");
			e1.printStackTrace();
			return("Command Failed.");
		} catch (InterruptedException e) {
			e.printStackTrace();
		} 
		return(output.toString());
	}

	
	public void updateStatus() {
		final CheckBox oorCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
		final TextView oorCheckBoxLabel = (TextView) findViewById(R.id.startStopCheckboxLabel);
		final TextView statusView = (TextView) findViewById(R.id.infoView);
		

		oorRunning = OORVPNService.vpn_running;

		if (OORVPNService.vpn_running) {
			oorCheckBoxLabel.setText(R.string.oorRunning);
			oorCheckBoxLabel.setTextColor(Color.WHITE);
			oorCheckBox.setChecked(true);
			//updateInfoView();
			statusView.setText("");
			oorWasRunning = true;
		} else if (oorWasRunning) {
			oorCheckBoxLabel.setText("OOR has exited, click to restart.");
			oorCheckBoxLabel.setTextColor(Color.RED);
			oorCheckBox.setChecked(false);
			//updateInfoView();
			statusView.setText("");
		} else {
			oorCheckBoxLabel.setText(R.string.oorNotRunning);
			oorCheckBoxLabel.setTextColor(Color.WHITE);
			oorCheckBox.setChecked(false);
			//updateInfoView();
			statusView.setText("");
		}
		
		if (!err_msg_detected && OORVPNService.err_msg_code != 0){
			err_msg_detected = true;
			Resources res = getResources();
			String[] err_msg = res.getStringArray(R.array.ErrMsgArray);
			showMessage(err_msg[OORVPNService.err_msg_code],
					false, new Runnable() { public void run() {
						OORVPNService.err_msg_code =0;
						err_msg_detected = false;
					}
			});
		}

	}
	
	

	public final class statusTask extends TimerTask {
		public void run() {
			handler.post(doUpdateView);
		}
	}

	public void showMessage(String message, boolean cancelAble, final Runnable task) {

		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setTitle("Attention:");
		builder.setMessage(message)
		.setCancelable(cancelAble)
		.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int id) {
				if (task != null) {
					task.run();
				} else {
					dialog.dismiss();
				}
			}
		});
		if (cancelAble) {
			builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					dialog.dismiss();
				}
			});
		}
		AlertDialog alert = builder.create();
		alert.show();
	}

	
	void restartOOR(){
		System.out.println("OOR: Restarting oor");
		stopVPN();
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		startVPN();
	}
	
	public void startVPN(){
		startVPN = true;
		Intent intent = VpnService.prepare(this);
		if (intent != null) {
			startActivityForResult(intent, VPN_SER);
		} else {
			onActivityResult(VPN_SER, RESULT_OK, null);
		}
	}
	
	public void stopVPN(){
		startVPN = false;

		Intent intent = VpnService.prepare(this);
		if (intent == null) {
			onActivityResult(VPN_SER, RESULT_OK, null);
		} 
	}
	
	
	public void onActivityResult(int request, int result, Intent data) {
		switch (request){
		case CONF_ACT:
			if (result == updateConfActivity.CONFIG_UPDATED){
				if (OORVPNService.vpn_running){
					restartOOR();
				}
			}
			break;
		case VPN_SER:
			String prefix = getPackageName();
			if (result == RESULT_OK) {
				if (startVPN == true){
					vpn_intent = new Intent(this, OORVPNService.class);
					vpn_intent.putExtra(prefix+".START", true);
					startService(vpn_intent);
					
				}else{
					vpn_intent = new Intent(this, OORVPNService.class);
					vpn_intent.putExtra(prefix+".START", false);
					startService(vpn_intent);
				}
			}
			break;
		default:
			break;
		}
    }

	public void onClick(View V) {
		CheckBox oorCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);
		if (V == findViewById(R.id.startStopCheckbox)) {
			if (oorCheckBox.isChecked()) {
				startVPN();
				return;
			}
			showMessage(this.getString(R.string.askStopServiceString),
					true, new Runnable() { public void run() {
						stopVPN();
						oorWasRunning = false;
					}
			});
		}
	}
}

