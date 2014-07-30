/*
 *
 * This file is part of the LISP on Android (LISPDroid) project
 * of LISPmob.
 * 
 * Copyright (C) 2010-2012 Cisco Systems, Inc, 2012. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Chris White       <chris@logicalelegance.com>
 *
 */
package org.lispmob.noroot;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Timer;
import java.util.TimerTask;

import org.lispmob.noroot.R;

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
public class LISPmob extends Activity implements OnClickListener {

	public static String lispd_path = null;
	private static String system_dns[] = new String[2];
	private boolean lispdWasRunning = false;
	private static boolean lispdRunning = false;
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
			lispd_path =  getPackageManager().getApplicationInfo("org.lispmob.noroot", 0).nativeLibraryDir;
			
		}catch(Exception e)
		{
			e.printStackTrace();
		};

		/*
		 * Set up the button handlers
		 */
		CheckBox lispCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);
		lispCheckBox.setOnClickListener(this);
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
		Log.v("lispMonitor", "Pausing..");
		super.onPause();

		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onStop() {
		Log.v("LISPmob", "Stopping...");
		super.onStop();
		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onResume() {
		Log.v("lispMonitor", "Resuming...");
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
			System.out.println("LISPmob: Command Failed.");
			e1.printStackTrace();
			return("Command Failed.");
		} catch (InterruptedException e) {
			e.printStackTrace();
		} 
		return(output.toString());
	}

	
	public void updateStatus() {
		final CheckBox lispCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
		final TextView lispCheckBoxLabel = (TextView) findViewById(R.id.startStopCheckboxLabel);
		final TextView statusView = (TextView) findViewById(R.id.infoView);
		

		lispdRunning = LISPmobVPNService.vpn_running;

		if (LISPmobVPNService.vpn_running) {
			lispCheckBoxLabel.setText(R.string.lispRunning);
			lispCheckBoxLabel.setTextColor(Color.WHITE);
			lispCheckBox.setChecked(true);
			//updateInfoView();
			statusView.setText("");
			lispdWasRunning = true;
		} else if (lispdWasRunning) {
			lispCheckBoxLabel.setText("lispd has exited, click to restart.");
			lispCheckBoxLabel.setTextColor(Color.RED);
			lispCheckBox.setChecked(false);
			//updateInfoView();
			statusView.setText("");
		} else {
			lispCheckBoxLabel.setText(R.string.lispNotRunning);
			lispCheckBoxLabel.setTextColor(Color.WHITE);
			lispCheckBox.setChecked(false);
			//updateInfoView();
			statusView.setText("");
		}
		
		if (!err_msg_detected && LISPmobVPNService.err_msg_code != 0){
			err_msg_detected = true;
			Resources res = getResources();
			String[] err_msg = res.getStringArray(R.array.ErrMsgArray);
			showMessage(err_msg[LISPmobVPNService.err_msg_code],
					false, new Runnable() { public void run() {
						LISPmobVPNService.err_msg_code =0;
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

	
	void restartLispd(){
		System.out.println("LISPmob: Restarting lispd");
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
				if (LISPmobVPNService.vpn_running){
					restartLispd();
				}
			}
			break;
		case VPN_SER:
			String prefix = getPackageName();
			if (result == RESULT_OK) {
				if (startVPN == true){
					vpn_intent = new Intent(this, LISPmobVPNService.class);
					vpn_intent.putExtra(prefix+".START", true);
					startService(vpn_intent);
					
				}else{
					vpn_intent = new Intent(this, LISPmobVPNService.class);
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
		CheckBox lispCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);
		if (V == findViewById(R.id.startStopCheckbox)) {
			if (lispCheckBox.isChecked()) {
				startVPN();
				return;
			}
			showMessage(this.getString(R.string.askStopServiceString),
					true, new Runnable() { public void run() {
						stopVPN();
						lispdWasRunning = false;
					}
			});
		}
	}
}

