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
package org.lispmob;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import android.app.Activity;
import android.app.AlertDialog;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Bundle;
import android.os.Handler;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.widget.CheckBox;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;

public class LISPmob extends Activity implements OnClickListener {

	protected static SuShell shell;
	public static String lispd_path = "";
	private static String system_dns[] = new String[2];
	private boolean lispdWasRunning = false;
	private static boolean lispdRunning = false;
	
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		
		shell = new SuShell();
		
		/* Get the directory of the executable */
		
		try{
			lispd_path =  getPackageManager().getApplicationInfo("org.lispmob", 0).nativeLibraryDir;
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
				startActivityForResult(myIntent, 0);
			}
		}
				);
		Button conf = (Button) findViewById(R.id.showConfButton);
		conf.setOnClickListener(new View.OnClickListener() {
			public void onClick(View view) {
				Intent myIntent = new Intent(view.getContext(), confActivity.class);
				startActivityForResult(myIntent, 0);
			}
		}
				);

		Button updateconf = (Button) findViewById(R.id.updateConfButton);
		updateconf.setOnClickListener(new View.OnClickListener() {
			public void onClick(View view) {
				Intent myIntent = new Intent(view.getContext(), updateConfActivity.class);
				startActivityForResult(myIntent, 0);
			}
		}
				);
		
		system_dns = get_dns_servers();
		
	}


	Location lastLocation;

	Timer mUpdateTimer = null;
	@Override
	protected void onPause() {
		super.onPause();

		Log.v("lispMonitor", "Pausing..");
		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onStop() {
		super.onStop();

		Log.v("lispMonitor", "Stopping...");
		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onResume() {
		super.onResume();

		Log.v("lispMonitor", "Resuming...");

		// Rebuild the timer
		if (mUpdateTimer != null) {
			mUpdateTimer.cancel();
		}
		mUpdateTimer = new Timer();
		mUpdateTimer.scheduleAtFixedRate(new statusTask(), 0, fONCE_PER_SECOND);
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

	final String infoFileLocation = "/sdcard/lispd.info";
	public void updateInfoView() {
		final TextView statusView = (TextView) findViewById(R.id.infoView);
		File infoFile = new File(infoFileLocation);
		BufferedReader reader;

		try {
			reader = new BufferedReader(new FileReader(infoFile));
		} catch (FileNotFoundException e) {
			statusView.setText("Info file missing.");
			return;
		}
		String line;
		StringBuffer output = new StringBuffer();

		try {
			while ((line = reader.readLine()) != null) {
				output.append(line);
				output.append("\n");
			}
		} catch (IOException e) {
			statusView.setText("Info file read error.");
			return;
		}
		statusView.setText(output.toString());
	}


	
	public void updateStatus() {
		final CheckBox lispCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
		final TextView lispCheckBoxLabel = (TextView) findViewById(R.id.startStopCheckboxLabel);
		final TextView statusView = (TextView) findViewById(R.id.infoView);

		String psOutput = runTask("/system/bin/ps", "", false);

		lispdRunning = psOutput.contains("R "+lispd_path+"/liblispd.so") || psOutput.contains("S "+lispd_path+"/liblispd.so"); // No zombies only running or sleeping.

		if (lispdRunning) {
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
	}
	
	public static boolean isLispRunning(){
		return (lispdRunning);
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

	static public void killLispd() {
		String command = "killall -s 15 liblispd.so";
		shell.run_no_output(command);
		return;
	}

	static public String startLispd() {
		String command = lispd_path+"/liblispd.so -D -f /sdcard/lispd.conf";
		return(shell.run(command));
	}
	
	static public void restartLispd(){
		System.out.println("LISPmob: Restarting lispd");
		killLispd();
		startLispd();
	}

	Handler handler;
	Runnable doUpdateView;
	//expressed in milliseconds
	private final static long fONCE_PER_SECOND = 1000;

	public void onClick(View V) {
		CheckBox lispCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);
		if (V == findViewById(R.id.startStopCheckbox)) {
			if (lispCheckBox.isChecked()) {
				if (updateConfActivity.isOverrideDNS()){
					String dns[] = updateConfActivity.getNewDNS();
					set_dns_servers(dns[0],dns[1]);
				}
				startLispd();
				return;
			}
			showMessage("Stop the LISP service?",
					true, new Runnable() { public void run() {
						if (updateConfActivity.isOverrideDNS()){
							set_dns_servers(system_dns[0],system_dns[1]);
						}
						killLispd();
						lispdWasRunning = false;
					}
			});
		}
	}
	
	public String[] get_dns_servers(){
		String command = null;
		String dns[] = new String[2];
		
		command = "getprop net.dns1";
		dns[0] = shell.run(command);
		
		command = "getprop net.dns2";
		dns[1] = shell.run(command);
		
		System.out.println("LISPmob: DNS Server 1: "+dns[0]+", DNS Server 2: "+dns[1]);
		
		return dns;
	}
	
	public static void set_dns_servers(String dns1, String dns2){
		String command = null;
						
		command = "setprop net.dns1 \""+dns1+"\"";
		shell.run_no_output(command);
		
		command = "setprop net.dns2 \""+dns2+"\"";
		shell.run_no_output(command);
		
		System.out.println("LISPmob: Set DNS Server 1: "+dns1+" and  DNS Server 2: "+dns2);
	
	}
}

