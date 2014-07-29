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
package org.lispmob.root;

import java.io.File;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import android.app.Activity;
import android.app.AlertDialog;
import android.location.Location;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
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
	private boolean lispdWasRunning = false;
	public static String conf_file = "";
	public static String prefix = "";
	private static final int CONF_ACT = 1;
	
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {

		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		
		try{
			shell = new SuShell();
		}catch (IOException e){
			showMessage(this.getString(R.string.noRootedString),
					false, new Runnable() { public void run() {
						finish();
					}
			});
		}
		
		/* Get the directory of the executable */
		
		try{
			lispd_path =  getPackageManager().getApplicationInfo("org.lispmob.root", 0).nativeLibraryDir;
			conf_file = Environment.getExternalStorageDirectory().getAbsolutePath() + "/lispd.conf";
		}catch(Exception e)
		{
			e.printStackTrace();
		};

		prefix = getPackageName();

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
				startActivityForResult(myIntent, CONF_ACT);
			}
		}
				);
		
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
		mUpdateTimer.scheduleAtFixedRate(new statusTask(), 0, 1000);
	}

	
	
	public void updateStatus() {
		final CheckBox lispCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
		final TextView lispCheckBoxLabel = (TextView) findViewById(R.id.startStopCheckboxLabel);
		final TextView statusView = (TextView) findViewById(R.id.infoView);

		if (isLispRunning()) {
			lispCheckBoxLabel.setText(R.string.lispRunning);
			lispCheckBoxLabel.setTextColor(Color.WHITE);
			lispCheckBox.setChecked(true);
			statusView.setText("");
			lispdWasRunning = true;
		} else {
			if (lispdWasRunning) {
				lispCheckBoxLabel.setText("lispd has exited, click to restart.");
				lispCheckBoxLabel.setTextColor(Color.RED);
				lispCheckBox.setChecked(false);
				statusView.setText("");
			} else {
				lispCheckBoxLabel.setText(R.string.lispNotRunning);
				lispCheckBoxLabel.setTextColor(Color.WHITE);
				lispCheckBox.setChecked(false);
				statusView.setText("");
			}
		}
	}
	
	public static boolean isLispRunning(){
		return (LISPmobService.isRunning);
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

	public void startLispd() {
		String command = lispd_path+"/liblispd.so -D -f "+conf_file;
		shell.run_no_output(command);
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {e.printStackTrace();}
		Intent serviceIntent = new Intent(this, LISPmobService.class);
		serviceIntent.putExtra(prefix+".START", true);
		startService(serviceIntent);
	}
	
	public void killLispd() {
		String command = "killall liblispd.so";
		shell.run_no_output(command);
		
		lispdWasRunning = false;
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {e.printStackTrace();}
		Intent serviceIntent = new Intent(this, LISPmobService.class);
		serviceIntent.putExtra(prefix+".START", false);
		startService(serviceIntent);
		return;
	}
	
	public void restartLispd(){
		System.out.println("LISPmob: Restarting lispd");
		killLispd();
		startLispd();
	}

	Handler handler;
	Runnable doUpdateView;

	public void onClick(View V) {
		View objView = findViewById(R.id.startStopCheckbox);
		CheckBox lispCheckBox = null; 
		if (V == objView) {
			lispCheckBox = (CheckBox)objView;
			if (lispCheckBox.isChecked()) {
				/* Check if the configuration file exists*/
				File file = new File(conf_file);
				if (!file.exists()){
					showMessage(this.getString(R.string.noConfFile),false, null);
				}
				startLispd();
			}else{
				showMessage(this.getString(R.string.askStopServiceString),
						true, new Runnable() { public void run() {
							killLispd();
						}
				});
			}

		}
	}

	public void onActivityResult(int request, int result, Intent data) {
		switch (request){
		case CONF_ACT:
			if (result == updateConfActivity.CONFIG_UPDATED){
				if (isLispRunning()){
					restartLispd();
				}
			}
			break;
		default:
			break;
		}
    }
	
}

