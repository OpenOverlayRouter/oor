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

package org.openoverlayrouter.root;

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

public class OOR extends Activity implements OnClickListener {

	protected static SuShell shell;
	public static String oor_path = "";
	private boolean oorWasRunning = false;
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
			oor_path =  getPackageManager().getApplicationInfo("org.openoverlayrouter.root", 0).nativeLibraryDir;
			conf_file = Environment.getExternalStorageDirectory().getAbsolutePath() + "/oor.conf";
		}catch(Exception e)
		{
			e.printStackTrace();
		};

		prefix = getPackageName();

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

		Log.v("OOR", "Pausing..");
		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onStop() {
		super.onStop();

		Log.v("OOR", "Stopping...");
		// Stop all timers
		mUpdateTimer.cancel();
	}

	@Override
	protected void onResume() {
		super.onResume();

		Log.v("OOR", "Resuming...");

		// Rebuild the timer
		if (mUpdateTimer != null) {
			mUpdateTimer.cancel();
		}
		mUpdateTimer = new Timer();
		mUpdateTimer.scheduleAtFixedRate(new statusTask(), 0, 1000);
	}

	
	
	public void updateStatus() {
		final CheckBox oorCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
		final TextView oorCheckBoxLabel = (TextView) findViewById(R.id.startStopCheckboxLabel);
		final TextView statusView = (TextView) findViewById(R.id.infoView);

		if (isOorRunning()) {
			oorCheckBoxLabel.setText(R.string.oorRunning);
			oorCheckBoxLabel.setTextColor(Color.WHITE);
			oorCheckBox.setChecked(true);
			statusView.setText("");
			oorWasRunning = true;
		} else {
			if (oorWasRunning) {
				oorCheckBoxLabel.setText("oor has exited, click to restart.");
				oorCheckBoxLabel.setTextColor(Color.RED);
				oorCheckBox.setChecked(false);
				statusView.setText("");
			} else {
				oorCheckBoxLabel.setText(R.string.oorNotRunning);
				oorCheckBoxLabel.setTextColor(Color.WHITE);
				oorCheckBox.setChecked(false);
				statusView.setText("");
			}
		}
	}
	
	public static boolean isOorRunning(){
		return (OORService.isRunning);
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

	public void startOOR() {
		String command = oor_path+"/liboor.so -D -d 2 -f "+conf_file;
		shell.run_no_output(command);
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {e.printStackTrace();}
		Intent serviceIntent = new Intent(this, OORService.class);
		serviceIntent.putExtra(prefix+".START", true);
		startService(serviceIntent);
	}
	
	public void killOOR() {
		String command = "killall liboor.so";
		shell.run_no_output(command);
		
		oorWasRunning = false;
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {e.printStackTrace();}
		Intent serviceIntent = new Intent(this, OORService.class);
		serviceIntent.putExtra(prefix+".START", false);
		startService(serviceIntent);
		return;
	}
	
	public void restartOOR(){
		System.out.println("OOR: Restarting oor");
		killOOR();
		startOOR();
	}

	Handler handler;
	Runnable doUpdateView;

	public void onClick(View V) {
		View objView = findViewById(R.id.startStopCheckbox);
		CheckBox oorCheckBox = null; 
		if (V == objView) {
			oorCheckBox = (CheckBox)objView;
			if (oorCheckBox.isChecked()) {
				/* Check if the configuration file exists*/
				File file = new File(conf_file);
				if (!file.exists()){
					showMessage(this.getString(R.string.noConfFile),false, null);
				}
				startOOR();
			}else{
				showMessage(this.getString(R.string.askStopServiceString),
						true, new Runnable() { public void run() {
							killOOR();
						}
				});
			}

		}
	}

	public void onActivityResult(int request, int result, Intent data) {
		switch (request){
		case CONF_ACT:
			if (result == updateConfActivity.CONFIG_UPDATED){
				if (isOorRunning()){
					restartOOR();
				}
			}
			break;
		default:
			break;
		}
    }
	
}

