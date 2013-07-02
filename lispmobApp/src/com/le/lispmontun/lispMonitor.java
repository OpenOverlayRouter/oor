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
package com.le.lispmontun;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
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

public class lispMonitor extends Activity implements OnClickListener {
	protected static final float MinLocationUpdateDistance = 100; // 100 Meters
	/** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
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
        
        Button cache = (Button) findViewById(R.id.showCacheButton);
        cache.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), mapCacheActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );
        
        Button ping = (Button) findViewById(R.id.pingButton);
        ping.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), pingActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );
        
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
    
        Button datacache = (Button) findViewById(R.id.showDataCacheButton);
        datacache.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), dataCacheActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );

        Button clearcache = (Button) findViewById(R.id.showClearCacheButton);
        clearcache.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), clearCacheActivity.class);
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
        
        // Acquire a reference to the system Location Manager
        LocationManager locationManager = (LocationManager) this.getSystemService(Context.LOCATION_SERVICE);

        // Define a listener that responds to location updates
        LocationListener locationListener = new LocationListener() {
			public void onLocationChanged(Location location) {
				// Called when a new location is found by the network location
				// provider.
				float distance = MinLocationUpdateDistance + 1.0f; // Force first update
				String locInfo = String.format(
"(%f, %f, %f)", location
						.getLatitude(), location.getLongitude(), location
						.getAltitude());
				if (lastLocation != null) {
					distance = location.distanceTo(lastLocation);
				}
				lastLocation = location;

				if (distance > MinLocationUpdateDistance) {
					// Send location to lispd
					lispdSocket = new LocalSocket();
					try {
						lispdSocket.connect(lispdSocketAddr);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						Log.v("lispMonitor", "Failed to open lispd socket");
						e.printStackTrace();
						return;
					}
					OutputStream out;
					try {
						out = lispdSocket.getOutputStream();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						Log.v("lispMonitor",
								"Failed to get output stream to lispd");
						e.printStackTrace();
						return;
					}

					OutputStreamWriter writer = new OutputStreamWriter(out);
					try {
						writer.write("LOCATION:");
						writer.write(locInfo);
						writer.flush();
						lispdSocket.close();
					} catch (IOException e) {

						// TODO Auto-generated catch block
						Log.v("lispMonitor",
								"Failed to send location command to lispd");
						e.printStackTrace();
					}

					Log.v("lispMonitor", "Got location update." + locInfo);
				}
			}
            public void onStatusChanged(String provider, int status, Bundle extras) {}

            public void onProviderEnabled(String provider) {}

            public void onProviderDisabled(String provider) {}
          };

        // Register the listener with the Location Manager to receive location updates
    //    locationManager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 0, 0, locationListener);
    //    locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0, locationListener);

        // Set up the communication path to lispd. This will be extended to take over
        // from lispconf eventually.
        lispdSocketAddr = new LocalSocketAddress("/data/data/com.le.lispmontun/lispd_ipc_server", LocalSocketAddress.Namespace.FILESYSTEM);
        lispdSocket = new LocalSocket();
    }
    
    LocalSocketAddress lispdSocketAddr;
    LocalSocket        lispdSocket;
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
    		return("Command Failed.");
    	} catch (InterruptedException e) {
			// TODO Auto-generated catch block
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
    
    boolean lispdWasRunning = false;
    public void updateStatus() {
    	final CheckBox lispCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
    	final TextView lispCheckBoxLabel = (TextView) findViewById(R.id.startStopCheckboxLabel);
    	final TextView statusView = (TextView) findViewById(R.id.infoView);
    	boolean lispdRunning = false;
    	
    	String psOutput = runTask("/system/bin/ps", "", false);
    	
    	lispdRunning = psOutput.contains("R /system/bin/lispd") || psOutput.contains("S /system/bin/lispd"); // No zombies only running or sleeping.
    	
    	if (lispdRunning) {
    		lispCheckBoxLabel.setText(R.string.lispRunning);
    		lispCheckBoxLabel.setTextColor(Color.WHITE);
    		lispCheckBox.setChecked(true);
    		updateInfoView();
    		lispdWasRunning = true;
    	} else if (lispdWasRunning) {
    		lispCheckBoxLabel.setText("lispd has exited, click to restart.");
    		lispCheckBoxLabel.setTextColor(Color.RED);
    		
    		lispCheckBox.setChecked(false);
    		try {
				lispdSocket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    		updateInfoView();
    	} else {
    		lispCheckBoxLabel.setText(R.string.lispNotRunning);
    		lispCheckBoxLabel.setTextColor(Color.WHITE);
    		lispCheckBox.setChecked(false);
    		updateInfoView();

    		statusView.setText("");
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
    
    public String killLispd() {
    	String command = "/system/bin/lispmanager";
    	return(runTask(command, "stop", true));
    }
    
    public String startLispd() {
    	String command = "/system/bin/lispmanager";
    	 return(runTask(command, "start", true));
    }
    
    Handler handler;
    Runnable doUpdateView;
    //expressed in milliseconds
	private final static long fONCE_PER_SECOND = 1000;

	public void onClick(View V) {
		CheckBox lispCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);

		if (V == findViewById(R.id.startStopCheckbox)) {
			if (lispCheckBox.isChecked()) {
				startLispd();
				return;
			}
			showMessage("Stop the LISP service?",
					true, new Runnable() { public void run() {
						killLispd();
						lispdWasRunning = false;
					}
			});
		}
	}
}

