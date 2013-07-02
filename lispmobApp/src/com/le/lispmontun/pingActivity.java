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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpTrace;
import org.apache.http.impl.client.DefaultHttpClient;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.view.View.OnClickListener;
import android.view.View.OnKeyListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.AdapterView.OnItemSelectedListener;

public class pingActivity extends Activity implements OnItemSelectedListener {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.ping); 
		
		Spinner spin = (Spinner) findViewById(R.id.recentsSpinner);
		
		m_adapterForSpinner = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
		m_adapterForSpinner.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spin.setAdapter(m_adapterForSpinner);
		spin.setOnItemSelectedListener(this);
		
		loadRecentsList();
		
		EditText ed = (EditText) findViewById(R.id.addressField);
		ed.setOnKeyListener(new OnKeyListener() {
		    public boolean onKey(View v, int keyCode, KeyEvent event) {
		    	
		        // If the event is a key-down event on the "enter" button
		        if ((event.getAction() == KeyEvent.ACTION_DOWN) &&
		            (keyCode == KeyEvent.KEYCODE_ENTER)) {
		          // Perform action on key press
		          Button goButton = (Button) findViewById(R.id.goButton);
		          goClicked(goButton);
		          return true;
		        }
		        return false;
		    }
		});
	}
	
	public void runPing(String address) {
		StringBuffer output = new StringBuffer();
		running = true;
		Process process = null;
		int timeoutCounter = 100;
		String command = "/system/bin/busybox";
		String extraArg = "";
		if (address.contains(":")) {
			extraArg = "ping6";
		} else {
			command = "/system/bin/ping";
			extraArg = "-i1";
		}
		String sizeArg = "-s";
		sizeArg = sizeArg.concat(Integer.toString(mPingSize));
		try {
			process = new ProcessBuilder()
			.command(command, extraArg, "-c100", sizeArg, address) // c 100 prevents running forever if lispmonapp crashes
			.redirectErrorStream(true)
			.start();
			InputStream in = process.getInputStream();
			BufferedReader reader = new BufferedReader(new InputStreamReader(in));
			String line;
			
			while ((!stopPing) && (timeoutCounter != 0)) {
				if (!reader.ready()) {
					Thread.sleep(100);
					timeoutCounter--;
					if ((timeoutCounter % 20) == 0) {
						output.append(".");
						final StringBuffer tmp = output;
						mHandler.post(new Runnable() { public void run() {
							// Put the file contents into the TextView

							TextView log = (TextView) findViewById(R.id.pingView); 
							log.setText(tmp);
						}
						}
						);
					}
					continue;
					
				}
			
				timeoutCounter = 100; // Reset
				line = reader.readLine();

				if (line != null) {
					output.append(line);
					output.append('\n');
					final StringBuffer tmp = output;
					mHandler.post(new Runnable() { public void run() {
						// Put the file contents into the TextView

						TextView log = (TextView) findViewById(R.id.pingView); 
						log.setText(tmp);
					}
					}
					);
				}
			}
			
			if (timeoutCounter == 0) {
				output.append("No response from ");
				output.append(address);
				output.append(" after 10 seconds, stopping.");
				final StringBuffer tmp = output;
				mHandler.post(new Runnable() { public void run() {
					// Put the file contents into the TextView

					TextView log = (TextView) findViewById(R.id.pingView); 
					log.setText(tmp);
				}
				}
				);
			}
		} catch (IOException e1) {
		} catch (InterruptedException e) {
		} 
		if (process != null) {
			process.destroy();
		}	
		
		// Update the button to be go again.
		mHandler.post(new Runnable() { public void run() {
			// Put the file contents into the TextView

			Button b = (Button) findViewById(R.id.goButton); 
			b.setText("Go");
		}
		}
		);
		running = false;
	}
	
	final int tcpPort = 80;
	public void runTCPPing(String address) {
		StringBuffer output = new StringBuffer();
		running = true;
	
		Runnable updateButton = new Runnable() { public void run() {
			// Put the file contents into the TextView

			Button b = (Button) findViewById(R.id.goButton); 
			b.setText("Go");
		}
		};
		
		int timeoutCounter = 100;
		
		HttpClient httpClient = new DefaultHttpClient();
		StringBuilder uriBuilder = new StringBuilder("http://");
		uriBuilder.append(address);
		 
		HttpTrace request = new HttpTrace(uriBuilder.toString());
		HttpResponse response = null;
		try {
			response = httpClient.execute(request);
		} catch (ClientProtocolException e1) {
			// TODO Auto-generated catch block
			Log.e("TCP Ping", "ClientProtocolException");
			e1.printStackTrace();
			mHandler.post(updateButton);

			running = false;
			return;
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			Log.e("TCP Ping", "IOException");
			mHandler.post(updateButton);

			running = false;
			e1.printStackTrace();
			return;
		}
		 
		int status = response.getStatusLine().getStatusCode();
		 
		// we assume that the response body contains the error message
		if (status != HttpStatus.SC_OK) {
		    ByteArrayOutputStream ostream = new ByteArrayOutputStream();
	
		    try {
				response.getEntity().writeTo(ostream);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			final String tmp = ostream.toString();
			mHandler.post(new Runnable() { public void run() {
				// Put the file contents into the TextView

				TextView log = (TextView) findViewById(R.id.pingView); 
				log.setText(tmp);
			}
			}
			);
		   
		
		} else {
		
		    InputStream content = null;
			try {
				content = response.getEntity().getContent();
			} catch (IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		    // <consume response>
		    BufferedReader reader = new BufferedReader(new InputStreamReader(content));
			
			while ((!stopPing) && (timeoutCounter != 0)) {
					String line = null;
					try {
						line = reader.readLine();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						continue;
					}

					if (line != null) {
						output.append(line);
						output.append('\n');
						final StringBuffer tmp = output;
						mHandler.post(new Runnable() { public void run() {
							// Put the file contents into the TextView

							TextView log = (TextView) findViewById(R.id.pingView); 
							log.setText(tmp);
						}
						}
						);
					}
			}
		    try {
				content.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} // this will also close the connection
		
		}
		// Update the button to be go again.
		mHandler.post(updateButton);
		running = false;
	}
	
	private volatile boolean stopPing = false;
	private Handler mHandler = new Handler();
	private boolean running = false;
	private Thread pingThread = null;
	
	private final int maxRecents = 5;
	private String[] recentsArray = new String[maxRecents];
	private int numRecents = 0;
	private ArrayAdapter<CharSequence> m_adapterForSpinner;
	
	public void goClicked(View v) {
		Button goButton = (Button) findViewById(R.id.goButton);
		final EditText ed = (EditText) findViewById(R.id.addressField);
		TextView pingView = (TextView) findViewById(R.id.pingView);
		Spinner spinner = (Spinner) findViewById(R.id.recentsSpinner);
		
		if (!running) {
			boolean dup = false;
			
			// Ignore duplicates
			for (int i = 0; i < numRecents; i++) {
				final String edText = ed.getText().toString();
				if (recentsArray[i].equals(edText)) { 
					dup = true;
					break;
				} 
			}
			
			if (!dup) {
				
				// Rotate if numRecents reaches max.
				if (numRecents < maxRecents) {
					recentsArray[numRecents] = ed.getText().toString();
					numRecents++;
					m_adapterForSpinner.add(ed.getText().toString());
				} else {
					m_adapterForSpinner.clear();
					for (int i = maxRecents - 1; i >= 1; i--) {
						recentsArray[i] = recentsArray[i - 1];
					}
					recentsArray[0] = ed.getText().toString();
					for (int i = 0; i < maxRecents; i++) {
						m_adapterForSpinner.add(recentsArray[i]);
					}
				}
			} 
			spinner.setSelection(m_adapterForSpinner.getPosition(ed.getText().toString()));

			stopPing = false;
			pingView.setText("Starting ping...");
			InputMethodManager imm = (InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE);
			imm.hideSoftInputFromWindow(ed.getWindowToken(), 0);  // dismiss keyboard
			
			if (!pingModeTCP) {
			pingThread = new Thread(new Runnable() {
				public void run() {
					final EditText ed = (EditText) findViewById(R.id.addressField);
					runPing(ed.getText().toString());
				}
			});
			} else {
				pingThread = new Thread(new Runnable() {
					public void run() {
						final EditText ed = (EditText) findViewById(R.id.addressField);
						runTCPPing(ed.getText().toString());
					}
				});
			}
			pingThread.start();
			goButton.setText("Stop");
		} else {
			stopPing = true;
			goButton.setText("...");
			goButton.setEnabled(false);
			try {
				pingThread.join(5000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			 
			if (running) {
				  Toast.makeText(this,
		                     "Failed to kill ping", Toast.LENGTH_LONG).show();
				  goButton.setText("Stop");
			} else {
				goButton.setText("Go");
			}
			goButton.setEnabled(true);
		}
	}

	public void onItemSelected(AdapterView<?> arg0, View arg1, int arg2,
			long arg3) {
		EditText ed = (EditText) findViewById(R.id.addressField);
		ed.setText(arg0.getItemAtPosition(arg2).toString());
	}
	

	public void onNothingSelected(AdapterView<?> arg0) {
		// TODO Auto-generated method stub
		
	}
	
	@Override
	
	// Save the recent pings list across invocations
	protected void onPause() {
		super.onPause();
		
		// Stop any ongoing activity
		stopPing = true;
		try {
			if ((pingThread != null) && pingThread.isAlive()) {
			pingThread.join(5000);
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SharedPreferences preferences = getPreferences(MODE_PRIVATE);
		SharedPreferences.Editor editor = preferences.edit();
		
		for (int i = 0; i < numRecents; i++) {
			String key = new String();
			
			key = key.concat("RecentPing");
			key = key.concat(Integer.toString(i));
			editor.putString(key, recentsArray[i]);
		}
		editor.commit();
	}
	
	private void loadRecentsList() 
	{

		SharedPreferences preferences = getPreferences(MODE_PRIVATE);

		for (int i = 0; i < maxRecents; i++) {
			String key = new String();

			key = key.concat("RecentPing");
			key = key.concat(Integer.toString(i));
			recentsArray[i] = preferences.getString(key, "");
			m_adapterForSpinner.add(recentsArray[i]);
		}
		numRecents = maxRecents;
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
	    MenuInflater inflater = getMenuInflater();
	    inflater.inflate(R.layout.pingmenu, menu);
	    return true;
	}
	
	boolean pingModeTCP = false;
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
	    // Handle item selection
	    switch (item.getItemId()) {
	    case R.id.pingMode:
	    	Log.v("pingActivity", "Ping mode changed");
	    	pingModeTCP = !pingModeTCP;
	    	if (pingModeTCP) {
	    		item.setTitle("Set ping mode to ICMP");
	    	} else {
	    		item.setTitle("Set ping mode to TCP");
	    	}
	    	break;
	    case R.id.pingSize:
	    	Log.v("pingActivity", "Changing ping size");
	    	showDialog(0);
	    	break;
	    default:
	        return super.onOptionsItemSelected(item);
	    }
		return super.onOptionsItemSelected(item);
	}
	int mPingSize = 56;
	
	protected Dialog onCreateDialog(int id) {
		Dialog dialog = new Dialog(this);
		dialog.setContentView(R.layout.pingsizedialog);
		dialog.setTitle("Enter ICMP ping size");
		Button button = (Button) dialog.findViewById(R.id.okButton);
		final Dialog tmp = dialog;
		button.setOnClickListener(new OnClickListener() {
			public void onClick(View V) {
				EditText ed = (EditText) tmp.findViewById(R.id.sizeField);
				mPingSize = Integer.parseInt(ed.getText().toString());
				String pingStr = "ping size changed to ";
				pingStr = pingStr.concat(Integer.toString(mPingSize));
				Log.e("pingActivity", pingStr);
				tmp.dismiss();
			}
		});
		return dialog;
	}
}
