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

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.view.View;
import android.widget.TextView;
import android.widget.ScrollView;

import java.io.*;

public class logActivity extends Activity {


	private ProgressDialog myDialog = null;
	private Handler mHandler = new Handler();


	private static File log_file = null;
	public static final int maxReadBytes = 200000;
	
	
	public void onConfigurationChanged(Configuration newConfig) {
		super.onConfigurationChanged(newConfig);
		setContentView(R.layout.log);
		if (myDialog == null){
			myDialog = ProgressDialog.show( logActivity.this, null, null,true );
		}
		new Thread(new Runnable() {
			public void run() {
				refresh();
			}
		}).start();
	}
	
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		File sdcardDir = Environment.getExternalStorageDirectory();
		log_file = new File(sdcardDir, "lispd.log");

		setContentView(R.layout.log);
		//myDialog = ProgressDialog.show( logActivity.this, " " , " Loading. Please wait ... ", true);
		myDialog = ProgressDialog.show( logActivity.this, null, null,true );

		new Thread(new Runnable() {
			public void run() {
				refresh();
			}
		}).start();
	}
	public void refresh() {
	
		StringBuffer contents = new StringBuffer();

		final StringBuffer fixedContents = contents;

		try { 
			RandomAccessFile logFile = new RandomAccessFile(log_file, "r");
			if (logFile.length() > maxReadBytes) {
				logFile.seek(logFile.length() - maxReadBytes);
			}
			String currentLine = logFile.readLine();
			while (currentLine != null) {

				if (currentLine != null) {
					contents.append(currentLine);
					contents.append('\n');
				}
				currentLine = logFile.readLine();
			}
			try {
				if (logFile != null) {
					logFile.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {

		}
		
		mHandler.post(new Runnable() { public void run() {
			
			
			// Put the file contents into the TextView
			TextView log = (TextView) findViewById(R.id.logView); 
			log.setText(fixedContents);

			// Auto scroll to the bottom
			final ScrollView scroll = (ScrollView) findViewById(R.id.scrollView1);
			scroll.post(new Runnable() {            
				public void run() {
					scroll.fullScroll(View.FOCUS_DOWN);              
				}
			});
			if (myDialog != null){
				myDialog.dismiss();
				myDialog = null;
			}
		}
		}
				);
	}

	public void refreshClicked(View v) {
		myDialog = ProgressDialog.show( logActivity.this, null, null );

		new Thread(new Runnable() {
			public void run() {
				refresh();
			}
		}).start();
	}
}
