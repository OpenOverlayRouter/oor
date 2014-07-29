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
