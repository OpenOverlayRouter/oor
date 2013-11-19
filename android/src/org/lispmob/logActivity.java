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

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.TextView;
import android.widget.ScrollView;

import java.io.*;

public class logActivity extends Activity {

	public static final String logFileLocation = "/sdcard/lispd.log";
	public static final int maxReadBytes = 200000;
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		
		setContentView(R.layout.log);
	    MyDialog = progressDialog.show( logActivity.this, " " , " Loading. Please wait ... ", true);

		new Thread(new Runnable() {
            public void run() {
               refresh();
            }
        }).start();
	}
	public void refresh() {
	    StringBuffer contents = new StringBuffer();
		
		try { 
			File tmpFile = new File(logFileLocation);
			RandomAccessFile logFile = new RandomAccessFile(tmpFile, "r");
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
		
		final StringBuffer fixedContents = contents;
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
			MyDialog.dismiss();
		}
		}
		);
	}
	
	private Handler mHandler = new Handler();
	private progressDialog MyDialog = null;
	
	public void refreshClicked(View v) {
	    MyDialog = progressDialog.show( logActivity.this, null, null );

	    new Thread(new Runnable() {
            public void run() {
               refresh();
            }
        }).start();
	}
}
