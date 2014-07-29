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

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.widget.TextView;

public class confActivity extends Activity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.conf); 
		refresh();
	}
	
	private static final String confFile = "lispd.conf";
	
	private void refresh() {
		final TextView statusView = (TextView) findViewById(R.id.confView);
		File sdcardDir = Environment.getExternalStorageDirectory();
		File infoFile = new File(sdcardDir, confFile);
    	BufferedReader reader;
    	
    	
		try {
			reader = new BufferedReader(new FileReader(infoFile));
		} catch (FileNotFoundException e) {
			statusView.setText("Configuration file missing.\nPlease Go To \"Update LISP Configuration\" screen to input configuration.\n");
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
			statusView.setText("Configuration file read error.");
			return;
		}
    	statusView.setText(output.toString());
	}
	
}
