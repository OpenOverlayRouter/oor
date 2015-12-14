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

package org.openoverlayrouter.noroot;

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
	
	private static final String confFile = "oor.conf";
	
	private void refresh() {
		final TextView statusView = (TextView) findViewById(R.id.confView);
		File sdcardDir = Environment.getExternalStorageDirectory();
		File infoFile = new File(sdcardDir, confFile);
    	BufferedReader reader;
    	
    	
		try {
			reader = new BufferedReader(new FileReader(infoFile));
		} catch (FileNotFoundException e) {
			statusView.setText("Configuration file missing.\nPlease Go To \"Update OOR Configuration\" screen to create configuration.\n");
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
