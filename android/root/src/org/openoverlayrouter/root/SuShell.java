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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class SuShell {
	
	private Process 			process;
	private DataOutputStream 	stdin;
	private BufferedReader 		stdout;
	private BufferedReader 		stderr;
	
	
	public SuShell() throws IOException 
	{
		process = Runtime.getRuntime().exec("su");
		stdin  = new DataOutputStream(process.getOutputStream());
		stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
		stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()));
	}
	
	public String run(String command)
	{
		String res 	= "";
		try {
			stdin.writeBytes(command+"\n");
			stdin.flush();
			res = stdout.readLine();
		} catch (IOException e) {
			e.printStackTrace();
			return res;
		}
		return res;
	}
	
	public void run_no_output(String command)
	{
		try {
			stdin.writeBytes(command+"\n");
			stdin.flush();
		
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
