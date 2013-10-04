package org.lispmob;

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
	
	
	public SuShell()
	{
		try {
			process = Runtime.getRuntime().exec("su");
			stdin  = new DataOutputStream(process.getOutputStream());
			stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
			stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		} catch (IOException e) {
			// shell probably not found
		}
	}
	
	public String run(String command)
	{
		String res 	= null;
		
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
