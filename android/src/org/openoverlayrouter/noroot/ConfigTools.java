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
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.os.Environment;
import android.util.Log;

public class ConfigTools {
	
	public static final String confFile = "oor.conf";
	
	public static List<String> getEIDs() throws FileNotFoundException
	{
		File sdcardDir = Environment.getExternalStorageDirectory();
		File file = new File(sdcardDir, confFile);
		
		if (!file.exists()){
			Log.w("OOR", "Configuration file not exist");
			throw new FileNotFoundException();
		}
		
		List<String> eids = new ArrayList<String>();
		
		try {
			
			BufferedReader  br = new BufferedReader(new FileReader(file));
			String line 	= br.readLine();
			String sub_line	= null;
			
			while ( line != null ) {
				if (line.startsWith("#")){
					line = br.readLine();
					continue;
				}
				line = line.toLowerCase();
				line = line.replaceAll("\\s", "");
				
				if (line.contains("database-mapping")){
					do{
						sub_line = br.readLine();
						if (sub_line.startsWith("#")){
							sub_line = br.readLine();
							continue;
						}
						sub_line = sub_line.toLowerCase();
						sub_line = sub_line.replaceAll("\\s", "");
						
						if (sub_line.contains("eid-prefix")){
							String[] tmp 	= sub_line.split("=");
							if (tmp.length < 2)
								continue;
							String[] tmp_1  = tmp[1].split("/");
							if (tmp_1.length < 2)
								continue;
							if (validate_IP_Address(tmp_1[0])){
								eids.add(tmp_1[0]);
							}
						}
					}while (!sub_line.contains("}"));
				}
				line = br.readLine();
			}
		}
		catch (IOException e) {
			;
		}
		
		return eids;
	}
	
	public static List<String> getDNS() throws FileNotFoundException
	{
		File sdcardDir = Environment.getExternalStorageDirectory();
		File file = new File(sdcardDir, confFile);
		boolean overrideDNS = false;
		

		if (!file.exists()){
			Log.w("OOR", "Configuration file not exist");
			throw new FileNotFoundException();
		}
		
		List<String> dns_servers = new ArrayList<String>();
		
		try {
			
			BufferedReader  br = new BufferedReader(new FileReader(file));
			String line 	= br.readLine();
			
			while ( line != null ) {
				if (line.startsWith("#")){
					line = br.readLine();
					continue;
				}
				line = line.toLowerCase();
				line = line.replaceAll("\\s", "");
				
				
				if (line.contains("override-dns=")) {	
					String[] tmp = line.split("=");
					if(tmp.length > 1 ){
						String overrideDNS_aux = tmp[1];
						if (overrideDNS_aux.equals("on") || overrideDNS_aux.equals("true")){
							overrideDNS = true;
						}else{
							overrideDNS = false;
						}
					}
				}else if (line.contains("override-dns-primary=")) {
					String[] tmp = line.split("=");
					if (tmp.length > 1){
						if (validate_IP_Address(tmp[1])){
							dns_servers.add(tmp[1]);
						}
					}
				} else if (line.contains("override-dns-secondary=")) {
					String[] tmp = line.split("=");
					if (tmp.length > 1){
						if (validate_IP_Address(tmp[1])){
							dns_servers.add(tmp[1]);
						}
					}
				} 
			
				line = br.readLine();
			}
		}
		catch (IOException e) {
			;
		}
		if (overrideDNS){
			return (dns_servers);
		}else{
			return (null);
		}
	}
	
	
	
	
	public static boolean validate_IP_Address(String ip)
	{
		String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
		String ipv6Pattern = "([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]){1,4}";
		String ipv6Patter_com = "\\A((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)\\z";

		
		Pattern VALID_IPV4_PATTERN = null;
		Pattern VALID_IPV6_PATTERN = null;
		Pattern VALID_IPV6_COMP_PATTERN = null;
		try {
			VALID_IPV4_PATTERN = Pattern.compile(ipv4Pattern, Pattern.CASE_INSENSITIVE);
			VALID_IPV6_PATTERN = Pattern.compile(ipv6Pattern, Pattern.CASE_INSENSITIVE);
			VALID_IPV6_COMP_PATTERN = Pattern.compile(ipv6Patter_com, Pattern.CASE_INSENSITIVE);
		} catch (Exception e) {
			//logger.severe("Unable to compile pattern", e);
		}
		
		Matcher m1 = VALID_IPV4_PATTERN.matcher(ip);
	    if (m1.matches()) {
	      return true;
	    }
	    Matcher m2 = VALID_IPV6_PATTERN.matcher(ip);
	    if (m2.matches()){
	    	return true;
	    }
	    Matcher m3 = VALID_IPV6_COMP_PATTERN.matcher(ip);
	    return m3.matches();
	}
	
	/*
	 * Convination of two technics to get the list of interfaces. 
	 *  getNetworkInterfaces: in some devices it doesn't return down interfaces 
	 *  /proc/net/xt_qtaguid/iface_stat_all is not used in all versions of android
	 */
	public static List<String> get_ifaces_list()
	{
		
		List<String> iface_list = new ArrayList<String>();
		try {
			Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
			while (en.hasMoreElements())
			{
				NetworkInterface intf = en.nextElement();
				iface_list.add(intf.getName());
			}
			
			try{
				FileReader reader = new FileReader("/proc/net/xt_qtaguid/iface_stat_all");
				BufferedReader in = new BufferedReader(reader);
				String line = null;
				String device;
				while( (line = in.readLine()) != null) {
					device = line.substring(0,line.indexOf(" "));
					if (!iface_list.contains(device)){
						iface_list.add(device);
					}
				}
				reader.close();
			}catch (Exception e){e.printStackTrace();};
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return (iface_list);
	}

}
