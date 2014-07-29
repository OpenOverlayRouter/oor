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
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.content.DialogInterface;
import android.content.Intent;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.ArrayAdapter;


public class updateConfActivity extends Activity {
	
	public static final String confFile = "lispd.conf";
	
	public static String eidIPv4 = "";
	public static String eidIPv6 = "";
	public static List<String> ifaces = null;
	public static String MR = "";
	public static String MS = "";
	public static String MSKey = "password";
	public static String proxyETR = "";
	public static String DNS1 = "";
	public static String DNS2 = "";
	public static boolean overrideDNS = false; 
	public static boolean nat_aware = false;
	public static int rloc_prob_interval = 30;
	public static int rloc_prob_retries = 2;
	public static int rloc_prob_retries_interval = 5;
	public static String logLevel = "1";
	public static final int CONFIG_UPDATED = 1;
	public static File conf_file = null;
	public static List<String> iface_list = null;
	
	@Override
	public void onCreate(Bundle savedInstanceState) {
		
		super.onCreate(savedInstanceState);
		setContentView(R.layout.updateconf); 
		
		File sdcardDir = Environment.getExternalStorageDirectory();
		conf_file = new File(sdcardDir, confFile);
		
		
		iface_list = ConfigTools.get_ifaces_list();
		

		//Spinner spinner = (Spinner) findViewById(R.id.IfaceNameSpinner);
		MultiSelectionSpinner spinner = (MultiSelectionSpinner) findViewById(R.id.IfaceNameSpinner);
		ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,android.R.layout.simple_spinner_item,iface_list);
		// Specify the layout to use when the list of choices appears
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		// Apply the adapter to the spinner
		//spinner.setAdapter(adapter);
		spinner.setItems(iface_list);

		Spinner logSpinner = (Spinner) findViewById(R.id.LogSpinner);
		ArrayAdapter<CharSequence> logAdapter = ArrayAdapter.createFromResource(this,R.array.LogLevelArray, android.R.layout.simple_spinner_item);
		logSpinner.setAdapter(logAdapter);

		if ( !conf_file.exists() ) {
			createConfFile();
		}
		
		readConfFileAndFillParameters();
		
	}
	
	
		
	public void readConfFileAndFillParameters() 
	{
		
		try {
			
			BufferedReader  br = new BufferedReader(new FileReader(conf_file));
			String line 	= br.readLine();
			String sub_line	= null;
			String sub_line_1 = null;
			ifaces = new ArrayList<String>();
			
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
							if (tmp_1[0].contains(":")){
								eidIPv6 = tmp_1[0];
								EditText e = (EditText) findViewById(R.id.updateConfeid6Text);
								e.setText(eidIPv6);
							}else if (tmp_1[0].contains(".")){
								eidIPv4 = tmp_1[0];
								EditText e = (EditText) findViewById(R.id.updateConfeid4Text);
								e.setText(eidIPv4);
							}
						}
						if (sub_line.contains("interface")){
							String[] tmp 	= sub_line.split("=");
							if (tmp.length < 2)
								continue;
							String iface_name = tmp[1];
							
							Iterator <String>iface_it = iface_list.iterator();
							while (iface_it.hasNext())
							{
								if (iface_it.next().equals(iface_name)){
									if (!ifaces.contains(iface_name)){
										ifaces.add(iface_name);
									}
									break;
								}
							}	
						}
					}while (!sub_line.contains("}"));
				}else if (line.contains("map-resolver")) {
					sub_line = br.readLine();
					if (sub_line.startsWith("#")){
						sub_line = br.readLine();
						continue;
					}
					sub_line = sub_line.replaceAll("\\s", "");

					if (sub_line.contains(",")){
						String[] tmp = sub_line.split(",");
						if (tmp.length!=0){
							MR = tmp[0];
						}
					}else {
						MR = sub_line;
					}
					
					EditText e = (EditText) findViewById(R.id.updateConfMRText);
					e.setText(MR);
				} else if (line.contains("nat-traversal") && !line.startsWith("#")) {
					do {
						sub_line = br.readLine();
						if (sub_line.startsWith("#")){
							sub_line = br.readLine();
							continue;
						}
						sub_line = sub_line.toLowerCase();
						sub_line = sub_line.replaceAll("\\s", "");						

						if (sub_line.contains("nat_aware")) {
							String[] tmp = sub_line.split("=");
							if(tmp.length < 2)
								continue;
							String nat_aware_aux = tmp[1];
							if (nat_aware_aux.equals("on") || nat_aware_aux.equals("true")){
								nat_aware = true;
							}else{
								nat_aware = false;
							}
						}
					}while (!sub_line.contains("}"));
					CheckBox c = (CheckBox)findViewById(R.id.updateConf_NAT_aware);
					c.setChecked(nat_aware);
				} else if (line.contains("map-server")) {
					do {
						sub_line = br.readLine();
						if (sub_line.startsWith("#")){
							sub_line = br.readLine();
							continue;
						}
						sub_line_1 = sub_line; // Not lose uppercase in password
						sub_line = sub_line.toLowerCase();
						sub_line = sub_line.replaceAll("\\s", "");

						if (sub_line.contains("address")) {
							String[] tmp = sub_line.split("=");
							if (tmp.length>1){
								MS = tmp[1];
							}
						} else if (sub_line.contains("key")) {
							String[] tmp = sub_line_1.split("=");
							if (tmp.length>1){
								MSKey = tmp[1];
							}
						} 
					} while (!sub_line.contains("}"));
					
					EditText e = (EditText) findViewById(R.id.updateConfMSText);
					e.setText(MS);

					EditText et = (EditText) findViewById(R.id.updateConfMSKeyText);
					et.setText(MSKey);
				} else if (line.contains("proxy-etr")) {
					do {
						sub_line = br.readLine();
						if (sub_line.startsWith("#")){
							sub_line = br.readLine();
							continue;
						}
						sub_line = sub_line.toLowerCase();
						sub_line = sub_line.replaceAll("\\s", "");

						if (sub_line.contains("address")) {
							String[] tmp = sub_line.split("=");
							if (tmp.length > 1){
								proxyETR = tmp[1];
							}
						}
					} while (!sub_line.contains("}"));
					
					EditText e = (EditText) findViewById(R.id.updateConf_proxy_etr);
					e.setText(proxyETR);

				}else if (line.contains("override-dns=")) {	
					String[] tmp = line.split("=");
					if(tmp.length > 1 ){
						String overrideDNS_aux = tmp[1];
						if (overrideDNS_aux.equals("on") || overrideDNS_aux.equals("true")){
							overrideDNS = true;
						}else{
							overrideDNS = false;
						}
					}
					
					CheckBox c = (CheckBox)findViewById(R.id.updateConfDNSCheck);
					c.setChecked(overrideDNS);
				}else if (line.contains("override-dns-primary=")) {
					String[] tmp = line.split("=");
					if (tmp.length > 1){
						if (ConfigTools.validate_IP_Address(tmp[1])){
							DNS1 = tmp[1];
						}
					}
					EditText e = (EditText)findViewById(R.id.updateConfDNS1Text);
					e.setText(DNS1);
				} else if (line.contains("override-dns-secondary=")) {
					String[] tmp = line.split("=");
					if (tmp.length > 1){
						if (ConfigTools.validate_IP_Address(tmp[1])){
							DNS2 = tmp[1];
						}
					}
					EditText e = (EditText)findViewById(R.id.updateConfDNS2Text);
					e.setText(DNS2);
				} 
				else if (line.contains("debug=")) {
					String[] tmp = line.split("=");
					if (tmp.length > 1){
						logLevel = tmp[1];
					}
					Spinner log_spinner = (Spinner) findViewById(R.id.LogSpinner);
					log_spinner.setSelection(new Integer(logLevel).intValue());					
				} 
				
				line = br.readLine();
			}
			MultiSelectionSpinner spinner = (MultiSelectionSpinner) findViewById(R.id.IfaceNameSpinner);
			spinner.setSelection(ifaces);
			
			EditText e = (EditText)findViewById(R.id.updateConfDNS1Text);
			e.setEnabled(overrideDNS);
			e = (EditText)findViewById(R.id.updateConfDNS2Text);
			e.setEnabled(overrideDNS);
			
		}
		catch (IOException e) {
			;
		}
		
	}
	
	public void createConfFile()
	{
		/* 
		 * If a configuration file is not found, a default configuration file is created.
		 * */
		try {
			String defText;
			defText = new StringBuilder()
						.append("#       *** LISPD EXAMPLE CONFIG FILE ***\n\n\n")
						.append("# General configuration\n")
						.append("#      debug: Debug levels [0..3]\n")
						.append("#      map-request-retries: Additional Map-Requests to send per map cache miss\n\n")
						.append("router-mode            = off\n")
						.append("debug                  = "+logLevel+"\n") 
						.append("map-request-retries    = 2\n\n\n")
						.append("# RLOC Probing configuration\n")
						.append("#   rloc-probe-interval: interval at which periodic RLOC probes are sent\n")
						.append("#     (seconds). A value of 0 disables RLOC Probing\n")
						.append("#   rloc-probe-retries: RLOC Probe retries before setting the locator with\n")
						.append("#     status down. [0..5]\n")
						.append("#   rloc-probe-retries-interval: interval at which RLOC probes retries are\n")
						.append("#     sent (seconds) [1..#rloc-probe-interval]\n\n")
						.append("rloc-probing {\n")
						.append("    rloc-probe-interval             = "+rloc_prob_interval+"\n")
						.append("    rloc-probe-retries              = "+rloc_prob_retries+"\n")
						.append("    rloc-probe-retries-interval     = "+rloc_prob_retries_interval+"\n")
						.append("}\n\n\n")
						.append("# NAT Traversal configuration.\n") 
						.append("#   nat_aware: check if the node is behind NAT\n")
						.append("# Limitation of version 0.3.3 when nat_aware is enabled:\n")
						.append("#   - Only one interface is supported.\n")
						.append("#   - Only one Map Server and one Map Resolver\n\n")
						.append("nat-traversal {\n")
						.append("    nat_aware   = "+nat_aware+"\n")
						.append("}\n\n\n")
						.append("# Encapsulated Map-Requests are sent to this map-resolver\n")
						.append("# You can define several map-resolvers. Encapsulated Map-Request messages will\n")
						.append("# be sent to only one.\n")
						.append("#   address: IPv4 or IPv6 address of the map resolver\n")
						.append("map-resolver        = {\n")
						.append("        "+MR+",\n")
						.append("}\n\n\n")
						.append("# DDT Client section.\n")
						.append("# DDT configuration has prefernece over map-resolver configuration\n")
						.append("#\n")
						.append("##   ddt-client [on/off]: Obtain the mapping from EIDs to RLOCs through the DDT tree\n")
						.append("#ddt-client  = on\n\n")
						.append("# DDT Encapsulated Map-Requests are sent to these ddt root node. You can define\n")
						.append("# several ddt-root-node. DDT Encapsulated Map-Request messages will be sent to the\n")
						.append("# ddt-root-node with higher priority (lowest value).\n")
						.append("#\n")
						.append("#   address: IPv4 or IPv6 address of the DDT root node\n")
						.append("#   priority [0..255]: DDT root nodes with lower values are more preferable.\n")
						.append("#   weight [0..255]: Not yet implemented\n\n")
						.append("#ddt-root-node {\n")
						.append("#        address     = <IPv4 or FQDN name>\n")
						.append("#        priority    = 1\n")
						.append("#        weight      = 100\n")
						.append("#}\n\n")
						.append("# Some LISP beta-network (lisp4.net/lisp6.net) DDT root nodes\n")
						.append("ddt-root-node {\n")
						.append("        address     = 84.88.16.10\n")
						.append("        priority    = 1\n")
						.append("        weight      = 100\n")
						.append("}\n\n")
						.append("# Current LISP beta-network (lisp4.net/lisp6.net) DDT root nodes:\n")
						.append("# IPv4: \n")
						.append("#      - arin-ddt.rloc.lisp4.net: 192.149.252.136\n")
						.append("#      - ripe-ddt.rloc.lisp4.net: 193.0.0.170\n")
						.append("#      - vxnet-ddt.rloc.lisp4.net: 199.119.73.8\n\n\n")
						.append("# Map-Registers are sent to this map-server\n")
						.append("# You can define several map-servers. Map-Register messages will be sent to all\n")
						.append("# of them.\n")
						.append("#   address: IPv4 or IPv6 address of the map-server\n")
						.append("#   key-type: Only 1 supported (HMAC-SHA-1-96)\n")
						.append("#   key: password to authenticate with the map-server\n")
						.append("#   proxy-reply [on/off]: Configure map-server to Map-Reply on behalf of the xTR\n\n")
						.append("map-server {\n")
						.append("        address     = "+MS+"\n")
						.append("        key-type    = 1\n")
						.append("        key         = "+MSKey+"\n")
						.append("        proxy-reply = on\n")
						.append("}\n\n\n")       
						.append("# Packets addressed to non-LISP sites will be encapsulated to this Proxy-ETR\n")
						.append("# You can define several Proxy-ETR. Traffic will be balanced according to\n")
						.append("# priority and weight.\n")
						.append("#   address: IPv4 or IPv6 address of the Proxy-ETR\n")
						.append("#   priority [0-255]: Proxy-ETR with lower values are more preferable.\n")
						.append("#   weight [0-255]: When priorities are the same for multiple Proxy-ETRs,\n")
						.append("#     the Weight indicates how to balance unicast traffic between them.\n")
						.append("proxy-etr {\n")
						.append("        address     = "+proxyETR+"\n")
						.append("        priority    = 1\n")
						.append("        weight      = 100\n")
						.append("}\n\n\n")
						.append("# List of PITRs to SMR on handover\n")
						.append("#   address: IPv4 or IPv6 address of the Proxy-ITR\n")
						.append("#   Current LISP beta-network (lisp4.net/lisp6.net) PITR addresses\n\n")
						.append("proxy-itrs = {\n")
						.append("        69.31.31.98,\n") 
						.append("        149.20.48.60,\n")
						.append("        198.6.255.37,\n")
						.append("        173.36.193.25,\n")
						.append("        129.250.1.63,\n")
						.append("        217.8.98.33,\n")
						.append("        217.8.98.35,\n")
						.append("        193.162.145.46,\n")
						.append("        193.34.30.222,\n")
						.append("        193.34.31.222,\n")
						.append("        147.83.131.32,\n")
						.append("        158.38.1.92,\n")
						.append("        203.181.249.172,\n")
						.append("        202.51.247.10\n")
						.append("}\n")
						.append("# IPv4 / IPv6 EID of the node.\n")
						.append("# One database-mapping structure is defined for each interface with RLOCs\n")
						.append("# associated to this EID\n")
						.append("#   eid-prefix: EID prefspinner.setSelection(position);ix (IPvX/mask) of the mapping\n")
						.append("#   interface: interface containing the RLOCs associated to this mapping\n")
						.append("#   priority_vX [0-255]: Priority for the IPvX RLOC of the interface. Locators\n")
						.append("#     with lower values are more preferable. This is used for both incoming\n")
						.append("#     policy announcements and outcoming traffic policy management. (A value\n")
						.append("#     of -1  means that IPvX address of that interface is not used)\n")
						.append("#   weight [0-255]: When priorities are the same for multiple RLOCs, the Weight\n")
						.append("#     indicates how to balance unicast traffic between them.\n\n")
						.toString();
			
			if (ifaces != null){
				Iterator <String> it = ifaces.iterator();
				while (it.hasNext()){
					String iface_name = it.next();

					if (!eidIPv4.equals("")){
						defText= defText.concat("database-mapping {\n")
								.concat("        eid-prefix     = "+eidIPv4+"/32\n")
								.concat("        interface      = "+iface_name+"\n")
								.concat("        priority_v4    = 1\n")
								.concat("        weight_v4      = 100\n")
								.concat("        priority_v6    = 1\n")
								.concat("        weight_v6      = 100\n")
								.concat("}\n\n");
					}
					if (!eidIPv6.equals("")){
						defText= defText.concat("database-mapping {\n")
								.concat("        eid-prefix     = "+eidIPv6+"/128\n")
								.concat("        interface      = "+iface_name+"\n")
								.concat("        priority_v4    = 1\n")
								.concat("        weight_v4      = 100\n")
								.concat("        priority_v6    = 1\n")
								.concat("        weight_v6      = 100\n")
								.concat("}\n\n\n");
					}
				}
			}
			defText= defText.concat("override-dns     		 = "+overrideDNS+"\n");
			if (!DNS1.equals(""))
				defText= defText.concat("override-dns-primary    = "+DNS1+"\n");
			if (!DNS2.equals(""))
				defText= defText.concat("override-dns-secondary  = "+DNS2+"\n");

			FileWriter fstream = new FileWriter(conf_file);
			BufferedWriter out = new BufferedWriter(fstream);
			out.write(defText);
			out.close();
			
		} catch (Exception e) {
			displayMessage("Error while writing Default Conf file to sdcard!!", false, null);
		}
		
	}
	
	public void displayMessage(String message, boolean cancelAble, final Runnable task) 
	{		
		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setTitle("Attention");
		builder.setMessage(message);
		builder.setCancelable(cancelAble);
		builder.setPositiveButton("OK", new DialogInterface.OnClickListener() { 
			public void onClick( DialogInterface dialog, int id ) {
				if ( task != null ) {
					task.run();
				} else {
					dialog.dismiss();
				}
			}
		} );
		
		if ( cancelAble ) {
			builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() { 
				public void onClick(DialogInterface dialog, int id) {
					dialog.dismiss();
				}
			} );
		}
		
		AlertDialog alert = builder.create();
		alert.show();
		
	}

	
	public boolean get_and_validate_parameters(){
		EditText e;
		CheckBox c;
		MultiSelectionSpinner multi_spinner;
		Spinner	spinner;
		String eidv4 = "";
		String eidv6 = "";
		String mapResolver = "";
		String mapServer = "";
		String mapServerKey = "password";
		String pETR = "";
		String DNS_1 = "";
		String DNS_2 = "";
		boolean overrideDNS_bool = false; 
		boolean nat_aware_bool = false;

		
		String message = "ERROR: The following fields are not valid: \n";
		String error = "";
		
		
		e = (EditText) findViewById(R.id.updateConfeid4Text);
		eidv4 = e.getText().toString();
		
		e = (EditText) findViewById(R.id.updateConfeid6Text);
		eidv6 = e.getText().toString();
		
		c = (CheckBox)findViewById(R.id.updateConf_NAT_aware);
		nat_aware_bool = c.isChecked();
		
		e = (EditText) findViewById(R.id.updateConfMRText);
		mapResolver = e.getText().toString();
		
		e = (EditText) findViewById(R.id.updateConfMSText);
		mapServer = e.getText().toString();
		
		e = (EditText) findViewById(R.id.updateConfMSKeyText);
		mapServerKey = e.getText().toString();
				
		e = (EditText) findViewById(R.id.updateConf_proxy_etr);
		pETR = e.getText().toString();
		
		c = (CheckBox)findViewById(R.id.updateConfDNSCheck);
		overrideDNS_bool = c.isChecked();
		
		e = (EditText) findViewById(R.id.updateConfDNS1Text);
		DNS_1 = e.getText().toString();
		
		e = (EditText) findViewById(R.id.updateConfDNS2Text);
		DNS_2 = e.getText().toString();
		
		multi_spinner = (MultiSelectionSpinner)findViewById(R.id.IfaceNameSpinner);
		ifaces = multi_spinner.getSelectedStrings();
		
		spinner = (Spinner)findViewById(R.id.LogSpinner);
		logLevel = spinner.getSelectedItem().toString();
		
		
		
		if (!eidv4.equals("") && !ConfigTools.validate_IP_Address(eidv4)){
			error = error.concat("  - EID-IPv4\n");
		}		
		if (!eidv6.equals("") && !ConfigTools.validate_IP_Address(eidv6)){
			error = error.concat("  - EID-IPv6\n");
		}
		if (!ConfigTools.validate_IP_Address(mapResolver)){
			error = error.concat("  - Map-Resolver\n");
		}
		if (!ConfigTools.validate_IP_Address(mapServer)){
			error = error.concat("  - Map-Server\n");
		}
		if (!ConfigTools.validate_IP_Address(pETR)){
			error = error.concat("  - Proxy ETR\n");
		}
		if (overrideDNS_bool && ( DNS_1.equals("") || !ConfigTools.validate_IP_Address(DNS_1))){
			error = error.concat("  - Primary DNS\n");
		}
		if ((overrideDNS_bool &&  !DNS_2.equals("") && !ConfigTools.validate_IP_Address(DNS_2))){
			error = error.concat("  - Secondary DNS\n");
		}
		if (nat_aware_bool == true && !eidv4.equals("") && !eidv6.equals("")){
			error = error.concat("  - Only one EID is supported\n");
		}
		
		

		
		if (!error.equals("")){
			displayMessage(message+error, false, null);
			return (false);
		}
		if (eidv4.equals("") && eidv6.equals("")){
			displayMessage("ERROR: At least one EID should be supplied", false, null);
			return (false);
		}

		eidIPv4 = eidv4;
		eidIPv6 = eidv6;
		MR = mapResolver;
		MS = mapServer;
		MSKey = mapServerKey;
		proxyETR = pETR;
		DNS1 = DNS_1;
		DNS2 = DNS_2;
		overrideDNS = overrideDNS_bool;
		nat_aware = nat_aware_bool;
		
		return (true);
	}
	
	public void updateConfFile() 
	{
		if (get_and_validate_parameters() == true){
			createConfFile();
			setResult(CONFIG_UPDATED);
			finish();
		}		
	}
	
	public void updateConfDNSClicked(View v) 
	{
		CheckBox c = (CheckBox)v;
		if (c.isChecked()) {
			overrideDNS = true;
			
			EditText e = (EditText)findViewById(R.id.updateConfDNS1Text);
			e.setEnabled(true);
			
			e = (EditText)findViewById(R.id.updateConfDNS2Text);
			e.setEnabled(true);
		} else {
			overrideDNS = false;
			EditText e = (EditText)findViewById(R.id.updateConfDNS1Text);
			e.setEnabled(false);
			
			e = (EditText)findViewById(R.id.updateConfDNS2Text);
			e.setEnabled(false);
		}
	}
	
	public void updateConfNATAwareClicked(View v)
	{
		CheckBox c = (CheckBox)v;
		if (c.isChecked()) {
			nat_aware = true;
		} else {
			nat_aware = false;
		}
	}
	
	public void updateConfClicked(View v) 
	{
		displayMessage("This will overwrite the existing configuration.\nDo you want to Continue?", true, new Runnable() { public void run() {
				updateConfFile();			
			}
		});
	}
	
	public static boolean isOverrideDNS(){
		return(overrideDNS);
	}
	
	public static String[] getNewDNS(){
		String[] dns = {DNS1, DNS2};
		return (dns);
	}
	
}
