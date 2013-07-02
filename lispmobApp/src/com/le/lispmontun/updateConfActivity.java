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
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.content.DialogInterface;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.ArrayAdapter;


public class updateConfActivity extends Activity {
	
	public static final String confFile = "lispd.conf";
	
	StringBuilder text;
	public String eidIPv4 = "";
	public String eidIPv6 = "";
	public String MR = "";
	public String MS = "";
	public String MSKey = "";
	public String DNS1 = "";
	public String DNS2 = "";
	public String InstanceID = "";
	public boolean overrideDNS = false; 
	public boolean useInstanceID = false;
	public String keyType = "";
	
	@Override
	public void onCreate(Bundle savedInstanceState) {
		
		super.onCreate(savedInstanceState);
		setContentView(R.layout.updateconf); 
		
		File sdcardDir = Environment.getExternalStorageDirectory();
		File file = new File(sdcardDir, confFile);
		
		if ( !file.exists() ) {
			createDefaultConfFile();
		}
		
		Spinner spinner = (Spinner) findViewById(R.id.keyTypeSpinner);
		// Create an ArrayAdapter using the string array and a default spinner layout
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(this,
		        R.array.keytypearray, android.R.layout.simple_spinner_item);
		// Specify the layout to use when the list of choices appears
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		// Apply the adapter to the spinner
		spinner.setAdapter(adapter);
		
		readConfFileAndFillParameters();
		
	}
		
	public void readConfFileAndFillParameters() 
	{
		File sdcardDir = Environment.getExternalStorageDirectory();
		File file = new File(sdcardDir, confFile);
		
		text = new StringBuilder();
		
		try {
			
			BufferedReader  br = new BufferedReader(new FileReader(file));
			String line = br.readLine();
			
			while ( line != null ) {
				text.append(line);
				text.append("\n");
				if (line.contains("eid-address-ipv4") && !line.startsWith("#")) {
					String[] tmp = line.split("=");
					String[] tmp_1 = tmp[1].split(" ");
					eidIPv4 = tmp_1[1];
					EditText e = (EditText) findViewById(R.id.updateConfeid4Text);
					e.setText(eidIPv4);
				} else if (line.contains("eid-address-ipv6") && !line.startsWith("#")) {
					String[] tmp = line.split("=");
					String[] tmp_1 = tmp[1].split(" ");
					eidIPv6 = tmp_1[1];
					EditText e = (EditText) findViewById(R.id.updateConfeid6Text);
					e.setText(eidIPv6);
				} else if (line.contains("map-resolver") && !line.startsWith("#")) {
					String[] tmp = line.split("=");
					String[] tmp_1 = tmp[1].split(" ");
					MR = tmp_1[1];
					EditText e = (EditText) findViewById(R.id.updateConfMRText);
					e.setText(MR);
				} else if (line.contains("override-dns-primary") && !line.startsWith("#")) {	
						String[] tmp = line.split("=");
						String[] tmp2 = tmp[1].split(" ");
						DNS1 = tmp2[1];
						EditText e = (EditText)findViewById(R.id.updateConfDNS1Text);
						e.setText(DNS1);
						e.setEnabled(true);
						overrideDNS = true;
						CheckBox c = (CheckBox)findViewById(R.id.updateConfDNSCheck);
						c.setChecked(true);
				} else if (line.contains("override-dns-secondary") && !line.startsWith("#")) {
					String[] tmp = line.split("=");
					String[] tmp2 = tmp[1].split(" ");
					DNS2 = tmp2[1];
					EditText e = (EditText)findViewById(R.id.updateConfDNS2Text);
					e.setText(DNS2);
					e.setEnabled(true);
					overrideDNS = true;
					CheckBox c = (CheckBox)findViewById(R.id.updateConfDNSCheck);
					c.setChecked(true);
				} else if (line.contains("instance-id") && !line.startsWith("#")) {
					String[] tmp = line.split("=");
					String[] tmp2 = tmp[1].split(" ");
					InstanceID = tmp2[1];
					EditText e = (EditText)findViewById(R.id.updateConfInstanceID);
					e.setText(InstanceID);
					e.setEnabled(true);
					useInstanceID = true;
					CheckBox c = (CheckBox)findViewById(R.id.updateConfUseInstance);
					c.setChecked(true);
				} else if (line.contains("map-server") && !line.startsWith("#")) {
					boolean flg1=false, flg2=false;
					do {
						String line_1 = br.readLine();
						text.append(line_1);
						text.append("\n");
						if (line_1.contains("address") && !line_1.startsWith("#")) {
							String[] tmp = line_1.split("=");
							String[] tmp_1 = tmp[1].split(" ");
							MS = tmp_1[1];
							flg1 = true;
						} else if (line_1.contains("key-type") && !line_1.startsWith("#")) {
							Scanner scanner = new Scanner(line_1);
							scanner.useDelimiter("=");
							Spinner spinner = (Spinner) findViewById(R.id.keyTypeSpinner);
							 if ( scanner.hasNext() ){
							      String name = scanner.next();
							      String value = scanner.next();
							     
							      if (value.contains("0")) {
							    	  spinner.setSelection(0);
							    	  keyType = "0";
							      } else if (value.contains("1")) {
							    	  spinner.setSelection(1);
							    	  keyType = "1";
							      }
							    }
						} else if (line_1.contains("key") && !line_1.startsWith("#")) {
							String[] tmp = line_1.split("=");
							String[] tmp_1 = tmp[1].split(" ");
							MSKey = tmp_1[1];
							flg2 = true;
						} 
					} while (flg1 == false || flg2 == false);
					
					EditText e = (EditText) findViewById(R.id.updateConfMSText);
					e.setText(MS);

					EditText et = (EditText) findViewById(R.id.updateConfMSKeyText);
					et.setText(MSKey);

				}
				line = br.readLine();
			}
			
		}
		catch (IOException e) {
			;
		}
		
	}
	
	public void createDefaultConfFile()
	{
		/* 
		 * If a configuration file is not found, a default configuration file is created.
		 * eid-ipv4 = 0.0.0.0
		 * eid-ipv6 = 0:0:0:0::0
		 * MS,MR = asp-isis (198.6.255.40) 
		 * */
		try {
			String defText;
			defText = new StringBuilder()
			          .append("#\n")
			          .append("#Include the following configuration before giving out the device \n")
			          .append("# map-resolver = asp-isis (198.6.255.40) \n")
			          .append("# eid-address-ipv4 = 0.0.0.0 \n")
			          .append("# eid-address-ipv6 = 0:0:0:0::0 \n\n")
			          .append("debug                = on \n")
			          .append("map-request-retries  = 3			# send 3 before giving up\n")
			          .append("map-resolver = 198.6.255.40 \n")
			          .append("eid-interface = lo:4 \n")
			          .append("eid-address-ipv4  = 0.0.0.0 \n")
			          .append("eid-address-ipv6 = 0:0:0:0::0 \n")
			          .append("rloc-probe-interval = 0 \n")
			          .append("use-nat-tunneling = on \n")
			          .append("# \n")
			          .append("#       LISP Config\n")
			          .append("#\n")
			          .append("map-server {\n")
			          .append("        address	    = 198.6.255.40\n")
			          .append("        key-type    = 1		                # SHA1\n")
			          .append("        key	    = chris-mn\n")
			          .append("	       verify	    = off	                # on --> lig(self)\n")
			          .append("	proxy-reply = on	                # ask ms to proxy reply\n")
			          .append("}\n\n\n")
			          .append("# Lispd always prefers the first up interface\n")
			          .append("# for sourcing, in the priority order specified below\n")
			          .append("interface {\n")
			          .append("	name = eth0\n")
			          .append("        detect-nat = on\n")
			          .append("	device-priority = 1\n")
			          .append("}\n\n\n")
			          .append("interface {\n")
			          .append("	name = rmnet0\n")
			          .append("	detect-nat = on\n")
			          .append("        device-priority = 2\n")
			          .append("}\n\n\n")
			          .append("database-mapping {\n\teid-prefix  = 0.0.0.0/32\n\tpriority   = 1\n\tweight     = 50\n}\n\n")
			          .append("database-mapping {\n\teid-prefix = 0:0:0:0::0/128\n\tpriority   = 1\n\tweight     = 50\n}\n")
			          .toString();

			FileWriter fstream = new FileWriter("/sdcard/"+confFile);
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
	
	public String replace_if_required_eidipv4(String str)
	{
		Pattern eidipv4Ptrn = Pattern.compile("^(\\s*)(\\S*)(\\s*)eid-address-ipv4(\\s*)=(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
		Matcher eidipv4Mtchr = eidipv4Ptrn.matcher(str);
		if (eidipv4Mtchr.matches()) {
			String[] tmp_1 = str.split("=");
			Pattern ipaddrPtrn = Pattern.compile("(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
			Matcher ipaddrMtchr = ipaddrPtrn.matcher(tmp_1[1]);
			if (ipaddrMtchr.matches()) {
				StringBuilder op = new StringBuilder();
				op.append(ipaddrMtchr.group(2));op.append(".");
				op.append(ipaddrMtchr.group(3));op.append(".");
				op.append(ipaddrMtchr.group(4));op.append(".");
				op.append(ipaddrMtchr.group(5));
				
				if ( op.toString().equals(eidIPv4) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfeid4Text);
					StringBuilder opStr = new StringBuilder();
					opStr.append(tmp_1[0]); opStr.append("= ");
					opStr.append(e.getText().toString());
					str = opStr.toString();
					//displayMessage("The string is :"+str+":", false, null);
				}
			}
		}
		
		return str;
	}
	
	public String replace_if_required_primary_dns(String str)
	{
		Pattern DNSipv4Ptrn = Pattern.compile("^(\\s*)(\\S*)(\\s*)override-dns-primary(\\s*)=(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
		Matcher DNSipv4Mtchr = DNSipv4Ptrn.matcher(str);
		
		if (DNSipv4Mtchr.matches()) {
			String[] tmp_1 = str.split("=");
			Pattern ipaddrPtrn = Pattern.compile("(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
			Matcher ipaddrMtchr = ipaddrPtrn.matcher(tmp_1[1]);
			if (ipaddrMtchr.matches()) {
				StringBuilder op = new StringBuilder();
				op.append(ipaddrMtchr.group(2));op.append(".");
				op.append(ipaddrMtchr.group(3));op.append(".");
				op.append(ipaddrMtchr.group(4));op.append(".");
				op.append(ipaddrMtchr.group(5));
				
				if ( op.toString().equals(DNS1) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfDNS1Text);
					
					if (!overrideDNS) {
						str = "";
						//displayMessage("Clearing override DNS config", false, null);
					} else {
						StringBuilder opStr = new StringBuilder();
						opStr.append(tmp_1[0]); opStr.append("= ");
						opStr.append(e.getText().toString());
						str = opStr.toString();
						//displayMessage("The string is :"+str+":", false, null);
					}
				}
			}
		}
		
		return str;
	}
	
	public String replace_if_required_secondary_dns(String str)
	{
		Pattern DNSipv4Ptrn = Pattern.compile("^(\\s*)(\\S*)(\\s*)override-dns-secondary(\\s*)=(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
		Matcher DNSipv4Mtchr = DNSipv4Ptrn.matcher(str);
		
		if (DNSipv4Mtchr.matches()) {
			String[] tmp_1 = str.split("=");
			Pattern ipaddrPtrn = Pattern.compile("(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
			Matcher ipaddrMtchr = ipaddrPtrn.matcher(tmp_1[1]);
			if (ipaddrMtchr.matches()) {
				StringBuilder op = new StringBuilder();
				op.append(ipaddrMtchr.group(2));op.append(".");
				op.append(ipaddrMtchr.group(3));op.append(".");
				op.append(ipaddrMtchr.group(4));op.append(".");
				op.append(ipaddrMtchr.group(5));
				
				if ( op.toString().equals(DNS2) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfDNS2Text);
					
					if (!overrideDNS) {
						str = "";
						//displayMessage("Clearing override DNS config", false, null);
					} else {
						StringBuilder opStr = new StringBuilder();
						opStr.append(tmp_1[0]); opStr.append("= ");
						opStr.append(e.getText().toString());
						str = opStr.toString();
						//displayMessage("The string is :"+str+":", false, null);
					}
				}
			}
		}
		
		return str;
	}
	
	public String replace_if_required_instance_id(String str)
	{
		Pattern IDLinePattern = Pattern.compile("^(\\s*)(\\S*)(\\s*)instance-id(\\s*)=(\\s*)(\\d{1,5})(\\s*)");
		Matcher IDLineMatcher = IDLinePattern.matcher(str);
		
		if (IDLineMatcher.matches()) {
			String[] tmp_1 = str.split("=");
			Pattern IDValPattern = Pattern.compile("(\\s*)(\\d{1,5})(\\s*)");
			Matcher IDValMatcher = IDValPattern.matcher(tmp_1[1]);
			if (IDValMatcher.matches()) {
				StringBuilder op = new StringBuilder();
				op.append(IDValMatcher.group(2));
				if ( op.toString().equals(InstanceID) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfInstanceID);
					
					if (!useInstanceID) {
						str = "";
						//displayMessage("Clearing instance ID config", false, null);
					} else {
						StringBuilder opStr = new StringBuilder();
						opStr.append(tmp_1[0]); opStr.append("= ");
						opStr.append(e.getText().toString());
						str = opStr.toString();
						//displayMessage("The string is :"+str+":", false, null);
					}
				}
			}
		}
		
		return str;
	}
	
	public String replace_if_required_eidipv4_dbmapping(String str)
	{
		Pattern eidipv4PrefPtrn = Pattern.compile("^(\\s*)eid-prefix(\\s*)=(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})/(\\d{1,2})(\\s*)");

		Matcher eidipv4PrefMtchr = eidipv4PrefPtrn.matcher(str);
		if (eidipv4PrefMtchr.matches()) {
			String[] tmp_2 = str.split("=");
			String[] tmp_1 = tmp_2[1].split("/");
			
			Pattern ipaddrPtrn = Pattern.compile("(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
			Matcher ipaddrMtchr = ipaddrPtrn.matcher(tmp_1[0]);
			if (ipaddrMtchr.matches()) {
				
				StringBuilder op = new StringBuilder();
				op.append(ipaddrMtchr.group(2));op.append(".");
				op.append(ipaddrMtchr.group(3));op.append(".");
				op.append(ipaddrMtchr.group(4));op.append(".");
				op.append(ipaddrMtchr.group(5));
				
				if ( op.toString().equals(eidIPv4) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfeid4Text);
					StringBuilder opStr = new StringBuilder();
					opStr.append(tmp_2[0]); opStr.append("= ");
					opStr.append(e.getText().toString()); opStr.append("/"+tmp_1[1]);
					str = opStr.toString();
					//displayMessage("The string is :"+str+":", false, null);
				}
			}
		}

		return str;
	}
		
	public String replace_eid_ipv6(String str)
	{
		EditText e = (EditText) findViewById(R.id.updateConfeid6Text);
		String out = str.replaceAll(eidIPv6, e.getText().toString());
		return out;
	}
	
	public String replace_if_required_mr(String str)
	{
		Pattern mrPtrn = Pattern.compile("^(\\s*)(\\S*)(\\s*)map-resolver(\\s*)=(\\s*)(\\S*)(\\s*)((\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*))(\\s*)");
		Matcher mrMtchr = mrPtrn.matcher(str);
		if (mrMtchr.matches()) {
			String[] tmp_1 = str.split("=");
			Pattern ipaddrPtrn = Pattern.compile("(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
			Matcher ipaddrMtchr = ipaddrPtrn.matcher(tmp_1[1]);
			if (ipaddrMtchr.matches()) {
				StringBuilder op = new StringBuilder();
				op.append(ipaddrMtchr.group(2));op.append(".");
				op.append(ipaddrMtchr.group(3));op.append(".");
				op.append(ipaddrMtchr.group(4));op.append(".");
				op.append(ipaddrMtchr.group(5));
				
				if ( op.toString().equals(MR) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfMRText);
					StringBuilder opStr = new StringBuilder();
					opStr.append(tmp_1[0]); opStr.append("= ");
					opStr.append(e.getText().toString());
					str = opStr.toString();
				    //displayMessage("The string is :"+str+":", false, null);
				}
			}
		}
		
		return str;
	}
	
	public String replace_if_required_ms(String str)
	{
		Pattern msPtrn = Pattern.compile("^(\\s*)(\\S*)(\\s*)address(\\s*)=(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
		Matcher msMtchr = msPtrn.matcher(str);
		if (msMtchr.matches()) {
			String[] tmp_1 = str.split("=");
			Pattern ipaddrPtrn = Pattern.compile("(\\s*)(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})(\\s*)");
			Matcher ipaddrMtchr = ipaddrPtrn.matcher(tmp_1[1]);
			if (ipaddrMtchr.matches()) {
				StringBuilder op = new StringBuilder();
				op.append(ipaddrMtchr.group(2));op.append(".");
				op.append(ipaddrMtchr.group(3));op.append(".");
				op.append(ipaddrMtchr.group(4));op.append(".");
				op.append(ipaddrMtchr.group(5));
				
				if ( op.toString().equals(MS) ) { 
					EditText e = (EditText) findViewById(R.id.updateConfMSText);
					StringBuilder opStr = new StringBuilder();
					opStr.append(tmp_1[0]); opStr.append("= ");
					opStr.append(e.getText().toString());
					str = opStr.toString();
					//displayMessage("The string is :"+str+":", false, null);
				}
			}
		}
		
		return str;
	}

	public String replace_ms_key(String str)
	{
		EditText e = (EditText) findViewById(R.id.updateConfMSKeyText);
		String out = str.replaceAll(MSKey, e.getText().toString());
		return out;
	}
	
	public String replace_if_required_ms_keytype(String str)
	{
		
		String out = str;
		
		if (str.contains("key-type")) {
			Spinner spinner = (Spinner)findViewById(R.id.keyTypeSpinner);
			String value = spinner.getSelectedItem().toString();
			String replacer = "";
			if (value.contains("Cleartext")) {
				replacer = "key-type = 0";
				keyType = "0";
			} else if (value.contains("SHA1")) {
				replacer = "key-type = 1";
				keyType = "1";
			}
			out = replacer;
			keyType = replacer;
		}
		return out;
	}
	
	public String replace_parameters(String str) 
	{
		StringBuilder out = new StringBuilder();
		String[] tmp = str.split("\n");
		int i=0;
		boolean DNSWasfound = false;
		boolean instanceIDWasFound = false;
		
		while (i < tmp.length) {
			
			tmp[i] = replace_if_required_eidipv4(tmp[i]);
			tmp[i] = replace_if_required_eidipv4_dbmapping(tmp[i]);
			tmp[i] = replace_if_required_mr(tmp[i]);
			tmp[i] = replace_if_required_ms(tmp[i]);
			tmp[i] = replace_if_required_primary_dns(tmp[i]);
			tmp[i] = replace_if_required_secondary_dns(tmp[i]);
			tmp[i] = replace_if_required_instance_id(tmp[i]);
			tmp[i] = replace_if_required_ms_keytype(tmp[i]);

			if (tmp[i].contains("override-dns-primary")) {
				DNSWasfound = true;
			}
			
			if (tmp[i].contains("instance-id")) {
				instanceIDWasFound = true;
			}
					
			out.append(tmp[i]);
			out.append("\n");
			i++;
		}
		
		
		// If DNS went from unconfigured to configured, add the line.
		if (!DNSWasfound && overrideDNS) {

			EditText DNSe = (EditText)findViewById(R.id.updateConfDNS1Text);
			int index = out.toString().indexOf("eid-interface"); // place after eid-interace config
			
			StringBuilder DNSString = new StringBuilder();
			DNSString.append("override-dns-primary = ");
			DNSString.append(DNSe.getText().toString());
			DNSString.append("\n");
			
			DNSString.append("override-dns-secondary = ");
		    DNSe = (EditText)findViewById(R.id.updateConfDNS2Text);
			DNSString.append(DNSe.getText().toString());
			DNSString.append("\n");
			
			out.insert(index, DNSString.toString());
		}
		
		
		// Same for instance ID
		if (!instanceIDWasFound && useInstanceID) {
			
			EditText IDe = (EditText)findViewById(R.id.updateConfInstanceID);
			int index = out.toString().indexOf("map-resolver"); // place after map-resolver config
			
			StringBuilder IDString = new StringBuilder();
			IDString.append("instance-id = ");
			IDString.append(IDe.getText().toString());
			IDString.append("\n");
			
			out.insert(index, IDString.toString());
		}
		
		EditText e = (EditText) findViewById(R.id.updateConfeid4Text);
		eidIPv4 = e.getText().toString();
		
		return out.toString();
	}
	
	public void updateConfFile() 
	{
		
		try {
			FileWriter fstream = new FileWriter("/sdcard/lispd.conf.tmp");
			BufferedWriter out = new BufferedWriter(fstream);
			
			String ostr = text.toString();
			
			ostr = replace_parameters(ostr);

			ostr = replace_eid_ipv6(ostr);
			EditText et = (EditText) findViewById(R.id.updateConfeid6Text);
			eidIPv6 = et.getText().toString();

			ostr = replace_ms_key(ostr);
			EditText et1 = (EditText) findViewById(R.id.updateConfMSKeyText);
			MSKey = et1.getText().toString();
			
			out.write(ostr);
			out.close();
			
			//Overwrite the lispd.conf file
			try {
				File destDir = Environment.getExternalStorageDirectory();
				File destfile = new File(destDir, confFile);
				File srcDir = Environment.getExternalStorageDirectory();
				File srcfile = new File(srcDir, "lispd.conf.tmp");
				FileChannel dest = new FileOutputStream(destfile).getChannel();
				FileChannel src = new FileInputStream(srcfile).getChannel();
				dest.transferFrom(src, 0, src.size());
				src.close();
				dest.close();
			} catch(Exception e) {
				displayMessage("Error in Copying files!", false, null);
			}
			
			//Restart LISP for the updated configuration to take effect
			String command = "/system/bin/lispmanager";
	    	lispMonitor.runTask(command, "stop", true);
	    	lispMonitor.runTask(command, "start", true);
	    	
		} catch (Exception e) {
			displayMessage("Error while writing file to sdcard!! "+e, false, null);
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
	
	public void updateConfInstanceIDClicked(View v)
	{
		CheckBox c = (CheckBox)v;
		if (c.isChecked()) {
			useInstanceID = true;
			EditText e = (EditText)findViewById(R.id.updateConfInstanceID);
			e.setEnabled(true);
		} else {
			useInstanceID = false;
			EditText e = (EditText)findViewById(R.id.updateConfInstanceID);
			e.setEnabled(false);
		}
	}
	
	public void updateConfClicked(View v) 
	{
		displayMessage("This will overwrite the existing configuration.\nDo you want to Continue?", true, new Runnable() { public void run() {
				updateConfFile();			
			}
		});
	}
	
}
