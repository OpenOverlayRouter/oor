package org.lispmob.root;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.IBinder;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

public class LISPmobService extends Service implements Runnable{
	
	private static String 			TAG 			= "LISPmob DNS service";
	private static SuShell 		shell			= null;
	private static String 			system_dns[] 	= new String[2];
	private static String 			lispmob_dns[] 	= new String[2];
	private static boolean 		start			= false;
	public static boolean 		isRunning		= false;
	private static Thread			thread			= null;
	private static ScheduledExecutorService scheduler = null;
	private static ScheduledFuture<?> scheduledFuture = null;
	private static String 			prefix			= null;
	private static String 			lispd_path			= null;

	@Override
	public IBinder onBind(Intent intent) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int onStartCommand(Intent intent, int flags, int startId){
		
		try {
			shell = new SuShell();
		} catch (IOException e1) {}
		
		
		prefix = getPackageName();
		try {
			lispd_path =  getPackageManager().getApplicationInfo("org.lispmob.root", 0).nativeLibraryDir;
		} catch (NameNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		

		if (intent != null){
			start = intent.getBooleanExtra(prefix + ".START",true);
		}else{
			Log.i(TAG, "LISPmob service stopped and it has been reestarted");
			start 	= true;
		}
   
		if (start == true){
			if (thread != null){
				Log.i(TAG, "LISPmob Service already running");
				try {
					lispmob_dns = ConfigTools.getDNS();
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					return START_NOT_STICKY;
				}
			}else{
				Log.i(TAG, "Starting LISPmob Service.");
				system_dns = get_dns_servers();
				try {
					lispmob_dns = ConfigTools.getDNS();
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					return START_NOT_STICKY;
				}
				thread = new Thread(this, "LISPmobService");
				thread.start();
				/* Put the service in background mode */
				Intent mainIntent = new Intent(this, LISPmob.class);
				NotificationCompat.Builder builder =  new NotificationCompat.Builder(getApplicationContext());
				builder.setContentTitle("LISPmob");
				builder.setContentText("LISPmob running");
				builder.setContentIntent(PendingIntent.getActivity(this, PendingIntent.FLAG_UPDATE_CURRENT, mainIntent, 0));
				Notification notif = builder.build();
				startForeground(1234, notif);    
			}
		}else{
			this.onDestroy();
		}  
		
		if (start == true){
			return (START_STICKY);
		}else{
			return (START_NOT_STICKY);
		}
    }
    @Override
    public void onDestroy() {
		Log.d(TAG, "Destroying LISPmob DNS Service thread");
		scheduledFuture.cancel(true);
		scheduler.shutdown();
		set_dns_servers(system_dns);
		if (thread != null){ 
			thread.interrupt();
			thread = null;
		}
		stopForeground(true);
    }
    
    public synchronized void run(){
    	scheduler = Executors.newScheduledThreadPool(1);
		Runnable dnsCheck = new Runnable() {	
			public void run() {
				
				String psOutput = runTask("/system/bin/ps", "", false);
				isRunning = psOutput.matches("(?s)(.*)[RS]\\s[a-zA-Z0-9\\/\\.\\-]*liblispd\\.so(.*)");
				if (isRunning && lispmob_dns != null){
					String 	dns[] = get_dns_servers();
					if (!dns[0].equals(lispmob_dns[0]) || !dns[1].equals(lispmob_dns[1])){
						system_dns = get_dns_servers();
						set_dns_servers(lispmob_dns);
					}
				}
				
				if (isRunning == false){
					onDestroy();
				}
			}
		};
		scheduledFuture = scheduler.scheduleAtFixedRate(dnsCheck, 0, 1, TimeUnit.SECONDS);
    }
    

    
    public String[] get_dns_servers(){
		String command = null;
		String dns[] = new String[2];
		
		command = "getprop net.dns1";
		dns[0] = shell.run(command);
		
		command = "getprop net.dns2";
		dns[1] = shell.run(command);
		
		return dns;
	}
	
	public static void set_dns_servers(String[] dns){
		String command = null;
						
		command = "setprop net.dns1 \""+dns[0]+"\"";
		shell.run_no_output(command);
		
		command = "setprop net.dns2 \""+dns[1]+"\"";
		shell.run_no_output(command);
	
	}
	
	static public String runTask(String command, String args, boolean ignoreOutput) {
		StringBuffer output = new StringBuffer();
		Process process = null;
		try {
			process = new ProcessBuilder()
			.command(command, args)
			.redirectErrorStream(true)
			.start();
			InputStream in = process.getInputStream();
			BufferedReader reader = new BufferedReader(new InputStreamReader(in));
			String line;
			process.waitFor();
			if (!ignoreOutput) {
				while ((line = reader.readLine()) != null) {
					output.append(line);
					output.append('\n');
				}
			}
		} catch (IOException e1) {
			System.out.println("LISPmob: Command Failed.");
			e1.printStackTrace();
			return("Command Failed.");
		} catch (InterruptedException e) {
			e.printStackTrace();
		} 
		return(output.toString());
	}
	

}
