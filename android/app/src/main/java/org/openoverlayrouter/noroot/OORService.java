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

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.IBinder;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.List;

public class OORService extends Service implements Runnable {

    private static String TAG = "OOR DNS service";
    private static SuShell shell = null;
    private static String system_dns[] = new String[2];
    private static List<String> oor_dns = null;
    private static boolean start = false;
    public static boolean isRunning = false;
    private static Thread thread = null;
    private static ScheduledExecutorService scheduler = null;
    private static ScheduledFuture<?> scheduledFuture = null;
    private static String prefix = null;
    private static String oor_path = null;
    private static String pidExecutable = "";

    @Override
    public IBinder onBind(Intent intent) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        try {
            shell = new SuShell();
        } catch (IOException e1) {
        }


        prefix = getPackageName();
        try {
            oor_path = getPackageManager().getApplicationInfo("org.openoverlayrouter.noroot", 0).nativeLibraryDir;
        } catch (NameNotFoundException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }


        if (intent != null) {
            start = intent.getBooleanExtra(prefix + ".START", true);
        } else {
            Log.i(TAG, "OOR service stopped and it has been reestarted");
            start = true;
        }

        if (start == true) {
            if (thread != null) {
                Log.i(TAG, "OOR Service already running");
                try {
                    oor_dns = ConfigTools.getDNS();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    return START_NOT_STICKY;
                }
            } else {
                Log.i(TAG, "Starting OOR Service.");
                system_dns = get_dns_servers();
                try {
                    oor_dns = ConfigTools.getDNS();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    return START_NOT_STICKY;
                }
                thread = new Thread(this, "OORService");
                thread.start();
                /* Put the service in background mode */
                Intent mainIntent = new Intent(this, OOR.class);
                NotificationCompat.Builder builder = new NotificationCompat.Builder(getApplicationContext());
                builder.setContentTitle("OOR");
                builder.setContentText("OOR running");
                builder.setContentIntent(PendingIntent.getActivity(this, PendingIntent.FLAG_UPDATE_CURRENT, mainIntent, 0));
                Notification notif = builder.build();
                startForeground(1234, notif);
            }
        } else {
            this.onDestroy();
        }

        if (start == true) {
            return (START_STICKY);
        } else {
            return (START_NOT_STICKY);
        }
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "Destroying OOR Service thread");
        scheduledFuture.cancel(true);
        scheduler.shutdown();
        set_dns_servers(system_dns);
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }
        stopForeground(true);
    }

    public synchronized void run() {
        scheduler = Executors.newScheduledThreadPool(1);
        Runnable dnsCheck = new Runnable() {
            public void run() {
                String psOutput = shell.run("/system/bin/ps | grep liboorexec.so");
                isRunning = psOutput.matches("(?s)(.*)[RS]\\s[a-zA-Z0-9\\/\\.\\-]*liboorexec\\.so(.*)");
                isRunning = true;
                if (oor_dns != null) {
                    String dns[] = get_dns_servers();
                    if ((dns[0] != null && !oor_dns.contains(dns[0])) ||
                            (dns[1] != null && !oor_dns.contains(dns[1]))){
                        system_dns = get_dns_servers();
                        set_dns_servers(oor_dns.toArray(new String[0]));
                    }
                }

                if (isRunning == false) {
                    onDestroy();
                }
            }
        };
        scheduledFuture = scheduler.scheduleAtFixedRate(dnsCheck, 0, 1, TimeUnit.SECONDS);
    }


    public String[] get_dns_servers() {
        String command = null;
        String dns[] = new String[2];

        command = "getprop net.dns1";
        dns[0] = shell.run(command);

        command = "getprop net.dns2";
        dns[1] = shell.run(command);

        return dns;
    }

    public static void set_dns_servers(String[] dns) {
        String command = null;

        command = "setprop net.dns1 \"" + dns[0] + "\"";
        shell.run_no_output(command);

        command = "setprop net.dns2 \"" + dns[1] + "\"";
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
            System.out.println("OOR: Command Failed.");
            e1.printStackTrace();
            return ("Command Failed.");
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return (output.toString());
    }


}
