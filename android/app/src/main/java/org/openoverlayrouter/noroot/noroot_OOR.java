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

import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Timer;
import java.util.TimerTask;

import static android.app.Activity.RESULT_OK;


@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class noroot_OOR extends Fragment {

    public static String oor_path = null;
    private static String system_dns[] = new String[2];
    private boolean oorWasRunning = false;
    private static boolean oorRunning = false;
    private static boolean err_msg_detected = false;
    private static boolean startVPN = false;
    private Intent vpn_intent = null;
    private static final int CONF_ACT = 1;
    private static final int VPN_SER = 2;
    private static noroot_OORVPNService vpn;

    private Handler handler;
    private Runnable doUpdateView;

    private LinearLayout llLayout;
    private FragmentActivity faActivity;

    private Timer mUpdateTimer = null;

    /**
     * Called when the activity is first created.
     */
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {

        faActivity = (FragmentActivity) super.getActivity();
        llLayout = (LinearLayout) inflater.inflate(R.layout.main, container, false);



    /* Get the directory of the executable */

        try {
            oor_path = faActivity.getPackageManager().getApplicationInfo("org.openoverlayrouter", 0).nativeLibraryDir;

        } catch (Exception e) {
            e.printStackTrace();
        }
        ;

    /*
     * Set up the button handlers
     */

        handler = new Handler();
        doUpdateView = new Runnable() {
            public void run() {
                updateStatus();
            }
        };

        ImageButton oor = (ImageButton) llLayout.findViewById(R.id.oorStart);
        oor.setOnClickListener(new OnClickListener() {
                                   public void onClick(View view) {
                                       vpn = new noroot_OORVPNService();
                                       if (oorRunning == false) {
                                           startVPN();

                                       } else {
                                           showMessage(faActivity.getString(R.string.askStopServiceString),
                                                   true, new Runnable() {
                                                       public void run() {
                                                           stopVPN();
                                                           oorWasRunning = false;
                                                           oorRunning = false;
                                                       }
                                                   });
                                       }


                                   }
                               }
        );

        updateStatus();

        return llLayout;

    }


    @Override
    public void onPause() {
        Log.v("noroot_OOR", "Pausing..");
        super.onPause();

        // Stop all timers
        if (mUpdateTimer != null) mUpdateTimer.cancel();
    }

    @Override
    public void onStop() {
        Log.v("noroot_OOR", "Stopping...");
        super.onStop();
        // Stop all timers
        if (mUpdateTimer != null) mUpdateTimer.cancel();
    }

    @Override
    public void onResume() {
        Log.v("noroot_OOR", "Resuming...");
        super.onResume();

        // Rebuild the timer
        if (mUpdateTimer != null) {
            mUpdateTimer.cancel();
        }
        mUpdateTimer = new Timer();
        mUpdateTimer.scheduleAtFixedRate(new statusTask(), 0, 1000);

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


    public void updateStatus() {
        final TextView oorCheckBoxLabel = (TextView) llLayout.findViewById(R.id.startStopCheckboxLabel);
        final TextView oorTextClick = (TextView) llLayout.findViewById(R.id.textClick);

        oorRunning = vpn.vpn_running;


        if (vpn.vpn_running) {
            oorTextClick.setText("Click on the icon to stop the service");
            oorCheckBoxLabel.setText(R.string.oorRunning);
            oorCheckBoxLabel.setTextColor(Color.BLACK);
            oorWasRunning = true;
        } else if (oorWasRunning) {
            oorTextClick.setText("Click on the icon to restart the service");
            oorCheckBoxLabel.setText("OOR has exited");
            oorCheckBoxLabel.setTextColor(Color.RED);
        } else {
            oorTextClick.setText("Click on the icon to start the service");
            oorCheckBoxLabel.setText(R.string.oorNotRunning);
            oorCheckBoxLabel.setTextColor(Color.BLACK);
        }

        if (!err_msg_detected && noroot_OORVPNService.err_msg_code != 0) {
            err_msg_detected = true;
            Resources res = getResources();
            String[] err_msg = res.getStringArray(R.array.ErrMsgArray);
            showMessage(err_msg[noroot_OORVPNService.err_msg_code],
                    false, new Runnable() {
                        public void run() {
                            noroot_OORVPNService.err_msg_code = 0;
                            err_msg_detected = false;
                        }
                    });
        }

    }


    public final class statusTask extends TimerTask {
        public void run() {
            handler.post(doUpdateView);
        }
    }

    public void showMessage(String message, boolean cancelAble, final Runnable task) {

        AlertDialog.Builder builder = new AlertDialog.Builder(faActivity);
        builder.setTitle("Attention:");
        builder.setMessage(message)
                .setCancelable(cancelAble)
                .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        if (task != null) {
                            task.run();
                        } else {
                            dialog.dismiss();
                        }
                    }
                });
        if (cancelAble) {
            builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    dialog.dismiss();
                }
            });
        }
        AlertDialog alert = builder.create();
        alert.show();
    }


    void restartOOR() {
        System.out.println("OOR: Restarting oor");
        stopVPN();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        startVPN();
    }

    public void startVPN() {
        startVPN = true;
        Intent intent = VpnService.prepare(faActivity);
        if (intent != null) {
            startActivityForResult(intent, VPN_SER);
        } else {
            onActivityResult(VPN_SER, RESULT_OK, null);
        }

        oorRunning = true;

        updateStatus();

    }

    public void stopVPN() {
        startVPN = false;

        Intent intent = VpnService.prepare(faActivity);
        if (intent == null) {
            onActivityResult(VPN_SER, RESULT_OK, null);
        }

        updateStatus();

    }


    public void onActivityResult(int request, int result, Intent data) {
        switch (request) {
            case CONF_ACT:
                if (result == noroot_updateConfActivity.CONFIG_UPDATED) {
                    if (noroot_OORVPNService.vpn_running) {
                        restartOOR();
                    }
                }
                break;
            case VPN_SER:
                String prefix = faActivity.getPackageName();
                if (result == RESULT_OK) {
                    if (startVPN == true) {
                        vpn_intent = new Intent(faActivity, noroot_OORVPNService.class);
                        vpn_intent.putExtra(prefix + ".START", true);
                        faActivity.startService(vpn_intent);

                    } else {
                        vpn_intent = new Intent(faActivity, noroot_OORVPNService.class);
                        vpn_intent.putExtra(prefix + ".START", false);
                        faActivity.startService(vpn_intent);
                    }
                }
                break;
            default:
                break;
        }
    }
}

