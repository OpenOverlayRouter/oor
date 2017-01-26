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

import android.app.ProgressDialog;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;


public class logActivity extends Fragment {


    private ProgressDialog myDialog = null;
    private Handler mHandler = new Handler();


    private static File log_file = null;
    public static final int maxReadBytes = 200000;

    private LinearLayout llLayout;
    private FragmentActivity faActivity;
    private Toast mToast = null;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        faActivity = (FragmentActivity) super.getActivity();
        llLayout = (LinearLayout) inflater.inflate(R.layout.log, container, false);


        File sdcardDir = Environment.getExternalStorageDirectory();
        log_file = new File(sdcardDir, "oor.log");

        LinearLayout refreshButton = (LinearLayout) llLayout.findViewById(R.id.linearbutton);


        refreshButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                refreshClicked(llLayout);
            }
        });

        new Thread(new Runnable() {
            public void run() {
                refresh();
            }
        }).start();

        return llLayout;
    }

    public void refresh() {

        StringBuffer contents = new StringBuffer();

        final StringBuffer fixedContents = contents;

        try {
            RandomAccessFile logFile = new RandomAccessFile(log_file, "r");
            if (logFile.length() > maxReadBytes) {
                logFile.seek(logFile.length() - maxReadBytes);
            }
            String currentLine = logFile.readLine();
            while (currentLine != null) {

                if (currentLine != null) {
                    contents.append(currentLine);
                    contents.append('\n');
                }
                currentLine = logFile.readLine();
            }
            try {
                if (logFile != null) {
                    logFile.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {

        }

        mHandler.post(new Runnable() {
                          public void run() {


                              // Put the file contents into the TextView
                              TextView log = (TextView) llLayout.findViewById(R.id.logView);
                              log.setText(fixedContents);

                              // Auto scroll to the bottom
                              final ScrollView scroll = (ScrollView) llLayout.findViewById(R.id.scrollView1);
                              scroll.post(new Runnable() {
                                  public void run() {
                                      scroll.fullScroll(View.FOCUS_DOWN);
                                  }
                              });
                              if (myDialog != null) {
                                  myDialog.dismiss();
                                  myDialog = null;
                              }
                          }
                      }
        );
    }

    public void refreshClicked(View v) {
        if (mToast != null) {
            mToast.cancel();
        }
        mToast = Toast.makeText(faActivity.getApplicationContext(), "refreshing logs", Toast.LENGTH_SHORT);
        mToast.show();

        new Thread(new Runnable() {
            public void run() {
                refresh();
            }
        }).start();
    }
}
