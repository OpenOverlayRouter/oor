package org.openoverlayrouter.noroot;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.support.v4.app.FragmentTabHost;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.text.Html;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;


public class MainActivity extends AppCompatActivity {
    private FragmentTabHost mTabHost;

    private SuShell shell;
    private Boolean root;
    private static final int REQUEST_PERMISSIONS = 1;
    private static String[] PERMISSIONS = {
            Manifest.permission.INTERNET,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };
    private Boolean hideLogin;


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        hideLogin = true; // hide login button

        verifyPermissions(this);         //Get permissions for API 23+

        ActionBar actionbar = getSupportActionBar();
        actionbar.setElevation(0);
        actionbar.setBackgroundDrawable(new ColorDrawable(Color.parseColor("#00796b")));
        actionbar.setTitle(Html.fromHtml("<font color='#ffffff'>Open Overlay Router</font>"));
        setContentView(R.layout.maintabs);

        // If android version is >= 6 start no root application
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            // only for marshmallow and newer versions
            root = false;
        } else {
            try {
                shell = new SuShell();
                Toast.makeText(this, this.getString(R.string.RootedString), Toast.LENGTH_LONG).show();
                root = true;
            } catch (IOException e) {
                Toast.makeText(this, this.getString(R.string.noRootedString), Toast.LENGTH_LONG).show();
                root = false;
            }
        }

        mTabHost = (FragmentTabHost) findViewById(android.R.id.tabhost);
        mTabHost.setup(this, getSupportFragmentManager(), android.R.id.tabcontent);
        if (root) {
            mTabHost.addTab(mTabHost.newTabSpec("tab1").setIndicator("OOR", null), OOR.class, null);
            mTabHost.addTab(mTabHost.newTabSpec("tab2").setIndicator("CONFIG", null), updateConfActivity.class, null);
        } else {
            mTabHost.addTab(mTabHost.newTabSpec("tab1").setIndicator("OOR", null), noroot_OOR.class, null);
            mTabHost.addTab(mTabHost.newTabSpec("tab2").setIndicator("CONFIG", null), noroot_updateConfActivity.class, null);
        }
        mTabHost.addTab(mTabHost.newTabSpec("tab3").setIndicator("LOGS", null), logActivity.class, null);
        updateConfActivity conf = new updateConfActivity();
        if (conf.lowLogLevel())
            mTabHost.getTabWidget().getChildAt(2).setVisibility(View.GONE); // erase log (tab 3)

        for (int i = 0; i < mTabHost.getTabWidget().getTabCount(); ++i) {
            TextView tv = (TextView) mTabHost.getTabWidget().getChildAt(i).findViewById(android.R.id.title);
            tv.setTextColor(Color.parseColor("#FFFFFF"));
        }


    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        if(!hideLogin) getMenuInflater().inflate(R.menu.loginmenu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_login) {
            Intent intent = new Intent(this, LoginActivity.class);
            intent.putExtra("fromMain", true);
            this.startActivity(intent);
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    public static void verifyPermissions(Activity activity) {
        // Check if we have write permission
        int permission = ActivityCompat.checkSelfPermission(activity, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // We don't have permission so prompt the user
            ActivityCompat.requestPermissions(
                    activity,
                    PERMISSIONS,
                    REQUEST_PERMISSIONS
            );
        }


    }
}
