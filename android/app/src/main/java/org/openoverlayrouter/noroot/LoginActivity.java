package org.openoverlayrouter.noroot;

import android.Manifest;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.text.Html;
import android.text.TextUtils;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.HurlStack;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.rengwuxian.materialedittext.MaterialEditText;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class LoginActivity extends AppCompatActivity {
    private static final String TAG = LoginActivity.class.getSimpleName();
    private Button btnLogin;
    private Button btnLinkToRegister;
    private Button btnManualConf;
    private EditText inputEmail;
    private EditText inputServer;
    private EditText inputPassword;
    private ProgressDialog pDialog;
    private RequestQueue mRequestQueue;
    private String[] userConf;
    private Boolean updated;
    private static final int REQUEST_PERMISSIONS = 1;
    private static String[] PERMISSIONS = {
            Manifest.permission.INTERNET,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };
    public static final String confFile = "oor.conf";
    public static File conf_file = null;
    public boolean fromMain = false;
    ActionBar actionbar;


    public static String url = "https://84.88.81.68/login.php";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Boolean hideLogin = true; //Hide login activity

        if(hideLogin) startMain();

        setContentView(R.layout.activity_login);
        setTextHintAlphas();

        //Get permissions for API 23+
        verifyPermissions(this);
        actionbar = getSupportActionBar();
        actionbar.setBackgroundDrawable(new ColorDrawable(Color.parseColor("#00796b")));

        inputServer = (EditText) findViewById(R.id.server);
        inputEmail = (EditText) findViewById(R.id.email);
        inputPassword = (EditText) findViewById(R.id.password);
        btnLogin = (Button) findViewById(R.id.btnLogin);
        btnLinkToRegister = (Button) findViewById(R.id.btnLinkToRegisterScreen);
        btnManualConf = (Button) findViewById(R.id.btnLinkToManualConfig);

        //Check if coming from MainActivity
        if (savedInstanceState == null) {
            Bundle extras = getIntent().getExtras();
            if (extras == null) {
                fromMain = false;
            } else {
                fromMain = extras.getBoolean("fromMain");
            }
        } else {
            fromMain = (Boolean) savedInstanceState.getSerializable("fromMain");
        }

        if (!fromMain) {
            File sdcardDir = Environment.getExternalStorageDirectory();
            conf_file = new File(sdcardDir, confFile);

            if (conf_file.exists()) {
                startMain();
            } else {
                actionbar.setTitle(Html.fromHtml("<font color='#ffffff'>Open Overlay Router</font>"));
            }
        } else {
            actionbar.setTitle(Html.fromHtml("<font color='#ffffff'>Login</font>"));
            actionbar.setDisplayHomeAsUpEnabled(true);

            btnManualConf.setVisibility(View.GONE);
        }


        HurlStack hurlStack = new HurlStack() {
            @Override
            protected HttpURLConnection createConnection(URL url) throws IOException {
                HttpsURLConnection httpsURLConnection = (HttpsURLConnection) super.createConnection(url);
                try {
                    httpsURLConnection.setSSLSocketFactory(getSSLSocketFactory());
                    httpsURLConnection.setHostnameVerifier(getHostnameVerifier());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return httpsURLConnection;
            }
        };
        mRequestQueue = Volley.newRequestQueue(this, hurlStack);
        pDialog = new ProgressDialog(this);
        pDialog.setCancelable(false);


        btnLogin.setOnClickListener(new View.OnClickListener() {

            public void onClick(View view) {
                String server = inputServer.getText().toString().trim();
                String email = inputEmail.getText().toString().trim();
                String password = inputPassword.getText().toString().trim();

                // Check for empty data in the form
                if (!email.isEmpty() && !password.isEmpty() && !server.isEmpty()) {
                    updated = false;
                    checkLogin(email, password); //needs to add server in the future
                    startMain();

                } else {
                    // Prompt user to enter credentials
                    Toast.makeText(getApplicationContext(),
                            "Please enter the credentials!", Toast.LENGTH_LONG)
                            .show();
                }
            }

        });
        btnManualConf.setOnClickListener(new View.OnClickListener() {

            public void onClick(View view) {
                startMain();
            }
        });

        // Link to Register Screen
        btnLinkToRegister.setOnClickListener(new View.OnClickListener() {

            public void onClick(View view) {

            }
        });

    }


    private void checkLogin(final String email, final String password) {
        String tag_string_req = "req_login";

        pDialog.setMessage("Logging in ...");
        showDialog();

        StringRequest strReq = new StringRequest(Request.Method.POST,
                url, new Response.Listener<String>() {

            @Override
            public void onResponse(String response) {
                //Log.d(TAG, "Login Response: " + response.toString());
                if (!LoginActivity.this.isFinishing() && pDialog != null) {
                    hideDialog();
                }


                try {
                    JSONObject jObj = new JSONObject(response);
                    boolean error = jObj.getBoolean("error");

                    // Check for error node in json
                    if (!error) {
                        userConf = new String[14];
                        // user successfully logged in

                        String uid = jObj.getString("uid");

                        JSONObject user = jObj.getJSONObject("user");


                        userConf[0] = user.getString("name");
                        userConf[1] = user.getString("email");
                        userConf[2] = user.getString("eidipv4");
                        userConf[3] = user.getString("eidipv6");
                        userConf[4] = user.getString("ifaces");
                        userConf[5] = user.getString("mr");
                        userConf[6] = user.getString("ms");
                        userConf[7] = user.getString("mskey");
                        userConf[8] = user.getString("proxyetr");
                        userConf[9] = user.getString("dns1");
                        userConf[10] = user.getString("dns2");
                        userConf[11] = user.getString("overrideDNS");
                        userConf[12] = user.getString("nat_aware");
                        userConf[13] = user.getString("loglevel");


                        updateConfActivity config = new updateConfActivity();
                        config.createLoginFile(userConf);
                    } else {
                        // Error in login. Get the error message
                        String errorMsg = jObj.getString("error_msg");
                        Toast.makeText(getApplicationContext(),
                                errorMsg, Toast.LENGTH_LONG).show();
                    }
                } catch (JSONException e) {
                    // JSON error
                    e.printStackTrace();
                    Toast.makeText(getApplicationContext(), "Json error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }

            }
        }, new Response.ErrorListener() {

            @Override
            public void onErrorResponse(VolleyError error) {
                Log.e(TAG, "Login Error: " + error.getMessage());
                Toast.makeText(getApplicationContext(),
                        error.getMessage(), Toast.LENGTH_LONG).show();
                if (!LoginActivity.this.isFinishing() && pDialog != null) {
                    hideDialog();
                }
            }
        }) {

            @Override
            protected Map<String, String> getParams() {
                // Posting parameters to login url
                Map<String, String> params = new HashMap<String, String>();
                params.put("email", email);
                params.put("password", password);

                return params;
            }

        };

        // Adding request to request queue
        addToRequestQueue(strReq, tag_string_req);
    }

    private void showDialog() {
        if (!pDialog.isShowing())
            pDialog.show();
    }

    private void hideDialog() {
        if (pDialog.isShowing())
            pDialog.dismiss();
    }

    public <T> void addToRequestQueue(Request<T> req, String tag) {
        req.setTag(TextUtils.isEmpty(tag) ? TAG : tag);
        mRequestQueue.add(req);
    }

    private HostnameVerifier getHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
                return hv.verify("OOR", session);
            }
        };
    }

    private TrustManager[] getWrappedTrustManagers(TrustManager[] trustManagers) {
        final X509TrustManager originalTrustManager = (X509TrustManager) trustManagers[0];
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return originalTrustManager.getAcceptedIssuers();
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        try {
                            if (certs != null && certs.length > 0) {
                                certs[0].checkValidity();
                            } else {
                                originalTrustManager.checkClientTrusted(certs, authType);
                            }
                        } catch (CertificateException e) {
                            Log.w("checkClientTrusted", e.toString());
                        }
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        try {
                            if (certs != null && certs.length > 0) {
                                certs[0].checkValidity();
                            } else {
                                originalTrustManager.checkServerTrusted(certs, authType);
                            }
                        } catch (CertificateException e) {
                            Log.w("checkServerTrusted", e.toString());
                        }
                    }
                }
        };
    }

    private SSLSocketFactory getSSLSocketFactory()
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream caInput = getResources().openRawResource(R.raw.apache); // this cert file stored in \app\src\main\res\raw folder path

        Certificate ca = cf.generateCertificate(caInput);
        caInput.close();

        KeyStore keyStore = KeyStore.getInstance("BKS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        TrustManager[] wrappedTrustManagers = getWrappedTrustManagers(tmf.getTrustManagers());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, wrappedTrustManagers, null);

        return sslContext.getSocketFactory();
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

    public void startMain() {
        Intent intent = new Intent(LoginActivity.this,
                MainActivity.class);
        startActivity(intent);
        finish();
    }

    public void setTextHintAlphas() {
        MaterialEditText aux;
        aux = (MaterialEditText) findViewById(R.id.email);
        aux.setFocusFraction(0.9f);
        aux = (MaterialEditText) findViewById(R.id.password);
        aux.setFocusFraction(0.9f);
        aux = (MaterialEditText) findViewById(R.id.server);
        aux.setFocusFraction(0.9f);

    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        finish();
        return true;

    }

    @Override
    protected void onDestroy() {
        hideDialog();
        super.onDestroy();
    }
}