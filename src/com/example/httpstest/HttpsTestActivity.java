package com.example.httpstest;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import android.app.Activity;
import android.content.res.Resources.NotFoundException;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;

public class HttpsTestActivity extends Activity {
	private static final String TAG = HttpsTestActivity.class.getSimpleName();

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_https_test);
		new NetworkTask().execute();
	}

	public class NetworkTask extends AsyncTask<Void, Void, Void> {

		@Override
		public Void doInBackground(Void... params) {
			initSslContextTest();
			try {
				final URL url = new URL("https://free.temafon.ru");
				final HttpsURLConnection connection = (HttpsURLConnection) url
						.openConnection();
				if (connection.getResponseCode() == HttpsURLConnection.HTTP_OK) {
					Log.d("Test", "OK");
				} else {
					Log.d("Test", "Failed :(");
				}
			} catch (MalformedURLException e) {
				Log.e(TAG, Log.getStackTraceString(e));
			} catch (IOException e) {
				Log.e(TAG, Log.getStackTraceString(e));
			}

			return null;
		}

	}

	private void initSslContextTest() {
		try {
			final KeyStore keystore = KeyStore.getInstance("BKS");
			keystore.load(getResources().openRawResource(R.raw.temafon),
					"W0d3Uoa5PkED".toCharArray());

			final TrustManager trustManager = new TemafonTrustManager(keystore);

			final SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, new TrustManager[] { trustManager }, null);

			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
					.getSocketFactory());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
