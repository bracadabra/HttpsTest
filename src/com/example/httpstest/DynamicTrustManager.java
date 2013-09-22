package com.example.httpstest;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class DynamicTrustManager implements X509TrustManager {

	private X509TrustManager mTemafonTrustManager;
	private X509TrustManager mDefaultTrustManager;

	private X509Certificate[] mAcceptedIssuers;

	public DynamicTrustManager(final KeyStore temafonKeyStore,
			final KeyStore intechKeyStore) {
		try {
			final TrustManagerFactory trustManagerFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init((KeyStore) null);

			mDefaultTrustManager = SecurityUtils
					.findX509TrustManager(trustManagerFactory);
			if (mDefaultTrustManager == null) {
				throw new IllegalStateException(
						"Couldn't find X509TrustManager");
			}

			mTemafonTrustManager = new TemafonTrustManager(temafonKeyStore);

			final List<X509Certificate> allIssuers = new ArrayList<X509Certificate>();
			for (X509Certificate cert : mDefaultTrustManager
					.getAcceptedIssuers()) {
				allIssuers.add(cert);
			}
			for (X509Certificate cert : mTemafonTrustManager
					.getAcceptedIssuers()) {
				allIssuers.add(cert);
			}
			mAcceptedIssuers = allIssuers
					.toArray(new X509Certificate[allIssuers.size()]);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}

	}

	@Override
	public void checkClientTrusted(final X509Certificate[] chain,
			final String authType)
			throws CertificateException {
		try {
			mTemafonTrustManager.checkClientTrusted(chain, authType);
		} catch (final CertificateException e1) {
			mDefaultTrustManager.checkClientTrusted(chain, authType);
		}
	}

	@Override
	public void checkServerTrusted(final X509Certificate[] chain,
			final String authType)
			throws CertificateException {
		try {
			mTemafonTrustManager.checkServerTrusted(chain, authType);
		} catch (final CertificateException e1) {
			mDefaultTrustManager.checkServerTrusted(chain, authType);
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return mAcceptedIssuers;
	}

}
