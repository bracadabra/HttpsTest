package com.example.httpstest;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class SecurityUtils {

	private SecurityUtils() {

	}

	public static X509TrustManager findX509TrustManager(
			final TrustManagerFactory trustManagerFactory) {
		final TrustManager trustManagers[] = trustManagerFactory
				.getTrustManagers();
		for (int i = 0; i < trustManagers.length; i++) {
			if (trustManagers[i] instanceof X509TrustManager) {
				return (X509TrustManager) trustManagers[i];
			}
		}

		return null;
	}

}
