package com.example.httpstest;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class TemafonTrustManager implements X509TrustManager {

	private final X509TrustManager mTrustManager;
	private final KeyStore mTemafonKeyStore;

	public TemafonTrustManager(final KeyStore temafonKeyStore) {
		mTemafonKeyStore = temafonKeyStore;
		try {
			final TrustManagerFactory trustManagerFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init(temafonKeyStore);

			mTrustManager = SecurityUtils
					.findX509TrustManager(trustManagerFactory);
			if (mTrustManager == null) {
				throw new IllegalStateException(
						"Couldn't find X509TrustManager");
			}
		} catch (final GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void checkClientTrusted(final X509Certificate[] chain,
			final String authType)
			throws CertificateException {
		mTrustManager.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		try {
			final X509Certificate[] reorderedChain = reorderCertificateChain(chain);
			mTrustManager.checkServerTrusted(reorderedChain, authType);
		} catch (final CertificateException e) {
			try {

				final X509Certificate[] reorderedChain = reorderCertificateChain(chain);
				mTrustManager.checkServerTrusted(reorderedChain, authType);

				/*X509Certificate[] reorderedChain = reorderCertificateChain(chain);
				CertPathValidator validator = CertPathValidator
						.getInstance("PKIX");
				CertificateFactory factory = CertificateFactory
						.getInstance("X509");
				CertPath certPath = factory.generateCertPath(Arrays
						.asList(reorderedChain));
				PKIXParameters params = new PKIXParameters(mTemafonKeyStore);
				params.setRevocationEnabled(false);
				validator.validate(certPath, params);*/
			} catch (Exception ex) {
				throw e;
			}
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return mTrustManager.getAcceptedIssuers();
	}

	private X509Certificate[] reorderCertificateChain(X509Certificate[] chain) {

		final X509Certificate[] reorderedChain = new X509Certificate[chain.length];
		final List<X509Certificate> certificates = Arrays.asList(chain);

		int position = chain.length - 1;
		X509Certificate rootCert = findRootCert(certificates);
		reorderedChain[position] = rootCert;

		X509Certificate cert = rootCert;
		while ((cert = findSignedCert(cert, certificates)) != null
				&& position > 0) {
			reorderedChain[--position] = cert;
		}

		return reorderedChain;
	}

	private X509Certificate findRootCert(List<X509Certificate> certificates) {
		X509Certificate rootCert = null;

		for (X509Certificate cert : certificates) {
			X509Certificate signer = findSigner(cert, certificates);
			if (signer == null || signer.equals(cert)) {
				rootCert = cert;
				break;
			}
		}

		return rootCert;
	}

	private X509Certificate findSignedCert(X509Certificate signingCert,
			List<X509Certificate> certificates) {
		X509Certificate signed = null;

		for (X509Certificate cert : certificates) {
			Principal signingCertSubjectDN = signingCert.getSubjectDN();
			Principal certIssuerDN = cert.getIssuerDN();
			if (certIssuerDN.equals(signingCertSubjectDN)
					&& !cert.equals(signingCert)) {
				signed = cert;
				break;
			}
		}

		return signed;
	}

	private X509Certificate findSigner(X509Certificate signedCert,
			List<X509Certificate> certificates) {
		X509Certificate signer = null;

		for (X509Certificate cert : certificates) {
			final Principal certSubjectDN = cert.getSubjectDN();
			final Principal issuerDN = signedCert.getIssuerDN();
			if (certSubjectDN.equals(issuerDN)) {
				signer = cert;
				break;
			}
		}

		return signer;
	}

}
