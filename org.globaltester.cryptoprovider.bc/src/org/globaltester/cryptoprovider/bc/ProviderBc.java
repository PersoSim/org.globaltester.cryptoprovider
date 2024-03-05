package org.globaltester.cryptoprovider.bc;

import java.security.Provider;
import java.security.Security;
import java.util.Hashtable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globaltester.cryptoprovider.Cryptoprovider;

public class ProviderBc implements Cryptoprovider {

	private static Cryptoprovider instance;
	private BouncyCastleProvider provider;

	private ProviderBc() {
		provider = new BouncyCastleProvider();
		System.out.println("CryptoProvider is " + provider);
		Security.addProvider(provider);
		Security.setProperty("org.bouncycastle.rsa.allow_unsafe_mod", "true"); // allow e.g. rsa1_5WithSHA1 signature algorithm
	}

	public static Cryptoprovider getInstance() {
		if (instance == null) {
			instance = new ProviderBc();
		}
		return instance;
	}

	@Override
	public String getCryptoProviderString() {
		getInstance();
		return provider.getInfo(); // returns "BC"
	}

	@Override
	public Provider getCryptoProviderObject() {
		getInstance();
		return provider;
	}

	@Override
	public Hashtable<String, String> getProperties() {
		Hashtable<String, String> props = new Hashtable<String, String>();
		props.put(Cryptoprovider.NAME, getCryptoProviderObject().getName());
		props.put(Cryptoprovider.VERSION, String.valueOf(getCryptoProviderObject().getVersion()));
		props.put(Cryptoprovider.INFO, getCryptoProviderObject().getInfo());
		return props;
	}

}
