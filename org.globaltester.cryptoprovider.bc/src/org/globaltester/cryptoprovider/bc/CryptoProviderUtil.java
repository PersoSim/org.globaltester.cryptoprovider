package org.globaltester.cryptoprovider.bc;

import java.security.spec.ECParameterSpec;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

public class CryptoProviderUtil {

	public static final boolean WITH_COMPRESSED_ECPOINT_ENCODING = false;
	
	private CryptoProviderUtil() {
		// hide implicit public constructor
	}

	public static org.bouncycastle.jce.spec.ECParameterSpec convertECParameterSpec(ECParameterSpec ecSpec) {
		return EC5Util.convertSpec(ecSpec);
	}
}
