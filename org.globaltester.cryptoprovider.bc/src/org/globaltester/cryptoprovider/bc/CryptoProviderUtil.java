package org.globaltester.cryptoprovider.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

public class CryptoProviderUtil {

	public static final boolean WITH_COMPRESSED_ECPOINT_ENCODING = false;

	private CryptoProviderUtil() {
		// hide implicit public constructor
	}

	public static org.bouncycastle.jce.spec.ECParameterSpec convertECParameterSpec(ECParameterSpec ecSpec) {
		return EC5Util.convertSpec(ecSpec);
	}

	public static byte[] ecdsaSigToASN1(byte[] sigBuff) {
		int sigHalfOfBuffLength = sigBuff.length / 2;
		BigInteger r = new BigInteger(1, Arrays.copyOfRange(sigBuff, 0, sigHalfOfBuffLength));
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(sigBuff, sigHalfOfBuffLength, sigHalfOfBuffLength * 2));
		ASN1EncodableVector vector = new ASN1EncodableVector();
		vector.add(new ASN1Integer(r));
		vector.add(new ASN1Integer(s));
		try {
			return new DERSequence(vector).getEncoded();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static boolean verifySignature(String sigAlg, PublicKey pubKey, byte[] hash, byte[] sigToVerify) {
		boolean verifyResult = false;
		try {
			// initialize the signature object
			Signature sig = java.security.Signature.getInstance(sigAlg, org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
			sig.initVerify(pubKey);

			// add input data to signature object
			sig.update(hash, 0, hash.length);

			// verify the signature
			verifyResult = sig.verify(sigToVerify, 0, sigToVerify.length);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
			verifyResult = false;
			e.printStackTrace();
		}
		return verifyResult;
	}
}
