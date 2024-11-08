package org.globaltester.cryptoprovider.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.ECPoint;
import org.globaltester.cryptoprovider.Crypto;

public class CryptoProviderUtil
{

	public static final boolean WITH_COMPRESSED_ECPOINT_ENCODING = false;

	private CryptoProviderUtil()
	{
		// hide implicit public constructor
	}

	public static org.bouncycastle.jce.spec.ECParameterSpec convertECParameterSpec(ECParameterSpec ecSpec)
	{
		return EC5Util.convertSpec(ecSpec);
	}

	public static byte[] ecdsaSigToASN1(byte[] sigBuff)
	{
		int sigHalfOfBuffLength = sigBuff.length / 2;
		BigInteger r = new BigInteger(1, Arrays.copyOfRange(sigBuff, 0, sigHalfOfBuffLength));
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(sigBuff, sigHalfOfBuffLength, sigHalfOfBuffLength * 2));
		ASN1EncodableVector vector = new ASN1EncodableVector();
		vector.add(new ASN1Integer(r));
		vector.add(new ASN1Integer(s));
		try {
			return new DERSequence(vector).getEncoded();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PublicKey convertECPublicKeyFromECPrivateKey(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), Crypto.getCryptoProvider());
		ECPrivateKeySpec specPriv = factory.getKeySpec(privateKey, ECPrivateKeySpec.class);
		org.bouncycastle.jce.spec.ECParameterSpec params = EC5Util.convertSpec(specPriv.getParams());
		ECPoint q = params.getG().multiply(specPriv.getS());
		java.security.spec.ECPublicKeySpec spec = new java.security.spec.ECPublicKeySpec(
				new java.security.spec.ECPoint(q.normalize().getXCoord().toBigInteger(), q.normalize().getYCoord().toBigInteger()), specPriv.getParams());
		return factory.generatePublic(spec);
	}

}
