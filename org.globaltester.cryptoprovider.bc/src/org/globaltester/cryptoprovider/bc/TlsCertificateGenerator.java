package org.globaltester.cryptoprovider.bc;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TlsCertificateGenerator {

	private static SecureRandom random = new SecureRandom();

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		// create keypair
		KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("RSA");
		keypairGen.initialize(3072, random);
		KeyPair keypair = keypairGen.generateKeyPair();
		return keypair;
	}

	public static Certificate generateTlsCertificate(KeyPair keypair) {
		Calendar calendar = Calendar.getInstance();
		Date effective = calendar.getTime();
		
		calendar.setTime(effective);
		calendar.set(Calendar.YEAR, calendar.get(Calendar.YEAR)+10);
		System.out.println(calendar.getTime());
		Date expiry = calendar.getTime();
		
		return generateTlsCertificate(keypair, effective, expiry);
	}

	public static Certificate generateTlsCertificate(KeyPair keypair, Date effectiveDate, Date expiryDate) {
		try {
			X500Name subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "PersoSim").build();
			byte[] id = new byte[16];
			random.nextBytes(id);
			BigInteger serial = new BigInteger(160, random);
			X509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(subject, serial,
					effectiveDate, expiryDate, subject, keypair.getPublic());

			ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keypair.getPrivate());
			X509CertificateHolder holder = certificate.build(signer);

			JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
			converter.setProvider(new BouncyCastleProvider());
			return converter.getCertificate(holder);
		} catch (CertificateException | OperatorCreationException e) {
			throw new IllegalStateException("Could not create self signed certificate", e);
		}
	}
}
