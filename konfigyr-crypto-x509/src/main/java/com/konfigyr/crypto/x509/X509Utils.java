package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetPurpose;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

/**
 * Internal utilities used to generate key identifiers and to issue self-signed X.509 certificates.
 * <p>
 * BouncyCastle is only used to build the certificate structure. The certificate signature, and every
 * other cryptographic operation, is performed by the default JCA providers of the JDK, as no
 * BouncyCastle security provider is registered or used.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 */
@NullMarked
final class X509Utils {

	/**
	 * Margin added to the end of the certificate validity, so that the certificate remains valid until the
	 * scheduled keyset maintenance tasks destroyed its key, even when they run with a delay.
	 */
	static final Duration CERTIFICATE_VALIDITY_MARGIN = Duration.ofDays(1);

	private static final SecureRandom RANDOM = new SecureRandom();

	private X509Utils() {
	}

	static SecureRandom random() {
		return RANDOM;
	}

	static String generateKeyId() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Calculates the end of the validity of a certificate whose key becomes the primary key at the given time.
	 * <p>
	 * The certificate remains valid while its key is the primary key, for the rotation interval, and while it
	 * is retired afterwards, for the destruction grace period, followed by the
	 * {@link #CERTIFICATE_VALIDITY_MARGIN validity margin}:
	 * <pre>
	 *     notAfter = activatesAt + rotationInterval + destructionGracePeriod + margin
	 * </pre>
	 * When automatic key rotation is disabled, the {@link KeysetDefinition#MAXIMUM_ROTATION_INTERVAL maximum
	 * rotation interval} is used, and no destruction grace period counts as zero.
	 *
	 * @param activatesAt            the time when the key becomes the primary key
	 * @param rotationInterval       the rotation interval of the keyset, can be {@literal null}
	 * @param destructionGracePeriod the destruction grace period of the keyset, can be {@literal null}
	 * @return the end of the certificate validity, never {@literal null}
	 */
	static Instant certificateNotAfter(Instant activatesAt, @Nullable Duration rotationInterval,
			@Nullable Duration destructionGracePeriod) {
		return activatesAt
			.plus(rotationInterval == null ? KeysetDefinition.MAXIMUM_ROTATION_INTERVAL : rotationInterval)
			.plus(destructionGracePeriod == null ? Duration.ZERO : destructionGracePeriod)
			.plus(CERTIFICATE_VALIDITY_MARGIN);
	}

	/**
	 * Calculates the latest time at which a key, whose certificate is valid until the given time, may expire
	 * as the primary key, so that it remains covered by its certificate for the destruction grace period
	 * during which it is retired afterwards.
	 *
	 * @param notAfter               the end of the certificate validity
	 * @param destructionGracePeriod the destruction grace period of the keyset, can be {@literal null}
	 * @return the latest expiration time of the key, never {@literal null}
	 */
	static Instant latestExpiration(Instant notAfter, @Nullable Duration destructionGracePeriod) {
		return notAfter
			.minus(destructionGracePeriod == null ? Duration.ZERO : destructionGracePeriod)
			.minus(CERTIFICATE_VALIDITY_MARGIN);
	}

	/**
	 * Issues a self-signed X.509 v3 certificate for the given key pair.
	 * <p>
	 * The certificate is marked as an end-entity certificate ({@code CA=false}) and its key usage is
	 * derived from the {@link KeysetPurpose} of the algorithm: {@code digitalSignature} for signing keys
	 * and {@code keyEncipherment} for encryption keys.
	 *
	 * @param subject   common name of the certificate subject and issuer
	 * @param pair      key pair that is certified and that self-signs the certificate
	 * @param algorithm algorithm of the key pair
	 * @param notBefore start of the certificate validity period
	 * @param notAfter  end of the certificate validity period
	 * @return the self-signed certificate
	 */
	static X509Certificate issueSelfSignedCertificate(
		String subject,
		KeyPair pair,
		X509Algorithm algorithm,
		Instant notBefore,
		Instant notAfter
	) throws GeneralSecurityException, IOException, OperatorCreationException {
		final X500Name name = new X500NameBuilder(BCStyle.INSTANCE)
			.addRDN(BCStyle.CN, subject)
			.build();

		// positive, non-zero serial number with 126 bits of entropy (RFC 5280 §4.1.2.2)
		final BigInteger serial = new BigInteger(126, random()).setBit(126);

		final int usage = algorithm.purpose() == KeysetPurpose.SIGNING ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment;

		final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			name,
			serial,
			Date.from(notBefore.truncatedTo(ChronoUnit.SECONDS)),
			Date.from(notAfter.truncatedTo(ChronoUnit.SECONDS)),
			name,
			pair.getPublic()
		);

		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
			.addExtension(Extension.keyUsage, true, new KeyUsage(usage))
			.addExtension(Extension.subjectKeyIdentifier, false,
				new JcaX509ExtensionUtils().createSubjectKeyIdentifier(pair.getPublic()));

		final ContentSigner signer = new JcaContentSignerBuilder(algorithm.signatureAlgorithm())
			.setSecureRandom(random())
			.build(pair.getPrivate());

		return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
	}

}
