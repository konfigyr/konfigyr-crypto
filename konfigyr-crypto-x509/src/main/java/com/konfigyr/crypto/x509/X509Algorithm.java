package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Collection of {@link Algorithm algorithms} for asymmetric key pairs that are bound to an
 * X.509 certificate, such as the signing and encryption credentials of a SAML 2.0 Relying Party.
 * <p>
 * Each algorithm describes the key specification (key type and size or curve) and its
 * {@link KeysetPurpose}. The purpose is part of the algorithm name, as the same key specification
 * is used for both purposes while the keys themselves must never be shared between them
 * (NIST SP 800-57 Part 1 §5.2):
 * <ul>
 *     <li>
 *         {@link KeysetPurpose#SIGNING}: RSA and ECDSA key pairs whose certificate carries the
 *         {@code digitalSignature} key usage
 *     </li>
 *     <li>
 *         {@link KeysetPurpose#ENCRYPTION}: RSA key pairs used for RSA-OAEP key transport whose
 *         certificate carries the {@code keyEncipherment} key usage
 *     </li>
 * </ul>
 * <p>
 * Algorithm names follow the {@code x509:<key type>-<size or curve>-<purpose>} pattern. They are
 * persisted alongside the key material and must never change once keys have been created.
 * <p>
 * Algorithms do not fix the signature or encryption scheme used by protocols such as XML
 * Signature or XML Encryption, as those are negotiated when the operation is performed. The
 * {@link #signatureAlgorithm() signature algorithm} declared here is used to self-sign the
 * certificate and by the {@link com.konfigyr.crypto.Keyset#sign(com.konfigyr.io.ByteArray)}
 * operation.
 * <p>
 * Custom algorithms can be created using the {@link #rsa(String, KeysetPurpose, int, String)} and
 * {@link #ec(String, String, String)} factory methods and registered via an
 * {@link com.konfigyr.crypto.AlgorithmRegistrar} bean.
 *
 * @author Vladimir Spasic
 * @since 1.1.0
 * @see KeyPairGenerator
 * @see java.security.Signature
 */
@NullMarked
public final class X509Algorithm implements Algorithm {

	private static final String PREFIX = X509KeysetFactory.NAME + ":";

	private static final int MINIMUM_RSA_KEY_SIZE = 2048;

	private static final Set<String> SUPPORTED_CURVES = Set.of("secp256r1", "secp384r1", "secp521r1");

	/* -------------------------------------------------------------------------
	 * RSA signing algorithms (KeysetPurpose.SIGNING)
	 * ---------------------------------------------------------------------- */

	/**
	 * RSA 3072-bit signing key pair, using {@code SHA256withRSA} (RSASSA-PKCS1-v1_5).
	 * <p>
	 * PKCS#1 v1.5 signatures are used for XML Signature interoperability
	 * ({@code http://www.w3.org/2001/04/xmldsig-more#rsa-sha256}).
	 */
	public static final X509Algorithm RSA_3072_SIGNING = rsa(
		"x509:RSA-3072-SIGNING", KeysetPurpose.SIGNING, 3072, "SHA256withRSA"
	);

	/**
	 * RSA 4096-bit signing key pair, using {@code SHA512withRSA} (RSASSA-PKCS1-v1_5).
	 * <p>
	 * PKCS#1 v1.5 signatures are used for XML Signature interoperability
	 * ({@code http://www.w3.org/2001/04/xmldsig-more#rsa-sha512}).
	 */
	public static final X509Algorithm RSA_4096_SIGNING = rsa(
		"x509:RSA-4096-SIGNING", KeysetPurpose.SIGNING, 4096, "SHA512withRSA"
	);

	/**
	 * RSA 2048-bit signing key pair, using {@code SHA256withRSA} (RSASSA-PKCS1-v1_5).
	 * <p>
	 * Meets the NIST minimum (SP 800-131A Rev 2) but is below the preferred key size. Only use it
	 * when a counterparty does not accept larger keys.
	 */
	public static final X509Algorithm RSA_2048_SIGNING = rsa(
		"x509:RSA-2048-SIGNING", KeysetPurpose.SIGNING, 2048, "SHA256withRSA"
	);

	/* -------------------------------------------------------------------------
	 * RSA encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * RSA 3072-bit key transport key pair, used with RSA-OAEP. NIST SP 800-56B Rev 2.
	 */
	public static final X509Algorithm RSA_3072_ENCRYPTION = rsa(
		"x509:RSA-3072-ENCRYPTION", KeysetPurpose.ENCRYPTION, 3072, "SHA256withRSA"
	);

	/**
	 * RSA 4096-bit key transport key pair, used with RSA-OAEP. NIST SP 800-56B Rev 2.
	 */
	public static final X509Algorithm RSA_4096_ENCRYPTION = rsa(
		"x509:RSA-4096-ENCRYPTION", KeysetPurpose.ENCRYPTION, 4096, "SHA512withRSA"
	);

	/**
	 * RSA 2048-bit key transport key pair, used with RSA-OAEP. NIST SP 800-56B Rev 2.
	 * <p>
	 * Meets the NIST minimum (SP 800-131A Rev 2) but is below the preferred key size. Only use it
	 * when a counterparty does not accept larger keys.
	 */
	public static final X509Algorithm RSA_2048_ENCRYPTION = rsa(
		"x509:RSA-2048-ENCRYPTION", KeysetPurpose.ENCRYPTION, 2048, "SHA256withRSA"
	);

	/* -------------------------------------------------------------------------
	 * ECDSA signing algorithms (KeysetPurpose.SIGNING)
	 * ---------------------------------------------------------------------- */

	/**
	 * ECDSA signing key pair using NIST P-256 and SHA-256. NIST FIPS 186-5.
	 */
	public static final X509Algorithm EC_P256_SIGNING = ec(
		"x509:EC-P256-SIGNING", "secp256r1", "SHA256withECDSA"
	);

	/**
	 * ECDSA signing key pair using NIST P-384 and SHA-384. NIST FIPS 186-5.
	 */
	public static final X509Algorithm EC_P384_SIGNING = ec(
		"x509:EC-P384-SIGNING", "secp384r1", "SHA384withECDSA"
	);

	/**
	 * ECDSA signing key pair using NIST P-521 and SHA-512. NIST FIPS 186-5.
	 */
	public static final X509Algorithm EC_P521_SIGNING = ec(
		"x509:EC-P521-SIGNING", "secp521r1", "SHA512withECDSA"
	);

	/**
	 * Algorithms that are registered by default. They provide at least 128-bit security strength
	 * (NIST SP 800-57 Part 1 Rev 5).
	 */
	public static final List<X509Algorithm> DEFAULT_ALGORITHMS = List.of(
		RSA_3072_SIGNING, RSA_4096_SIGNING,
		RSA_3072_ENCRYPTION, RSA_4096_ENCRYPTION,
		EC_P256_SIGNING, EC_P384_SIGNING, EC_P521_SIGNING
	);

	/**
	 * RSA 2048-bit algorithms retained exclusively for interoperability with counterparties that
	 * do not accept larger RSA keys.
	 * <p>
	 * These algorithms are <strong>not</strong> registered automatically and must be opted in
	 * explicitly. Prefer the 3072 or 4096-bit variants in new designs.
	 */
	public static final List<X509Algorithm> LEGACY_ALGORITHMS = List.of(RSA_2048_SIGNING, RSA_2048_ENCRYPTION);

	/** Stable unique algorithm name with {@code "x509:"} prefix. */
	private final String name;

	/** Key material type produced by this algorithm. */
	private final KeyType type;

	/** Intended cryptographic purpose (signing or encryption). */
	private final KeysetPurpose purpose;

	/** RSA modulus size in bits, or the field size of the curve for EC keys. */
	private final int keySize;

	/** Standard name of the EC curve, {@literal null} for RSA keys. */
	private final @Nullable String curve;

	/** JCA standard signature algorithm name used for signing and certificate self-signing. */
	private final String signatureAlgorithm;

	private X509Algorithm(
		String name,
		KeyType type,
		KeysetPurpose purpose,
		int keySize,
		@Nullable String curve,
		String signatureAlgorithm
	) {
		Assert.hasText(name, "X509 algorithm name can't be blank");
		Assert.isTrue(name.startsWith(PREFIX), "X509 algorithm names must start with 'x509:' prefix");
		Assert.notNull(purpose, "X509 algorithm purpose can't be null");
		Assert.hasText(signatureAlgorithm, "X509 signature algorithm can't be blank");
		this.name = name;
		this.type = type;
		this.purpose = purpose;
		this.keySize = keySize;
		this.curve = curve;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * Creates a custom RSA algorithm.
	 * <p>
	 * The {@code name} must be unique across all registered algorithms and must not change
	 * once key material has been created with this algorithm.
	 *
	 * @param name               stable unique algorithm name with {@code "x509:"} prefix, can't be blank
	 * @param purpose            intended cryptographic purpose, can't be {@literal null}
	 * @param keySize            RSA modulus size in bits, can't be less than {@code 2048}
	 * @param signatureAlgorithm JCA standard signature algorithm name, e.g. {@code SHA256withRSA},
	 *                           can't be blank
	 * @return the RSA algorithm, never {@literal null}
	 * @throws IllegalArgumentException when any of the arguments are invalid
	 */
	public static X509Algorithm rsa(String name, KeysetPurpose purpose, int keySize, String signatureAlgorithm) {
		Assert.isTrue(keySize >= MINIMUM_RSA_KEY_SIZE,
			() -> "RSA key size must be at least " + MINIMUM_RSA_KEY_SIZE + " bits, got: " + keySize);
		return new X509Algorithm(name, KeyType.RSA, purpose, keySize, null, signatureAlgorithm);
	}

	/**
	 * Creates a custom ECDSA signing algorithm.
	 * <p>
	 * Elliptic curve keys are only supported for {@link KeysetPurpose#SIGNING}, as EC key agreement
	 * is not supported by the X.509 keysets.
	 * <p>
	 * The {@code name} must be unique across all registered algorithms and must not change
	 * once key material has been created with this algorithm.
	 *
	 * @param name               stable unique algorithm name with {@code "x509:"} prefix, can't be blank
	 * @param curve              standard curve name, one of {@code secp256r1}, {@code secp384r1} or
	 *                           {@code secp521r1}
	 * @param signatureAlgorithm JCA standard signature algorithm name, e.g. {@code SHA256withECDSA},
	 *                           can't be blank
	 * @return the EC algorithm, never {@literal null}
	 * @throws IllegalArgumentException when any of the arguments are invalid
	 */
	public static X509Algorithm ec(String name, String curve, String signatureAlgorithm) {
		Assert.isTrue(SUPPORTED_CURVES.contains(curve),
			() -> "Unsupported EC curve: " + curve + ", supported curves are: " + SUPPORTED_CURVES);
		final int keySize = switch (curve) {
			case "secp256r1" -> 256;
			case "secp384r1" -> 384;
			default -> 521;
		};
		return new X509Algorithm(name, KeyType.EC, KeysetPurpose.SIGNING, keySize, curve, signatureAlgorithm);
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public String factory() {
		return X509KeysetFactory.NAME;
	}

	@Override
	public KeysetPurpose purpose() {
		return purpose;
	}

	@Override
	public KeyType type() {
		return type;
	}

	/**
	 * Returns the RSA modulus size in bits, or the field size in bits of the curve for EC keys.
	 *
	 * @return key size in bits
	 */
	public int keySize() {
		return keySize;
	}

	/**
	 * Returns the standard name of the elliptic curve used by this algorithm.
	 *
	 * @return curve name, or {@literal null} for RSA algorithms
	 */
	public @Nullable String curve() {
		return curve;
	}

	/**
	 * Returns the JCA standard signature algorithm name, e.g. {@code SHA256withRSA}, that is used
	 * to self-sign the certificate and by the signing operations of the keyset.
	 *
	 * @return signature algorithm name, never {@literal null}
	 */
	public String signatureAlgorithm() {
		return signatureAlgorithm;
	}

	/**
	 * Creates a new {@link KeyPairGenerator} that is initialized with the key specification of
	 * this algorithm and the given source of randomness.
	 *
	 * @param random source of randomness, can't be {@literal null}
	 * @return initialized key pair generator, never {@literal null}
	 * @throws GeneralSecurityException when the key specification is not supported by the
	 *                                  available security providers
	 */
	public KeyPairGenerator keyPairGenerator(SecureRandom random) throws GeneralSecurityException {
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(type.name());
		generator.initialize(parameterSpec(), random);
		return generator;
	}

	private AlgorithmParameterSpec parameterSpec() {
		if (curve != null) {
			return new ECGenParameterSpec(curve);
		}
		return new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4);
	}

	@Override
	public boolean equals(@Nullable Object o) {
		if (this == o) return true;
		if (!(o instanceof X509Algorithm that)) return false;
		return Objects.equals(name, that.name);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
	}

	@Override
	public String toString() {
		return name;
	}

}
