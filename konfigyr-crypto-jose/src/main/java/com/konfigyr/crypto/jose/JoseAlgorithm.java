package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.EqualsAndHashCode;
import org.jspecify.annotations.NullMarked;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

/**
 * Collection of {@link Algorithm algorithms} supported by the
 * <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE JWT</a> library.
 * <p>
 * Algorithms are grouped by their intended cryptographic purpose:
 * <ul>
 *     <li>{@link KeysetPurpose#SIGNING} — JWS algorithms (HMAC, ECDSA, RSA-PSS, RSA-PKCS1)</li>
 *     <li>{@link KeysetPurpose#ENCRYPTION} — JWE key management algorithms (RSA-OAEP,
 *         AES Key Wrap, ECDH-ES, AES-GCM Key Wrap)</li>
 * </ul>
 * <p>
 * Algorithm names follow the IANA-registered names from RFC 7518 (JWA), prefixed with
 * {@code "jose:"} to identify this factory family.
 * <p>
 * Custom JOSE algorithms can be created by constructing an instance directly and registering
 * it via an {@link com.konfigyr.crypto.AlgorithmRegistrar} bean.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see com.nimbusds.jose.JWSAlgorithm
 * @see com.nimbusds.jose.JWEAlgorithm
 */
@NullMarked
@EqualsAndHashCode(of = "name")
public final class JoseAlgorithm implements Algorithm {

	/* -------------------------------------------------------------------------
	 * HMAC symmetric signing algorithms (KeysetPurpose.SIGNING)
	 * ---------------------------------------------------------------------- */

	/**
	 * HMAC using SHA-256. NIST FIPS 198-1.
	 */
	public static final JoseAlgorithm HS256 = new JoseAlgorithm(
		"jose:HS256", KeyType.OCTET, KeysetPurpose.SIGNING, JWSAlgorithm.HS256,
		() -> new OctetSequenceKeyGenerator(256)
	);

	/**
	 * HMAC using SHA-384. NIST FIPS 198-1.
	 */
	public static final JoseAlgorithm HS384 = new JoseAlgorithm(
		"jose:HS384", KeyType.OCTET, KeysetPurpose.SIGNING, JWSAlgorithm.HS384,
		() -> new OctetSequenceKeyGenerator(384)
	);

	/**
	 * HMAC using SHA-512. NIST FIPS 198-1.
	 */
	public static final JoseAlgorithm HS512 = new JoseAlgorithm(
		"jose:HS512", KeyType.OCTET, KeysetPurpose.SIGNING, JWSAlgorithm.HS512,
		() -> new OctetSequenceKeyGenerator(512)
	);

	/* -------------------------------------------------------------------------
	 * ECDSA asymmetric signing algorithms (KeysetPurpose.SIGNING)
	 * ---------------------------------------------------------------------- */

	/**
	 * ECDSA using NIST P-256 and SHA-256. NIST FIPS 186-5.
	 */
	public static final JoseAlgorithm ES256 = new JoseAlgorithm(
		"jose:ES256", KeyType.EC, KeysetPurpose.SIGNING, JWSAlgorithm.ES256, () -> new ECKeyGenerator(Curve.P_256)
	);

	/**
	 * ECDSA using NIST P-384 and SHA-384. NIST FIPS 186-5.
	 */
	public static final JoseAlgorithm ES384 = new JoseAlgorithm(
		"jose:ES384", KeyType.EC, KeysetPurpose.SIGNING, JWSAlgorithm.ES384, () -> new ECKeyGenerator(Curve.P_384)
	);

	/**
	 * ECDSA using NIST P-521 and SHA-512. NIST FIPS 186-5.
	 */
	public static final JoseAlgorithm ES512 = new JoseAlgorithm(
		"jose:ES512", KeyType.EC, KeysetPurpose.SIGNING, JWSAlgorithm.ES512, () -> new ECKeyGenerator(Curve.P_521)
	);

	/* -------------------------------------------------------------------------
	 * RSA-PSS asymmetric signing algorithms (KeysetPurpose.SIGNING)
	 * ---------------------------------------------------------------------- */

	/**
	 * RSASSA-PSS using SHA-256 and MGF1 with SHA-256. NIST FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final JoseAlgorithm PS256 = new JoseAlgorithm(
		"jose:PS256", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.PS256,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS * 2)
	);

	/**
	 * RSASSA-PSS using SHA-384 and MGF1 with SHA-384. NIST FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final JoseAlgorithm PS384 = new JoseAlgorithm(
		"jose:PS384", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.PS384,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS * 2)
	);

	/**
	 * RSASSA-PSS using SHA-512 and MGF1 with SHA-512. NIST FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final JoseAlgorithm PS512 = new JoseAlgorithm(
		"jose:PS512", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.PS512,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS * 2)
	);

	/* -------------------------------------------------------------------------
	 * RSA-PKCS1 signing algorithms (KeysetPurpose.SIGNING)
	 * Included for JOSE interoperability only; disallowed for new applications
	 * by NIST SP 800-131A Rev 2. Prefer PS256/PS384/PS512 for new designs.
	 * ---------------------------------------------------------------------- */

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-256. Retained for JOSE interoperability only;
	 * new applications should use {@link #PS256} instead.
	 */
	public static final JoseAlgorithm RS256 = new JoseAlgorithm(
		"jose:RS256", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.RS256,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS)
	);

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-384. Retained for JOSE interoperability only;
	 * new applications should use {@link #PS384} instead.
	 */
	public static final JoseAlgorithm RS384 = new JoseAlgorithm(
		"jose:RS384", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.RS384,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS)
	);

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-512. Retained for JOSE interoperability only;
	 * new applications should use {@link #PS512} instead.
	 */
	public static final JoseAlgorithm RS512 = new JoseAlgorithm(
		"jose:RS512", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.RS512,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS * 2)
	);

	/* -------------------------------------------------------------------------
	 * RSA-OAEP encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * Preferred RSA key size in bits (3072), meeting NIST SP 800-131A Rev 2 guidance
	 * for keys with security lifetimes beyond 2030 (112-bit strength minimum requires 2048;
	 * 3072 provides 128-bit strength).
	 */
	private static final int PREFERRED_RSA_KEY_SIZE = 3072;

	/**
	 * RSA-OAEP with SHA-256. NIST SP 800-56B Rev 2.
	 */
	public static final JoseAlgorithm RSA_OAEP_256 = new JoseAlgorithm(
		"jose:RSA-OAEP-256", KeyType.RSA, KeysetPurpose.ENCRYPTION, JWEAlgorithm.RSA_OAEP_256,
		() -> new RSAKeyGenerator(PREFERRED_RSA_KEY_SIZE)
	);

	/**
	 * RSA-OAEP with SHA-384. NIST SP 800-56B Rev 2.
	 */
	public static final JoseAlgorithm RSA_OAEP_384 = new JoseAlgorithm(
		"jose:RSA-OAEP-384", KeyType.RSA, KeysetPurpose.ENCRYPTION, JWEAlgorithm.RSA_OAEP_384,
		() -> new RSAKeyGenerator(PREFERRED_RSA_KEY_SIZE)
	);

	/**
	 * RSA-OAEP with SHA-512. NIST SP 800-56B Rev 2.
	 */
	public static final JoseAlgorithm RSA_OAEP_512 = new JoseAlgorithm(
		"jose:RSA-OAEP-512", KeyType.RSA, KeysetPurpose.ENCRYPTION, JWEAlgorithm.RSA_OAEP_512,
		() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS * 2)
	);

	/* -------------------------------------------------------------------------
	 * AES Key Wrap encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * AES Key Wrap (RFC 3394) using 128-bit keys. NIST SP 800-38F.
	 */
	public static final JoseAlgorithm A128KW = new JoseAlgorithm(
		"jose:A128KW", KeyType.OCTET, KeysetPurpose.ENCRYPTION, JWEAlgorithm.A128KW,
		() -> new OctetSequenceKeyGenerator(128)
	);

	/**
	 * AES Key Wrap (RFC 3394) using 192-bit keys. NIST SP 800-38F.
	 */
	public static final JoseAlgorithm A192KW = new JoseAlgorithm(
		"jose:A192KW", KeyType.OCTET, KeysetPurpose.ENCRYPTION, JWEAlgorithm.A192KW,
		() -> new OctetSequenceKeyGenerator(192)
	);

	/**
	 * AES Key Wrap (RFC 3394) using 256-bit keys. NIST SP 800-38F.
	 */
	public static final JoseAlgorithm A256KW = new JoseAlgorithm(
		"jose:A256KW", KeyType.OCTET, KeysetPurpose.ENCRYPTION, JWEAlgorithm.A256KW,
		() -> new OctetSequenceKeyGenerator(256)
	);

	/* -------------------------------------------------------------------------
	 * AES-GCM Key Wrap encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * AES-GCM Key Wrap using 128-bit keys. NIST SP 800-38D.
	 */
	public static final JoseAlgorithm A128GCMKW = new JoseAlgorithm(
		"jose:A128GCMKW", KeyType.OCTET, KeysetPurpose.ENCRYPTION, JWEAlgorithm.A128GCMKW,
		() -> new OctetSequenceKeyGenerator(128)
	);

	/**
	 * AES-GCM Key Wrap using 192-bit keys. NIST SP 800-38D.
	 */
	public static final JoseAlgorithm A192GCMKW = new JoseAlgorithm(
		"jose:A192GCMKW", KeyType.OCTET, KeysetPurpose.ENCRYPTION, JWEAlgorithm.A192GCMKW,
		() -> new OctetSequenceKeyGenerator(192)
	);

	/**
	 * AES-GCM Key Wrap using 256-bit keys. NIST SP 800-38D.
	 */
	public static final JoseAlgorithm A256GCMKW = new JoseAlgorithm(
		"jose:A256GCMKW", KeyType.OCTET, KeysetPurpose.ENCRYPTION, JWEAlgorithm.A256GCMKW,
		() -> new OctetSequenceKeyGenerator(256)
	);

	/* -------------------------------------------------------------------------
	 * ECDH-ES encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * ECDH-ES using Concat KDF with the agreed-upon key as the CEK. NIST SP 800-56A Rev 3.
	 */
	public static final JoseAlgorithm ECDH_ES = new JoseAlgorithm(
		"jose:ECDH-ES", KeyType.EC, KeysetPurpose.ENCRYPTION, JWEAlgorithm.ECDH_ES,
		() -> new ECKeyGenerator(Curve.P_256)
	);

	/**
	 * ECDH-ES with AES-128 Key Wrap of the CEK. NIST SP 800-56A Rev 3.
	 */
	public static final JoseAlgorithm ECDH_ES_A128KW = new JoseAlgorithm(
		"jose:ECDH-ES+A128KW", KeyType.EC, KeysetPurpose.ENCRYPTION, JWEAlgorithm.ECDH_ES_A128KW,
		() -> new ECKeyGenerator(Curve.P_256)
	);

	/**
	 * ECDH-ES with AES-192 Key Wrap of the CEK. NIST SP 800-56A Rev 3.
	 */
	public static final JoseAlgorithm ECDH_ES_A192KW = new JoseAlgorithm(
		"jose:ECDH-ES+A192KW", KeyType.EC, KeysetPurpose.ENCRYPTION, JWEAlgorithm.ECDH_ES_A192KW,
		() -> new ECKeyGenerator(Curve.P_384)
	);

	/**
	 * ECDH-ES with AES-256 Key Wrap of the CEK. NIST SP 800-56A Rev 3.
	 */
	public static final JoseAlgorithm ECDH_ES_A256KW = new JoseAlgorithm(
		"jose:ECDH-ES+A256KW", KeyType.EC, KeysetPurpose.ENCRYPTION, JWEAlgorithm.ECDH_ES_A256KW,
		() -> new ECKeyGenerator(Curve.P_521)
	);

	/**
	 * List of all built-in JOSE algorithm constants that are registered automatically.
	 * <p>
	 * RSA-PKCS1v1.5 signing algorithms ({@link #RS256}, {@link #RS384}, {@link #RS512}) are
	 * intentionally excluded. They are conditionally acceptable for JOSE interoperability only
	 * (NIST SP 800-131A Rev 2) and must be opted in explicitly via {@link #LEGACY_ALGORITHMS}.
	 */
	public static final List<JoseAlgorithm> DEFAULT_ALGORITHMS = List.of(
		HS256, HS384, HS512,
		ES256, ES384, ES512,
		PS256, PS384, PS512,
		RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512,
		A128KW, A192KW, A256KW,
		A128GCMKW, A192GCMKW, A256GCMKW,
		ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW
	);

	/**
	 * RSA-PKCS1v1.5 signing algorithms retained exclusively for interoperability with external
	 * relying parties that require PKCS1v1.5 signatures (e.g. legacy JOSE / JWT consumers).
	 * <p>
	 * These algorithms are <strong>not</strong> registered automatically. They must be explicitly
	 * enabled by setting {@code konfigyr.crypto.jose.register-legacy-algorithms=true}.
	 * <p>
	 * Do not use these algorithms in new designs. Prefer {@link #PS256}, {@link #PS384},
	 * or {@link #PS512} instead (NIST SP 800-131A Rev 2).
	 */
	public static final List<JoseAlgorithm> LEGACY_ALGORITHMS = List.of(RS256, RS384, RS512);

	private final String name;
	private final KeyType type;
	private final KeysetPurpose purpose;
	private final com.nimbusds.jose.Algorithm algorithm;
	private final Supplier<JWKGenerator<? extends JWK>> generator;

	/**
	 * Creates a custom JOSE algorithm with an explicit name, key type, purpose, backing
	 * JOSE algorithm identifier, and JWK generator.
	 * <p>
	 * The {@code name} must be unique across all registered algorithms and must not change
	 * once key material has been created with this algorithm.
	 *
	 * @param name      stable unique algorithm name with {@code "jose:"} prefix, must not be blank
	 * @param type      key material type, must not be {@literal null}
	 * @param purpose   intended cryptographic purpose, must not be {@literal null}
	 * @param algorithm the backing Nimbus JOSE algorithm identifier, must not be {@literal null}
	 * @param generator JWK generator factory used to create key material, can be {@literal null}
	 */
	public JoseAlgorithm(
		String name,
		KeyType type,
		KeysetPurpose purpose,
		com.nimbusds.jose.Algorithm algorithm,
		Supplier<JWKGenerator<? extends JWK>> generator
	) {
		Assert.isTrue(name.startsWith("jose:"), "JOSE algorithm names must start with 'jose:' prefix");
		this.name = name;
		this.type = type;
		this.purpose = purpose;
		this.algorithm = algorithm;
		this.generator = generator;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public String factory() {
		return JoseKeysetFactory.NAME;
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
	 * Returns the Nimbus JOSE algorithm identifier that backs this algorithm.
	 *
	 * @return backing JOSE algorithm, never {@literal null}.
	 */
	public com.nimbusds.jose.Algorithm algorithm() {
		return algorithm;
	}

	/**
	 * Returns the JWK generator used to generate key material for this algorithm.
	 *
	 * @param <T> the JWK type produced by the generator
	 * @return JWK generator, never {@literal null}.
	 */
	@SuppressWarnings("unchecked")
	public <T extends JWK> JWKGenerator<T> generator() {
		return (JWKGenerator<T>) generator.get()
			.algorithm(algorithm)
			.keyUse(JoseUtils.resolveKeyUse(purpose))
			.keyOperations(JoseUtils.resolveKeyOperations(purpose))
			.notBeforeTime(Date.from(Instant.ofEpochSecond(System.currentTimeMillis() / 1000)));
	}

	@Override
	public String toString() {
		return name;
	}

}
