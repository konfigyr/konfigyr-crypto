package com.konfigyr.crypto.tink;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.hybrid.EciesAeadHkdfPrivateKeyManager;
import com.google.crypto.tink.signature.EcdsaSignKeyManager;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1SignKeyManager;
import com.google.crypto.tink.signature.RsaSsaPssSignKeyManager;
import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import lombok.EqualsAndHashCode;
import org.jspecify.annotations.NullMarked;
import org.springframework.util.Assert;

import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Collection of {@link Algorithm algorithms} supported by the
 * <a href="https://developers.google.com/tink/">Google Tink</a> library.
 * <p>
 * All built-in constants follow NIST recommendations (FIPS 186-5, SP 800-57, SP 800-38D,
 * SP 800-38A, SP 800-56A Rev 3). Algorithm names carry a {@code "tink:"} prefix to
 * identify this factory family and distinguish them from algorithms provided by other modules.
 * <p>
 * Custom Tink-based algorithms can be created by constructing an instance directly and
 * registering it via an {@link com.konfigyr.crypto.AlgorithmRegistrar} bean.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see <a href="https://developers.google.com/tink/supported-key-types">Tink - Supported Key Types</a>
 **/
@NullMarked
@EqualsAndHashCode(of = "name")
public final class TinkAlgorithm implements Algorithm {

	/* -------------------------------------------------------------------------
	 * AES symmetric encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * AES-GCM with a 128-bit key and random IVs. NIST SP 800-38D.
	 */
	public static final TinkAlgorithm AES128_GCM = new TinkAlgorithm(
		"tink:AES128_GCM", KeysetPurpose.ENCRYPTION, KeyType.OCTET, AesGcmKeyManager.aes128GcmTemplate()
	);

	/**
	 * AES-GCM with a 256-bit key and random IVs. NIST SP 800-38D.
	 */
	public static final TinkAlgorithm AES256_GCM = new TinkAlgorithm(
		"tink:AES256_GCM", KeysetPurpose.ENCRYPTION, KeyType.OCTET, AesGcmKeyManager.aes256GcmTemplate()
	);

	/**
	 * AES-128 in CTR mode with HMAC-SHA256 authentication. NIST SP 800-38A + FIPS 198-1.
	 */
	public static final TinkAlgorithm AES128_CTR_HMAC_SHA256 = new TinkAlgorithm(
		"tink:AES128_CTR_HMAC_SHA256", KeysetPurpose.ENCRYPTION, KeyType.OCTET,
		AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template()
	);

	/**
	 * AES-256 in CTR mode with HMAC-SHA256 authentication. NIST SP 800-38A + FIPS 198-1.
	 */
	public static final TinkAlgorithm AES256_CTR_HMAC_SHA256 = new TinkAlgorithm(
		"tink:AES256_CTR_HMAC_SHA256", KeysetPurpose.ENCRYPTION, KeyType.OCTET,
		AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template()
	);

	/* -------------------------------------------------------------------------
	 * Hybrid public-key encryption algorithms (KeysetPurpose.ENCRYPTION)
	 * ---------------------------------------------------------------------- */

	/**
	 * ECIES with NIST P-256, HKDF-HMAC-SHA256, and AES-128-GCM. NIST SP 800-56A Rev 3.
	 */
	public static final TinkAlgorithm ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM = new TinkAlgorithm(
		"tink:ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM", KeysetPurpose.ENCRYPTION, KeyType.EC,
		EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate()
	);

	/**
	 * ECIES with NIST P-256, HKDF-HMAC-SHA256, and AES-128-CTR-HMAC-SHA256. NIST SP 800-56A Rev 3.
	 */
	public static final TinkAlgorithm ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 = new TinkAlgorithm(
		"tink:ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256", KeysetPurpose.ENCRYPTION, KeyType.EC,
		EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128CtrHmacSha256Template()
	);

	/* -------------------------------------------------------------------------
	 * Digital signature algorithms (KeysetPurpose.SIGNING)
	 * ---------------------------------------------------------------------- */

	/**
	 * ECDSA with NIST P-256. FIPS 186-5.
	 */
	public static final TinkAlgorithm ECDSA_P256 = new TinkAlgorithm(
		"tink:ECDSA_P256", KeysetPurpose.SIGNING, KeyType.EC, EcdsaSignKeyManager.ecdsaP256Template()
	);

	/**
	 * ECDSA with NIST P-384. FIPS 186-5.
	 */
	public static final TinkAlgorithm ECDSA_P384 = new TinkAlgorithm(
		"tink:ECDSA_P384", KeysetPurpose.SIGNING, KeyType.EC, PredefinedSignatureParameters.ECDSA_P384
	);

	/**
	 * ECDSA with NIST P-521. FIPS 186-5.
	 */
	public static final TinkAlgorithm ECDSA_P521 = new TinkAlgorithm(
		"tink:ECDSA_P521", KeysetPurpose.SIGNING, KeyType.EC, PredefinedSignatureParameters.ECDSA_P521
	);

	/**
	 * EdDSA with Curve25519 (Ed25519). NIST FIPS 186-5.
	 */
	public static final TinkAlgorithm ED25519 = new TinkAlgorithm(
		"tink:ED25519", KeysetPurpose.SIGNING, KeyType.EC, Ed25519PrivateKeyManager.ed25519Template()
	);

	/**
	 * RSA-PSS with 3072-bit key, SHA-256 hash, and public exponent F4. FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final TinkAlgorithm RSA_SSA_PSS_3072_SHA256_F4 = new TinkAlgorithm(
		"tink:RSA_SSA_PSS_3072_SHA256_F4", KeysetPurpose.SIGNING, KeyType.RSA,
		RsaSsaPssSignKeyManager.rsa3072PssSha256F4Template()
	);

	/**
	 * RSA-PSS with 4096-bit key, SHA-512 hash, and public exponent F4. FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final TinkAlgorithm RSA_SSA_PSS_4096_SHA512_F4 = new TinkAlgorithm(
		"tink:RSA_SSA_PSS_4096_SHA512_F4", KeysetPurpose.SIGNING, KeyType.RSA,
		RsaSsaPssSignKeyManager.rsa4096PssSha512F4Template()
	);

	/**
	 * RSA-PKCS1 with 3072-bit key, SHA-256 hash, and public exponent F4. FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final TinkAlgorithm RSA_SSA_PKCS1_3072_SHA256_F4 = new TinkAlgorithm(
		"tink:RSA_SSA_PKCS1_3072_SHA256_F4", KeysetPurpose.SIGNING, KeyType.RSA,
		RsaSsaPkcs1SignKeyManager.rsa3072SsaPkcs1Sha256F4Template()
	);

	/**
	 * RSA-PKCS1 with 4096-bit key, SHA-512 hash, and public exponent F4. FIPS 186-5, SP 800-131A Rev 2.
	 */
	public static final TinkAlgorithm RSA_SSA_PKCS1_4096_SHA512_F4 = new TinkAlgorithm(
		"tink:RSA_SSA_PKCS1_4096_SHA512_F4", KeysetPurpose.SIGNING, KeyType.RSA,
		RsaSsaPkcs1SignKeyManager.rsa4096SsaPkcs1Sha512F4Template()
	);

	/**
	 * List of default, built-in Tink algorithms.
	 */
	public static final List<TinkAlgorithm> DEFAULT_ALGORITHMS = List.of(
		AES128_GCM, AES256_GCM, AES128_CTR_HMAC_SHA256, AES256_CTR_HMAC_SHA256,
		ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM, ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
		ECDSA_P256, ECDSA_P384, ECDSA_P521, ED25519,
		RSA_SSA_PSS_3072_SHA256_F4, RSA_SSA_PSS_4096_SHA512_F4,
		RSA_SSA_PKCS1_3072_SHA256_F4, RSA_SSA_PKCS1_4096_SHA512_F4
	);

	private final String name;
	private final KeysetPurpose purpose;
	private final KeyType type;
	private final KeyTemplate template;

	/**
	 * Creates a custom Tink algorithm with an explicit name, purpose, key type, and key parameters.
	 * <p>
	 * Use this constructor to define custom Tink-backed algorithms beyond the built-in constants.
	 * The {@code name} must be unique across all registered algorithms and must not change once
	 * key material has been created with this algorithm.
	 *
	 * @param name        unique name for the algorithm, must not be blank
	 * @param purpose     intended cryptographic purpose, must not be {@literal null}
	 * @param type        key material type, must not be {@literal null}
	 * @param parameters Tink key parameters used to create the {@link KeyTemplate}, must not be {@literal null}
	 */
	public TinkAlgorithm(String name, KeysetPurpose purpose, KeyType type, Parameters parameters) {
		this(name, purpose, type, keyTemplate(parameters));
	}

	/**
	 * Creates a custom Tink algorithm with an explicit name, purpose, key type, and key template.
	 * <p>
	 * Use this constructor to define custom Tink-backed algorithms beyond the built-in constants.
	 * The {@code name} must be unique across all registered algorithms and must not change once
	 * key material has been created with this algorithm.
	 *
	 * @param name     unique name for the algorithm, must not be blank
	 * @param purpose  intended cryptographic purpose, must not be {@literal null}
	 * @param type     key material type, must not be {@literal null}
	 * @param template Tink key template defining the key parameters, must not be {@literal null}
	 */
	public TinkAlgorithm(String name, KeysetPurpose purpose, KeyType type, KeyTemplate template) {
		Assert.isTrue(name.startsWith("tink:"), "Tink algorithm names must start with 'tink:' prefix");
		this.name = name;
		this.purpose = purpose;
		this.type = type;
		this.template = template;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public KeysetPurpose purpose() {
		return purpose;
	}

	@Override
	public KeyType type() {
		return type;
	}

	@Override
	public String factory() {
		return TinkKeysetFactory.NAME;
	}

	KeyTemplate template() {
		return template;
	}

	@Override
	public String toString() {
		return name;
	}

	private static KeyTemplate keyTemplate(Parameters parameters) {
		try {
			return KeyTemplate.createFrom(parameters);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Failed to create Tink KeyTemplate from parameters", e);
		}
	}

}
