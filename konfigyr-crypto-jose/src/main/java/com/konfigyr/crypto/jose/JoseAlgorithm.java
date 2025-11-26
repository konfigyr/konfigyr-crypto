package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetOperation;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.jspecify.annotations.NullMarked;

import java.util.Set;

/**
 * An enumeration of the cryptographic algorithms defined by the following RFCs:
 * <ul>
 *     <li>
 *         <a target="_blank" href="https://tools.ietf.org/html/rfc7518">JSON Web Algorithms (JWA)</a>
 *     </li>
 *     <li>
 *         <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption (JWE)</a>
 *     </li>
 * </ul>
 *
 * @author : Vladimir Spasic
 * @since : 24.11.25, Mon
 * @see com.nimbusds.jose.JWSAlgorithm
 * @see com.nimbusds.jose.JWEAlgorithm
 */
@NullMarked
public enum JoseAlgorithm implements Algorithm {

	/**
	 * HMAC using SHA-256.
	 */
	HS256(KeyType.OCTET, JWSAlgorithm.HS256, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * HMAC using SHA-384.
	 */
	HS384(KeyType.OCTET, JWSAlgorithm.HS384, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * HMAC using SHA-512.
	 */
	HS512(KeyType.OCTET, JWSAlgorithm.HS512, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-256. This algorithm is still widely supported but explicitly
	 * disallowed for new systems in NIST SP 800-131A.
	 */
	RS256(KeyType.RSA, JWSAlgorithm.RS256, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-384. This algorithm is still widely supported but explicitly
	 * disallowed for new systems in NIST SP 800-131A.
	 */
	RS384(KeyType.RSA, JWSAlgorithm.RS384, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-512. This algorithm is still widely supported but explicitly
	 * disallowed for new systems in NIST SP 800-131A.
	 */
	RS512(KeyType.RSA, JWSAlgorithm.RS512, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * ECDSA using P-256 and SHA-256 (Recommended+).
	 */
	ES256(KeyType.EC, JWSAlgorithm.ES256, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * ECDSA using P-384 and SHA-384.
	 */
	ES384(KeyType.EC, JWSAlgorithm.ES384, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * ECDSA using P-521 and SHA-512.
	 */
	ES512(KeyType.EC, JWSAlgorithm.ES512, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	 */
	PS256(KeyType.RSA, JWSAlgorithm.PS256, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	 */
	PS384(KeyType.RSA, JWSAlgorithm.PS384, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	 */
	PS512(KeyType.RSA, JWSAlgorithm.PS512, KeysetOperation.SIGN, KeysetOperation.VERIFY),

	/**
	 * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
	 * with the SHA-256 hash function and the MGF1 with SHA-256 mask
	 * generation function.
	 */
	RSA_OAEP_256(KeyType.RSA, JWEAlgorithm.RSA_OAEP_256, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
	 * with the SHA-512 hash function and the MGF1 with SHA-384 mask
	 * generation function.
	 */
	RSA_OAEP_384(KeyType.RSA, JWEAlgorithm.RSA_OAEP_384, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
	 * with the SHA-512 hash function and the MGF1 with SHA-512 mask
	 * generation function.
	 */
	RSA_OAEP_512(KeyType.RSA, JWEAlgorithm.RSA_OAEP_512, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) using 128-bit keys.
	 */
	A128KW(KeyType.OCTET, JWEAlgorithm.A128KW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) using 192-bit keys.
	 */
	A192KW(KeyType.OCTET, JWEAlgorithm.A192KW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) using 256-bit keys.
	 */
	A256KW(KeyType.OCTET, JWEAlgorithm.A256KW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Static (RFC 6090) key
	 * agreement using the Concat KDF, as defined in section 5.8.1 of
	 * NIST.800-56A, with the agreed-upon key being used directly as the
	 * Content Encryption Key (CEK) (rather than being used to wrap the
	 * CEK).
	 */
	ECDH_ES(KeyType.EC, JWEAlgorithm.ECDH_ES, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
	 * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
	 * Encryption Key (CEK) with the "A128KW" function (rather than being
	 * used directly as the CEK).
	 */
	ECDH_ES_A128KW(KeyType.EC, JWEAlgorithm.ECDH_ES_A128KW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
	 * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
	 * Encryption Key (CEK) with the "A192KW" function (rather than being
	 * used directly as the CEK).
	 */
	ECDH_ES_A192KW(KeyType.EC, JWEAlgorithm.ECDH_ES_A192KW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
	 * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
	 * Encryption Key (CEK) with the "A256KW" function (rather than being
	 * used directly as the CEK).
	 */
	ECDH_ES_A256KW(KeyType.EC, JWEAlgorithm.ECDH_ES_A256KW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 128-bit keys.
	 */
	A128GCMKW(KeyType.OCTET, JWEAlgorithm.A128GCMKW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 192-bit keys.
	 */
	A192GCMKW(KeyType.OCTET, JWEAlgorithm.A192GCMKW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 256-bit keys.
	 */
	A256GCMKW(KeyType.OCTET, JWEAlgorithm.A256GCMKW, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT);

	private final KeyType type;
	private final Set<KeysetOperation> operations;
	private final com.nimbusds.jose.Algorithm algorithm;

	JoseAlgorithm(KeyType type, com.nimbusds.jose.Algorithm algorithm, KeysetOperation... operations) {
		this.type = type;
		this.algorithm = algorithm;
		this.operations = Set.of(operations);
	}

	/**
	 * Method that returns the {@link com.nimbusds.jose.Algorithm JOSE Algorithm} that backs this
	 * {@link JoseAlgorithm}.
	 *
	 * @return the backing JOSE algorithm, never {@literal null}.
	 */
	public com.nimbusds.jose.Algorithm algorithm() {
		return algorithm;
	}

	@Override
	public KeyType type() {
		return type;
	}

	@Override
	public Set<KeysetOperation> operations() {
		return operations;
	}

}
