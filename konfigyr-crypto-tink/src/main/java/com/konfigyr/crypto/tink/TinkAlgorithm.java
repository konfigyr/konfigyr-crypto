package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetOperation;
import org.jspecify.annotations.NonNull;

import java.util.Set;

/**
 * Collection of {@link com.konfigyr.crypto.Algorithm algorithm} that are supported by
 * <a href="https://developers.google.com/tink/">Google Tink</a> library.
 *
 * @author : Vladimir Spasic
 * @since : 25.08.23, Fri
 * @see <a href="https://developers.google.com/tink/supported-key-types">Tink - Supported
 * Key Types</a>
 **/
public enum TinkAlgorithm implements Algorithm {

	/* AES Algorithms */

	/**
	 * Algorithm that uses AES-GCM cipher with a 16 bytes long secret key and random IVs.
	 */
	AES128_GCM(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Algorithm that uses AES-GCM cipher with a 32 bytes long secret key and random IVs.
	 */
	AES256_GCM(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Algorithm that uses AES cipher using EAX mode with a 16 bytes long secret key and
	 * random nonce.
	 */
	AES128_EAX(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Algorithm that uses AES cipher using EAX mode with a 32 bytes long secret key and
	 * random nonce.
	 */
	AES256_EAX(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Algorithm performs an encrypt-then-authenticate operation. Encryption is preformed
	 * using the AES counter mode with a 16 bytes long secret key and HMAC-SHA message
	 * authentication code (MAC).
	 */
	AES128_CTR_HMAC_SHA256(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Algorithm performs an encrypt-then-authenticate operation. Encryption is preformed
	 * using the AES counter mode with a 32 bytes long secret key and HMAC-SHA message
	 * authentication code (MAC).
	 */
	AES256_CTR_HMAC_SHA256(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/* Hybrid Public Keys */

	/**
	 * Encryption algorithm using Diffie-Hellman based key encapsulation mechanism
	 * (DH-KEM) with X25519 elliptic curve key agreement, SHA256 key derivation that would
	 * use the {@link TinkAlgorithm#AES128_GCM} to perform AEAD encryption.
	 */
	DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Encryption algorithm using Diffie-Hellman based key encapsulation mechanism
	 * (DH-KEM) with X25519 elliptic curve key agreement, SHA256 key derivation that would
	 * use the {@link TinkAlgorithm#AES256_GCM} to perform AEAD encryption.
	 */
	DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Encryption algorithm using Diffie-Hellman based key encapsulation mechanism
	 * (DH-KEM) with NIST P-256 elliptic curve key agreement, SHA256 key derivation that
	 * would use the {@link TinkAlgorithm#AES128_GCM} to perform AEAD encryption.
	 */
	DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * Encryption algorithm using Diffie-Hellman based key encapsulation mechanism
	 * (DH-KEM) NIST P-256 elliptic curve key agreement, SHA256 key derivation that would
	 * use the {@link TinkAlgorithm#AES256_GCM} to perform AEAD encryption.
	 */
	DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * ECIES encryption algorithm with HKDF-KEM (key encapsulation mechanism) and AEAD-DEM
	 * (data encapsulation mechanism) using the {@link TinkAlgorithm#AES128_GCM}
	 * algorithm.
	 */
	ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * ECIES encryption algorithm with HKDF-KEM (key encapsulation mechanism) and AEAD-DEM
	 * (data encapsulation mechanism) using the
	 * {@link TinkAlgorithm#AES128_CTR_HMAC_SHA256} algorithm.
	 */
	ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/* Signing Algorithms */

	/**
	 * Elliptic curve signing algorithm using NIST P-256.
	 */
	ECDSA_P256(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * Elliptic curve signing algorithm using NIST P-384.
	 */
	ECDSA_P384(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * Elliptic curve signing algorithm using NIST P-521.
	 */
	ECDSA_P521(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * Elliptic curve signing algorithm using EdDSA and Curve25519
	 */
	ED25519(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * RSA signing algorithm using Probabilistic Signature Scheme (PSS) with SHA256
	 * signature hash and 3072 RSA modulus size.
	 */
	RSA_SSA_PSS_3072_SHA256_SHA256_32_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * RSA signing algorithm using Probabilistic Signature Scheme (PSS) with SHA512
	 * signature hash and 4096 RSA modulus size.
	 */
	RSA_SSA_PSS_4096_SHA512_SHA512_64_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * RSA signing algorithm using PKCS1 (RFC 3447) padding scheme with SHA256 signature
	 * hash and 3072 RSA modulus size.
	 */
	RSA_SSA_PKCS1_3072_SHA256_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	/**
	 * RSA signing algorithm using PKCS1 (RFC 3447) padding scheme with SHA512 signature
	 * hash and 4096 RSA modulus size.
	 */
	RSA_SSA_PKCS1_4096_SHA512_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY);

	private final KeyType type;

	private final Set<KeysetOperation> operations;

	TinkAlgorithm(KeyType type, KeysetOperation... operations) {
		this.type = type;
		this.operations = Set.of(operations);
	}

	@NonNull
	@Override
	public KeyType type() {
		return type;
	}

	@NonNull
	@Override
	public Set<KeysetOperation> operations() {
		return operations;
	}

}
