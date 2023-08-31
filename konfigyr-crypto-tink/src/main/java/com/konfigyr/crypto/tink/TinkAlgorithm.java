package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetOperation;
import org.springframework.lang.NonNull;

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
	AES128_GCM(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	AES256_GCM(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	AES128_EAX(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	AES128_CTR_HMAC_SHA256(KeyType.OCTET, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/* Hybrid Public Keys */
	DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),
	ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256(KeyType.EC, KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/* Signing Algorithms */
	ECDSA_P256(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	ECDSA_P384(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	ECDSA_P521(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	ED25519(KeyType.EC, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	RSA_SSA_PSS_3072_SHA256_SHA256_32_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	RSA_SSA_PSS_4096_SHA512_SHA512_64_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY),
	RSA_SSA_PKCS1_3072_SHA256_F4(KeyType.RSA, KeysetOperation.SIGN, KeysetOperation.VERIFY),
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
