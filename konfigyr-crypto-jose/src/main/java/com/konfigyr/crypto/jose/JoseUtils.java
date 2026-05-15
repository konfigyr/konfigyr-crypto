package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;

import java.util.Set;
import java.util.stream.Collectors;

final class JoseUtils {

	static KeyUse resolveKeyUse(KeysetPurpose purpose) {
		return switch (purpose) {
			case SIGNING -> KeyUse.SIGNATURE;
			case ENCRYPTION -> KeyUse.ENCRYPTION;
		};
	}

	static Set<KeyOperation> resolveKeyOperations(KeysetPurpose purpose) {
		return purpose.operations().stream().map(operation -> switch (operation) {
			case SIGN -> KeyOperation.SIGN;
			case VERIFY -> KeyOperation.VERIFY;
			case ENCRYPT -> KeyOperation.ENCRYPT;
			case DECRYPT -> KeyOperation.DECRYPT;
		}).collect(Collectors.toUnmodifiableSet());
	}

	static KeyType resolveKeyType(com.nimbusds.jose.jwk.KeyType type) {
		if (com.nimbusds.jose.jwk.KeyType.RSA.equals(type)) {
			return KeyType.RSA;
		} else if (com.nimbusds.jose.jwk.KeyType.EC.equals(type)) {
			return KeyType.EC;
		} else if (com.nimbusds.jose.jwk.KeyType.OCT.equals(type)) {
			return KeyType.OCTET;
		} else {
			throw new IllegalArgumentException("Unsupported JWK key type: " + type);
		}
	}

}
