package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeysetPurpose;
import com.konfigyr.io.ByteArray;
import com.konfigyr.io.ByteArrayCodec;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@NullMarked
final class JoseUtils {

	static final String AAD_HEADER_NAME = "ext-aad";

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

	static JWEHeader createEncryptionHeader(JsonWebKey key, @Nullable ByteArray aad) {
		final JoseAlgorithm algorithm = key.getAlgorithm();

		Assert.isTrue(KeysetPurpose.ENCRYPTION == algorithm.purpose(),
			() -> "The supplied must have encryption Keyset purpose, but was: " + algorithm.purpose());

		final JWEHeader.Builder header = new JWEHeader.Builder(
			(JWEAlgorithm) algorithm.algorithm(),
			EncryptionMethod.A256GCM
		).keyID(key.getId());

		if (aad != null && !aad.isEmpty()) {
			header.customParam(AAD_HEADER_NAME, aad.encode(ByteArrayCodec.BASE64_URL_SAFE_NO_PADDING));
		}

		return header.build();
	}

	@Nullable
	static ByteArray resolveAdditionalAuthenticationData(Header header) {
		final Object value = header.getCustomParam(AAD_HEADER_NAME);

		if (value == null) {
			return null;
		}

		return ByteArray.decode(value.toString(), ByteArrayCodec.BASE64_URL_SAFE_NO_PADDING);
	}

	static String generateKeyId() {
		return UUID.randomUUID().toString();
	}

}
