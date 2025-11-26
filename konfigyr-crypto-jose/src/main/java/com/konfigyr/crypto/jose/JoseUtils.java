package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetOperation;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

final class JoseUtils {

	static JWKGenerator<? extends JWK> generatorForDefinition(KeysetDefinition definition) {
		Assert.isInstanceOf(JoseAlgorithm.class, definition.getAlgorithm());

		final JoseAlgorithm algorithm = (JoseAlgorithm) definition.getAlgorithm();

		final JWKGenerator<?> generator =  switch (algorithm.type()) {
			case RSA -> rsaKeyGenerator(algorithm);
			case EC -> ecKeyGenerator(algorithm);
			case OCTET -> octetKeyGenerator(algorithm);
		};

		if (generator == null) {
			throw new CryptoException.UnsupportedAlgorithmException(algorithm);
		}

		final long epochSeconds = System.currentTimeMillis() / 1000;

		return generator
			.keyID(UUID.randomUUID().toString())
			.algorithm(algorithm.algorithm())
			.keyUse(resolveKeyUse(algorithm))
			.keyOperations(resolveKeyOperations(algorithm))
			.notBeforeTime(Date.from(Instant.ofEpochSecond(epochSeconds)));
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

	private static RSAKeyGenerator rsaKeyGenerator(JoseAlgorithm algorithm) {
		return switch (algorithm) {
			case RS512, PS512 -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS * 2, false);
			default -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS, false);
		};
	}

	private static ECKeyGenerator ecKeyGenerator(JoseAlgorithm algorithm) {
		return switch (algorithm) {
			case ES384 -> new ECKeyGenerator(Curve.P_384);
			case ES512 -> new ECKeyGenerator(Curve.P_521);
			default-> new ECKeyGenerator(Curve.P_256);
		};
	}

	private static OctetSequenceKeyGenerator octetKeyGenerator(JoseAlgorithm algorithm) {
		return switch (algorithm) {
			case A128KW, A128GCMKW -> new OctetSequenceKeyGenerator(128);
			case A192KW, A192GCMKW -> new OctetSequenceKeyGenerator(192);
			case A256KW, A256GCMKW, HS256 -> new OctetSequenceKeyGenerator(256);
			case HS384 -> new OctetSequenceKeyGenerator(384);
			case HS512 -> new OctetSequenceKeyGenerator(512);
			default -> null;
		};
	}

	private static KeyUse resolveKeyUse(JoseAlgorithm algorithm) {
		if (algorithm.supports(KeysetOperation.SIGN) || algorithm.supports(KeysetOperation.VERIFY)) {
			return KeyUse.SIGNATURE;
		}

		if (algorithm.supports(KeysetOperation.ENCRYPT) || algorithm.supports(KeysetOperation.DECRYPT)) {
			return KeyUse.ENCRYPTION;
		}

		throw new IllegalStateException("Could not resolve JWK usage for algorithm: " + algorithm);
	}

	private static Set<KeyOperation> resolveKeyOperations(JoseAlgorithm algorithm) {
		return algorithm.operations().stream().map(operation -> switch (operation) {
			case SIGN -> KeyOperation.SIGN;
			case VERIFY -> KeyOperation.VERIFY;
			case ENCRYPT -> KeyOperation.ENCRYPT;
			case DECRYPT -> KeyOperation.DECRYPT;
		}).collect(Collectors.toUnmodifiableSet());
	}

}
