package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetFactory;
import com.konfigyr.crypto.test.AbstractKeysetFactoryTest;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.jwk.KeyOperation;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NullMarked
class JoseKeysetFactoryTest extends AbstractKeysetFactoryTest {

	final KeysetFactory factory = AbstractCryptoTest.createFactory();

	@Override
	protected KeysetFactory factory() {
		return factory;
	}

	@Override
	protected KeysetDefinition definition() {
		return KeysetDefinition.of("test", JoseAlgorithm.A128KW);
	}

	@Override
	protected Stream<Arguments> definitions() {
		return JoseAlgorithm.DEFAULT_ALGORITHMS.stream()
			.map(algorithm -> Arguments.of(algorithm.name(), KeysetDefinition.of(algorithm.name(), algorithm)));
	}

	static Stream<Arguments> keyOperations() {
		return Stream.of(
			Arguments.of(JoseAlgorithm.ES256, Set.of(KeyOperation.SIGN, KeyOperation.VERIFY), Set.of(KeyOperation.VERIFY)),
			Arguments.of(JoseAlgorithm.A128KW, Set.of(KeyOperation.ENCRYPT, KeyOperation.DECRYPT), Set.of(KeyOperation.DECRYPT))
		);
	}

	@MethodSource("keyOperations")
	@ParameterizedTest(name = "algorithm: {0}")
	@DisplayName("should grant the promoted key all key operations and restrict the demoted key to read operations")
	void shouldUpdateKeyOperationsOnPromotion(JoseAlgorithm algorithm, Set<KeyOperation> primary,
			Set<KeyOperation> demoted) throws IOException {
		final Keyset keyset = createKeyset(KeysetDefinition.of("promotion", algorithm));
		final Key original = keyset.getPrimary();

		final Keyset prepared = keyset.rotate(KeyDefinition.builder()
			.algorithm(algorithm)
			.primary(false)
			.build());

		final Keyset promoted = decryptKeyset(encryptKeyset(prepared)).rotate();

		assertThat(promoted.getPrimary())
			.isInstanceOf(JsonWebKey.class)
			.extracting(key -> ((JsonWebKey) key).getValue().getKeyOperations())
			.as("promoted key must permit all key operations of its algorithm purpose")
			.isEqualTo(primary);

		assertThat(promoted.getKey(original.getId()))
			.get()
			.isInstanceOf(JsonWebKey.class)
			.extracting(key -> ((JsonWebKey) key).getValue().getKeyOperations())
			.as("demoted key must only permit read operations")
			.isEqualTo(demoted);
	}

	@Test
	@DisplayName("should decrypt data encrypted with empty context when empty context is provided on decrypt")
	void shouldDecryptWithEmptyContext() throws IOException {
		final Keyset keyset = createKeyset(KeysetDefinition.of("empty-ctx", JoseAlgorithm.A128KW));
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-test-data");

		final ByteArray cipher = keyset.encrypt(data, ByteArray.empty());

		assertThat(keyset.decrypt(cipher, ByteArray.empty()))
			.as("decrypt with empty context must return original plaintext when encrypted with empty context")
			.isEqualTo(data);

		assertThat(keyset.decrypt(cipher))
			.as("decrypt with null context must return original plaintext when encrypted with empty context")
			.isEqualTo(data);
	}

	@Test
	@DisplayName("should decrypt data encrypted with null context when empty context is provided on decrypt")
	void shouldDecryptNullContextWithEmptyContext() throws IOException {
		final Keyset keyset = createKeyset(KeysetDefinition.of("null-ctx", JoseAlgorithm.A128KW));
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-test-data");

		final ByteArray cipher = keyset.encrypt(data);

		assertThat(keyset.decrypt(cipher, ByteArray.empty()))
			.as("decrypt with empty context must return original plaintext when encrypted with null context")
			.isEqualTo(data);
	}

}
