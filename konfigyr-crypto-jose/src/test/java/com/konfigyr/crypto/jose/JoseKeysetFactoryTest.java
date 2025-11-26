package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.shaded.gson.JsonSyntaxException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

class JoseKeysetFactoryTest extends AbstractCryptoTest {

	@EnumSource(JoseAlgorithm.class)
	@ParameterizedTest(name = "algorithm: {0}")
	@DisplayName("should support every defined JOSE Algorithm")
	void shouldSupportJoseAlgorithm(JoseAlgorithm algorithm) {
		assertThat(factory.supports(KeysetDefinition.of("test", algorithm))).isTrue();
	}

	@EnumSource(JoseAlgorithm.class)
	@ParameterizedTest(name = "algorithm: {0}")
	@DisplayName("should support every defined JOSE Algorithm from encrypted keyset")
	void shouldSupportJoseAlgorithmEncryptedKeysets(JoseAlgorithm algorithm) {
		final var keyset = EncryptedKeyset.builder(KeysetDefinition.of("test", algorithm))
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("Encrypted keyset"));

		assertThat(factory.supports(keyset)).isTrue();
	}

	@Test
	@DisplayName("should not support encrypted keyset that does not use JOSE Algorithm")
	void shouldNotSupportJoseAlgorithmEncryptedKeysets() {
		final var keyset = EncryptedKeyset.builder()
			.name("test")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.algorithm("unknown-algorithm")
			.rotationInterval(Duration.ofDays(90))
			.nextRotationTime(Instant.now().plus(Duration.ofDays(1)))
			.build(ByteArray.fromString("Encrypted keyset"));

		assertThat(factory.supports(keyset)).isFalse();
	}

	@Test
	@DisplayName("should create JOSE JSON web keyset instance")
	void shouldCreateKeyset() throws Exception {
		assertThatObject(generate("jose-key", JoseAlgorithm.ES256)).isNotNull()
			.isInstanceOf(JsonWebKeyset.class)
			.returns("jose-key", Keyset::getName)
			.returns(JoseAlgorithm.ES256, Keyset::getAlgorithm)
			.returns(1, Keyset::size);
	}

	@Test
	@DisplayName("should encrypt JOSE JSON web keyset instance")
	void shouldCreateEncryptedKeyset() throws Exception {
		final var keyset = generate("jose-key", JoseAlgorithm.HS256);

		assertThat(factory.create(keyset))
			.isNotNull()
			.returns("jose-key", EncryptedKeyset::getName)
			.returns(JoseAlgorithm.HS256.name(), EncryptedKeyset::getAlgorithm)
			.returns(kek.getProvider(), EncryptedKeyset::getProvider)
			.returns(kek.getId(), EncryptedKeyset::getKeyEncryptionKey)
			.returns(keyset.getRotationInterval(), EncryptedKeyset::getRotationInterval)
			.returns(keyset.getNextRotationTime(), EncryptedKeyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getData()).isNotNull());
	}

	@Test
	@DisplayName("should decrypt encrypted JOSE JSON web keyset instance")
	void shouldDecryptEncryptedKeyset() throws Exception {
		final var keyset = generate("jose-key", JoseAlgorithm.HS256);
		final var encrypted = factory.create(keyset);

		assertThat(factory.create(kek, encrypted))
			.isNotNull()
			.isEqualTo(keyset);
	}

	@Test
	@DisplayName("should fail to create JOSE JSON web keyset instance due to invalid JSON data")
	void shouldFailToCreateKeysetFromInvalidJsonData() {
		final var encrypted = EncryptedKeyset.builder()
			.name("jose-key")
			.keyEncryptionKey(kek)
			.algorithm(JoseAlgorithm.HS256)
			.rotationInterval(Duration.ofDays(1))
			.nextRotationTime(Instant.now().plus(Duration.ofDays(1)))
			.build(ByteArray.fromString("invalid json data"));

		assertThatIOException()
			.isThrownBy(() -> factory.create(kek, encrypted))
			.withMessageContaining("Fail to read encrypted JOSE keyset: jose-key")
			.withCauseInstanceOf(JsonSyntaxException.class);
	}

	@Test
	@DisplayName("should fail to create JOSE JSON web keyset instance due to invalid key data")
	void shouldFailToCreateKeysetFromInvalidKeyData() {
		final var encrypted = EncryptedKeyset.builder()
			.name("jose-key")
			.keyEncryptionKey(kek)
			.algorithm(JoseAlgorithm.HS256)
			.rotationInterval(Duration.ofDays(1))
			.nextRotationTime(Instant.now().plus(Duration.ofDays(1)))
			.build(ByteArray.fromString("[{}]"));

		assertThatIOException()
			.isThrownBy(() -> factory.create(kek, encrypted))
			.withMessageContaining("Fail to read encrypted JOSE keyset: jose-key")
			.withCauseInstanceOf(ParseException.class);
	}

}
