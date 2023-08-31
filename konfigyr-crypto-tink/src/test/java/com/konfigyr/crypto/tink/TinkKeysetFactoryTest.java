package com.konfigyr.crypto.tink;

import com.google.protobuf.InvalidProtocolBufferException;
import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.lang.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

class TinkKeysetFactoryTest extends AbstractCryptoTest {

	@ParameterizedTest
	@EnumSource(TinkAlgorithm.class)
	void shouldSupportTinkAlgorithmDefinitions(TinkAlgorithm algorithm) {
		assertThat(factory.supports(KeysetDefinition.of("test", algorithm))).isTrue();
	}

	@ParameterizedTest
	@EnumSource(TinkAlgorithm.class)
	void shouldSupportTinkAlgorithmEncryptedKeysets(TinkAlgorithm algorithm) {
		final var keyset = EncryptedKeyset.builder(KeysetDefinition.of("test", algorithm))
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("Encrypted keyset"));

		assertThat(factory.supports(keyset)).isTrue();
	}

	@ParameterizedTest
	@EnumSource(TinkAlgorithm.class)
	void shouldSupportEncryptedKeysetsWithTinkAlgorithmNames(TinkAlgorithm algorithm) {
		final var keyset = EncryptedKeyset.builder()
			.name("test")
			.algorithm(algorithm.name())
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.nextRotationTime(System.currentTimeMillis())
			.build(ByteArray.fromString("Encrypted keyset"));

		assertThat(factory.supports(keyset)).isTrue();
	}

	@Test
	void shouldNotSupportDefinitionWithNonTinkAlgorithms() {
		assertThat(factory.supports(KeysetDefinition.of("test", mockAlgo("AES128_GCM", KeyType.EC)))).isFalse();

		assertThat(factory.supports(KeysetDefinition.of("test", TestAlgorithm.ENCRYPTION))).isFalse();

		assertThat(factory.supports(KeysetDefinition.of("test", TestAlgorithm.SIGNING))).isFalse();
	}

	@Test
	void shouldNotSupportEncryptedKeysetsWithNonTinkAlgorithmNames() {
		assertThat(factory.supports(EncryptedKeyset.builder(KeysetDefinition.of("test", mockAlgo("AES128", KeyType.EC)))
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("Encrypted keyset")))).isFalse();

		assertThat(factory.supports(EncryptedKeyset.builder(KeysetDefinition.of("test", TestAlgorithm.ENCRYPTION))
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("Encrypted keyset")))).isFalse();

		assertThat(factory.supports(EncryptedKeyset.builder(KeysetDefinition.of("test", TestAlgorithm.SIGNING))
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("Encrypted keyset")))).isFalse();
	}

	@Test
	void shouldCreateTinkKeyset() throws Exception {
		assertThat(generate("tink-key", TinkAlgorithm.AES128_EAX)).isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.returns("tink-key", Keyset::getName)
			.returns(TinkAlgorithm.AES128_EAX, Keyset::getAlgorithm);
	}

	@Test
	void shouldCreateEncryptedKeyset() throws Exception {
		final var keyset = generate("tink-key", TinkAlgorithm.ECDSA_P256);

		assertThat(factory.create(keyset)).isNotNull()
			.returns("tink-key", EncryptedKeyset::getName)
			.returns(TinkAlgorithm.ECDSA_P256.name(), EncryptedKeyset::getAlgorithm)
			.returns(kek.getProvider(), EncryptedKeyset::getProvider)
			.returns(kek.getId(), EncryptedKeyset::getKeyEncryptionKey)
			.returns(keyset.getRotationInterval(), EncryptedKeyset::getRotationInterval)
			.returns(keyset.getNextRotationTime(), EncryptedKeyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getData()).isNotNull());
	}

	@Test
	void shouldDecryptEncryptedKeyset() throws Exception {
		final var keyset = generate("tink-key", TinkAlgorithm.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
		final var encrypted = factory.create(keyset);

		assertThat(factory.create(keyset.getKeyEncryptionKey(), encrypted)).isNotNull().isEqualTo(keyset);
	}

	@Test
	void shouldFailToDecryptEncryptedKeyset() throws Exception {
		final var keyset = generate("tink-key", TinkAlgorithm.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
		final var kek = TinkKeyEncryptionKey.builder("test-provider").generate("test-kek");
		final var encrypted = factory.create(keyset);

		assertThatThrownBy(() -> factory.create(kek, encrypted))
			.satisfies(assertKeysetException(CryptoException.UnwrappingException.class, keyset.getName()))
			.hasRootCauseInstanceOf(GeneralSecurityException.class);
	}

	@Test
	void shouldFailToGenerateTinkKeysetForUnknownAlgorithm() {
		assertThatThrownBy(() -> generate("tink-key", mockAlgo("unknown", KeyType.EC)))
			.isInstanceOf(CryptoException.UnsupportedAlgorithmException.class)
			.hasMessageContaining("Unsupported algorithm: unknown");
	}

	@Test
	void shouldFailToEncryptKeyset() throws IOException {
		final var kek = mock(KeyEncryptionKey.class);
		final var keyset = factory.create(kek, KeysetDefinition.of("failing-key", TinkAlgorithm.AES128_GCM));

		doThrow(IOException.class).when(kek).wrap(any());

		assertThatThrownBy(() -> factory.create(keyset))
			.satisfies(assertKeysetException(CryptoException.WrappingException.class, keyset.getName()))
			.hasRootCauseInstanceOf(IOException.class);
	}

	@Test
	void shouldFailToEncryptUnsupportedKeysets() {
		final var keyset = mock(Keyset.class);

		assertThatThrownBy(() -> factory.create(keyset)).isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("This keyset factory only supports Tink keysets");
	}

	@Test
	void shouldFailToDecryptCorruptedKeyset() {
		final var keyset = EncryptedKeyset.builder(KeysetDefinition.of("test", TinkAlgorithm.AES128_GCM))
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("Encrypted keyset"));

		assertThatThrownBy(() -> factory.create(kek, keyset)).isInstanceOf(InvalidProtocolBufferException.class);
	}

	enum TestAlgorithm implements Algorithm {

		ENCRYPTION, SIGNING;

		@NonNull
		@Override
		public KeyType type() {
			return KeyType.OCTET;
		}

		@NonNull
		@Override
		public Set<KeysetOperation> operations() {
			return Set.of(KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT);
		}

	}

}