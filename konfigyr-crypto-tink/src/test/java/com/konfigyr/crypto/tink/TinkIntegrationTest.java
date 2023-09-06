package com.konfigyr.crypto.tink;

import com.google.crypto.tink.KeysetHandle;
import com.konfigyr.crypto.*;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(classes = TinkIntegrationConfiguration.class)
public class TinkIntegrationTest {

	static final KeysetDefinition definition = KeysetDefinition.of("test-keyset", TinkAlgorithm.AES128_GCM);

	@Autowired
	KeysetStore store;

	@Test
	@Order(1)
	void shouldRetrieveProviders() {
		assertThat(store.provider("aes-provider")).isPresent()
			.get()
			.satisfies(provider -> assertThat(provider.provide("random-kek")).isNotNull())
			.satisfies(provider -> assertThat(provider.provide("aes-kek")).isNotNull())
			.satisfies(provider -> assertThatThrownBy(() -> provider.provide("missing"))
				.isInstanceOf(CryptoException.KeyEncryptionKeyNotFoundException.class));

		assertThat(store.provider("kms-provider")).isPresent()
			.get()
			.satisfies(provider -> assertThat(provider.provide(TinkIntegrationConfiguration.KMS_KEY_URI)).isNotNull())
			.satisfies(provider -> assertThat(provider.provide(TinkIntegrationConfiguration.ENVELOPE_KMS_KEY_URI))
				.isNotNull())
			.satisfies(provider -> assertThatThrownBy(() -> provider.provide("missing"))
				.isInstanceOf(CryptoException.KeyEncryptionKeyNotFoundException.class));

		assertThat(store.provider("unknown-provider")).isEmpty();
	}

	@Test
	@Order(1)
	void shouldRetrieveKeyEncryptionKeys() {
		assertThat(store.kek("aes-provider", "random-kek")).isNotNull();
		assertThat(store.kek("aes-provider", "aes-kek")).isNotNull();
		assertThatThrownBy(() -> store.kek("aes-provider", "missing"))
			.isInstanceOf(CryptoException.KeyEncryptionKeyNotFoundException.class)
			.extracting("provider", "id")
			.isEqualTo(List.of("aes-provider", "missing"));

		assertThat(store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI)).isNotNull();
		assertThat(store.kek("kms-provider", TinkIntegrationConfiguration.ENVELOPE_KMS_KEY_URI)).isNotNull();
		assertThatThrownBy(() -> store.kek("kms-provider", "missing"))
			.isInstanceOf(CryptoException.KeyEncryptionKeyNotFoundException.class)
			.extracting("provider", "id")
			.isEqualTo(List.of("kms-provider", "missing"));

		assertThatThrownBy(() -> store.kek("unknown-provider", "random-kek"))
			.isInstanceOf(CryptoException.ProviderNotFoundException.class)
			.extracting("provider")
			.isEqualTo("unknown-provider");
	}

	@Test
	@Order(2)
	void shouldGenerateKeyset() {
		assertThatObject(store.create("aes-provider", "aes-kek", definition)).isInstanceOf(TinkKeyset.class)
			.returns(definition.getName(), Keyset::getName)
			.returns(definition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(store.kek("aes-provider", "aes-kek"), Keyset::getKeyEncryptionKey)
			.returns(definition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(definition.getNextRotationTime(), Keyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getKeys()).isNotNull()
				.hasSize(1)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactly(tuple(KeyType.OCTET, KeyStatus.ENABLED, true)));
	}

	@Test
	@Order(3)
	void shouldWriteKeyset() throws Exception {
		final var handle = KeysetHandle.generateNew(TinkUtils.keyTemplateForAlgorithm(TinkAlgorithm.ED25519));

		final var keyset = TinkKeyset.builder(handle)
			.name("singing-key")
			.algorithm(TinkAlgorithm.ED25519)
			.keyEncryptionKey(store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI))
			.rotationInterval(Duration.ofDays(180))
			.nextRotationTime(Instant.now().plus(Duration.ofDays(180)))
			.build();

		assertThatNoException().isThrownBy(() -> store.write(keyset));
	}

	@Test
	@Order(4)
	void shouldReadKeyset() {
		final var kek = store.kek("aes-provider", "aes-kek");

		assertThatObject(store.read(definition.getName())).isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.returns(definition.getName(), Keyset::getName)
			.returns(definition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(definition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(definition.getNextRotationTime(), Keyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.stream()).isNotNull()
				.hasSize(1)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactly(tuple(KeyType.OCTET, KeyStatus.ENABLED, true)));
	}

	@Test
	@Order(4)
	void shouldReadCustomKeyset() {
		final var kek = store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI);

		assertThatObject(store.read("singing-key")).isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.returns("singing-key", Keyset::getName)
			.returns(TinkAlgorithm.ED25519, Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(Duration.ofDays(180), Keyset::getRotationInterval)
			.returns(1, Keyset::size);
	}

	@Test
	@Order(5)
	void shouldRotateKeyset() {
		final var keyset = store.read(definition.getName());

		assertThatObject(keyset).returns(1, Keyset::size)
			.extracting("handle")
			.extracting(KeysetHandle.class::cast)
			.returns(1, KeysetHandle::size);

		assertThatNoException().isThrownBy(() -> store.rotate(definition.getName()));

		assertThatObject(store.read(definition.getName())).isNotEqualTo(keyset)
			.returns(2, Keyset::size)
			.extracting("handle")
			.extracting(KeysetHandle.class::cast)
			.returns(2, KeysetHandle::size);
	}

	@Test
	@Order(6)
	void shouldRemoveKeyset() {
		assertThatNoException().isThrownBy(() -> store.remove(definition.getName()));

		assertThatThrownBy(() -> store.read(definition.getName()))
			.isInstanceOf(CryptoException.KeysetNotFoundException.class);
	}

}
