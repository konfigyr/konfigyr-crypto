package com.konfigyr.crypto.tink;

import com.google.crypto.tink.KeysetHandle;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetStore;
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
		assertThatNoException().isThrownBy(() -> store.create("aes-provider", "aes-kek", definition));
	}

	@Test
	@Order(3)
	void shouldWriteKeyset() throws Exception {
		final var keyset = TinkKeyset.builder()
			.name("singing-key")
			.algorithm(TinkAlgorithm.ED25519)
			.keyEncryptionKey(store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI))
			.rotationInterval(Duration.ofDays(180))
			.nextRotationTime(Instant.now().plus(Duration.ofDays(180)))
			.handle(KeysetHandle.generateNew(TinkUtils.keyTemplateForAlgorithm(TinkAlgorithm.ED25519)))
			.build();

		assertThatNoException().isThrownBy(() -> store.write(keyset));
	}

	@Test
	@Order(4)
	void shouldReadKeyset() {
		final var kek = store.kek("aes-provider", "aes-kek");

		assertThat(store.read(definition.getName())).isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.returns(definition.getName(), Keyset::getName)
			.returns(definition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(definition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(definition.getNextRotationTime(), Keyset::getNextRotationTime);
	}

	@Test
	@Order(4)
	void shouldReadCustomKeyset() {
		final var kek = store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI);

		assertThat(store.read("singing-key")).isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.returns("singing-key", Keyset::getName)
			.returns(TinkAlgorithm.ED25519, Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(Duration.ofDays(180), Keyset::getRotationInterval);
	}

	@Test
	@Order(5)
	void shouldRotateKeyset() {
		final var keyset = store.read(definition.getName());

		assertThat(keyset).extracting("handle").extracting(KeysetHandle.class::cast).returns(1, KeysetHandle::size);

		assertThatNoException().isThrownBy(() -> store.rotate(definition.getName()));

		assertThat(store.read(definition.getName())).isNotEqualTo(keyset)
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
