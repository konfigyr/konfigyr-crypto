package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.KeysetAssert;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(classes = TinkIntegrationConfiguration.class)
public class TinkIntegrationTest {

	static final KeysetDefinition definition = KeysetDefinition.of("test-keyset", TinkAlgorithm.AES128_GCM);

	@Autowired
	KeysetStore store;

	@Test
	@Order(1)
	@DisplayName("should retrieve configured key encryption key providers")
	void shouldRetrieveProviders() {
		assertThat(store.provider("aes-provider")).isPresent()
			.get()
			.satisfies(provider -> assertThat(provider.provide("random-kek")).isNotNull())
			.satisfies(provider -> assertThat(provider.provide("aes-kek")).isNotNull())
			.satisfies(provider -> assertThatExceptionOfType(CryptoException.KeyEncryptionKeyNotFoundException.class)
				.isThrownBy(() -> provider.provide("missing")));

		assertThat(store.provider("kms-provider")).isPresent()
			.get()
			.satisfies(provider -> assertThat(provider.provide(TinkIntegrationConfiguration.KMS_KEY_URI)).isNotNull())
			.satisfies(provider -> assertThat(provider.provide(TinkIntegrationConfiguration.ENVELOPE_KMS_KEY_URI))
				.isNotNull())
			.satisfies(provider -> assertThatExceptionOfType(CryptoException.KeyEncryptionKeyNotFoundException.class)
				.isThrownBy(() -> provider.provide("missing")));

		assertThat(store.provider("unknown-provider")).isEmpty();
	}

	@Test
	@Order(1)
	@DisplayName("should retrieve configured key encryption keys")
	void shouldRetrieveKeyEncryptionKeys() {
		assertThat(store.kek("aes-provider", "random-kek")).isNotNull();
		assertThat(store.kek("aes-provider", "aes-kek")).isNotNull();
		assertThatExceptionOfType(CryptoException.KeyEncryptionKeyNotFoundException.class)
			.isThrownBy(() -> store.kek("aes-provider", "missing"))
			.returns("aes-provider", CryptoException.ProviderException::getProvider)
			.returns("missing", CryptoException.KeyEncryptionKeyNotFoundException::getId);

		assertThat(store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI)).isNotNull();
		assertThat(store.kek("kms-provider", TinkIntegrationConfiguration.ENVELOPE_KMS_KEY_URI)).isNotNull();
		assertThatExceptionOfType(CryptoException.KeyEncryptionKeyNotFoundException.class)
			.isThrownBy(() -> store.kek("kms-provider", "missing"))
			.returns("kms-provider", CryptoException.ProviderException::getProvider)
			.returns("missing", CryptoException.KeyEncryptionKeyNotFoundException::getId);

		assertThatExceptionOfType(CryptoException.ProviderNotFoundException.class)
			.isThrownBy(() -> store.kek("unknown-provider", "random-kek"))
			.returns("unknown-provider", CryptoException.ProviderException::getProvider);
	}

	@Test
	@Order(2)
	@DisplayName("should generate keyset using supported Tink algorithm")
	void shouldGenerateKeyset() {
		KeysetAssert.assertThat(store.create("aes-provider", "aes-kek", definition))
			.isInstanceOf(TinkKeyset.class)
			.matchesDefinition(definition)
			.hasKeyEncryptionKey("aes-provider", "aes-kek")
			.assertThatKeys()
			.hasSize(1)
			.extracting(Key::getType, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(KeyType.OCTET, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(3)
	@DisplayName("should wrap and write keyset with a signing algorithm in the repository")
	void shouldWriteKeyset() {
		final var definition = KeysetDefinition.of("signing-keyset", TinkAlgorithm.ED25519);

		final var keyset = new TinkKeyset.Builder(definition)
			.keyEncryptionKey(store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI))
			.key(TinkKey.generate(KeyDefinition.of(definition), TinkUtils.generateKeyId()))
			.build();

		assertThatNoException().isThrownBy(() -> store.write(keyset));
	}

	@Test
	@Order(4)
	@DisplayName("should read and unwrap keyset from the repository")
	void shouldReadKeyset() {
		KeysetAssert.assertThat(store.read(definition.getName()))
			.isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.matchesDefinition(definition)
			.hasKeyEncryptionKey("aes-provider", "aes-kek")
			.assertThatKeys()
			.hasSize(1)
			.extracting(Key::getType, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(KeyType.OCTET, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(4)
	@DisplayName("should read keyset that uses a KMS key encryption key provider")
	void shouldReadCustomKeyset() {
		final var kek = store.kek("kms-provider", TinkIntegrationConfiguration.KMS_KEY_URI);

		KeysetAssert.assertThat(store.read("signing-keyset")).isNotNull()
			.isInstanceOf(TinkKeyset.class)
			.hasName("signing-keyset")
			.hasPurpose(KeysetPurpose.SIGNING)
			.hasKeyEncryptionKey(kek)
			.hasSize(1);
	}

	@Test
	@Order(5)
	@DisplayName("should rotate Tink keyset and store it in the repository")
	void shouldRotateKeyset() {
		final var keyset = store.read(definition.getName());

		KeysetAssert.assertThat(keyset)
			.hasSize(1);

		assertThatNoException()
			.isThrownBy(() -> store.rotate(definition.getName()));

		KeysetAssert.assertThat(store.read(definition.getName()))
			.isNotEqualTo(keyset)
			.hasSize(2)
			.assertThatKeys()
			.filteredOn(Key::isPrimary)
			.map(Key::getId)
			.isNotEqualTo(keyset.getPrimary().getId());
	}

	@Test
	@Order(6)
	@DisplayName("should rotate keyset successfully after a key has been destroyed")
	void shouldRotateAfterKeyDestruction() {
		final var keyset = store.read(definition.getName());

		KeysetAssert.assertThat(keyset).hasSize(2);

		final var oldKey = keyset.stream()
			.filter(key -> !key.isPrimary())
			.findFirst()
			.orElseThrow();

		assertThatNoException()
			.isThrownBy(() -> store.destroy(definition.getName(), oldKey.getId()));

		assertThatNoException()
			.isThrownBy(() -> store.rotate(definition.getName()));

		KeysetAssert.assertThat(store.read(definition.getName()))
			.isInstanceOf(TinkKeyset.class)
			.hasSize(2)
			.assertThatKeys()
			.filteredOn(Key::isPrimary)
			.map(Key::getId)
			.isNotEqualTo(keyset.getPrimary().getId());
	}

	@Test
	@Order(7)
	@DisplayName("should remove keyset from the repository")
	void shouldRemoveKeyset() {
		assertThatNoException().isThrownBy(() -> store.remove(definition.getName()));

		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.read(definition.getName()));
	}

}
