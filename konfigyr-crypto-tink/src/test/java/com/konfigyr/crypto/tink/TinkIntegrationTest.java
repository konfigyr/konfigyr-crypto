package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.KeyAssert;
import com.konfigyr.crypto.test.KeysetAssert;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

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
	@Order(5)
	@DisplayName("should not decrypt data with a disabled key after rotation")
	void shouldNotDecryptWithDisabledKey() {
		final var definition = KeysetDefinition.of("disabled-encryption-keyset", TinkAlgorithm.AES128_GCM);
		final var data = ByteArray.fromString("konfigyr-crypto-test-data");

		final var keyset = store.create("aes-provider", "aes-kek", definition);
		final var previous = keyset.getPrimary().getId();
		final var cipher = keyset.encrypt(data);

		store.rotate(definition.getName());

		assertThat(store.read(definition.getName()).decrypt(cipher))
			.as("data encrypted by the previous primary key must still decrypt after rotation")
			.isEqualTo(data);

		store.disable(definition.getName(), previous);

		final var current = store.read(definition.getName());

		assertThatExceptionOfType(CryptoException.KeysetDisabledException.class)
			.isThrownBy(() -> current.decrypt(cipher))
			.withMessageStartingWith("Key '%s' in keyset '%s'", previous, definition.getName())
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		KeysetAssert.assertThat(current)
			.hasSize(2);

		assertThat(current.decrypt(current.encrypt(data)))
			.as("the new primary key must not be affected by the disabled key")
			.isEqualTo(data);

		store.remove(definition.getName());
	}

	@Test
	@Order(5)
	@DisplayName("should not verify signatures with a compromised key after rotation")
	void shouldNotVerifyWithCompromisedKey() {
		final var definition = KeysetDefinition.of("compromised-signing-keyset", TinkAlgorithm.ED25519);
		final var data = ByteArray.fromString("konfigyr-crypto-test-data");

		final var keyset = store.create("aes-provider", "aes-kek", definition);
		final var previous = keyset.getPrimary().getId();
		final var signature = keyset.sign(data);

		store.rotate(definition.getName());

		assertThat(store.read(definition.getName()).verify(signature, data))
			.as("signature produced by the previous primary key must still verify after rotation")
			.isTrue();

		store.compromise(definition.getName(), previous);

		final var current = store.read(definition.getName());

		assertThatExceptionOfType(CryptoException.KeysetCompromisedException.class)
			.isThrownBy(() -> current.verify(signature, data))
			.withMessageStartingWith("Key '%s' in keyset '%s'", previous, definition.getName())
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		KeysetAssert.assertThat(current)
			.hasSize(2);

		assertThat(current.verify(current.sign(data), data))
			.as("the new primary key must not be affected by the compromised key")
			.isTrue();

		store.remove(definition.getName());
	}

	@Test
	@Order(5)
	@DisplayName("should read or create a keyset and use it to encrypt data, as shown in the README quick start")
	void shouldReadOrCreateKeysetAsShownInReadme() {
		final var name = "readme-documents";

		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.read(name));

		final var created = readOrCreate(name);
		final var ciphertext = created.encrypt(ByteArray.fromString("confidential"));

		final var read = readOrCreate(name);

		KeyAssert.assertThat(read.getPrimary())
			.as("the existing keyset must be read instead of being created again")
			.hasId(created.getPrimary().getId());

		assertThat(read.decrypt(ciphertext).toString(StandardCharsets.UTF_8))
			.isEqualTo("confidential");

		store.remove(name);
	}

	@Test
	@Order(5)
	@DisplayName("should create keyset with a key encryption key resolved from the store, as shown in the README")
	void shouldCreateKeysetWithResolvedKeyEncryptionKey() {
		final var kek = store.kek("aes-provider", "aes-kek");
		final var keyset = store.create(kek, KeysetDefinition.of("readme-dek", TinkAlgorithm.AES256_GCM));

		KeysetAssert.assertThat(store.read("readme-dek"))
			.hasKeyEncryptionKey(kek)
			.hasSize(1);

		store.rotate("readme-dek");

		KeysetAssert.assertThat(store.read("readme-dek"))
			.hasSize(2);

		store.remove("readme-dek");

		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.read(keyset.getName()));
	}

	@Test
	@Order(5)
	@DisplayName("should disable the previous primary key and schedule its destruction, as shown in the README")
	void shouldScheduleDestructionUsingGracePeriod() {
		final var name = "readme-lifecycle";
		final var oldKey = store.create("aes-provider", "aes-kek", KeysetDefinition.of(name, TinkAlgorithm.AES256_GCM))
			.getPrimary();

		store.rotate(name);

		// disable the old primary key after rotating to a new one
		store.disable(name, oldKey.getId());

		// schedule it for destruction using the keyset's configured grace period
		store.scheduleDestruction(name, oldKey.getId());

		KeyAssert.assertThat(store.read(name).getKey(oldKey.getId()).orElseThrow())
			.hasStatus(KeyStatus.PENDING_DESTRUCTION)
			.destructionScheduledAt(Instant.now().plus(Duration.ofDays(30)), Duration.ofMinutes(1));

		store.remove(name);
	}

	@Test
	@Order(5)
	@DisplayName("should encrypt and decrypt with associated data, as shown in the module README")
	void shouldEncryptWithAssociatedData() {
		store.create("aes-provider", "aes-kek", KeysetDefinition.of("customer-data", TinkAlgorithm.AES256_GCM));

		final Keyset keyset = store.read("customer-data");
		final ByteArray context = ByteArray.fromString("customer:42");

		final ByteArray ciphertext = keyset.encrypt(ByteArray.fromString("confidential"), context);
		final ByteArray plaintext = keyset.decrypt(ciphertext, context);

		assertThat(plaintext)
			.isEqualTo(ByteArray.fromString("confidential"));

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.as("decrypting with a different context must fail")
			.isThrownBy(() -> keyset.decrypt(ciphertext, ByteArray.fromString("customer:43")));

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.as("decrypting without a context must fail")
			.isThrownBy(() -> keyset.decrypt(ciphertext));

		store.remove("customer-data");
	}

	@Test
	@Order(5)
	@DisplayName("should create and use a keyset with a custom Tink algorithm, as shown in the module README")
	void shouldUseCustomTinkAlgorithm() {
		final var data = ByteArray.fromString("konfigyr-crypto-test-data");
		final var keyset = store.create("aes-provider", "aes-kek",
			KeysetDefinition.of("documents", TinkIntegrationConfiguration.AES256_EAX));

		final var ciphertext = keyset.encrypt(data);
		final var read = store.read("documents");

		KeyAssert.assertThat(read.getPrimary())
			.hasAlgorithm(TinkIntegrationConfiguration.AES256_EAX);

		assertThat(read.decrypt(ciphertext))
			.isEqualTo(data);

		store.remove("documents");
	}

	@Test
	@Order(5)
	@DisplayName("should create and read keyset wrapped by an envelope KMS key encryption key")
	void shouldUseEnvelopeKmsKeyEncryptionKey() {
		final var data = ByteArray.fromString("konfigyr-crypto-test-data");
		final var keyset = store.create("kms-provider", TinkIntegrationConfiguration.ENVELOPE_KMS_KEY_URI,
			KeysetDefinition.of("envelope-keyset", TinkAlgorithm.AES256_GCM));

		final var ciphertext = keyset.encrypt(data);

		KeysetAssert.assertThat(store.read("envelope-keyset"))
			.hasKeyEncryptionKey("kms-provider", TinkIntegrationConfiguration.ENVELOPE_KMS_KEY_URI);

		assertThat(store.read("envelope-keyset").decrypt(ciphertext))
			.isEqualTo(data);

		store.remove("envelope-keyset");
	}

	private Keyset readOrCreate(String name) {
		try {
			return store.read(name);
		} catch (CryptoException.KeysetNotFoundException ex) {
			return store.create("aes-provider", "aes-kek", KeysetDefinition.of(name, TinkAlgorithm.AES256_GCM));
		}
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
			.isThrownBy(() -> store.disable(definition.getName(), oldKey.getId()));

		assertThatNoException()
			.isThrownBy(() -> store.scheduleDestruction(definition.getName(), oldKey.getId(),
				Instant.now().plus(Duration.ofDays(1))));

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
