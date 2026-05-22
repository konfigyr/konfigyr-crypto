package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
class KeyEncryptionKeyProviderTest {

	@Test
	@DisplayName("should not create a provider with a blank name")
	void shouldNotCreateProviderWithABlankName() {
		assertThatIllegalArgumentException().isThrownBy(() -> KeyEncryptionKeyProvider.of(null));
		assertThatIllegalArgumentException().isThrownBy(() -> KeyEncryptionKeyProvider.of(""));
		assertThatIllegalArgumentException().isThrownBy(() -> KeyEncryptionKeyProvider.of("  "));
	}

	@Test
	@DisplayName("should not create a provider with no keys")
	void shouldNotCreateProviderWithNoKeys() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> KeyEncryptionKeyProvider.of("empty"));
	}

	@Test
	@DisplayName("should not create a provider when the key list contains null entries")
	void shouldNotCreateProviderWithNullKeys() {
		final var keys = new ArrayList<KeyEncryptionKey>();
		keys.add(null);

		assertThatIllegalStateException()
			.isThrownBy(() -> KeyEncryptionKeyProvider.of("provider", keys));
	}

	@Test
	@DisplayName("should not create a provider when a key belongs to a different provider")
	void shouldNotCreateProviderWithInvalidKeyProvider() {
		final var keys = new ArrayList<KeyEncryptionKey>();
		keys.add(new TestKeyEncryptionKey("kek", "other"));

		assertThatIllegalStateException()
			.isThrownBy(() -> KeyEncryptionKeyProvider.of("provider", keys));
	}

	@Test
	@DisplayName("should not create a provider with duplicate key identifiers")
	void shouldNotCreateProviderWithDuplicateKeyIdentifier() {
		final var keys = new ArrayList<KeyEncryptionKey>();
		keys.add(new TestKeyEncryptionKey("kek", "provider"));
		keys.add(new TestKeyEncryptionKey("kek", "provider"));

		assertThatIllegalStateException()
			.isThrownBy(() -> KeyEncryptionKeyProvider.of("provider", keys));
	}

	@Test
	@DisplayName("should resolve a key encryption key by its identifier")
	void shouldResolveKeyEncryptionKey() {
		final var resolver = KeyEncryptionKeyProvider.of("test-provider",
				new TestKeyEncryptionKey("first", "test-provider"),
				new TestKeyEncryptionKey("second", "test-provider"),
				new TestKeyEncryptionKey("third", "test-provider"));

		assertThat(resolver).returns("test-provider", KeyEncryptionKeyProvider::getName)
			.satisfies(it -> assertThat(it.provide("first")).isNotNull().returns("first", KeyEncryptionKey::getId))
			.satisfies(it -> assertThat(it.provide("second")).isNotNull().returns("second", KeyEncryptionKey::getId))
			.satisfies(it -> assertThat(it.provide("third")).isNotNull().returns("third", KeyEncryptionKey::getId))
			.satisfies(it -> assertThatExceptionOfType(CryptoException.KeyEncryptionKeyNotFoundException.class)
				.isThrownBy(() -> it.provide("missing"))
				.returns("test-provider", CryptoException.ProviderException::getProvider)
				.returns("missing", CryptoException.KeyEncryptionKeyNotFoundException::getId));
	}

}
