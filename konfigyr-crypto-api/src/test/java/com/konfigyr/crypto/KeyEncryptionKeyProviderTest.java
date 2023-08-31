package com.konfigyr.crypto;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author : vladimir.spasic@ebf.com
 * @since : 31.08.23, Thu
 **/
class KeyEncryptionKeyProviderTest {

	@Test
	void shouldNotCreateProviderWithABlankName() {
		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of("")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of("  ")).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void shouldNotCreateProviderWithNoKeys() {
		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of("empty")).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void shouldNotCreateProviderWithNullKeys() {
		final var keys = new ArrayList<KeyEncryptionKey>();
		keys.add(null);

		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of("provider", keys))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void shouldNotCreateProviderWithInvalidKeyProvider() {
		final var keys = new ArrayList<KeyEncryptionKey>();
		keys.add(mockKey("other", "kek"));

		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of("provider", keys))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void shouldNotCreateProviderWithDuplicateKeyIdentifier() {
		final var keys = new ArrayList<KeyEncryptionKey>();
		keys.add(mockKey("provider", "kek"));
		keys.add(mockKey("provider", "kek"));

		assertThatThrownBy(() -> KeyEncryptionKeyProvider.of("provider", keys))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void shouldResolveKeyEncryptionKey() {
		final var resolver = KeyEncryptionKeyProvider.of("test-provider", mockKey("test-provider", "first"),
				mockKey("test-provider", "second"), mockKey("test-provider", "third"));

		assertThat(resolver).returns("test-provider", KeyEncryptionKeyProvider::getName)
			.satisfies(it -> assertThat(it.provide("first")).isNotNull().returns("first", KeyEncryptionKey::getId))
			.satisfies(it -> assertThat(it.provide("second")).isNotNull().returns("second", KeyEncryptionKey::getId))
			.satisfies(it -> assertThat(it.provide("third")).isNotNull().returns("third", KeyEncryptionKey::getId))
			.satisfies(it -> assertThatThrownBy(() -> it.provide("missing"))
				.isInstanceOf(CryptoException.KeyEncryptionKeyNotFoundException.class)
				.extracting("provider", "id")
				.containsExactly("test-provider", "missing"));
	}

	private static KeyEncryptionKey mockKey(String provider, String id) {
		final var key = Mockito.mock(KeyEncryptionKey.class);
		doReturn(provider).when(key).getProvider();
		doReturn(id).when(key).getId();
		return key;
	}

}