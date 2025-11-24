package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@AutoConfigureTestDatabase
@SpringBootTest(classes = JdbcKeysetRepositoryTest.Config.class)
class JdbcKeysetRepositoryTest {

	private static final KeysetDefinition definition = KeysetDefinition.of("test", TestAlgorithm.ENCRYPTION,
			Duration.ofDays(180), Instant.ofEpochMilli(System.currentTimeMillis()));

	@Autowired
	KeysetRepository repository;

	@Test
	@DisplayName("should manage Keysets in a database")
	void shouldManageKeysets() throws IOException {
		assertThat(repository.read(definition.getName())).isEmpty();

		var keyset = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("encrypted key material"));

		assertThatNoException().isThrownBy(() -> repository.write(keyset));

		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(keyset);

		final var updated = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(ByteArray.fromString("updated key material"));

		assertThatNoException().isThrownBy(() -> repository.write(updated));

		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(updated);

		assertThatNoException().isThrownBy(() -> repository.remove(updated.getName()));

		assertThat(repository.read(definition.getName())).isEmpty();
	}

	@SpringBootApplication
	static class Config {

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
