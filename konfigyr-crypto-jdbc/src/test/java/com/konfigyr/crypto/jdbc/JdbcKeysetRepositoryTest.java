package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.TestAlgorithm;
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
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@AutoConfigureTestDatabase
@SpringBootTest(classes = JdbcKeysetRepositoryTest.Config.class)
class JdbcKeysetRepositoryTest {

	private static final KeysetDefinition definition = KeysetDefinition.builder()
		.name("test")
		.algorithm(TestAlgorithm.INSTANCE)
		.rotationInterval(Duration.ofDays(180))
		.destructionGracePeriod(Duration.ofDays(30))
		.build();

	@Autowired
	KeysetRepository repository;

	@Test
	@DisplayName("should manage Keysets in a database")
	void shouldManageKeysets() throws IOException {
		assertThat(repository.read(definition.getName())).isEmpty();

		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);

		// --- initial write: one key ---
		final EncryptedKey primaryKey = encryptedKey("key-1", true, t0, ByteArray.fromString("encrypted key material"));
		final EncryptedKeyset keyset = encryptedKeyset(primaryKey);

		assertThatNoException().isThrownBy(() -> repository.write(keyset));
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(keyset);

		// --- update: rotate primary, keep key-1 unchanged, add key-2 ---
		final Instant t1 = t0.plusSeconds(1);
		final EncryptedKey demotedKey = encryptedKey("key-1", false, t0, ByteArray.fromString("encrypted key material"));
		final EncryptedKey newPrimary = encryptedKey("key-2", true, t1, ByteArray.fromString("rotated key material"));

		final EncryptedKeyset rotated = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(demotedKey, newPrimary);

		assertThatNoException().isThrownBy(() -> repository.write(rotated));
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(rotated);

		// --- second update: drop demoted key-1, leaving only key-2 — exercises single-key DELETE ---
		final EncryptedKeyset pruned = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(newPrimary);

		assertThatNoException().isThrownBy(() -> repository.write(pruned));
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(pruned);

		// --- third update: only metadata changes, key-2 identical — no key rows touched ---
		final EncryptedKeyset metadataOnly = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("updated-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(newPrimary);

		assertThatNoException().isThrownBy(() -> repository.write(metadataOnly));
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(metadataOnly);

		// --- remove ---
		assertThatNoException().isThrownBy(() -> repository.remove(metadataOnly.getName()));
		assertThat(repository.read(definition.getName())).isEmpty();
	}

	@NonNull
	private static EncryptedKeyset encryptedKeyset(EncryptedKey... keys) {
		return EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(keys);
	}

	@NonNull
	private static EncryptedKey encryptedKey(String id, boolean primary, Instant createdAt, ByteArray data) {
		return EncryptedKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE.name())
			.type(TestAlgorithm.INSTANCE.type())
			.status(KeyStatus.ENABLED)
			.primary(primary)
			.createdAt(createdAt)
			.build(data);
	}

	@SpringBootApplication
	static class Config {

	}

}
