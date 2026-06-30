package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.io.ByteArray;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionOperations;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

	@Autowired
	JdbcOperations jdbcOperations;

	@Autowired
	TransactionOperations transactionOperations;

	@Test
	@DisplayName("should manage Keysets in a database")
	void shouldManageKeysets() throws IOException {
		assertThat(repository.read(definition.getName())).isEmpty();

		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);

		// --- initial write: one key ---
		final EncryptedKey primaryKey = encryptedKey("key-1", true, t0, ByteArray.fromString("encrypted key material"));
		final EncryptedKeyset keyset = encryptedKeyset(primaryKey);

		EncryptedKeyset written = repository.write(keyset);
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(keyset);

		// --- update: rotate primary, keep key-1 unchanged, add key-2 ---
		final Instant t1 = t0.plusSeconds(1);
		final EncryptedKey demotedKey = encryptedKey("key-1", false, t0, ByteArray.fromString("encrypted key material"));
		final EncryptedKey newPrimary = encryptedKey("key-2", true, t1, ByteArray.fromString("rotated key material"));

		final EncryptedKeyset rotated = EncryptedKeyset.builder(written)
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(demotedKey, newPrimary);

		written = repository.write(rotated);
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(rotated);

		// --- second update: drop demoted key-1, leaving only key-2 — exercises single-key DELETE ---
		final EncryptedKeyset pruned = EncryptedKeyset.builder(written)
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(newPrimary);

		written = repository.write(pruned);
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(pruned);

		// --- third update: only metadata changes, key-2 identical — no key rows touched ---
		final EncryptedKeyset metadataOnly = EncryptedKeyset.builder(written)
			.keyEncryptionKey("updated-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(newPrimary);

		repository.write(metadataOnly);
		assertThat(repository.read(definition.getName())).isNotEmpty().hasValue(metadataOnly);

		// --- remove ---
		repository.remove(metadataOnly.name());
		assertThat(repository.read(definition.getName())).isEmpty();
	}

	@Test
	@DisplayName("should update key status without altering key data")
	void shouldUpdateKeyStatus() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey key = encryptedKey("key-1", true, t0, ByteArray.fromString("secret"));
		final EncryptedKeyset stored = repository.write(encryptedKeyset("lifecycle-status", key));

		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.disable(stored, "key-1")));

		assertThat(repository.read("lifecycle-status"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.status()).isEqualTo(KeyStatus.DISABLED);
						assertThat(k.data()).isNotNull();
					})
			);

		repository.remove("lifecycle-status");
	}

	@Test
	@DisplayName("should erase key data and set destroyed-at when key is destroyed")
	void shouldDestroyKeyAndEraseData() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final Instant scheduled = t0.minus(Duration.ofDays(1));
		final EncryptedKey key = EncryptedKey.builder()
			.id("key-1")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.PENDING_DESTRUCTION)
			.primary(true)
			.createdAt(t0)
			.destructionScheduledAt(scheduled)
			.build(ByteArray.fromString("secret"));
		final EncryptedKeyset stored = repository.write(encryptedKeyset("lifecycle-destroy", key));

		final Instant destroyedAt = t0.plusSeconds(1);
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.destroy(stored, "key-1", destroyedAt)));

		assertThat(repository.read("lifecycle-destroy"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.status()).isEqualTo(KeyStatus.DESTROYED);
						assertThat(k.data()).isNull();
						assertThat(k.destroyedAt()).isEqualTo(destroyedAt);
					})
			);

		repository.remove("lifecycle-destroy");
	}

	@Test
	@DisplayName("should return only keys whose scheduled destruction time has elapsed")
	void shouldFindKeysPendingDestruction() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final Instant pastSchedule = t0.minus(Duration.ofDays(1));
		final Instant futureSchedule = t0.plus(Duration.ofDays(7));

		final EncryptedKey pastKey = EncryptedKey.builder()
			.id("past-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.PENDING_DESTRUCTION)
			.primary(true)
			.createdAt(t0)
			.destructionScheduledAt(pastSchedule)
			.build(ByteArray.fromString("secret"));

		final EncryptedKey futureKey = EncryptedKey.builder()
			.id("future-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.PENDING_DESTRUCTION)
			.primary(false)
			.createdAt(t0)
			.destructionScheduledAt(futureSchedule)
			.build(ByteArray.fromString("secret"));

		repository.write(encryptedKeyset("lifecycle-pending", pastKey, futureKey));

		final var results = repository.findPendingDestruction();

		assertThat(results)
			.hasSize(1)
			.first()
			.returns("lifecycle-pending", EncryptedKeyset::name)
			.extracting(EncryptedKeyset::keys, InstanceOfAssertFactories.iterable(EncryptedKey.class))
			.hasSize(1)
			.first()
			.returns("past-key", EncryptedKey::id);

		repository.remove("lifecycle-pending");
	}

	@Test
	@DisplayName("should return empty list when no keys have an elapsed destruction schedule")
	void shouldNotFindFutureScheduledKeys() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey futureKey = EncryptedKey.builder()
			.id("future-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.PENDING_DESTRUCTION)
			.primary(true)
			.createdAt(t0)
			.destructionScheduledAt(t0.plus(Duration.ofDays(30)))
			.build(ByteArray.fromString("secret"));

		repository.write(encryptedKeyset("lifecycle-future", futureKey));

		assertThat(repository.findPendingDestruction())
			.extracting(EncryptedKeyset::name)
			.doesNotContain("lifecycle-future");

		repository.remove("lifecycle-future");
	}

	@Test
	@DisplayName("should return keysets whose primary key expiry time has elapsed")
	void shouldFindKeysetsPendingRotation() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final Instant pastExpiry = t0.minus(Duration.ofDays(1));
		final EncryptedKey primaryKey = EncryptedKey.builder()
			.id("pk-expired")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(pastExpiry.minus(Duration.ofDays(90)))
			.expiresAt(pastExpiry)
			.build(ByteArray.fromString("enc-key-material"));

		repository.write(encryptedKeyset("rotation-due", primaryKey));

		final var results = repository.findPendingRotation();

		assertThat(results)
			.extracting(EncryptedKeyset::name)
			.contains("rotation-due");
		assertThat(results)
			.filteredOn(ks -> "rotation-due".equals(ks.name()))
			.first()
			.extracting(EncryptedKeyset::keys)
			.isEqualTo(List.of());

		repository.remove("rotation-due");
	}

	@Test
	@DisplayName("should not return keysets whose primary key expiry time is in the future")
	void shouldNotFindKeysetsPendingRotationIfNotDue() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final Instant futureExpiry = t0.plus(Duration.ofDays(30));
		final EncryptedKey primaryKey = EncryptedKey.builder()
			.id("pk-fresh")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(t0)
			.expiresAt(futureExpiry)
			.build(ByteArray.fromString("enc-material"));

		repository.write(encryptedKeyset("rotation-not-due", primaryKey));

		assertThat(repository.findPendingRotation())
			.extracting(EncryptedKeyset::name)
			.doesNotContain("rotation-not-due");

		repository.remove("rotation-not-due");
	}

	@NonNull
	private static EncryptedKeyset encryptedKeyset(String name, EncryptedKey... keys) {
		return EncryptedKeyset.builder()
			.name(name)
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory(TestAlgorithm.INSTANCE.factory())
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(180))
			.destructionGracePeriod(Duration.ofDays(30))
			.build(keys);
	}

	@NonNull
	private static EncryptedKeyset encryptedKeyset(EncryptedKey... keys) {
		return encryptedKeyset(definition.getName(), keys);
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

	@Test
	@DisplayName("should preserve key rows with null data when writing a keyset that no longer includes them")
	void shouldPreserveNullDataKeyRowsOnWrite() throws IOException {
		final Instant instant = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final Instant destroyedAt = instant.plusSeconds(1);

		final EncryptedKey primaryKey = encryptedKey("primary-key", true, instant, ByteArray.fromString("primary material"));
		final EncryptedKey oldKey = encryptedKey("old-key", false, instant, ByteArray.fromString("old material"));
		final EncryptedKeyset written = repository.write(encryptedKeyset("keyset", primaryKey, oldKey));

		repository.updateKeyStatus(KeyTransition.destroy(written, "old-key", destroyedAt));

		// Simulate the factory skipping the DESTROYED key: read the current state (version bumped
		// by updateKeyStatus), then write a keyset containing only the primary key.
		final EncryptedKeyset current = repository.read("keyset").orElseThrow();
		repository.write(EncryptedKeyset.builder(current).build(primaryKey));

		final var stored = repository.read("keyset").orElseThrow();

		assertThat(stored.getKey("old-key"))
			.isPresent()
			.hasValueSatisfying(key -> {
				assertThat(key.status()).isEqualTo(KeyStatus.DESTROYED);
				assertThat(key.data()).isNull();
				assertThat(key.destroyedAt()).isEqualTo(destroyedAt);
			});

		assertThat(stored.getKey("primary-key"))
			.isPresent()
			.hasValueSatisfying(key -> assertThat(key.data()).isNotNull());

		repository.remove("keyset");
	}

	@Test
	@DisplayName("should throw when a concurrent modification is detected on write")
	void shouldDetectConcurrentModificationOnWrite() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey key = encryptedKey("key-1", true, t0, ByteArray.fromString("key-material"));
		final EncryptedKeyset keyset = encryptedKeyset("version-conflict", key);

		repository.write(keyset); // INSERT: version stays at 0

		jdbcOperations.update("UPDATE KEYSETS SET KEYSET_VERSION = 1 WHERE KEYSET_NAME = ?",
				"version-conflict");

		assertThatThrownBy(() -> repository.write(keyset)) // keyset carries v0; DB has v1
				.isInstanceOf(CryptoException.KeysetConcurrentModificationException.class);

		repository.remove("version-conflict");
	}

	@Test
	@DisplayName("should throw when a concurrent modification is detected on updateKeyStatus")
	void shouldDetectConcurrentModificationOnUpdateKeyStatus() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey key = encryptedKey("key-1", true, t0, ByteArray.fromString("key-material"));
		final EncryptedKeyset written = repository.write(encryptedKeyset("status-conflict", key)); // INSERT: version stays at 0

		jdbcOperations.update("UPDATE KEYSETS SET KEYSET_VERSION = 1 WHERE KEYSET_NAME = ?",
				"status-conflict");

		// written carries keysetVersion=0; DB version is now 1 → bump fails
		assertThatThrownBy(() -> repository.updateKeyStatus(KeyTransition.disable(written, "key-1")))
				.isInstanceOf(CryptoException.KeysetConcurrentModificationException.class);

		repository.remove("status-conflict");
	}

	@Test
	@DisplayName("should roll back KEYSETS row when insertKeys throws during create")
	void shouldRollbackCreateOnInsertKeysFailure() throws IOException {
		final String name = "rollback-create";
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey key = encryptedKey("key-1", true, t0, ByteArray.fromString("key-material"));
		final EncryptedKeyset keyset = encryptedKeyset(name, key);

		final JdbcKeysetRepository failingRepo = new JdbcKeysetRepository(jdbcOperations, transactionOperations) {
			@Override
			protected void insertKeys(String keysetName, List<EncryptedKey> keys) {
				throw new DataIntegrityViolationException("simulated key insertion failure");
			}
		};
		failingRepo.afterPropertiesSet();

		try {
			assertThatThrownBy(() -> failingRepo.write(keyset))
				.isInstanceOf(DataAccessException.class);

			assertThat(repository.read(name)).isEmpty();
		} finally {
			repository.remove(name);
		}
	}

	@Test
	@DisplayName("should roll back KEYSETS update when updateKeys throws during update")
	void shouldRollbackUpdateOnUpdateKeysSyncFailure() throws IOException {
		final String name = "rollback-update";
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey originalKey = encryptedKey("key-1", true, t0, ByteArray.fromString("original-material"));
		final EncryptedKeyset original = encryptedKeyset(name, originalKey);

		final EncryptedKeyset written = repository.write(original);

		final JdbcKeysetRepository failingRepo = new JdbcKeysetRepository(jdbcOperations, transactionOperations) {
			@Override
			protected void updateKeys(String keysetName, List<EncryptedKey> newKeys) {
				throw new DataIntegrityViolationException("simulated key sync failure");
			}
		};
		failingRepo.afterPropertiesSet();

		try {
			final EncryptedKey newKey = encryptedKey("key-2", false, t0.plusSeconds(1), ByteArray.fromString("new-material"));
			final EncryptedKeyset updated = EncryptedKeyset.builder(written).build(originalKey, newKey);

			assertThatThrownBy(() -> failingRepo.write(updated))
				.isInstanceOf(DataAccessException.class);

			assertThat(repository.read(name))
				.isNotEmpty()
				.hasValue(original);
		} finally {
			repository.remove(name);
		}
	}

	@Test
	@DisplayName("should reject table names that are not valid SQL identifiers")
	void shouldRejectInvalidTableNames() {
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);

		repo.setTableName("KEYSETS; DROP TABLE KEYSETS;--");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setTableName("1INVALID");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setTableName("KEYSETS");
		repo.setKeysTableName("KEYSET_KEYS; DROP TABLE KEYSET_KEYS;--");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("2INVALID");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);
	}

	@SpringBootApplication
	static class Config {

	}

}
