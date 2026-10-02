package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.io.ByteArray;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
import static org.assertj.core.api.Assertions.tuple;

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
	@DisplayName("should store, update and clear the keyset rotation lead time")
	void shouldPersistRotationLeadTime() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final String name = "rotation-lead-time";

		final EncryptedKey primary = expiringKey("primary", true, KeyStatus.ENABLED, t0.minus(Duration.ofDays(1)));
		final EncryptedKey retired = EncryptedKey.builder()
			.id("retired")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.PENDING_DESTRUCTION)
			.primary(false)
			.createdAt(t0)
			.destructionScheduledAt(t0.minus(Duration.ofDays(1)))
			.build(ByteArray.fromString("secret"));

		final EncryptedKeyset keyset = EncryptedKeyset.builder(encryptedKeyset(name))
			.rotationLeadTime(Duration.ofDays(30))
			.build(primary, retired);

		try {
			final EncryptedKeyset written = repository.write(keyset);

			assertThat(repository.read(name))
				.get()
				.returns(Duration.ofDays(30), EncryptedKeyset::rotationLeadTime)
				.isEqualTo(written);

			assertThat(repository.findPendingRotation())
				.filteredOn(it -> name.equals(it.name()))
				.singleElement()
				.returns(Duration.ofDays(30), EncryptedKeyset::rotationLeadTime);

			assertThat(repository.findPendingDestruction())
				.filteredOn(it -> name.equals(it.name()))
				.singleElement()
				.returns(Duration.ofDays(30), EncryptedKeyset::rotationLeadTime);

			repository.write(EncryptedKeyset.builder(written)
				.rotationLeadTime(Duration.ofDays(60))
				.build(written.keys()));

			assertThat(repository.read(name))
				.get()
				.returns(Duration.ofDays(60), EncryptedKeyset::rotationLeadTime);

			final EncryptedKeyset updated = repository.read(name).orElseThrow();

			repository.write(EncryptedKeyset.builder(updated)
				.rotationLeadTime((Duration) null)
				.build(updated.keys()));

			assertThat(repository.read(name))
				.get()
				.returns(null, EncryptedKeyset::rotationLeadTime);
		} finally {
			repository.remove(name);
		}
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
	@DisplayName("should return compromised keys whose scheduled destruction time has elapsed")
	void shouldFindCompromisedKeysPendingDestruction() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);

		final EncryptedKey pendingKey = EncryptedKey.builder()
			.id("pending-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.PENDING_DESTRUCTION)
			.primary(true)
			.createdAt(t0)
			.destructionScheduledAt(t0.minus(Duration.ofDays(1)))
			.build(ByteArray.fromString("secret"));

		final EncryptedKey compromisedKey = EncryptedKey.builder()
			.id("compromised-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.COMPROMISED_PENDING_DESTRUCTION)
			.primary(false)
			.createdAt(t0)
			.destructionScheduledAt(t0.minus(Duration.ofDays(1)))
			.build(ByteArray.fromString("secret"));

		final EncryptedKey unscheduledKey = EncryptedKey.builder()
			.id("unscheduled-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.COMPROMISED)
			.primary(false)
			.createdAt(t0)
			.build(ByteArray.fromString("secret"));

		repository.write(encryptedKeyset("lifecycle-compromised", pendingKey, compromisedKey, unscheduledKey));

		assertThat(repository.findPendingDestruction())
			.filteredOn(keyset -> keyset.name().equals("lifecycle-compromised"))
			.singleElement()
			.extracting(EncryptedKeyset::keys, InstanceOfAssertFactories.iterable(EncryptedKey.class))
			.extracting(EncryptedKey::id, EncryptedKey::status)
			.containsExactly(
				tuple("compromised-key", KeyStatus.COMPROMISED_PENDING_DESTRUCTION),
				tuple("pending-key", KeyStatus.PENDING_DESTRUCTION)
			);

		repository.remove("lifecycle-compromised");
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

	@Test
	@DisplayName("should only return keysets whose primary and enabled key expiry time has elapsed")
	void shouldOnlyFindKeysetsPendingRotationForExpiredPrimaryKeys() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final Instant pastExpiry = t0.minus(Duration.ofDays(1));
		final Instant futureExpiry = t0.plus(Duration.ofDays(30));

		// primary key expired, alongside an expired non-primary key: returned exactly once
		repository.write(encryptedKeyset("rotation-primary-expired",
			expiringKey("primary", true, KeyStatus.ENABLED, pastExpiry),
			expiringKey("secondary", false, KeyStatus.ENABLED, pastExpiry)
		));

		// only the non-primary key expired: not returned
		repository.write(encryptedKeyset("rotation-secondary-expired",
			expiringKey("primary", true, KeyStatus.ENABLED, futureExpiry),
			expiringKey("secondary", false, KeyStatus.ENABLED, pastExpiry)
		));

		// expired primary key that is not enabled: not returned
		repository.write(encryptedKeyset("rotation-primary-disabled",
			expiringKey("primary", true, KeyStatus.DISABLED, pastExpiry)
		));

		try {
			assertThat(repository.findPendingRotation())
				.extracting(EncryptedKeyset::name)
				.filteredOn(name -> name.startsWith("rotation-"))
				.containsExactly("rotation-primary-expired");
		} finally {
			repository.remove("rotation-primary-expired");
			repository.remove("rotation-secondary-expired");
			repository.remove("rotation-primary-disabled");
		}
	}

	@Test
	@DisplayName("should only return keysets whose primary key expires within the rotation lead time and have no next key")
	void shouldFindKeysetsPendingPreparation() throws IOException {
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final List<String> names = List.of("preparation-within-lead-time", "preparation-missed-lead-time",
			"preparation-before-lead-time", "preparation-already-prepared", "preparation-not-prepared",
			"preparation-compromised", "preparation-no-lead-time");

		// primary key expires within the lead time and there is no next key yet: returned
		repository.write(preparedKeyset("preparation-within-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.plus(Duration.ofDays(20)))));

		// primary key already expired without the keyset being prepared: returned
		repository.write(preparedKeyset("preparation-missed-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(10)))));

		// primary key expires after the lead time: not returned
		repository.write(preparedKeyset("preparation-before-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.plus(Duration.ofDays(60)))));

		// next key, created after the primary key, already exists: not returned
		repository.write(preparedKeyset("preparation-already-prepared",
			expiringKey("primary", true, KeyStatus.ENABLED, now.plus(Duration.ofDays(20))),
			expiringKey("next", false, KeyStatus.ENABLED, now.plus(Duration.ofDays(85)))));

		// only an older, demoted, key and a disabled newer key exist: returned
		repository.write(preparedKeyset("preparation-not-prepared",
			expiringKey("previous", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(70))),
			expiringKey("primary", true, KeyStatus.ENABLED, now.plus(Duration.ofDays(20))),
			expiringKey("disabled", false, KeyStatus.DISABLED, now.plus(Duration.ofDays(85)))));

		// primary key is not enabled: not returned
		repository.write(preparedKeyset("preparation-compromised",
			expiringKey("primary", true, KeyStatus.COMPROMISED, now.plus(Duration.ofDays(20)))));

		// keyset without a rotation lead time: not returned
		repository.write(encryptedKeyset("preparation-no-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.plus(Duration.ofDays(20)))));

		try {
			assertThat(repository.findPendingPreparation())
				.filteredOn(keyset -> names.contains(keyset.name()))
				.extracting(EncryptedKeyset::name, EncryptedKeyset::rotationLeadTime, EncryptedKeyset::keys)
				.containsExactly(
					tuple("preparation-missed-lead-time", Duration.ofDays(30), List.of()),
					tuple("preparation-not-prepared", Duration.ofDays(30), List.of()),
					tuple("preparation-within-lead-time", Duration.ofDays(30), List.of())
				);
		} finally {
			for (String name : names) {
				repository.remove(name);
			}
		}
	}

	@Test
	@DisplayName("should bind the expiry time and primary flag parameters to a custom pending rotation query")
	void shouldBindParametersToCustomPendingRotationQuery() throws IOException {
		final Instant pastExpiry = Instant.now().truncatedTo(ChronoUnit.MILLIS).minus(Duration.ofDays(1));
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);
		repo.setFindPendingRotationQuery("""
				SELECT DISTINCT K.KEYSET_NAME, K.KEYSET_PURPOSE, K.KEYSET_FACTORY, K.KEYSET_PROVIDER, K.KEYSET_KEK,
					K.ROTATION_INTERVAL, K.ROTATION_LEAD_TIME, K.DESTRUCTION_GRACE_PERIOD, K.KEYSET_VERSION
				FROM %KEYSETS_TABLE_NAME% K
				INNER JOIN %KEYS_TABLE_NAME% E ON E.KEYSET_NAME = K.KEYSET_NAME
				WHERE E.EXPIRES_AT <= ? AND E.KEY_PRIMARY <> ?
				ORDER BY K.KEYSET_NAME
				""");
		repo.afterPropertiesSet();

		final Instant futureExpiry = pastExpiry.plus(Duration.ofDays(30));

		// custom query matches expired non-primary keys, only matched when the primary flag is bound as true
		repository.write(encryptedKeyset("rotation-custom-secondary",
			expiringKey("primary", true, KeyStatus.ENABLED, futureExpiry),
			expiringKey("secondary", false, KeyStatus.ENABLED, pastExpiry)
		));

		// would only be matched if the primary flag was bound as false
		repository.write(encryptedKeyset("rotation-custom-primary",
			expiringKey("primary", true, KeyStatus.ENABLED, pastExpiry),
			expiringKey("secondary", false, KeyStatus.ENABLED, futureExpiry)
		));

		try {
			assertThat(repo.findPendingRotation())
				.extracting(EncryptedKeyset::name)
				.filteredOn(name -> name.startsWith("rotation-custom-"))
				.containsExactly("rotation-custom-secondary");
		} finally {
			repository.remove("rotation-custom-secondary");
			repository.remove("rotation-custom-primary");
		}
	}

	@NonNull
	private static EncryptedKey expiringKey(String id, boolean primary, KeyStatus status, Instant expiresAt) {
		return EncryptedKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(primary)
			.createdAt(expiresAt.minus(Duration.ofDays(90)))
			.expiresAt(expiresAt)
			.build(ByteArray.fromString("enc-key-material"));
	}

	@NonNull
	private static EncryptedKeyset preparedKeyset(String name, EncryptedKey... keys) {
		return EncryptedKeyset.builder(encryptedKeyset(name))
			.rotationLeadTime(Duration.ofDays(30))
			.build(keys);
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

		// applied directly as the repository does not validate the key lifecycle
		repository.updateKeyStatus(new KeyTransition(written.name(), "old-key", KeyStatus.DESTROYED,
			null, destroyedAt, written.version()));

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
	@DisplayName("should accept custom SQL query overrides and still resolve defaults when null is provided")
	void shouldAcceptCustomSqlQueryOverrides() {
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);
		repo.setGetKeysetQuery(null);
		repo.setGetKeysQuery(null);
		repo.setKeysetExistsQuery(null);
		repo.setCreateKeysetQuery(null);
		repo.setUpdateKeysetQuery(null);
		repo.setCreateKeyQuery(null);
		repo.setUpdateKeyQuery(null);
		repo.setDeleteKeyQuery(null);
		repo.setDeleteKeysQuery(null);
		repo.setDeleteKeysetQuery(null);
		repo.setUpdateKeyStatusQuery(null);
		repo.setDestroyKeyQuery(null);
		repo.setFindPendingDestructionQuery(null);
		repo.setFindPendingRotationQuery(null);
		repo.setBumpKeysetVersionQuery(null);
		repo.afterPropertiesSet();

		assertThat(repo.read("non-existent")).isEmpty();
	}

	@Test
	@DisplayName("should reject table names that are not valid SQL identifiers")
	void shouldRejectInvalidTableNames() {
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);

		repo.setKeysetsTableName("KEYSETS; DROP TABLE KEYSETS;--");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysetsTableName("1INVALID");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysetsTableName("KEYSETS");
		repo.setKeysTableName("KEYSET_KEYS; DROP TABLE KEYSET_KEYS;--");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("2INVALID");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("my-schema.KEYSET_KEYS");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("schema..KEYSET_KEYS");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("\"schema\";DROP TABLE KEYSETS;--\".KEYSET_KEYS");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("`schema`;--`.KEYSET_KEYS");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setKeysTableName("a.b.c.KEYSET_KEYS");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);
	}

	@ParameterizedTest
	@ValueSource(strings = {
		"KEYSETS",
		"my_schema.KEYSETS",
		"catalog.my_schema.KEYSETS",
		"\"my-schema\".\"table-name\"",
		"`my-schema`.`table-name`"
	})
	@DisplayName("should accept table names qualified with a schema or catalog")
	void shouldAcceptQualifiedTableNames(String tableName) {
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);
		repo.setKeysetsTableName(tableName);
		repo.setKeysTableName(tableName);

		assertThatNoException().isThrownBy(repo::afterPropertiesSet);
	}

	@Test
	@SuppressWarnings("removal")
	@DisplayName("should configure the keysets table name using the deprecated setter")
	void shouldSupportDeprecatedTableNameSetter() {
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);

		repo.setTableName("KEYSETS; DROP TABLE KEYSETS;--");
		assertThatIllegalArgumentException().isThrownBy(repo::afterPropertiesSet);

		repo.setTableName(JdbcKeysetRepository.DEFAULT_TABLE_NAME);
		repo.afterPropertiesSet();

		assertThat(repo.read("non-existent")).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "%KEYSETS_TABLE_NAME%", "%TABLE_NAME%" })
	@DisplayName("should resolve keysets table name placeholders in custom SQL queries")
	void shouldResolveKeysetsTableNamePlaceholders(String placeholder) throws IOException {
		final String name = "custom-query-placeholder-keyset";
		final var repo = new JdbcKeysetRepository(jdbcOperations, transactionOperations);
		repo.setGetKeysetQuery("""
				SELECT K.KEYSET_NAME, K.KEYSET_PURPOSE, K.KEYSET_FACTORY, K.KEYSET_PROVIDER, K.KEYSET_KEK,
					K.ROTATION_INTERVAL, K.ROTATION_LEAD_TIME, K.DESTRUCTION_GRACE_PERIOD, K.KEYSET_VERSION
				FROM %s K
				WHERE K.KEYSET_NAME = ?
				""".formatted(placeholder));
		repo.afterPropertiesSet();

		repository.write(encryptedKeyset(name, encryptedKey("key-1", true, Instant.now(), ByteArray.fromString("material"))));

		try {
			assertThat(repo.read(name))
				.isPresent()
				.get()
				.returns(name, EncryptedKeyset::name)
				.returns(1, EncryptedKeyset::size);
		} finally {
			repository.remove(name);
		}
	}

	@SpringBootApplication
	static class Config {

	}

}
