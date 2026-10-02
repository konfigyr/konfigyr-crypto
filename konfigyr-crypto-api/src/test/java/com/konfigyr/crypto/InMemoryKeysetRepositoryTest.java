package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.io.ByteArray;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

class InMemoryKeysetRepositoryTest {

	static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

	KeysetRepository repository = new InMemoryKeysetRepository();

	@Test
	@DisplayName("should manage encrypted keysets in memory")
	void shouldManageEncryptionKeysets() throws IOException {
		final EncryptedKeyset keyset = encryptedKeyset("test-keyset",
			encryptedKey("key-1", KeyStatus.ENABLED, true, ByteArray.fromString("key-material"), null));

		assertThat(repository.read(keyset.name())).isEmpty();

		assertThatNoException().isThrownBy(() -> repository.write(keyset));
		assertThat(repository.read(keyset.name())).hasValue(keyset);

		assertThatNoException().isThrownBy(() -> repository.remove(keyset.name()));
		assertThat(repository.read(keyset.name())).isEmpty();
	}

	@Test
	@DisplayName("should update key status using the default read-modify-write")
	void shouldUpdateKeyStatus() throws IOException {
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.ENABLED, true,
			ByteArray.fromString("key-material"), null);
		final EncryptedKeyset stored = repository.write(encryptedKeyset("test-keyset", key));

		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.disable(stored, "key-1")));

		assertThat(repository.read("test-keyset"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.status()).isEqualTo(KeyStatus.DISABLED);
						assertThat(k.data()).isNotNull();
					})
			);
	}

	@Test
	@DisplayName("should erase key data when transitioning to DESTROYED status")
	void shouldEraseKeyDataOnDestruction() throws IOException {
		final Instant scheduledAt = NOW.minus(Duration.ofDays(1));
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.PENDING_DESTRUCTION, true,
			ByteArray.fromString("key-material"), scheduledAt);
		final EncryptedKeyset stored = repository.write(encryptedKeyset("test-keyset", key));

		final Instant destroyedAt = NOW;
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.destroy(stored, "key-1", destroyedAt)));

		assertThat(repository.read("test-keyset"))
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
	}

	@Test
	@DisplayName("should set destruction timestamp when scheduling a key for destruction")
	void shouldSetDestructionScheduledAtOnPendingDestruction() throws IOException {
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.DISABLED, true,
			ByteArray.fromString("key-material"), null);
		final EncryptedKeyset stored = repository.write(encryptedKeyset("test-keyset", key));

		final Instant scheduledAt = NOW.plus(Duration.ofDays(30));
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.scheduleDestruction(stored, "key-1", scheduledAt)));

		assertThat(repository.read("test-keyset"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.status()).isEqualTo(KeyStatus.PENDING_DESTRUCTION);
						assertThat(k.destructionScheduledAt()).isEqualTo(scheduledAt);
					})
			);
	}

	@Test
	@DisplayName("should return keys pending destruction with an elapsed schedule")
	void shouldFindKeysPendingDestruction() throws IOException {
		final Instant pastSchedule = NOW.minus(Duration.ofHours(1));
		final EncryptedKey pendingKey = encryptedKey("key-1", KeyStatus.PENDING_DESTRUCTION, true,
			ByteArray.fromString("key-material"), pastSchedule);
		repository.write(encryptedKeyset("test-keyset", pendingKey));

		final List<EncryptedKeyset> results = repository.findPendingDestruction();

		assertThat(results).hasSize(1);
		assertThat(results.getFirst().name()).isEqualTo("test-keyset");
		assertThat(results.getFirst().keys()).hasSize(1);
		assertThat(results.getFirst().keys().getFirst().id()).isEqualTo("key-1");
	}

	@Test
	@DisplayName("should return compromised keys pending destruction with an elapsed schedule")
	void shouldFindCompromisedKeysPendingDestruction() throws IOException {
		final EncryptedKey compromisedKey = encryptedKey("key-1", KeyStatus.COMPROMISED_PENDING_DESTRUCTION, true,
			ByteArray.fromString("key-material"), NOW.minus(Duration.ofHours(1)));
		final EncryptedKey futureKey = encryptedKey("key-2", KeyStatus.COMPROMISED_PENDING_DESTRUCTION, false,
			ByteArray.fromString("key-material"), Instant.now().plus(Duration.ofDays(7)));
		final EncryptedKey unscheduledKey = encryptedKey("key-3", KeyStatus.COMPROMISED, false,
			ByteArray.fromString("key-material"), null);
		repository.write(encryptedKeyset("test-keyset", compromisedKey, futureKey, unscheduledKey));

		assertThat(repository.findPendingDestruction())
			.hasSize(1)
			.first()
			.extracting(EncryptedKeyset::keys, InstanceOfAssertFactories.list(EncryptedKey.class))
			.extracting(EncryptedKey::id, EncryptedKey::status)
			.containsExactly(tuple("key-1", KeyStatus.COMPROMISED_PENDING_DESTRUCTION));
	}

	@Test
	@DisplayName("should not return keys whose destruction schedule is in the future")
	void shouldNotFindFutureScheduledDestructionKeys() throws IOException {
		final Instant futureSchedule = Instant.now().plus(Duration.ofDays(7));
		final EncryptedKey futureKey = encryptedKey("key-1", KeyStatus.PENDING_DESTRUCTION, true,
			ByteArray.fromString("key-material"), futureSchedule);
		repository.write(encryptedKeyset("test-keyset", futureKey));

		assertThat(repository.findPendingDestruction()).isEmpty();
	}

	@Test
	@DisplayName("should not return ENABLED keys from findPendingDestruction")
	void shouldNotFindEnabledKeys() throws IOException {
		final EncryptedKey enabledKey = encryptedKey("key-1", KeyStatus.ENABLED, true,
			ByteArray.fromString("key-material"), null);
		repository.write(encryptedKeyset("test-keyset", enabledKey));

		assertThat(repository.findPendingDestruction()).isEmpty();
	}

	@Test
	@DisplayName("should silently skip updateKeyStatus when the keyset does not exist")
	void shouldSkipUpdateForMissingKeyset() {
		final EncryptedKeyset missing = encryptedKeyset("missing-keyset");
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(new KeyTransition(missing.name(), "key-1", KeyStatus.DISABLED,
				null, null, missing.version())));
	}

	@Test
	@DisplayName("should return keysets whose primary key expiry time has elapsed")
	void shouldFindKeysetsPendingRotation() throws Exception {
		final Instant pastExpiry = Instant.now().minus(Duration.ofDays(1));
		final EncryptedKey expiredKey = EncryptedKey.builder()
			.id("key-1")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(pastExpiry.minus(Duration.ofDays(90)))
			.expiresAt(pastExpiry)
			.build(ByteArray.fromString("key-material"));
		repository.write(encryptedKeyset("due-for-rotation", expiredKey));

		final List<EncryptedKeyset> results = repository.findPendingRotation();

		assertThat(results)
			.hasSize(1)
			.first()
			.returns("due-for-rotation", EncryptedKeyset::name)
			.extracting(EncryptedKeyset::keys)
			.isEqualTo(List.of());
	}

	@Test
	@DisplayName("should not return keysets whose primary key expiry time is in the future")
	void shouldNotFindKeysetsPendingRotationIfExpiryInFuture() throws Exception {
		final Instant futureExpiry = Instant.now().plus(Duration.ofDays(30));
		final EncryptedKey freshKey = EncryptedKey.builder()
			.id("key-1")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(Instant.now())
			.expiresAt(futureExpiry)
			.build(ByteArray.fromString("key-material"));
		repository.write(encryptedKeyset("not-due", freshKey));

		assertThat(repository.findPendingRotation())
			.extracting(EncryptedKeyset::name)
			.doesNotContain("not-due");
	}

	@Test
	@DisplayName("should not return keysets whose primary key has no expiry time")
	void shouldNotFindKeysetsPendingRotationIfNoExpiry() throws Exception {
		final EncryptedKey keyWithoutExpiry = EncryptedKey.builder()
			.id("key-1")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(Instant.now().minus(Duration.ofDays(365)))
			.build(ByteArray.fromString("key-material"));
		final EncryptedKeyset keyset = EncryptedKeyset.builder()
			.name("no-expiry")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory(TestAlgorithm.INSTANCE.factory())
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(keyWithoutExpiry);
		repository.write(keyset);

		assertThat(repository.findPendingRotation())
			.extracting(EncryptedKeyset::name)
			.doesNotContain("no-expiry");
	}

	@Test
	@DisplayName("should return keysets whose primary key expires within the rotation lead time")
	void shouldFindKeysetsPendingPreparation() throws IOException {
		final Instant now = Instant.now();

		// primary key expires within the lead time and there is no next key yet: returned
		repository.write(preparedKeyset("within-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(70)), now.plus(Duration.ofDays(20)))));

		// primary key already expired without the keyset being prepared: returned
		repository.write(preparedKeyset("missed-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(100)), now.minus(Duration.ofDays(10)))));

		// primary key expires after the lead time: not returned
		repository.write(preparedKeyset("before-lead-time",
			expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(30)), now.plus(Duration.ofDays(60)))));

		// next key already exists: not returned
		repository.write(preparedKeyset("already-prepared",
			expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(70)), now.plus(Duration.ofDays(20))),
			expiringKey("next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(5)), now.plus(Duration.ofDays(85)))));

		// only an older, demoted, key and a disabled newer key exist: returned
		repository.write(preparedKeyset("not-prepared",
			expiringKey("previous", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(160)), now.minus(Duration.ofDays(70))),
			expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(70)), now.plus(Duration.ofDays(20))),
			expiringKey("disabled", false, KeyStatus.DISABLED, now.minus(Duration.ofDays(5)), now.plus(Duration.ofDays(85)))));

		// primary key is not enabled: not returned
		repository.write(preparedKeyset("compromised",
			expiringKey("primary", true, KeyStatus.COMPROMISED, now.minus(Duration.ofDays(70)), now.plus(Duration.ofDays(20)))));

		// keyset without a rotation lead time: not returned
		repository.write(EncryptedKeyset.builder(preparedKeyset("no-lead-time"))
			.rotationLeadTime((Duration) null)
			.build(expiringKey("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(70)), now.plus(Duration.ofDays(20)))));

		assertThat(repository.findPendingPreparation())
			.extracting(EncryptedKeyset::name, EncryptedKeyset::keys)
			.containsExactlyInAnyOrder(
				tuple("within-lead-time", List.of()),
				tuple("missed-lead-time", List.of()),
				tuple("not-prepared", List.of())
			);
	}

	@Test
	@DisplayName("should throw when a concurrent modification is detected on write")
	void shouldDetectConcurrentModificationOnWrite() throws IOException {
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.ENABLED, true,
			ByteArray.fromString("key-material"), null);
		final EncryptedKeyset keyset = encryptedKeyset("concurrent-test", key);

		repository.write(keyset); // INSERT: stored version = 0
		repository.write(keyset); // UPDATE: 0 == 0, stored bumped to version 1

		assertThatThrownBy(() -> repository.write(keyset)) // keyset is still v0, stored is v1
			.isInstanceOf(CryptoException.KeysetConcurrentModificationException.class);
	}

	private static EncryptedKeyset preparedKeyset(String name, EncryptedKey... keys) {
		return EncryptedKeyset.builder(encryptedKeyset(name))
			.rotationLeadTime(Duration.ofDays(30))
			.build(keys);
	}

	private static EncryptedKey expiringKey(String id, boolean primary, KeyStatus status, Instant createdAt,
			Instant expiresAt) {
		return EncryptedKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(primary)
			.createdAt(createdAt)
			.expiresAt(expiresAt)
			.build(ByteArray.fromString("key-material"));
	}

	private static EncryptedKeyset encryptedKeyset(String name, EncryptedKey... keys) {
		return EncryptedKeyset.builder()
			.name(name)
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory(TestAlgorithm.INSTANCE.factory())
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.destructionGracePeriod(Duration.ofDays(30))
			.build(keys);
	}

	private static EncryptedKey encryptedKey(
			String id, KeyStatus status, boolean primary,
			ByteArray data, Instant destructionScheduledAt) {
		return EncryptedKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(primary)
			.createdAt(NOW)
			.destructionScheduledAt(destructionScheduledAt)
			.build(data);
	}

}
