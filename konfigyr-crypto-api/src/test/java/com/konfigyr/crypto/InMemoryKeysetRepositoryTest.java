package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class InMemoryKeysetRepositoryTest {

	static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

	KeysetRepository repository = new InMemoryKeysetRepository();

	@Test
	@DisplayName("should manage encrypted keysets in memory")
	void shouldManageEncryptionKeysets() throws IOException {
		final EncryptedKeyset keyset = encryptedKeyset("test-keyset",
			encryptedKey("key-1", KeyStatus.ENABLED, true, ByteArray.fromString("key-material"), null));

		assertThat(repository.read(keyset.getName())).isEmpty();

		assertThatNoException().isThrownBy(() -> repository.write(keyset));
		assertThat(repository.read(keyset.getName())).hasValue(keyset);

		assertThatNoException().isThrownBy(() -> repository.remove(keyset.getName()));
		assertThat(repository.read(keyset.getName())).isEmpty();
	}

	@Test
	@DisplayName("should update key status using the default read-modify-write")
	void shouldUpdateKeyStatus() throws IOException {
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.ENABLED, true,
			ByteArray.fromString("key-material"), null);
		repository.write(encryptedKeyset("test-keyset", key));

		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.disable("test-keyset", "key-1")));

		assertThat(repository.read("test-keyset"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.getStatus()).isEqualTo(KeyStatus.DISABLED);
						assertThat(k.getData()).isNotNull();
					})
			);
	}

	@Test
	@DisplayName("should erase key data when transitioning to DESTROYED status")
	void shouldEraseKeyDataOnDestruction() throws IOException {
		final Instant scheduledAt = NOW.minus(Duration.ofDays(1));
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.PENDING_DESTRUCTION, true,
			ByteArray.fromString("key-material"), scheduledAt);
		repository.write(encryptedKeyset("test-keyset", key));

		final Instant destroyedAt = NOW;
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.destroy("test-keyset", "key-1", destroyedAt)));

		assertThat(repository.read("test-keyset"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.getStatus()).isEqualTo(KeyStatus.DESTROYED);
						assertThat(k.getData()).isNull();
						assertThat(k.getDestroyedAt()).isEqualTo(destroyedAt);
					})
			);
	}

	@Test
	@DisplayName("should set destruction timestamp when scheduling a key for destruction")
	void shouldSetDestructionScheduledAtOnPendingDestruction() throws IOException {
		final EncryptedKey key = encryptedKey("key-1", KeyStatus.DISABLED, true,
			ByteArray.fromString("key-material"), null);
		repository.write(encryptedKeyset("test-keyset", key));

		final Instant scheduledAt = NOW.plus(Duration.ofDays(30));
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.scheduleDestruction("test-keyset", "key-1", scheduledAt)));

		assertThat(repository.read("test-keyset"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.getStatus()).isEqualTo(KeyStatus.PENDING_DESTRUCTION);
						assertThat(k.getDestructionScheduledAt()).isEqualTo(scheduledAt);
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
		assertThat(results.getFirst().getName()).isEqualTo("test-keyset");
		assertThat(results.getFirst().getKeys()).hasSize(1);
		assertThat(results.getFirst().getKeys().getFirst().getId()).isEqualTo("key-1");
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
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.disable("missing-keyset", "key-1")));
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
			.returns("due-for-rotation", EncryptedKeyset::getName)
			.extracting(EncryptedKeyset::getKeys)
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
			.extracting(EncryptedKeyset::getName)
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
			.extracting(EncryptedKeyset::getName)
			.doesNotContain("no-expiry");
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
