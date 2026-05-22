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

	@Test
	@DisplayName("should update key status without altering key data")
	void shouldUpdateKeyStatus() throws IOException {
		final Instant t0 = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		final EncryptedKey key = encryptedKey("key-1", true, t0, ByteArray.fromString("secret"));
		repository.write(encryptedKeyset("lifecycle-status", key));

		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.disable("lifecycle-status", "key-1")));

		assertThat(repository.read("lifecycle-status"))
			.isPresent()
			.hasValueSatisfying(ks ->
				assertThat(ks.getKey("key-1"))
					.isPresent()
					.hasValueSatisfying(k -> {
						assertThat(k.getStatus()).isEqualTo(KeyStatus.DISABLED);
						assertThat(k.getData()).isNotNull();
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
		repository.write(encryptedKeyset("lifecycle-destroy", key));

		final Instant destroyedAt = t0.plusSeconds(1);
		assertThatNoException().isThrownBy(() ->
			repository.updateKeyStatus(KeyTransition.destroy("lifecycle-destroy", "key-1", destroyedAt)));

		assertThat(repository.read("lifecycle-destroy"))
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
			.returns("lifecycle-pending", EncryptedKeyset::getName)
			.extracting(EncryptedKeyset::getKeys, InstanceOfAssertFactories.iterable(EncryptedKey.class))
			.hasSize(1)
			.first()
			.returns("past-key", EncryptedKey::getId);

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
			.extracting(EncryptedKeyset::getName)
			.doesNotContain("lifecycle-future");

		repository.remove("lifecycle-future");
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

	@SpringBootApplication
	static class Config {

	}

}
