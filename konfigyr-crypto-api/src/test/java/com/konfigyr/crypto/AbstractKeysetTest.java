package com.konfigyr.crypto;

import com.konfigyr.crypto.test.KeyAssert;
import com.konfigyr.crypto.test.KeysetAssert;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.crypto.test.TestKey;
import com.konfigyr.crypto.test.TestKeyset;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

class AbstractKeysetTest {

	static final KeyEncryptionKey kek = new TestKeyEncryptionKey("test-kek", "test-provider");
	static final Instant now = Instant.parse("2026-01-01T00:00:00Z");

	static TestKey createKey(String id, boolean primary) {
		return createKey(id, primary, KeyStatus.ENABLED);
	}

	static TestKey createKey(String id, boolean primary, KeyStatus status) {
		return TestKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(primary)
			.createdAt(now)
			.build();
	}

	@Test
	@DisplayName("should build a keyset with all fields populated")
	void shouldBuildKeysetWithAllFields() {
		final var primaryKey = createKey("primary-key", true);
		final var secondKey = createKey("second-key", false);

		final var keyset = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.rotationInterval(Duration.ofDays(90))
			.destructionGracePeriod(Duration.ofDays(30))
			.key(primaryKey)
			.key(secondKey)
			.build();

		KeysetAssert.assertThat(keyset)
			.hasName("test-keyset")
			.createdByFactory("test-factory")
			.hasPurpose(KeysetPurpose.ENCRYPTION)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(Duration.ofDays(90))
			.hasDestructionGracePeriod(Duration.ofDays(30))
			.hasSize(2);
	}

	@Test
	@DisplayName("should build a keyset from a definition")
	void shouldBuildKeysetFromDefinition() {
		final var definition = KeysetDefinition.of("test-keyset", TestAlgorithm.INSTANCE);

		final var keyset = TestKeyset.builder(definition)
			.keyEncryptionKey(kek)
			.key(createKey("primary-key", true))
			.build();

		KeysetAssert.assertThat(keyset)
			.matchesDefinition(definition)
			.hasKeyEncryptionKey(kek);
	}

	@Test
	@DisplayName("should build a keyset from a definition with rotation interval and grace period disabled")
	void shouldBuildKeysetFromDefinitionWithDisabledOptionals() {
		final var definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(TestAlgorithm.INSTANCE)
			.disableAutomaticKeyRotation()
			.disableDestructionGracePeriod()
			.build();

		final var keyset = TestKeyset.builder(definition)
			.keyEncryptionKey(kek)
			.key(createKey("primary-key", true))
			.build();

		KeysetAssert.assertThat(keyset)
			.matchesDefinition(definition)
			.hasNoRotationInterval()
			.hasNoDestructionGracePeriod();
	}

	@Test
	@DisplayName("should copy all fields using the copy constructor")
	void shouldCopyAllFieldsUsingCopyConstructor() {
		final var primaryKey = createKey("primary-key", true);

		final var original = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.rotationInterval(Duration.ofDays(90))
			.destructionGracePeriod(Duration.ofDays(30))
			.key(primaryKey)
			.build();

		final var copy = TestKeyset.builder(original)
			.keys(original.getKeys())
			.build();

		assertThat(copy).isEqualTo(original);
		assertThat(copy.hashCode()).isEqualTo(original.hashCode());
	}

	@Test
	@DisplayName("should build a keyset from an encrypted keyset")
	void shouldBuildKeysetFromEncryptedKeyset() {
		final var encryptedKeyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.keyEncryptionKey(kek)
			.rotationInterval(Duration.ofDays(90))
			.destructionGracePeriod(Duration.ofDays(30))
			.build(List.of());

		final var keyset = TestKeyset.builder(encryptedKeyset)
			.keyEncryptionKey(kek)
			.key(createKey("primary-key", true))
			.build();

		KeysetAssert.assertThat(keyset)
			.hasName("test-keyset")
			.hasPurpose(KeysetPurpose.ENCRYPTION)
			.createdByFactory("test-factory")
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(Duration.ofDays(90))
			.hasDestructionGracePeriod(Duration.ofDays(30));
	}

	@Test
	@DisplayName("should return the primary key from the keyset")
	void shouldReturnPrimaryKey() {
		final var primaryKey = createKey("primary-key", true);
		final var otherKey = createKey("other-key", false);

		final var keyset = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.key(primaryKey)
			.key(otherKey)
			.build();

		KeyAssert.assertThat(keyset.getPrimary()).hasId("primary-key").isPrimary();
	}

	@Test
	@DisplayName("should throw when no primary key is present in the keyset")
	void shouldThrowWhenNoPrimaryKeyPresent() {
		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset")
				.factory("test-factory")
				.purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.key(createKey("non-primary-key", false))
				.build())
			.withMessageContaining("must have a primary key")
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should throw KeysetDisabledException when the primary key is disabled")
	void shouldThrowWhenPrimaryKeyIsDisabled() {
		assertThatExceptionOfType(CryptoException.KeysetDisabledException.class)
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset")
				.factory("test-factory")
				.purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.key(createKey("primary-key", true, KeyStatus.DISABLED))
				.build())
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should throw KeysetPendingDestructionException when the primary key is pending destruction")
	void shouldThrowWhenPrimaryKeyIsPendingDestruction() {
		assertThatExceptionOfType(CryptoException.KeysetPendingDestructionException.class)
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset")
				.factory("test-factory")
				.purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.key(createKey("primary-key", true, KeyStatus.PENDING_DESTRUCTION))
				.build())
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should throw KeysetDestroyedException when the primary key has been destroyed")
	void shouldThrowWhenPrimaryKeyIsDestroyed() {
		assertThatExceptionOfType(CryptoException.KeysetDestroyedException.class)
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset")
				.factory("test-factory")
				.purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.key(createKey("primary-key", true, KeyStatus.DESTROYED))
				.build())
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should throw KeysetCompromisedException when the primary key is compromised")
	void shouldThrowWhenPrimaryKeyIsCompromised() {
		assertThatExceptionOfType(CryptoException.KeysetCompromisedException.class)
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset")
				.factory("test-factory")
				.purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.key(createKey("primary-key", true, KeyStatus.COMPROMISED))
				.build())
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should find a key by its identifier")
	void shouldFindKeyById() {
		final var primaryKey = createKey("primary-key", true);
		final var otherKey = createKey("other-key", false);

		final var keyset = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.key(primaryKey)
			.key(otherKey)
			.build();

		assertThat(keyset.getKey("other-key"))
			.isPresent()
			.hasValueSatisfying(key -> KeyAssert.assertThat(key).hasId("other-key").isNotPrimary());

		assertThat(keyset.getKey("missing")).isEmpty();
	}

	@Test
	@DisplayName("should replace keys when using the keys builder method")
	void shouldReplaceKeysUsingKeysMethod() {
		final var replacement = createKey("replacement-key", true);

		final var keyset = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.key(createKey("first-key", true))
			.key(createKey("second-key", false))
			.keys(List.of(replacement))
			.build();

		KeysetAssert.assertThat(keyset).hasSize(1);
		KeyAssert.assertThat(keyset.getPrimary()).hasId("replacement-key");
	}

	@Test
	@DisplayName("should return rotation interval wrapped in an optional")
	void shouldReturnRotationIntervalAsOptional() {
		final var withInterval = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).rotationInterval(Duration.ofDays(90)).key(createKey("k", true)).build();

		final var withoutInterval = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).rotationInterval(null).key(createKey("k", true)).build();

		KeysetAssert.assertThat(withInterval).hasRotationInterval(Duration.ofDays(90));
		KeysetAssert.assertThat(withoutInterval).hasNoRotationInterval();
	}

	@Test
	@DisplayName("should return destruction grace period wrapped in an optional")
	void shouldReturnDestructionGracePeriodAsOptional() {
		final var withGrace = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).destructionGracePeriod(Duration.ofDays(30)).key(createKey("k", true)).build();

		final var withoutGrace = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).destructionGracePeriod(null).key(createKey("k", true)).build();

		KeysetAssert.assertThat(withGrace).hasDestructionGracePeriod(Duration.ofDays(30));
		KeysetAssert.assertThat(withoutGrace).hasNoDestructionGracePeriod();
	}

	@Test
	@DisplayName("should be equal when all fields match")
	void shouldBeEqualWhenAllFieldsMatch() {
		final var key = createKey("key-id", true);

		final var a = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).key(key).build();
		final var b = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).key(key).build();

		assertThat(a).isEqualTo(b);
		assertThat(a.hashCode()).isEqualTo(b.hashCode());
	}

	@Test
	@DisplayName("should not be equal when fields differ")
	void shouldNotBeEqualWhenFieldsDiffer() {
		final var key = createKey("key-id", true);

		final var keyset = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).key(key).build();

		assertThat(keyset).isNotEqualTo(TestKeyset.builder()
			.name("other-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).key(key).build());

		assertThat(keyset).isNotEqualTo(TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).rotationInterval(Duration.ofDays(90)).key(key).build());
	}

	@Test
	@DisplayName("should include keyset fields in toString output")
	void shouldIncludeFieldsInToString() {
		final var keyset = TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).key(createKey("k", true)).build();

		assertThat(keyset.toString())
			.contains("TestKeyset")
			.contains("test-keyset")
			.contains(KeysetPurpose.ENCRYPTION.name());
	}

	@Test
	@DisplayName("should fail to build when keyset name is blank")
	void shouldFailToBuildWithBlankName() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek).key(createKey("k", true)).build())
			.withMessage("Keyset name can't be blank");
	}

	@Test
	@DisplayName("should fail to build when factory is null")
	void shouldFailToBuildWithNullFactory() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset").purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek).key(createKey("k", true)).build())
			.withMessage("Keyset factory can't be null");
	}

	@Test
	@DisplayName("should fail to build when purpose is null")
	void shouldFailToBuildWithNullPurpose() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset").factory("test-factory")
				.keyEncryptionKey(kek).key(createKey("k", true)).build())
			.withMessage("Keyset purpose can't be null");
	}

	@Test
	@DisplayName("should fail to build when key encryption key is null")
	void shouldFailToBuildWithNullKek() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
				.key(createKey("k", true)).build())
			.withMessage("Keyset key encryption key can't be null");
	}

	@Test
	@DisplayName("should fail to build when the keyset has no keys")
	void shouldFailToBuildWithNoKeys() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek).build())
			.withMessage("Keyset must have at least one key");
	}

	@Test
	@DisplayName("should reject a duplicate key id when using the key builder method")
	void shouldRejectDuplicateKeyIdViaKeyMethod() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.key(createKey("duplicate-id", true))
				.key(createKey("duplicate-id", false)))
			.withMessage("Key with id 'duplicate-id' already exists in this keyset");
	}

	@Test
	@DisplayName("should reject a duplicate key id when using the keys builder method")
	void shouldRejectDuplicateKeyIdViaKeysMethod() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder()
				.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
				.keyEncryptionKey(kek)
				.keys(List.of(createKey("duplicate-id", true), createKey("duplicate-id", false))))
			.withMessage("Key with id 'duplicate-id' already exists in this keyset");
	}

}
