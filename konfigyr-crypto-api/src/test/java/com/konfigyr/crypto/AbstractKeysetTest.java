package com.konfigyr.crypto;

import com.konfigyr.crypto.test.KeyAssert;
import com.konfigyr.crypto.test.KeysetAssert;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.crypto.test.TestKey;
import com.konfigyr.crypto.test.TestKeyset;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

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

	static TestKey key(String id, boolean primary, KeyStatus status, Instant createdAt) {
		return TestKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(primary)
			.createdAt(createdAt)
			.expiresAt(createdAt.plus(Duration.ofDays(90)))
			.build();
	}

	static TestKeyset keyset(Duration rotationInterval, TestKey... keys) {
		return TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.rotationInterval(rotationInterval)
			.keys(List.of(keys))
			.build();
	}

	static void assertGeneratedNewPrimary(Keyset original, Keyset rotated) {
		KeysetAssert.assertThat(rotated)
			.hasSize(original.size() + 1);

		assertThat(original.getKey(rotated.getPrimary().getId()))
			.as("rotated keyset must have a newly generated primary key")
			.isEmpty();

		assertThat(rotated.getKey(original.getPrimary().getId()))
			.hasValueSatisfying(demoted -> KeyAssert.assertThat(demoted).isNotPrimary());
	}

	static TestKeyset createKeyset(TestKey... keys) {
		return TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.keys(List.of(keys))
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
			.rotationLeadTime(Duration.ofDays(30))
			.destructionGracePeriod(Duration.ofDays(30))
			.retirementPolicy(RetirementPolicy.DESTROY)
			.key(primaryKey)
			.key(secondKey)
			.build();

		KeysetAssert.assertThat(keyset)
			.hasName("test-keyset")
			.createdByFactory("test-factory")
			.hasPurpose(KeysetPurpose.ENCRYPTION)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(Duration.ofDays(90))
			.hasRotationLeadTime(Duration.ofDays(30))
			.hasDestructionGracePeriod(Duration.ofDays(30))
			.hasRetirementPolicy(RetirementPolicy.DESTROY)
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
			.hasNoRotationLeadTime()
			.hasNoDestructionGracePeriod()
			.hasRetirementPolicy(RetirementPolicy.RETAIN);
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
			.rotationLeadTime(Duration.ofDays(30))
			.destructionGracePeriod(Duration.ofDays(30))
			.retirementPolicy(RetirementPolicy.DESTROY)
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
			.rotationLeadTime(Duration.ofDays(30))
			.destructionGracePeriod(Duration.ofDays(30))
			.retirementPolicy(RetirementPolicy.SCHEDULE_DESTRUCTION)
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
			.hasRotationLeadTime(Duration.ofDays(30))
			.hasDestructionGracePeriod(Duration.ofDays(30))
			.hasRetirementPolicy(RetirementPolicy.SCHEDULE_DESTRUCTION);
	}

	@Test
	@DisplayName("should return the primary key from the keyset")
	void shouldReturnPrimaryKey() {
		final var primaryKey = createKey("primary-key", true);
		final var otherKey = createKey("other-key", false);

		final var keyset = createKeyset(primaryKey, otherKey);

		KeyAssert.assertThat(keyset.getPrimary()).hasId("primary-key").isPrimary();
	}

	@Test
	@DisplayName("should throw when no primary key is present in the keyset")
	void shouldThrowWhenNoPrimaryKeyPresent() {
		final var keyset = createKeyset(createKey("non-primary-key", false));

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(keyset::getPrimary)
			.withMessageContaining("has no primary key")
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should return the primary key when it is enabled")
	void shouldReturnEnabledPrimaryKey() {
		final var keyset = createKeyset(createKey("primary-key", true), createKey("other-key", false));

		KeyAssert.assertThat(keyset.requireActivePrimary())
			.hasId("primary-key")
			.isPrimary()
			.isEnabled();
	}

	@MethodSource("blockedStatuses")
	@ParameterizedTest(name = "should throw {1} when the primary key is {0}")
	@DisplayName("should throw a status specific exception when the primary key is not usable")
	void shouldThrowWhenPrimaryKeyIsNotUsable(KeyStatus status, Class<? extends CryptoException.KeysetException> type) {
		final var keyset = createKeyset(createKey("primary-key", true, status), createKey("other-key", false));

		assertThat(keyset.getPrimary()).isNotNull();

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(keyset::requireActivePrimary)
			.isExactlyInstanceOf(type)
			.withMessageStartingWith("Primary key 'primary-key' in keyset 'test-keyset'")
			.returns("test-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should return a non-primary key by its identifier when it is enabled")
	void shouldReturnEnabledKeyById() {
		final var keyset = createKeyset(createKey("primary-key", true), createKey("other-key", false));

		KeyAssert.assertThat(keyset.requireUsableKey("other-key"))
			.hasId("other-key")
			.isNotPrimary()
			.isEnabled();
	}

	@MethodSource("blockedStatuses")
	@ParameterizedTest(name = "should throw {1} when a non-primary key is {0}")
	@DisplayName("should throw a status specific exception when a non-primary key is not usable")
	void shouldThrowWhenKeyIsNotUsable(KeyStatus status, Class<? extends CryptoException.KeysetException> type) {
		final var blocked = createKey("other-key", false, status);
		final var keyset = createKeyset(createKey("primary-key", true), blocked);

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> keyset.requireUsableKey("other-key"))
			.isExactlyInstanceOf(type)
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset'")
			.returns("test-keyset", CryptoException.KeysetException::getName);

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> keyset.requireUsableKey(blocked))
			.isExactlyInstanceOf(type)
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset'");

		assertThat(keyset.getKeys())
			.as("blocked keys must still be listed by the keyset")
			.hasSize(2)
			.contains(blocked);
	}

	@Test
	@DisplayName("should expose the identifier of the key that is not usable")
	void shouldExposeKeyIdentifier() {
		assertThatExceptionOfType(CryptoException.KeysetCompromisedException.class)
			.isThrownBy(() -> keysetWithKeyInStatus(KeyStatus.COMPROMISED).requireUsableKey("other-key"))
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset' is compromised")
			.returns("other-key", CryptoException.KeysetCompromisedException::getKeyId);

		assertThatExceptionOfType(CryptoException.KeysetCompromisedException.class)
			.isThrownBy(() -> keysetWithKeyInStatus(KeyStatus.COMPROMISED_PENDING_DESTRUCTION).requireUsableKey("other-key"))
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset' is compromised")
			.returns("other-key", CryptoException.KeysetCompromisedException::getKeyId);

		assertThatExceptionOfType(CryptoException.KeysetDisabledException.class)
			.isThrownBy(() -> keysetWithKeyInStatus(KeyStatus.DISABLED).requireUsableKey("other-key"))
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset' is disabled")
			.returns("other-key", CryptoException.KeysetDisabledException::getKeyId);

		assertThatExceptionOfType(CryptoException.KeysetPendingDestructionException.class)
			.isThrownBy(() -> keysetWithKeyInStatus(KeyStatus.PENDING_DESTRUCTION).requireUsableKey("other-key"))
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset' is pending destruction")
			.returns("other-key", CryptoException.KeysetPendingDestructionException::getKeyId);

		assertThatExceptionOfType(CryptoException.KeysetDestroyedException.class)
			.isThrownBy(() -> keysetWithKeyInStatus(KeyStatus.DESTROYED).requireUsableKey("other-key"))
			.withMessageStartingWith("Key 'other-key' in keyset 'test-keyset' has been permanently destroyed")
			.returns("other-key", CryptoException.KeysetDestroyedException::getKeyId);
	}

	@EnumSource(value = KeyStatus.class, names = { "INITIALIZING", "INITIALIZATION_FAILED", "DESTRUCTION_FAILED" })
	@ParameterizedTest(name = "should expose the {0} status of the unavailable key")
	@DisplayName("should expose the status of the key that is unavailable")
	void shouldExposeUnavailableKeyStatus(KeyStatus status) {
		final var keyset = createKeyset(createKey("primary-key", true, status), createKey("other-key", false, status));

		assertThatExceptionOfType(CryptoException.KeysetUnavailableException.class)
			.isThrownBy(keyset::requireActivePrimary)
			.returns("test-keyset", CryptoException.KeysetException::getName)
			.returns(status, CryptoException.KeysetUnavailableException::getStatus);

		assertThatExceptionOfType(CryptoException.KeysetUnavailableException.class)
			.isThrownBy(() -> keyset.requireUsableKey("other-key"))
			.returns(status, CryptoException.KeysetUnavailableException::getStatus);
	}

	@Test
	@DisplayName("should throw KeyNotFoundException when requiring a key that does not exist")
	void shouldThrowWhenRequiredKeyDoesNotExist() {
		final var keyset = createKeyset(createKey("primary-key", true));

		assertThatExceptionOfType(CryptoException.KeyNotFoundException.class)
			.isThrownBy(() -> keyset.requireUsableKey("missing"))
			.returns("test-keyset", CryptoException.KeysetException::getName)
			.returns("missing", CryptoException.KeyNotFoundException::getKeyId);
	}

	@EnumSource(value = KeyStatus.class, names = "ENABLED", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "should allow rotation when the primary key is {0}")
	@DisplayName("should allow rotation when the primary key is not usable")
	void shouldAllowRotationWhenPrimaryKeyIsNotUsable(KeyStatus status) {
		final var keyset = createKeyset(createKey("primary-key", true, status));

		assertThat(keyset.rotate(KeyDefinition.of(TestAlgorithm.INSTANCE)))
			.isNotNull();
	}

	static TestKeyset keysetWithKeyInStatus(KeyStatus status) {
		return createKeyset(createKey("primary-key", true), createKey("other-key", false, status));
	}

	static Stream<Arguments> statusExceptions() {
		return Stream.of(
			Arguments.of(KeyStatus.COMPROMISED, CryptoException.KeysetCompromisedException.class),
			Arguments.of(KeyStatus.COMPROMISED_PENDING_DESTRUCTION, CryptoException.KeysetCompromisedException.class),
			Arguments.of(KeyStatus.DISABLED, CryptoException.KeysetDisabledException.class),
			Arguments.of(KeyStatus.PENDING_DESTRUCTION, CryptoException.KeysetPendingDestructionException.class),
			Arguments.of(KeyStatus.DESTROYED, CryptoException.KeysetDestroyedException.class)
		);
	}

	static Stream<Arguments> blockedStatuses() {
		return Stream.concat(statusExceptions(), Stream.of(
			Arguments.of(KeyStatus.INITIALIZING, CryptoException.KeysetUnavailableException.class),
			Arguments.of(KeyStatus.INITIALIZATION_FAILED, CryptoException.KeysetUnavailableException.class),
			Arguments.of(KeyStatus.DESTRUCTION_FAILED, CryptoException.KeysetUnavailableException.class)
		));
	}

	@Test
	@DisplayName("should find a key by its identifier")
	void shouldFindKeyById() {
		final var primaryKey = createKey("primary-key", true);
		final var otherKey = createKey("other-key", false);

		final var keyset = createKeyset(primaryKey, otherKey);

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
	@DisplayName("should build a keyset from a definition with rotation lead time")
	void shouldBuildKeysetFromDefinitionWithRotationLeadTime() {
		final var definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(TestAlgorithm.INSTANCE)
			.rotationLeadTime(Duration.ofDays(30))
			.build();

		final var keyset = TestKeyset.builder(definition)
			.keyEncryptionKey(kek)
			.key(createKey("primary-key", true))
			.build();

		KeysetAssert.assertThat(keyset)
			.matchesDefinition(definition)
			.hasRotationLeadTime(Duration.ofDays(30));

		assertThat(KeysetDefinition.builder(keyset).algorithm(TestAlgorithm.INSTANCE).build())
			.as("definition created from the keyset must retain the rotation lead time")
			.isEqualTo(definition);
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
	@DisplayName("should promote the next key to be the primary key when rotating the keyset")
	void shouldPromoteNextKeyOnRotation() {
		final TestKey previous = key("previous", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(200)));
		final TestKey primary = key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90)));
		final TestKey next = key("next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(1)));

		final var keyset = keyset(Duration.ofDays(90), previous, primary, next);

		assertThat(keyset.getNextKey())
			.hasValue(next);

		final Keyset rotated = keyset.rotate();

		KeysetAssert.assertThat(rotated)
			.hasSize(3);

		KeyAssert.assertThat(rotated.getPrimary())
			.hasId("next")
			.isPrimary()
			.isEnabled();

		assertThat(rotated.getPrimary().getExpiresAt())
			.as("promoted key must expire one rotation interval after its promotion")
			.isCloseTo(Instant.now().plus(Duration.ofDays(90)), within(Duration.ofSeconds(5)));

		assertThat(rotated.getKey("primary"))
			.hasValueSatisfying(demoted -> KeyAssert.assertThat(demoted).isNotPrimary().isEnabled());

		assertThat(rotated.getKey("previous"))
			.get()
			.isEqualTo(previous);
	}

	@Test
	@DisplayName("should promote the next key without an expiration time when automatic rotation is disabled")
	void shouldPromoteNextKeyWithoutRotationInterval() {
		final var keyset = keyset(null,
			key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90))),
			key("next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(1)))
		);

		final Key promoted = keyset.rotate(KeyDefinition.of(TestAlgorithm.INSTANCE)).getPrimary();

		KeyAssert.assertThat(promoted)
			.hasId("next");

		assertThat(promoted.getExpiresAt())
			.isNull();
	}

	@Test
	@DisplayName("should promote the most recently created next key when there is more than one")
	void shouldPromoteMostRecentNextKey() {
		final var keyset = keyset(Duration.ofDays(90),
			key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90))),
			key("older-next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(20))),
			key("newer-next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(10)))
		);

		KeyAssert.assertThat(keyset.rotate().getPrimary())
			.hasId("newer-next");
	}

	@EnumSource(value = KeyStatus.class, names = "ENABLED", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "next key status: {0}")
	@DisplayName("should generate a new primary key when the next key is not enabled")
	void shouldNotPromoteNextKeyThatIsNotEnabled(KeyStatus status) {
		final var keyset = keyset(Duration.ofDays(90),
			key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90))),
			key("next", false, status, now.minus(Duration.ofDays(1)))
		);

		assertThat(keyset.getNextKey())
			.isEmpty();

		assertGeneratedNewPrimary(keyset, keyset.rotate());
	}

	@Test
	@DisplayName("should generate a new primary key when the keyset only contains older keys")
	void shouldNotPromoteKeysCreatedBeforePrimary() {
		final var keyset = keyset(Duration.ofDays(90),
			key("previous", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(200))),
			key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90)))
		);

		assertThat(keyset.getNextKey())
			.isEmpty();

		assertGeneratedNewPrimary(keyset, keyset.rotate());
	}

	@EnumSource(value = KeyStatus.class, names = "ENABLED", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "primary key status: {0}")
	@DisplayName("should generate a new primary key instead of promoting the next key when the primary is not enabled")
	void shouldNotPromoteNextKeyWhenPrimaryIsNotEnabled(KeyStatus status) {
		final var keyset = keyset(Duration.ofDays(90),
			key("primary", true, status, now.minus(Duration.ofDays(90))),
			key("next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(1)))
		);

		final Keyset rotated = keyset.rotate();

		assertGeneratedNewPrimary(keyset, rotated);

		assertThat(rotated.getKey("next"))
			.hasValueSatisfying(next -> KeyAssert.assertThat(next).isNotPrimary().isEnabled());
	}

	@Test
	@DisplayName("should generate a new primary key when the next key uses a different algorithm")
	void shouldNotPromoteNextKeyWithDifferentAlgorithm() {
		final Algorithm algorithm = mock(Algorithm.class);
		doReturn(KeysetPurpose.ENCRYPTION).when(algorithm).purpose();

		final var keyset = keyset(Duration.ofDays(90),
			key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90))),
			key("next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(1)))
		);

		final Keyset rotated = keyset.rotate(KeyDefinition.of(algorithm));

		assertGeneratedNewPrimary(keyset, rotated);

		KeyAssert.assertThat(rotated.getPrimary())
			.hasAlgorithm(algorithm);
	}

	@Test
	@DisplayName("should add a new non-primary key without promoting the next key")
	void shouldNotPromoteNextKeyWhenAddingNonPrimaryKey() {
		final var keyset = keyset(Duration.ofDays(90),
			key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90))),
			key("next", false, KeyStatus.ENABLED, now.minus(Duration.ofDays(1)))
		);

		final Keyset rotated = keyset.rotate(KeyDefinition.builder()
			.algorithm(TestAlgorithm.INSTANCE)
			.primary(false)
			.build());

		KeysetAssert.assertThat(rotated)
			.hasSize(3);

		KeyAssert.assertThat(rotated.getPrimary())
			.hasId("primary");
	}

	@Test
	@DisplayName("should rotate the keyset with a lead time when there is no next key")
	void shouldRotateKeysetWithLeadTimeWithoutNextKey() {
		final var keyset = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek)
			.rotationInterval(Duration.ofDays(90))
			.rotationLeadTime(Duration.ofDays(30))
			.key(key("primary", true, KeyStatus.ENABLED, now.minus(Duration.ofDays(90))))
			.build();

		assertGeneratedNewPrimary(keyset, keyset.rotate());
	}

	@Test
	@DisplayName("should fail to rotate keyset with an unsupported algorithm")
	void shouldFailToRotateWithUnsupportedAlgorithm() {
		final var keyset = TestKeyset.builder()
			.name("test-keyset")
			.factory("test-factory")
			.purpose(KeysetPurpose.SIGNING)
			.keyEncryptionKey(kek)
			.key(createKey("primary-key", true))
			.build();

		assertThatExceptionOfType(CryptoException.UnsupportedAlgorithmException.class)
			.isThrownBy(() -> keyset.rotate(KeyDefinition.of(TestAlgorithm.INSTANCE)))
			.withMessage("Unsupported algorithm: %s", TestAlgorithm.INSTANCE)
			.returns(TestAlgorithm.INSTANCE, CryptoException.UnsupportedAlgorithmException::getAlgorithm);
	}

	@Test
	@DisplayName("should be equal when all fields match")
	void shouldBeEqualWhenAllFieldsMatch() {
		final var key = createKey("key-id", true);

		final var a = createKeyset(key);
		final var b = createKeyset(key);

		assertThat(a).isEqualTo(b);
		assertThat(a.hashCode()).isEqualTo(b.hashCode());
	}

	@Test
	@DisplayName("should not be equal when fields differ")
	void shouldNotBeEqualWhenFieldsDiffer() {
		final var key = createKey("key-id", true);

		final var keyset = createKeyset(key);

		assertThat(keyset).isNotEqualTo(TestKeyset.builder()
			.name("other-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).key(key).build());

		assertThat(keyset).isNotEqualTo(TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).rotationInterval(Duration.ofDays(90)).key(key).build());

		assertThat(keyset).isNotEqualTo(TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).rotationLeadTime(Duration.ofDays(30)).key(key).build());

		assertThat(keyset).isNotEqualTo(TestKeyset.builder()
			.name("test-keyset").factory("test-factory").purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(kek).retirementPolicy(RetirementPolicy.DESTROY).key(key).build());
	}

	@Test
	@DisplayName("should build a keyset from a definition with a retirement policy")
	void shouldBuildKeysetFromDefinitionWithRetirementPolicy() {
		final var definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(TestAlgorithm.INSTANCE)
			.retirementPolicy(RetirementPolicy.DESTROY)
			.build();

		final var keyset = TestKeyset.builder(definition)
			.keyEncryptionKey(kek)
			.key(createKey("primary-key", true))
			.build();

		KeysetAssert.assertThat(keyset)
			.matchesDefinition(definition)
			.hasRetirementPolicy(RetirementPolicy.DESTROY);

		assertThat(KeysetDefinition.builder(keyset).algorithm(TestAlgorithm.INSTANCE).build())
			.as("definition created from the keyset must retain the retirement policy")
			.isEqualTo(definition);
	}

	@Test
	@DisplayName("should reject a null retirement policy")
	@SuppressWarnings("DataFlowIssue")
	void shouldRejectNullRetirementPolicy() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKeyset.builder().retirementPolicy(null))
			.withMessage("Keyset retirement policy can't be null");
	}

	@Test
	@DisplayName("should include keyset fields in toString output")
	void shouldIncludeFieldsInToString() {
		final var keyset = createKeyset(createKey("k", true));

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
