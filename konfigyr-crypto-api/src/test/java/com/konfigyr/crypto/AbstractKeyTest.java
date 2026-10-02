package com.konfigyr.crypto;

import com.konfigyr.crypto.test.KeyAssert;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.crypto.test.TestKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class AbstractKeyTest {

	static final Instant now = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	@DisplayName("should set creation timestamp to current time by default")
	void shouldSetCreationTimestampByDefault() {
		final var before = Instant.now();

		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.build();

		assertThat(key.getCreatedAt()).isBetween(before, Instant.now());
	}

	@Test
	@DisplayName("should check if the key uses the given algorithm")
	void shouldCheckKeyAlgorithm() {
		final Algorithm other = mock(Algorithm.class);

		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.build();

		assertThat(key.isUsing(TestAlgorithm.INSTANCE))
			.as("key must use the algorithm it was created with")
			.isTrue();

		assertThat(key.isUsing(other))
			.as("key must not use a different algorithm")
			.isFalse();
	}

	@Test
	@DisplayName("should promote the key to be primary and reset its expiration time")
	void shouldPromoteKey() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(false)
			.createdAt(now)
			.expiresAt(now.plus(Duration.ofDays(90)))
			.build();

		final Instant expiresAt = now.plus(Duration.ofDays(120));

		KeyAssert.assertThat(TestKey.builder(key).promote(expiresAt).build())
			.hasId("key-id")
			.isPrimary()
			.isCreatedAt(now)
			.expiresAt(expiresAt);

		KeyAssert.assertThat(TestKey.builder(key).promote(null).build())
			.as("promoted key must not expire when automatic key rotation is disabled")
			.isPrimary()
			.expiresAt(null);
	}

	@Test
	@DisplayName("should demote the key and retain its expiration time")
	void shouldDemoteKey() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(now)
			.expiresAt(now.plus(Duration.ofDays(90)))
			.build();

		KeyAssert.assertThat(TestKey.builder(key).demote().build())
			.hasId("key-id")
			.isNotPrimary()
			.isCreatedAt(now)
			.expiresAt(now.plus(Duration.ofDays(90)));
	}

	@Test
	@DisplayName("should retire the key until the given destruction time")
	void shouldRetireKey() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build();

		KeyAssert.assertThat(TestKey.builder(key).demote().retire(now.plus(Duration.ofDays(30))).build())
			.hasId("key-id")
			.hasStatus(KeyStatus.RETIRED)
			.isNotPrimary()
			.destructionScheduledAt(now.plus(Duration.ofDays(30)));

		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKey.builder(key).retire(null))
			.withMessage("Retired key destruction time can't be null");
	}

	@Test
	@DisplayName("should build a key with all fields populated")
	void shouldBuildKeyWithAllFields() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(now)
			.initializedAt(now)
			.expiresAt(now.plusSeconds(3600))
			.destructionScheduledAt(now.plusSeconds(7200))
			.destroyedAt(null)
			.build();

		KeyAssert.assertThat(key)
			.hasId("key-id")
			.hasAlgorithm(TestAlgorithm.INSTANCE)
			.hasType(TestAlgorithm.INSTANCE.type())
			.hasStatus(KeyStatus.ENABLED)
			.isPrimary()
			.isCreatedAt(now)
			.isInitializedAt(now)
			.expiresAt(now.plusSeconds(3600))
			.destructionScheduledAt(now.plusSeconds(7200))
			.isDestroyedAt(null);
	}

	@Test
	@DisplayName("should use enabled() shorthand to set ENABLED status")
	void shouldUseEnabledShorthand() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.enabled()
			.createdAt(now)
			.build();

		KeyAssert.assertThat(key).isEnabled();
	}

	@Test
	@DisplayName("should use primary() shorthand to mark key as primary")
	void shouldUsePrimaryShorthand() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.enabled()
			.primary()
			.createdAt(now)
			.build();

		KeyAssert.assertThat(key).isPrimary();
	}

	@ValueSource(booleans = { true, false })
	@ParameterizedTest(name = "should be usable when key is ENABLED and primary flag is {0}")
	@DisplayName("should be usable for cryptographic operations when key is enabled")
	void shouldBeUsableWhenEnabled(boolean primary) {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(primary)
			.createdAt(now)
			.build();

		assertThat(key.isEnabled()).isTrue();
	}

	@EnumSource(value = KeyStatus.class, names = "ENABLED", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "should not be usable when key is {0}")
	@DisplayName("should not be usable for cryptographic operations when key is not enabled")
	void shouldNotBeUsableWhenNotEnabled(KeyStatus status) {
		final var primary = TestKey.builder()
			.id("primary-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary()
			.createdAt(now)
			.build();

		final var secondary = TestKey.builder(primary)
			.id("secondary-key")
			.primary(false)
			.build();

		assertThat(primary.isEnabled())
			.as("primary key in %s status must not be usable", status)
			.isFalse();

		assertThat(secondary.isEnabled())
			.as("non-primary key in %s status must not be usable", status)
			.isFalse();
	}

	@Test
	@DisplayName("should calculate expiry time from rotation interval")
	void shouldCalculateExpiryFromRotationInterval() {
		final var before = Instant.now();

		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.enabled()
			.createdAt(now)
			.expiresIn(Duration.ofDays(90))
			.build();

		assertThat(key.getExpiresAt())
			.isNotNull()
			.isBetween(before.plus(Duration.ofDays(90)), Instant.now().plus(Duration.ofDays(90)));
	}

	@Test
	@DisplayName("should set expiry time to null when rotation interval is null")
	void shouldSetExpiryToNullWhenRotationIntervalIsNull() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.enabled()
			.createdAt(now)
			.expiresIn(null)
			.build();

		KeyAssert.assertThat(key).expiresAt(null);
	}

	@Test
	@DisplayName("should calculate scheduled destruction time from grace period")
	void shouldCalculateDestructionTimeFromGracePeriod() {
		final var before = Instant.now();

		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.enabled()
			.createdAt(now)
			.scheduleDestructionIn(Duration.ofDays(30))
			.build();

		assertThat(key.getDestructionScheduledAt())
			.isNotNull()
			.isBetween(before.plus(Duration.ofDays(30)), Instant.now().plus(Duration.ofDays(30)));
	}

	@Test
	@DisplayName("should set scheduled destruction time to null when grace period is null")
	void shouldSetDestructionToNullWhenGracePeriodIsNull() {
		final var key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.enabled()
			.createdAt(now)
			.scheduleDestructionIn(null)
			.build();

		KeyAssert.assertThat(key).destructionScheduledAt(null);
	}

	@Test
	@DisplayName("should copy all fields using the copy constructor")
	void shouldCopyAllFieldsUsingCopyConstructor() {
		final var original = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(now)
			.initializedAt(now)
			.expiresAt(now.plusSeconds(3600))
			.build();

		final var copy = TestKey.builder(original).build();

		assertThat(copy).isEqualTo(original);
		assertThat(copy.hashCode()).isEqualTo(original.hashCode());
	}

	@Test
	@DisplayName("should be equal when all fields match")
	void shouldBeEqualWhenAllFieldsMatch() {
		final var a = TestKey.builder()
			.id("key-id").algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build();

		final var b = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build();

		assertThat(a).isEqualTo(b);
		assertThat(a.hashCode()).isEqualTo(b.hashCode());
	}

	@Test
	@DisplayName("should not be equal when fields differ")
	void shouldNotBeEqualWhenFieldsDiffer() {
		final var key = TestKey.builder()
			.id("key-id").algorithm(TestAlgorithm.INSTANCE).status(KeyStatus.ENABLED).createdAt(now).build();

		assertThat(key).isNotEqualTo(TestKey.builder()
			.id("other-id").algorithm(TestAlgorithm.INSTANCE).status(KeyStatus.ENABLED).createdAt(now).build());

		assertThat(key).isNotEqualTo(TestKey.builder()
			.id("key-id").algorithm(TestAlgorithm.INSTANCE).status(KeyStatus.DISABLED).createdAt(now).build());

		assertThat(key).isNotEqualTo(TestKey.builder()
			.id("key-id").algorithm(TestAlgorithm.INSTANCE).status(KeyStatus.ENABLED).primary(true).createdAt(now).build());
	}

	@Test
	@DisplayName("should include key fields in toString output")
	void shouldIncludeFieldsInToString() {
		final var key = TestKey.builder()
			.id("key-id").algorithm(TestAlgorithm.INSTANCE).status(KeyStatus.ENABLED).createdAt(now).build();

		assertThat(key.toString())
			.contains("TestKey")
			.contains("key-id")
			.contains(KeyStatus.ENABLED.name());
	}

	@Test
	@DisplayName("should fail to build when key identifier is null")
	void shouldFailToBuildWithNullId() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKey.builder()
				.algorithm(TestAlgorithm.INSTANCE)
				.status(KeyStatus.ENABLED)
				.createdAt(now)
				.build()
			).withMessage("Key identifier can't be null");
	}

	@Test
	@DisplayName("should fail to build when algorithm is null")
	void shouldFailToBuildWithNullAlgorithm() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKey.builder()
				.id("key-id").status(KeyStatus.ENABLED).createdAt(now).build())
			.withMessage("Key algorithm can't be null");
	}

	@Test
	@DisplayName("should fail to build when status is null")
	void shouldFailToBuildWithNullStatus() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKey.builder()
				.id("key-id").algorithm(TestAlgorithm.INSTANCE).createdAt(now).build())
			.withMessage("Key status can't be null");
	}

	@Test
	@DisplayName("should fail to build when creation timestamp is null")
	void shouldFailToBuildWithNullCreatedAt() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TestKey.builder()
				.id("key-id").algorithm(TestAlgorithm.INSTANCE).status(KeyStatus.ENABLED).createdAt(null).build())
			.withMessage("Key creation time can't be null");
	}

}
