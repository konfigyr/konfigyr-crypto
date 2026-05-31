package com.konfigyr.crypto.test;

import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("KeyAssert")
class KeyAssertTest {

	TestKey key;

	@BeforeEach
	void setup() {
		key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary()
			.createdAt(Instant.EPOCH)
			.initializedAt(Instant.EPOCH)
			.build();
	}

	@Test
	@DisplayName("hasId passes when identifier matches")
	void hasIdPassesWhenIdentifierMatches() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).hasId("key-id"));
	}

	@Test
	@DisplayName("hasId fails when identifier does not match")
	void hasIdFailsWhenIdentifierDoesNotMatch() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).hasId("other-id"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasAlgorithm passes when algorithm matches")
	void hasAlgorithmPassesWhenAlgorithmMatches() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).hasAlgorithm(TestAlgorithm.INSTANCE));
	}

	@Test
	@DisplayName("hasAlgorithm fails when algorithm does not match")
	void hasAlgorithmFailsWhenAlgorithmDoesNotMatch() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).hasAlgorithm(null))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasType passes when key type matches")
	void hasTypePassesWhenKeyTypeMatches() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).hasType(KeyType.OCTET));
	}

	@Test
	@DisplayName("hasType fails when key type does not match")
	void hasTypeFailsWhenKeyTypeDoesNotMatch() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).hasType(KeyType.EC))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isEnabled passes when key is ENABLED")
	void isEnabledPassesWhenKeyIsEnabled() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).isEnabled());
	}

	@Test
	@DisplayName("isEnabled fails when key is not ENABLED")
	void isEnabledFailsWhenKeyIsNotEnabled() {
		final TestKey disabled = TestKey.builder(key).status(KeyStatus.DISABLED).build();
		assertThatThrownBy(() -> KeyAssert.assertThat(disabled).isEnabled())
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasStatus passes when status matches")
	void hasStatusPassesWhenStatusMatches() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).hasStatus(KeyStatus.ENABLED));
	}

	@Test
	@DisplayName("hasStatus fails when status does not match")
	void hasStatusFailsWhenStatusDoesNotMatch() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).hasStatus(KeyStatus.DISABLED))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isPrimary passes when key is primary")
	void isPrimaryPassesWhenKeyIsPrimary() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).isPrimary());
	}

	@Test
	@DisplayName("isNotPrimary fails when key is primary")
	void isNotPrimaryFailsWhenKeyIsPrimary() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).isNotPrimary())
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isNotPrimary passes when key is not primary")
	void isNotPrimaryPassesWhenKeyIsNotPrimary() {
		final TestKey nonPrimary = TestKey.builder(key).primary(false).build();
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(nonPrimary).isNotPrimary());
	}

	@Test
	@DisplayName("isCreatedAt passes when timestamp matches exactly")
	void isCreatedAtPassesWhenTimestampMatchesExactly() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).isCreatedAt(Instant.EPOCH));
	}

	@Test
	@DisplayName("isCreatedAt passes when timestamp is within tolerance")
	void isCreatedAtPassesWhenTimestampIsWithinTolerance() {
		final TestKey recent = TestKey.builder(key).createdAt(Instant.now()).build();
		assertThatNoException().isThrownBy(() ->
			KeyAssert.assertThat(recent).isCreatedAt(Instant.now(), Duration.ofSeconds(1)));
	}

	@Test
	@DisplayName("isCreatedAt fails when timestamp differs from expected")
	void isCreatedAtFailsWhenTimestampDiffersFromExpected() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).isCreatedAt(Instant.now()))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("expiresAt passes when key has no expiry and null is expected")
	void expiresAtPassesWhenNullExpected() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).expiresAt(null));
	}

	@Test
	@DisplayName("expiresAt fails when key has no expiry but a timestamp is expected")
	void expiresAtFailsWhenKeyHasNoExpiry() {
		assertThatThrownBy(() -> KeyAssert.assertThat(key).expiresAt(Instant.now()))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isDestroyedAt passes when key has no destroyed timestamp and null is expected")
	void isDestroyedAtPassesWhenNullExpected() {
		assertThatNoException().isThrownBy(() -> KeyAssert.assertThat(key).isDestroyedAt(null));
	}

}
