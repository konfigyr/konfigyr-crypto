package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

class KeyTransitionTest {

	final KeysetDefinition definition = KeysetDefinition.of("test-keyset", TestAlgorithm.INSTANCE);

	@Test
	@DisplayName("should create a disable transition for an ENABLED key")
	void shouldCreateDisableTransition() {
		final EncryptedKeyset keyset = keyset(KeyStatus.ENABLED, null);

		assertThat(KeyTransition.disable(keyset, "key"))
			.isEqualTo(new KeyTransition("test-keyset", "key", KeyStatus.DISABLED, null, null, keyset.version()));
	}

	@Test
	@DisplayName("should create an enable transition for a DISABLED key")
	void shouldCreateEnableTransition() {
		final EncryptedKeyset keyset = keyset(KeyStatus.DISABLED, null);

		assertThat(KeyTransition.enable(keyset, "key"))
			.isEqualTo(new KeyTransition("test-keyset", "key", KeyStatus.ENABLED, null, null, keyset.version()));
	}

	@Test
	@DisplayName("should create a compromise transition for an ENABLED key")
	void shouldCreateCompromiseTransition() {
		final EncryptedKeyset keyset = keyset(KeyStatus.ENABLED, null);

		assertThat(KeyTransition.compromise(keyset, "key"))
			.isEqualTo(new KeyTransition("test-keyset", "key", KeyStatus.COMPROMISED, null, null, keyset.version()));
	}

	@Test
	@DisplayName("should keep the scheduled destruction time when compromising a PENDING_DESTRUCTION key")
	void shouldKeepDestructionScheduleWhenCompromising() {
		final Instant scheduledAt = Instant.now().plus(Duration.ofDays(7));
		final EncryptedKeyset keyset = keyset(KeyStatus.PENDING_DESTRUCTION, scheduledAt);

		assertThat(KeyTransition.compromise(keyset, "key"))
			.isEqualTo(new KeyTransition("test-keyset", "key", KeyStatus.COMPROMISED_PENDING_DESTRUCTION,
				scheduledAt, null, keyset.version()));
	}

	@Test
	@DisplayName("should resolve the schedule destruction target based on the current key status")
	void shouldCreateScheduleDestructionTransition() {
		final Instant scheduledAt = Instant.now().plus(Duration.ofDays(30));

		assertThat(KeyTransition.scheduleDestruction(keyset(KeyStatus.DISABLED, null), "key", scheduledAt))
			.returns(KeyStatus.PENDING_DESTRUCTION, KeyTransition::status)
			.returns(scheduledAt, KeyTransition::destructionScheduledAt)
			.returns(null, KeyTransition::destroyedAt);

		assertThat(KeyTransition.scheduleDestruction(keyset(KeyStatus.COMPROMISED, null), "key", scheduledAt))
			.returns(KeyStatus.COMPROMISED_PENDING_DESTRUCTION, KeyTransition::status)
			.returns(scheduledAt, KeyTransition::destructionScheduledAt)
			.returns(null, KeyTransition::destroyedAt);
	}

	@Test
	@DisplayName("should resolve the cancel destruction target based on the current key status")
	void shouldCreateCancelDestructionTransition() {
		final Instant scheduledAt = Instant.now().plus(Duration.ofDays(30));

		assertThat(KeyTransition.cancelDestruction(keyset(KeyStatus.PENDING_DESTRUCTION, scheduledAt), "key"))
			.returns(KeyStatus.DISABLED, KeyTransition::status)
			.returns(null, KeyTransition::destructionScheduledAt);

		assertThat(KeyTransition.cancelDestruction(keyset(KeyStatus.COMPROMISED_PENDING_DESTRUCTION, scheduledAt), "key"))
			.returns(KeyStatus.COMPROMISED, KeyTransition::status)
			.returns(null, KeyTransition::destructionScheduledAt);
	}

	@Test
	@DisplayName("should create a destroy transition for keys pending destruction")
	void shouldCreateDestroyTransition() {
		final Instant scheduledAt = Instant.now().minus(Duration.ofDays(1));
		final Instant destroyedAt = Instant.now();

		for (KeyStatus status : List.of(KeyStatus.PENDING_DESTRUCTION, KeyStatus.COMPROMISED_PENDING_DESTRUCTION)) {
			assertThat(KeyTransition.destroy(keyset(status, scheduledAt), "key", destroyedAt))
				.as("Expected a destroy transition for a %s key", status)
				.returns(KeyStatus.DESTROYED, KeyTransition::status)
				.returns(null, KeyTransition::destructionScheduledAt)
				.returns(destroyedAt, KeyTransition::destroyedAt);
		}
	}

	@Test
	@DisplayName("should not create a transition when the operation is not permitted from the current status")
	void shouldRejectOperationNotPermittedFromCurrentStatus() {
		final EncryptedKeyset keyset = keyset(KeyStatus.COMPROMISED, null);

		assertThatExceptionOfType(CryptoException.InvalidKeyStatusTransitionException.class)
			.isThrownBy(() -> KeyTransition.enable(keyset, "key"))
			.returns("test-keyset", CryptoException.KeysetException::getName)
			.returns("key", CryptoException.InvalidKeyStatusTransitionException::getKeyId)
			.returns(KeyStatus.Operation.ENABLE, CryptoException.InvalidKeyStatusTransitionException::getOperation)
			.returns(KeyStatus.COMPROMISED, CryptoException.InvalidKeyStatusTransitionException::getCurrentStatus)
			.withMessageContaining("ENABLE")
			.withMessageContaining("COMPROMISED");
	}

	@Test
	@DisplayName("should not create a transition for a key that does not exist in the keyset")
	void shouldRejectUnknownKey() {
		final EncryptedKeyset keyset = keyset(KeyStatus.ENABLED, null);

		assertThatExceptionOfType(CryptoException.KeyNotFoundException.class)
			.isThrownBy(() -> KeyTransition.disable(keyset, "missing-key"))
			.returns("test-keyset", CryptoException.KeyNotFoundException::getName)
			.returns("missing-key", CryptoException.KeyNotFoundException::getKeyId);
	}

	private EncryptedKeyset keyset(KeyStatus status, @Nullable Instant destructionScheduledAt) {
		final EncryptedKey key = EncryptedKey.builder()
			.id("key")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(true)
			.createdAt(Instant.now())
			.destructionScheduledAt(destructionScheduledAt)
			.build(ByteArray.fromString("key-material"));

		return EncryptedKeyset.builder(definition)
			.provider(TestKeyEncryptionKey.INSTANCE.getProvider())
			.keyEncryptionKey(TestKeyEncryptionKey.INSTANCE.getId())
			.build(List.of(key));
	}

}
