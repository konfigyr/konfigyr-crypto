package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.function.Function;

/**
 * Immutable value object that describes a single key-version lifecycle transition within a
 * {@link KeysetRepository}.
 * <p>
 * A {@code KeyTransition} carries the keyset name, key identifier, target {@link KeyStatus},
 * and the two optional timestamps ({@link #destructionScheduledAt () destructionScheduledAt}
 * and {@link #destroyedAt () destroyedAt}) that are set or cleared as part of the transition.
 * <p>
 * Instances must be created through one of the static factory methods. Each factory encodes
 * the semantics of exactly one lifecycle {@link KeyStatus.Operation} and ensures that only the timestamp fields
 * relevant to that edge are populated, preventing callers from constructing an inconsistent
 * combination of status and timestamps:
 *
 * <pre>{@code
 * // ENABLED → DISABLED
 * KeyTransition.disable(encryptedKeyset, keyId);
 *
 * // DISABLED | RETIRED → ENABLED
 * KeyTransition.enable(encryptedKeyset, keyId);
 *
 * // ENABLED | DISABLED → COMPROMISED, RETIRED | PENDING_DESTRUCTION → COMPROMISED_PENDING_DESTRUCTION
 * KeyTransition.compromise(encryptedKeyset, keyId);
 *
 * // DISABLED | RETIRED → PENDING_DESTRUCTION, COMPROMISED → COMPROMISED_PENDING_DESTRUCTION
 * KeyTransition.scheduleDestruction(encryptedKeyset, keyId, destructionTime);
 *
 * // PENDING_DESTRUCTION → DISABLED, COMPROMISED_PENDING_DESTRUCTION → COMPROMISED
 * KeyTransition.cancelDestruction(encryptedKeyset, keyId);
 *
 * // RETIRED | PENDING_DESTRUCTION | COMPROMISED_PENDING_DESTRUCTION → DESTROYED (key material erased)
 * KeyTransition.destroy(encryptedKeyset, keyId, Instant.now());
 * }</pre>
 * <p>
 * Every factory resolves the target status by applying its {@link KeyStatus.Operation} to the
 * current status of the key in the given keyset via {@link KeyStatus#next(KeyStatus.Operation)},
 * which keeps the {@link KeyStatus} state machine the single source of truth. When the operation
 * is not permitted from the current status, the factory throws a
 * {@link CryptoException.InvalidKeyStatusTransitionException} and no transition is created.
 *
 * @param keysetName             The name of the keyset that contains the key being transitioned.
 * @param keyId                  The identifier of the key version being transitioned.
 * @param status                 The target {@link KeyStatus} to assign to the key version.
 * @param destructionScheduledAt The time at which the key is scheduled for destruction. Populated when transitioning
 *                               to {@link KeyStatus#PENDING_DESTRUCTION} or
 *                               {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION}; {@code null} for all other
 *                               transitions.
 * @param destroyedAt            The time at which the key material was permanently erased. Populated when transitioning
 *                               to {@link KeyStatus#DESTROYED}; {@code null} for all other transitions.
 * @param keysetVersion          The expected {@link EncryptedKeyset#version() keyset version} against which the
 *                               repository should guard when applying this transition.
 *                               <p>
 *                               Implementations of {@link KeysetRepository} that apply transitions should reject
 *                               the update when the stored version no longer matches this value and throw
 *                               {@link CryptoException.KeysetConcurrentModificationException}.
 * @author Vladimir Spasic
 * @see KeysetRepository#updateKeyStatus(KeyTransition)
 * @see KeysetStore
 * @since 1.0.0
 */
@NullMarked
public record KeyTransition(
	String keysetName,
	String keyId,
	KeyStatus status,
	@Nullable Instant destructionScheduledAt,
	@Nullable Instant destroyedAt,
	long keysetVersion
) {

	/**
	 * Creates a transition that applies the {@link KeyStatus.Operation#DISABLE} operation, moving
	 * a key from {@link KeyStatus#ENABLED} to {@link KeyStatus#DISABLED}.
	 *
	 * @param keyset the keyset containing the key, can't be {@literal null}
	 * @param keyId  the identifier of the key to disable, can't be {@literal null}
	 * @return the transition, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException when no key with the given identifier exists in the keyset
	 * @throws CryptoException.InvalidKeyStatusTransitionException when the operation is not permitted
	 *         from the current status of the key
	 */
	public static KeyTransition disable(EncryptedKeyset keyset, String keyId) {
		return create(keyset, keyId, KeyStatus.Operation.DISABLE, key -> null, null);
	}

	/**
	 * Creates a transition that applies the {@link KeyStatus.Operation#ENABLE} operation, moving
	 * a key from {@link KeyStatus#DISABLED} or {@link KeyStatus#RETIRED} to {@link KeyStatus#ENABLED}.
	 * The scheduled destruction time of a retired key is cleared.
	 *
	 * @param keyset the keyset containing the key, can't be {@literal null}
	 * @param keyId  the identifier of the key to re-enable, can't be {@literal null}
	 * @return the transition, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException when no key with the given identifier exists in the keyset
	 * @throws CryptoException.InvalidKeyStatusTransitionException when the operation is not permitted
	 *         from the current status of the key
	 */
	public static KeyTransition enable(EncryptedKeyset keyset, String keyId) {
		return create(keyset, keyId, KeyStatus.Operation.ENABLE, key -> null, null);
	}

	/**
	 * Creates a transition that applies the {@link KeyStatus.Operation#COMPROMISE} operation.
	 * <p>
	 * A key in {@link KeyStatus#ENABLED} or {@link KeyStatus#DISABLED} state is moved to
	 * {@link KeyStatus#COMPROMISED}. A key that is in {@link KeyStatus#RETIRED} or
	 * {@link KeyStatus#PENDING_DESTRUCTION} is moved to {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION},
	 * keeping its existing
	 * {@link EncryptedKey#destructionScheduledAt() scheduled destruction time}.
	 * <p>
	 * This is an emergency transition. Once compromised, the key cannot be re-enabled or
	 * used for any cryptographic operation. Key material should subsequently be scheduled
	 * for destruction via {@link KeysetStore#scheduleDestruction(String, String)}.
	 *
	 * @param keyset the keyset containing the key, can't be {@literal null}
	 * @param keyId  the identifier of the key to mark as compromised, can't be {@literal null}
	 * @return the transition, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException when no key with the given identifier exists in the keyset
	 * @throws CryptoException.InvalidKeyStatusTransitionException when the operation is not permitted
	 *         from the current status of the key
	 */
	public static KeyTransition compromise(EncryptedKeyset keyset, String keyId) {
		// keys that are not pending destruction have no schedule, so the existing value can always be kept
		return create(keyset, keyId, KeyStatus.Operation.COMPROMISE, EncryptedKey::destructionScheduledAt, null);
	}

	/**
	 * Creates a transition that applies the {@link KeyStatus.Operation#SCHEDULE_DESTRUCTION}
	 * operation, recording the scheduled destruction time.
	 * <p>
	 * A {@link KeyStatus#DISABLED} or {@link KeyStatus#RETIRED} key is moved to
	 * {@link KeyStatus#PENDING_DESTRUCTION}, a
	 * {@link KeyStatus#COMPROMISED} key is moved to {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION}.
	 *
	 * @param keyset                 the keyset containing the key, can't be {@literal null}
	 * @param keyId                  the identifier of the key to schedule for destruction, can't be {@literal null}
	 * @param destructionScheduledAt the time at which the key should be destroyed,
	 *                               can't be {@literal null}
	 * @return the transition, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException when no key with the given identifier exists in the keyset
	 * @throws CryptoException.InvalidKeyStatusTransitionException when the operation is not permitted
	 *         from the current status of the key
	 */
	public static KeyTransition scheduleDestruction(
		EncryptedKeyset keyset, String keyId, Instant destructionScheduledAt) {
		return create(keyset, keyId, KeyStatus.Operation.SCHEDULE_DESTRUCTION, key -> destructionScheduledAt, null);
	}

	/**
	 * Creates a transition that applies the {@link KeyStatus.Operation#CANCEL_DESTRUCTION}
	 * operation, clearing the previously scheduled destruction time.
	 * <p>
	 * A {@link KeyStatus#PENDING_DESTRUCTION} key is moved back to {@link KeyStatus#DISABLED}, a
	 * {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION} key is moved back to {@link KeyStatus#COMPROMISED}.
	 *
	 * @param keyset the keyset containing the key, can't be {@literal null}
	 * @param keyId  the identifier of the key whose destruction should be canceled,
	 *               can't be {@literal null}
	 * @return the transition, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException when no key with the given identifier exists in the keyset
	 * @throws CryptoException.InvalidKeyStatusTransitionException when the operation is not permitted
	 *         from the current status of the key
	 */
	public static KeyTransition cancelDestruction(EncryptedKeyset keyset, String keyId) {
		return create(keyset, keyId, KeyStatus.Operation.CANCEL_DESTRUCTION, key -> null, null);
	}

	/**
	 * Creates a transition that applies the {@link KeyStatus.Operation#DESTROY} operation, moving
	 * a key from {@link KeyStatus#RETIRED}, {@link KeyStatus#PENDING_DESTRUCTION} or
	 * {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION} to {@link KeyStatus#DESTROYED}.
	 * <p>
	 * The key material ({@link EncryptedKey#data()}) is erased — set to {@code null} — by
	 * the repository when this transition is applied. The row itself is kept for audit purposes.
	 *
	 * @param keyset      the keyset containing the key, can't be {@literal null}
	 * @param keyId       the identifier of the key to destroy, can't be {@literal null}
	 * @param destroyedAt the instant at which the key material was erased, can't be
	 *                    {@literal null}
	 * @return the transition, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException when no key with the given identifier exists in the keyset
	 * @throws CryptoException.InvalidKeyStatusTransitionException when the operation is not permitted
	 *         from the current status of the key
	 */
	public static KeyTransition destroy(EncryptedKeyset keyset, String keyId, Instant destroyedAt) {
		return create(keyset, keyId, KeyStatus.Operation.DESTROY, key -> null, destroyedAt);
	}

	private static KeyTransition create(
		EncryptedKeyset keyset,
		String keyId,
		KeyStatus.Operation operation,
		Function<EncryptedKey, @Nullable Instant> destructionScheduledAt,
		@Nullable Instant destroyedAt
	) {
		final EncryptedKey key = keyset.getKey(keyId)
			.orElseThrow(() -> new CryptoException.KeyNotFoundException(keyset.name(), keyId));

		final KeyStatus target = key.status().next(operation)
			.orElseThrow(() -> new CryptoException.InvalidKeyStatusTransitionException(
				keyset.name(), keyId, operation, key.status()));

		return new KeyTransition(keyset.name(), keyId, target, destructionScheduledAt.apply(key), destroyedAt,
			keyset.version());
	}

}
