package com.konfigyr.crypto;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Immutable value object that describes a single key-version lifecycle transition within a
 * {@link KeysetRepository}.
 * <p>
 * A {@code KeyTransition} carries the keyset name, key identifier, target {@link KeyStatus},
 * and the two optional timestamps ({@link #getDestructionScheduledAt() destructionScheduledAt}
 * and {@link #getDestroyedAt() destroyedAt}) that are set or cleared as part of the transition.
 * <p>
 * Instances must be created through one of the static factory methods. Each factory encodes
 * the semantics of exactly one state-machine edge and ensures that only the timestamp fields
 * relevant to that edge are populated, preventing callers from constructing an inconsistent
 * combination of status and timestamps:
 *
 * <pre>{@code
 * // ENABLED → DISABLED
 * KeyTransition.disable(keysetName, keyId);
 *
 * // DISABLED → ENABLED
 * KeyTransition.enable(keysetName, keyId);
 *
 * // DISABLED → PENDING_DESTRUCTION
 * KeyTransition.scheduleDestruction(keysetName, keyId, destructionTime);
 *
 * // PENDING_DESTRUCTION → DISABLED
 * KeyTransition.cancelDestruction(keysetName, keyId);
 *
 * // PENDING_DESTRUCTION → DESTROYED (key material erased)
 * KeyTransition.destroy(keysetName, keyId, Instant.now());
 * }</pre>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetRepository#updateKeyStatus(KeyTransition)
 * @see KeysetStore
 **/
@Value
@NullMarked
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class KeyTransition {

	/**
	 * The name of the keyset that contains the key being transitioned.
	 */
	String keysetName;

	/**
	 * The identifier of the key version being transitioned.
	 */
	String keyId;

	/**
	 * The target {@link KeyStatus} to assign to the key version.
	 */
	KeyStatus status;

	/**
	 * The time at which the key is scheduled for destruction. Populated when transitioning
	 * to {@link KeyStatus#PENDING_DESTRUCTION}; {@code null} for all other transitions.
	 */
	@Nullable
	Instant destructionScheduledAt;

	/**
	 * The time at which the key material was permanently erased. Populated when transitioning
	 * to {@link KeyStatus#DESTROYED}; {@code null} for all other transitions.
	 */
	@Nullable
	Instant destroyedAt;

	/**
	 * Creates a transition that moves a key from {@link KeyStatus#ENABLED} to
	 * {@link KeyStatus#DISABLED}.
	 *
	 * @param keysetName the name of the keyset containing the key, can't be {@literal null}
	 * @param keyId the identifier of the key to disable, can't be {@literal null}
	 * @return the transition, never {@literal null}
	 */
	public static KeyTransition disable(String keysetName, String keyId) {
		return new KeyTransition(keysetName, keyId, KeyStatus.DISABLED, null, null);
	}

	/**
	 * Creates a transition that moves a key from {@link KeyStatus#DISABLED} to
	 * {@link KeyStatus#ENABLED}.
	 *
	 * @param keysetName the name of the keyset containing the key, can't be {@literal null}
	 * @param keyId the identifier of the key to re-enable, can't be {@literal null}
	 * @return the transition, never {@literal null}
	 */
	public static KeyTransition enable(String keysetName, String keyId) {
		return new KeyTransition(keysetName, keyId, KeyStatus.ENABLED, null, null);
	}

	/**
	 * Creates a transition that moves a key from {@link KeyStatus#ENABLED} or
	 * {@link KeyStatus#DISABLED} to {@link KeyStatus#COMPROMISED}.
	 * <p>
	 * This is an emergency transition. Once compromised, the key cannot be re-enabled or
	 * used for any cryptographic operation. Key material should subsequently be scheduled
	 * for destruction via {@link KeysetStore#scheduleDestruction(String, String)}.
	 *
	 * @param keysetName the name of the keyset containing the key, can't be {@literal null}
	 * @param keyId the identifier of the key to mark as compromised, can't be {@literal null}
	 * @return the transition, never {@literal null}
	 */
	public static KeyTransition compromise(String keysetName, String keyId) {
		return new KeyTransition(keysetName, keyId, KeyStatus.COMPROMISED, null, null);
	}

	/**
	 * Creates a transition that moves a key from {@link KeyStatus#DISABLED} to
	 * {@link KeyStatus#PENDING_DESTRUCTION}, recording the scheduled destruction time.
	 *
	 * @param keysetName the name of the keyset containing the key, can't be {@literal null}
	 * @param keyId the identifier of the key to schedule for destruction, can't be {@literal null}
	 * @param destructionScheduledAt the time at which the key should be destroyed,
	 *                               can't be {@literal null}
	 * @return the transition, never {@literal null}
	 */
	public static KeyTransition scheduleDestruction(
			String keysetName, String keyId, Instant destructionScheduledAt) {
		return new KeyTransition(keysetName, keyId, KeyStatus.PENDING_DESTRUCTION,
				destructionScheduledAt, null);
	}

	/**
	 * Creates a transition that moves a key from {@link KeyStatus#PENDING_DESTRUCTION} back to
	 * {@link KeyStatus#DISABLED}, clearing the previously scheduled destruction time.
	 *
	 * @param keysetName the name of the keyset containing the key, can't be {@literal null}
	 * @param keyId the identifier of the key whose destruction should be cancelled,
	 *              can't be {@literal null}
	 * @return the transition, never {@literal null}
	 */
	public static KeyTransition cancelDestruction(String keysetName, String keyId) {
		return new KeyTransition(keysetName, keyId, KeyStatus.DISABLED, null, null);
	}

	/**
	 * Creates a transition that moves a key from {@link KeyStatus#PENDING_DESTRUCTION} to
	 * {@link KeyStatus#DESTROYED}.
	 * <p>
	 * The key material ({@link EncryptedKey#getData()}) is erased — set to {@code null} — by
	 * the repository when this transition is applied. The row itself is kept for audit purposes.
	 *
	 * @param keysetName the name of the keyset containing the key, can't be {@literal null}
	 * @param keyId the identifier of the key to destroy, can't be {@literal null}
	 * @param destroyedAt the instant at which the key material was erased, can't be
	 *                    {@literal null}
	 * @return the transition, never {@literal null}
	 */
	public static KeyTransition destroy(String keysetName, String keyId, Instant destroyedAt) {
		return new KeyTransition(keysetName, keyId, KeyStatus.DESTROYED, null, destroyedAt);
	}

}
