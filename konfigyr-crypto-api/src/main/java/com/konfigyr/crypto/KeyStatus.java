package com.konfigyr.crypto;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

/**
 * Defines the lifecycle status of a {@link Key}.
 * <p>
 * Keys transition through statuses over their lifetime. Only {@link #ENABLED} keys
 * participate in cryptographic operations. The full lifecycle is:
 * <pre>
 * INITIALIZING ──► ENABLED | INITIALIZATION_FAILED
 *
 * ENABLED ◄──► DISABLED
 *
 * DISABLED ──► PENDING_DESTRUCTION ──► DESTROYED
 *                    └──► DISABLED (cancel)
 *
 * ENABLED | DISABLED ──► COMPROMISED ◄──► COMPROMISED_PENDING_DESTRUCTION ──► DESTROYED
 *                                    (schedule / cancel)
 *
 * PENDING_DESTRUCTION ──► COMPROMISED_PENDING_DESTRUCTION (compromised during the grace period)
 * </pre>
 * <p>
 * Both {@link #PENDING_DESTRUCTION} and {@link #COMPROMISED_PENDING_DESTRUCTION} may also
 * move to {@link #DESTRUCTION_FAILED}.
 * <p>
 * Once a key has been marked {@link #COMPROMISED} it can never return to {@link #ENABLED} or
 * {@link #DISABLED}: scheduling and cancelling its destruction only toggles between
 * {@link #COMPROMISED} and {@link #COMPROMISED_PENDING_DESTRUCTION}. Key material may only be
 * {@link #DESTROYED destroyed} from one of the two pending destruction statuses, an {@link #ENABLED}
 * key must always be deactivated before its destruction can be scheduled.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
public enum KeyStatus {

	/**
	 * Key material is being generated. The key is not yet usable. No cryptographic
	 * operations are permitted.
	 */
	INITIALIZING,

	/**
	 * Key is active and may perform all cryptographic operations permitted by its
	 * {@link Algorithm}.
	 */
	ENABLED,

	/**
	 * Key material is suspected or confirmed to have been compromised. All cryptographic
	 * operations are hard-blocked regardless of primary status.
	 */
	COMPROMISED,

	/**
	 * Key has been administratively disabled. No cryptographic operations are permitted.
	 * The key may be re-enabled or scheduled for destruction.
	 */
	DISABLED,

	/**
	 * Destruction has been scheduled; the key is in its grace period. No cryptographic
	 * operations are permitted. The transition to {@link #DESTROYED} happens after the
	 * {@link Keyset#getDestructionGracePeriod() destruction grace period} elapses.
	 */
	PENDING_DESTRUCTION,

	/**
	 * Key material has been compromised, and its destruction has been scheduled; the key is in
	 * its grace period. All cryptographic operations are hard-blocked, exactly as for
	 * {@link #COMPROMISED}. Cancelling the destruction returns the key to {@link #COMPROMISED},
	 * never to {@link #DISABLED} or {@link #ENABLED}.
	 */
	COMPROMISED_PENDING_DESTRUCTION,

	/**
	 * Key material has been permanently erased. No cryptographic operations are permitted,
	 * and the key can no longer be recovered.
	 */
	DESTROYED,

	/**
	 * Key generation failed during {@link #INITIALIZING}. No cryptographic operations are
	 * permitted. This is a terminal status.
	 */
	INITIALIZATION_FAILED,

	/**
	 * An attempt to destroy the key material failed. No cryptographic operations are
	 * permitted. Manual intervention is required to complete destruction.
	 */
	DESTRUCTION_FAILED;

	private static final Map<KeyStatus, Map<Operation, KeyStatus>> TRANSITIONS = new EnumMap<>(KeyStatus.class);

	static {
		TRANSITIONS.put(INITIALIZING, Map.of(
			Operation.ACTIVATE, ENABLED,
			Operation.FAIL_INITIALIZATION, INITIALIZATION_FAILED
		));
		TRANSITIONS.put(ENABLED, Map.of(
			Operation.DISABLE, DISABLED,
			Operation.COMPROMISE, COMPROMISED
		));
		TRANSITIONS.put(DISABLED, Map.of(
			Operation.ENABLE, ENABLED,
			Operation.COMPROMISE, COMPROMISED,
			Operation.SCHEDULE_DESTRUCTION, PENDING_DESTRUCTION
		));
		TRANSITIONS.put(PENDING_DESTRUCTION, Map.of(
			Operation.CANCEL_DESTRUCTION, DISABLED,
			Operation.COMPROMISE, COMPROMISED_PENDING_DESTRUCTION,
			Operation.DESTROY, DESTROYED,
			Operation.FAIL_DESTRUCTION, DESTRUCTION_FAILED
		));
		TRANSITIONS.put(COMPROMISED, Map.of(
			Operation.SCHEDULE_DESTRUCTION, COMPROMISED_PENDING_DESTRUCTION
		));
		TRANSITIONS.put(COMPROMISED_PENDING_DESTRUCTION, Map.of(
			Operation.CANCEL_DESTRUCTION, COMPROMISED,
			Operation.DESTROY, DESTROYED,
			Operation.FAIL_DESTRUCTION, DESTRUCTION_FAILED
		));
	}

	/**
	 * Resolves the {@link KeyStatus} a key in this status would transition to when the given
	 * lifecycle {@link Operation} is applied to it.
	 * <p>
	 * This is the single source of truth of the key lifecycle state machine. The permitted
	 * operations and their resulting statuses are:
	 * <ul>
	 *   <li>{@link #INITIALIZING}: {@link Operation#ACTIVATE} → {@link #ENABLED},
	 *       {@link Operation#FAIL_INITIALIZATION} → {@link #INITIALIZATION_FAILED}</li>
	 *   <li>{@link #ENABLED}: {@link Operation#DISABLE} → {@link #DISABLED},
	 *       {@link Operation#COMPROMISE} → {@link #COMPROMISED}</li>
	 *   <li>{@link #DISABLED}: {@link Operation#ENABLE} → {@link #ENABLED},
	 *       {@link Operation#COMPROMISE} → {@link #COMPROMISED},
	 *       {@link Operation#SCHEDULE_DESTRUCTION} → {@link #PENDING_DESTRUCTION}</li>
	 *   <li>{@link #PENDING_DESTRUCTION}: {@link Operation#CANCEL_DESTRUCTION} → {@link #DISABLED},
	 *       {@link Operation#COMPROMISE} → {@link #COMPROMISED_PENDING_DESTRUCTION},
	 *       {@link Operation#DESTROY} → {@link #DESTROYED},
	 *       {@link Operation#FAIL_DESTRUCTION} → {@link #DESTRUCTION_FAILED}</li>
	 *   <li>{@link #COMPROMISED}: {@link Operation#SCHEDULE_DESTRUCTION} →
	 *       {@link #COMPROMISED_PENDING_DESTRUCTION}</li>
	 *   <li>{@link #COMPROMISED_PENDING_DESTRUCTION}: {@link Operation#CANCEL_DESTRUCTION} →
	 *       {@link #COMPROMISED}, {@link Operation#DESTROY} → {@link #DESTROYED},
	 *       {@link Operation#FAIL_DESTRUCTION} → {@link #DESTRUCTION_FAILED}</li>
	 * </ul>
	 * No status reachable from {@link #COMPROMISED} leads back to {@link #ENABLED} or
	 * {@link #DISABLED}. An {@link #ENABLED} key must be deactivated, either disabled or marked as
	 * compromised, before its destruction can be scheduled, and {@link #DESTROYED} is only reachable
	 * from {@link #PENDING_DESTRUCTION} or {@link #COMPROMISED_PENDING_DESTRUCTION}.
	 * <p>
	 * {@link #DESTROYED}, {@link #INITIALIZATION_FAILED}, and {@link #DESTRUCTION_FAILED} are
	 * terminal statuses, they do not permit any operation and always return an empty result.
	 *
	 * @param operation the lifecycle operation to apply, can't be {@literal null}
	 * @return the resulting status, or an empty {@link Optional} when the operation is not
	 *         permitted from this status, never {@literal null}
	 */
	public Optional<KeyStatus> next(Operation operation) {
		return Optional.ofNullable(TRANSITIONS.getOrDefault(this, Map.of()).get(operation));
	}

	/**
	 * Returns {@code true} if this status may transition to the given {@code target} status
	 * through any lifecycle {@link Operation}.
	 * <p>
	 * This method is derived from {@link #next(Operation)}. Note that it can not tell which
	 * operation leads to the target status, e.g. {@link #PENDING_DESTRUCTION} → {@link #DISABLED}
	 * is only permitted through {@link Operation#CANCEL_DESTRUCTION} but not through
	 * {@link Operation#DISABLE}. Use {@link #next(Operation)} to validate a specific operation.
	 *
	 * @param target the target status to transition to, can't be {@literal null}
	 * @return {@code true} if the transition is allowed, {@code false} otherwise
	 * @see #next(Operation)
	 */
	public boolean canTransitionTo(KeyStatus target) {
		return TRANSITIONS.getOrDefault(this, Map.of()).containsValue(target);
	}

	/**
	 * Defines the lifecycle operations that can be applied to a {@link Key} and which drive the
	 * {@link KeyStatus} state machine.
	 * <p>
	 * Each operation is only permitted from specific statuses, and the resulting status depends on
	 * the status the key is currently in. For example, {@link #SCHEDULE_DESTRUCTION} moves a
	 * {@link KeyStatus#DISABLED} key to {@link KeyStatus#PENDING_DESTRUCTION}, but moves a
	 * {@link KeyStatus#COMPROMISED} key to {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION}.
	 *
	 * @see KeyStatus#next(Operation)
	 */
	public enum Operation {

		/**
		 * Marks the key as usable once its key material has been successfully generated.
		 */
		ACTIVATE,

		/**
		 * Marks the key as unusable because its key material could not be generated.
		 */
		FAIL_INITIALIZATION,

		/**
		 * Administratively deactivates a key.
		 *
		 * @see KeysetStore#disable(String, String)
		 */
		DISABLE,

		/**
		 * Re-activates a previously disabled key.
		 *
		 * @see KeysetStore#enable(String, String)
		 */
		ENABLE,

		/**
		 * Marks the key as compromised. This operation is irreversible.
		 *
		 * @see KeysetStore#compromise(String, String)
		 */
		COMPROMISE,

		/**
		 * Schedules the destruction of a deactivated key.
		 *
		 * @see KeysetStore#scheduleDestruction(String, String)
		 */
		SCHEDULE_DESTRUCTION,

		/**
		 * Cancels the scheduled destruction of a key.
		 *
		 * @see KeysetStore#cancelDestruction(String, String)
		 */
		CANCEL_DESTRUCTION,

		/**
		 * Erases the key material of a key that is pending destruction.
		 *
		 * @see KeysetStore#destroy(String, String)
		 */
		DESTROY,

		/**
		 * Marks that the key material of a key that is pending destruction could not be erased.
		 */
		FAIL_DESTRUCTION

	}

}
