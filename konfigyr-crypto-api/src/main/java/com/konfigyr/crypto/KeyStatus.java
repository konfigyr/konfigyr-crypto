package com.konfigyr.crypto;

import java.util.EnumMap;
import java.util.Set;

/**
 * Defines the lifecycle status of a {@link Key}.
 * <p>
 * Keys transition through statuses over their lifetime. Only {@link #ENABLED} keys
 * participate in cryptographic operations. The full lifecycle is:
 * <pre>
 * INITIALIZING ──► ENABLED ──► DISABLED ──► ENABLED
 *       │               │           └──► COMPROMISED ──► PENDING_DESTRUCTION ──► DISABLED
 *       │               └──► COMPROMISED ──┘                                 ├──► DESTROYED
 *       └──► INITIALIZATION_FAILED                                            └──► DESTRUCTION_FAILED
 * </pre>
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
	 * Key material has been permanently erased. No cryptographic operations are permitted
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

	static final EnumMap<KeyStatus, Set<KeyStatus>> SUPPORTED_TRANSITIONS = new EnumMap<>(KeyStatus.class);

	static {
		SUPPORTED_TRANSITIONS.put(INITIALIZING, Set.of(ENABLED, INITIALIZATION_FAILED));
		SUPPORTED_TRANSITIONS.put(ENABLED, Set.of(COMPROMISED, DISABLED, PENDING_DESTRUCTION, DESTROYED));
		SUPPORTED_TRANSITIONS.put(COMPROMISED, Set.of(DISABLED, PENDING_DESTRUCTION, DESTROYED));
		SUPPORTED_TRANSITIONS.put(DISABLED, Set.of(ENABLED, COMPROMISED, PENDING_DESTRUCTION, DESTROYED));
		SUPPORTED_TRANSITIONS.put(PENDING_DESTRUCTION, Set.of(DISABLED, DESTROYED, DESTRUCTION_FAILED));
	}

	public boolean canTransitionTo(KeyStatus target) {
		final Set<KeyStatus> allowedTransitions = SUPPORTED_TRANSITIONS.get(this);
		return allowedTransitions != null && allowedTransitions.contains(target);
	}

}
