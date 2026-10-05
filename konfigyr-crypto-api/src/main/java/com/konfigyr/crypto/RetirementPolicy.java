package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

/**
 * Policy that defines what happens to the primary {@link Key} of a {@link Keyset} once it is demoted,
 * because the keyset was {@link Keyset#rotate() rotated} and another key became the primary key.
 * <p>
 * A demoted key no longer signs or encrypts, but it may still be needed to verify signatures, or to decrypt
 * data, that it produced while it was the primary key. The policy defines for how long the demoted key
 * remains available for these operations:
 * <ul>
 *     <li>{@link #RETAIN}: the demoted key remains {@link KeyStatus#ENABLED} until it is disabled or destroyed
 *     manually.</li>
 *     <li>{@link #DESTROY}: the demoted key is {@link KeyStatus#RETIRED retired} for the
 *     {@link KeysetDefinition#getDestructionGracePeriod() destruction grace period}, and destroyed afterwards.</li>
 *     <li>{@link #SCHEDULE_DESTRUCTION}: the demoted key is {@link KeyStatus#RETIRED retired} for the
 *     destruction grace period, and then {@link KeyStatus#PENDING_DESTRUCTION scheduled for destruction} for
 *     another destruction grace period, during which the destruction can still be cancelled.</li>
 * </ul>
 * <p>
 * <strong>Warning:</strong> never use {@link #DESTROY} or {@link #SCHEDULE_DESTRUCTION} for keysets that encrypt
 * data at rest. Data encrypted by a demoted key becomes permanently unreadable once that key is destroyed. These
 * policies are meant for keysets whose output is short-lived, like signatures of tokens or SAML assertions.
 *
 * @author Vladimir Spasic
 * @since 1.1.0
 * @see KeysetDefinition#getRetirementPolicy()
 **/
@NullMarked
public enum RetirementPolicy {

	/**
	 * Retains the demoted key in the {@link KeyStatus#ENABLED} state, so it can verify and decrypt until it is
	 * disabled or destroyed manually. This is the default policy, as it never destroys key material that may
	 * still be needed to decrypt data at rest.
	 */
	RETAIN,

	/**
	 * Retires the demoted key for the destruction grace period and destroys it afterwards.
	 * <p>
	 * <strong>Warning:</strong> data encrypted by the demoted key becomes permanently unreadable once the key is
	 * destroyed, never use this policy for keysets that encrypt data at rest.
	 */
	DESTROY,

	/**
	 * Retires the demoted key for the destruction grace period, and then schedules it for destruction for
	 * another destruction grace period, during which the destruction can still be cancelled.
	 * <p>
	 * <strong>Warning:</strong> data encrypted by the demoted key becomes permanently unreadable once the key is
	 * destroyed, never use this policy for keysets that encrypt data at rest.
	 */
	SCHEDULE_DESTRUCTION

}
