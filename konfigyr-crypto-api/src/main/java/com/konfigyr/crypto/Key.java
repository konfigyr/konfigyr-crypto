package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Interface that describes the public attributes of a key within the {@link Keyset}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
public interface Key {

	/**
	 * Identifier of the {@link Key} within a single {@link Keyset}.
	 *
	 * @return unique key identifier, never {@literal null}.
	 */
	String getId();

	/**
	 * The algorithm that defines the usage, or supported operations, of this key.
	 *
	 * @return the key algorithm, never {@literal null}.
	 */
	Algorithm getAlgorithm();

	/**
	 * Defines the {@link KeyType} of the {@link Key}. Usually the {@link KeyType} is derived from the
	 * {@link Algorithm} used to create the key material.
	 *
	 * @return key type, never {@literal null}.
	 */
	default KeyType getType() {
		return getAlgorithm().type();
	}

	/**
	 * Returns the status of the key.
	 *
	 * @return key status, never {@literal null}.
	 */
	KeyStatus getStatus();

	/**
	 * Keys that are marked as primary are the ones that would perform the following
	 * {@link KeysetOperation crypto operations} within the {@link Keyset}:
	 * <ul>
	 * 		<li>{@link KeysetOperation#ENCRYPT}</li>
	 * 		<li>{@link KeysetOperation#SIGN}</li>
	 * </ul>
	 *
	 * @return {@literal true} if this key is marked as primary.
	 */
	boolean isPrimary();

	/**
	 * Timestamp when this key was created. This should not mean that the key material has been
	 * generated yet.
	 *
	 * @return creation timestamp, never {@literal null}.
	 */
	Instant getCreatedAt();

	/**
	 * Returns the timestamp when cryptographic key material was fully initialized and became
	 * ready for use. This method may return {@literal null} if the key material is still being
	 * initialized or if the initialization failed.
	 *
	 * @return the initialization time, may be {@literal null} if this key is not initialized yet.
	 * @see KeyStatus#INITIALIZING
	 * @see	KeyStatus#INITIALIZATION_FAILED
	 */
	@Nullable
	Instant getInitializedAt();

	/**
	 * Returns the time when this key should expire. Usually this is set when the key is created and
	 * an expiration duration has been specified for the {@link Keyset}. The keyset store uses this
	 * expiration time to perform automatic key rotation.
	 * <p>
	 * Keys without expiration time are never automatically rotated.
	 * <p>
	 * Expired keys should no longer be used for {@link KeysetOperation#ENCRYPT} or
	 * {@link KeysetOperation#SIGN} operations. Verification and decryption of existing data may
	 * still be possible beyond this time until the key is explicitly disabled or destroyed.
	 *
	 * @return expiry timestamp, or {@literal null} if the key does not expire.
	 * @see Keyset#getRotationInterval()
	 */
	@Nullable
	Instant getExpiresAt();

	/**
	 * The time when the cryptographic material should be destroyed for this key. This is usually
	 * specified when the key is marked as {@link KeyStatus#PENDING_DESTRUCTION}.
	 * <p>
	 * The key will be destroyed after the destruction grace period elapses.
	 *
	 * @return scheduled destruction timestamp, or {@literal null} if destruction has not
	 * been scheduled.
	 * @see KeyStatus#PENDING_DESTRUCTION
	 * @see Keyset#getDestructionGracePeriod()
	 */
	@Nullable
	Instant getDestructionScheduledAt();

	/**
	 * Timestamp when cryptographic key material was permanently erased and the key entered either
	 * {@link KeyStatus#DESTROYED} or {@link KeyStatus#DESTRUCTION_FAILED}.
	 *
	 * @return destruction timestamp, or {@literal null} if the key has not been destroyed.
	 * @see KeyStatus#DESTROYED
	 * @see KeyStatus#DESTRUCTION_FAILED
	 */
	@Nullable
	Instant getDestroyedAt();

}
