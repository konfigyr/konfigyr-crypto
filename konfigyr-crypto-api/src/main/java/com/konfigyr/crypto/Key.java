package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

/**
 * Interface that describes the public attributes of a key within the {@link Keyset}.
 *
 * @author : Vladimir Spasic
 * @since : 04.09.23, Mon
 **/
public interface Key {

	/**
	 * Identifier of the {@link Key} within a single {@link Keyset}.
	 * @return unique key identifier, never {@literal null}.
	 */
	@NonNull
	String getId();

	/**
	 * Defines the {@link KeyType} of the {@link Key}.
	 * @return key type, never {@literal null}.
	 */
	@NonNull
	KeyType getType();

	/**
	 * @return status of key, never {@literal null}.
	 */
	@NonNull
	KeyStatus getStatus();

	/**
	 * Keys that are marked as primary are the ones that would perform the following
	 * {@link KeysetOperation crypto operations} within the {@link Keyset}:
	 * <ul>
	 * <li>{@link KeysetOperation#ENCRYPT}</li>
	 * <li>{@link KeysetOperation#SIGN}</li>
	 * </ul>
	 * @return {@literal true} if this key is marked as primary.
	 */
	boolean isPrimary();

}
