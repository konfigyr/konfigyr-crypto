package com.konfigyr.crypto;

/**
 * Defines in which status the {@link Key} can be in.
 *
 * @author : Vladimir Spasic
 * @since : 04.09.23, Mon
 **/
public enum KeyStatus {

	/**
	 * Unknown key status, usually returned by implementations of the {@link Key} that do
	 * not track status of the key material.
	 */
	UNKNOWN,
	/**
	 * When in this status, {@link Key} can be used perform all crypto operations.
	 */
	ENABLED,
	/**
	 * {@link Key keys} in this status should not perform any crypto operations.
	 * Implementations should support re-enabling or destroying of such keys.
	 */
	DISABLED,
	/**
	 * Marks the {@link Key} as destroyed and should not be used to perform any crypto
	 * operations. It is advisable that key material of such keys is also removed from the
	 * repository after a certain period.
	 */
	DESTROYED

}
