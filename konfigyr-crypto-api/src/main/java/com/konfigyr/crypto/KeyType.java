package com.konfigyr.crypto;

/**
 * Enumeration that defines the type of the key material stored in the {@link Keyset}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
public enum KeyType {

	/**
	 * Type used for Elliptic Curve key pairs
	 */
	EC,

	/**
	 * Type used for RSA key pairs
	 */
	RSA,

	/**
	 * Type used for Octet sequence symmetric keys
	 */
	OCTET

}
