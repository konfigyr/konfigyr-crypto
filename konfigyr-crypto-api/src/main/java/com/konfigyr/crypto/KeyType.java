package com.konfigyr.crypto;

/**
 * Enumeration that defines the type of the key material stored in the {@link Keyset}.
 *
 * @author : Vladimir Spasic
 * @since : 20.08.23, Mon
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
