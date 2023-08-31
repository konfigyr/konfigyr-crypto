package com.konfigyr.crypto;

/**
 * Enumeration that defines which operations one {@link Algorithm} can perform.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 **/
public enum KeysetOperation {

	/**
	 * Key can be used to encrypt data
	 */
	ENCRYPT,

	/**
	 * Key can be used to decrypt data
	 */
	DECRYPT,

	/**
	 * Key can be used to sign data
	 */
	SIGN,

	/**
	 * Key can be used to verify signatures
	 */
	VERIFY

}
