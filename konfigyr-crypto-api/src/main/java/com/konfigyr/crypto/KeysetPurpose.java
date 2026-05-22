package com.konfigyr.crypto;

import java.util.Set;

/**
 * Defines the intended cryptographic purpose of a {@link Keyset}. Keys within the keyset
 * can only be used for the operations allowed by its purpose. The purpose also determines
 * which algorithms are supported for the key versions that are part of the keyset.
 * <p>
 * When cryptographic keys are created, a purpose and the algorithm must be defined. The
 * {@link KeysetStore} allows update of the acutal cryptographic algorithm when new key
 * versions are created, subject to the scope of its purpose, but its purpose cannot be
 * changed.
 * <p>
 * This means that keysets with the same purpose may use different underlying algorithms,
 * but they must support the same set of cryptographic operations.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Algorithm#purpose()
 * @see Keyset
 **/
public enum KeysetPurpose {

	/**
	 * The keyset is used for symmetric or hybrid data encryption and decryption.
	 * <p>
	 * Supported operations: {@link KeysetOperation#ENCRYPT}, {@link KeysetOperation#DECRYPT}.
	 * <p>
	 * Applicable algorithms include AES-GCM, AES-EAX, AES-CTR-HMAC, and hybrid
	 * encryption schemes such as ECIES and DHKEM.
	 */
	ENCRYPTION(KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT),

	/**
	 * The keyset is used to produce and verify digital signatures or MACs.
	 * <p>
	 * Supported operations: {@link KeysetOperation#SIGN}, {@link KeysetOperation#VERIFY}.
	 * <p>
	 * Applicable algorithms include ECDSA, Ed25519, RSA-PSS, and HMAC variants.
	 */
	SIGNING(KeysetOperation.SIGN, KeysetOperation.VERIFY);

	private final Set<KeysetOperation> operations;

	KeysetPurpose(KeysetOperation... operations) {
		this.operations = Set.of(operations);
	}

	/**
	 * Returns which keyset operations are supported for this purpose.
	 *
	 * @return the supported operations, never {@literal null}.
	 */
	public Set<KeysetOperation> operations() {
		return operations;
	}

	/**
	 * Checks if this purpose supports the given operation.
	 *
	 * @param operation key operation to be checked, never {@literal null}.
	 * @return {@code true} if the operation is supported, {@code false} otherwise.
	 */
	public boolean isOperationSupported(KeysetOperation operation) {
		return operations.contains(operation);
	}

}
