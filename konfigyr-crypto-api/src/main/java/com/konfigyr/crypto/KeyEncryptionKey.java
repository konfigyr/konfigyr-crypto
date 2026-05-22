package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;

/**
 * Represents the top-level cryptographic key used to protect {@link Keyset Data
 * Encryption Keys} which, in turn, protects all other credentials, keys, and certificates
 * that are encrypted by those keys or key sets.
 * <p>
 * It is a recommended industry standard to use this two-tier approach so that the
 * {@link KeyEncryptionKey} can easily be backed up, restored, and replaced in case of a
 * breach, without needing to touch any other encrypted data.
 * <p>
 * When a {@link Keyset Data Encryption Key} should be stored within the system it needs
 * to be encrypted with the this {@link KeyEncryptionKey} and kept in a form of a
 * {@link EncryptedKeyset}. When such a key is needed to decrypt the data, its encrypted
 * form would be retrieved and decrypted back to a {@link Keyset}.
 * <p>
 * To replace the {@link KeyEncryptionKey}, all the {@link Keyset Data Encryption Keys}
 * must be decrypted using the old {@link KeyEncryptionKey}, a new
 * {@link KeyEncryptionKey} must be generated, then all the {@link Keyset Data Encryption
 * Keys} must be encrypted (without changing them) with the new {@link KeyEncryptionKey}
 * and saved in form of a {@link EncryptedKeyset}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
public interface KeyEncryptionKey {

	/**
	 * The identifier of this {@link KeyEncryptionKey KEK}.
	 *
	 * @return the key identifier, never {@literal null}
	 */
	String getId();

	/**
	 * The identifier of the {@link KeyEncryptionKeyProvider} that provided the {@link KeyEncryptionKey KEK}.
	 *
	 * @return the key provider identifier, never {@literal null}
	 */
	String getProvider();

	/**
	 * Wraps or encrypts the {@link Keyset} private material using this
	 * {@link KeyEncryptionKey}. The encryption algorithm depends on the implementation.
	 *
	 * @param data private keyset material to wrap, can't be {@literal null}
	 * @return wrapped key material, never {@literal null}
	 * @throws IOException when there is an issue while wrapping the private key material.
	 */
	WrappedKeyMaterial wrap(ByteArray data) throws IOException;

	/**
	 * Unwraps or decrypts the given {@link WrappedKeyMaterial} and returns the plaintext
	 * {@link ByteArray} containing the private keyset material.
	 *
	 * @param data wrapped key material to unwrap, can't be {@literal null}
	 * @return decrypted private keyset material, never {@literal null}
	 * @throws IOException when there is an issue while unwrapping the encrypted private key material.
	 */
	ByteArray unwrap(WrappedKeyMaterial data) throws IOException;

	/**
	 * Formats the given {@link KeyEncryptionKey} as a safe log-friendly reference string
	 * containing only the provider name and key identifier — never key material.
	 *
	 * @param kek the key encryption key to format, can't be {@literal null}
	 * @return a {@code provider@id} string, never {@literal null}
	 */
	static String format(KeyEncryptionKey kek) {
		return kek.getProvider() + "@" + kek.getId();
	}

}
