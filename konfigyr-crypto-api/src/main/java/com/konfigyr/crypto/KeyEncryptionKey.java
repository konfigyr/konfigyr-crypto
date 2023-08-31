package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.springframework.lang.NonNull;

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
 * @author : Vladimir Spasic
 * @since : 26.08.23, Sat
 **/
public interface KeyEncryptionKey {

	/**
	 * The identifier of this {@link KeyEncryptionKey KEK}.
	 * @return the key identifier, never {@literal null}
	 */
	@NonNull
	String getId();

	/**
	 * The identifier of the {@link KeyEncryptionKeyProvider} that provided the
	 * {@link KeyEncryptionKey KEK}.
	 * @return the key provider identifier, never {@literal null}
	 */
	@NonNull
	String getProvider();

	/**
	 * Wraps or encrypts the {@link Keyset} private material. The encryption algorithm
	 * that used to encrypt the data depends on the implementation of the
	 * {@link KeyEncryptionKey}.
	 * @param data private keyset material, can't be {@literal null}
	 * @return encrypted private keyset material, never {@literal null}
	 * @throws IOException when there is an issue while wrapping the private key material.
	 */
	@NonNull
	ByteArray wrap(@NonNull ByteArray data) throws IOException;

	/**
	 * Unwraps or decrypts the {@link EncryptedKeyset} and returns the decrypted
	 * {@link ByteArray} containing the private keyset material.
	 * @param data encrypted keyset material to be unwrapped, can't be {@literal null}
	 * @return decrypted private keyset material, never {@literal null}
	 * @throws IOException when there is an issue while unwrapping the encrypted private
	 * key material.
	 */
	@NonNull
	ByteArray unwrap(@NonNull ByteArray data) throws IOException;

}
