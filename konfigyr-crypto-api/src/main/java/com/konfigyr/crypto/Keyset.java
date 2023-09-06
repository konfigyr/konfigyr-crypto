package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Keyset, or also known as a Data Encryption Key, represents a non-empty list of
 * {@link Key cryptographic keys}, with one designated primary key which can be rotated.
 * <p>
 * Keys in a {@link Keyset} get a unique identifier and, depending on the implementation,
 * a key status which allows to disable keys without removing them from a {@link Keyset}.
 * <p>
 * The designated primary key within the {@link Keyset} is used to perform sign and
 * encrypt operations. Non-primary keys are used only to perform signature verification
 * and decrypt operations, if they are not in a disabled state.
 * <p>
 * Rotating cryptographic keys is a recommended security practice. Some industry
 * standards, such as Payment Card Industry Data Security Standard (PCI DSS), require a
 * regular rotation of keys.
 * <p>
 * Key lifetime recommendations depend on the key's {@link Algorithm}, as well as either
 * the number of ciphers produced or the total number of bytes encrypted with the same key
 * version. For example, the recommended key lifetime for symmetric encryption keys in
 * Galois/Counter Mode (GCM) is based on the number of messages encrypted, as noted
 * <a href=
 * "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">here</a>.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see Key
 * @see KeysetFactory
 **/
public interface Keyset extends KeysetDefinition, Iterable<Key> {

	/**
	 * @return key encryption key that generated this keyset, never {@literal null}.
	 */
	@NonNull
	KeyEncryptionKey getKeyEncryptionKey();

	/**
	 * @return collection of {@link Key keys} contained within this {@link Keyset}, never
	 * {@literal null}.
	 */
	@NonNull
	List<Key> getKeys();

	/**
	 * Retrieves a single {@link Key} by its identifier from this {@link Keyset}.
	 * @param id key identifier, can't be {@literal null}
	 * @return matching key or an empty {@link Optional}
	 */
	@NonNull
	default Optional<Key> getKey(@NonNull String id) {
		return getKeys().stream().filter(key -> id.equals(key.getId())).findFirst();
	}

	/**
	 * Encrypt the byte buffer.
	 * @param data Data wrapped as a byte buffer that should be encrypted, can't be
	 * {@literal null}.
	 * @return Encrypted data wrapped inside a byte buffer.
	 */
	@NonNull
	default ByteArray encrypt(@NonNull ByteArray data) {
		return encrypt(data, null);
	}

	/**
	 * Encrypt the byte buffer with an additional data to be used as authentication
	 * context when performing encryption.
	 * @param data Data wrapped as a byte buffer that should be encrypted, can't be
	 * {@literal null}.
	 * @param context Authentication context byte bugger, can be {@literal null}.
	 * @return Encrypted data wrapped inside a byte buffer.
	 */
	@NonNull
	ByteArray encrypt(@NonNull ByteArray data, @Nullable ByteArray context);

	/**
	 * Decrypt the byte buffer.
	 * @param cipher Data wrapped as a byte buffer that should be decrypted, can't be
	 * {@literal null}.
	 * @return Decrypted data wrapped inside a byte buffer.
	 */
	@NonNull
	default ByteArray decrypt(@NonNull ByteArray cipher) {
		return decrypt(cipher, null);
	}

	/**
	 * Decrypt the byte buffer with an additional data was used during encryption as
	 * authentication context.
	 * @param cipher Data wrapped as a byte buffer that should be decrypted, can't be
	 * {@literal null}.
	 * @param context Authentication context byte bugger, can be {@literal null}.
	 * @return Decrypted data wrapped inside a byte buffer.
	 */
	@NonNull
	ByteArray decrypt(@NonNull ByteArray cipher, @Nullable ByteArray context);

	/**
	 * Signs the data wrapped inside a {@link ByteArray}. This method would return a
	 * {@link ByteArray} that contains both th digital signature.
	 * @param data Data wrapped as a byte buffer that should be signed, can't be
	 * {@literal null}.
	 * @return digital signature wrapped inside a byte buffer.
	 */
	@NonNull
	ByteArray sign(@NonNull ByteArray data);

	/**
	 * Verifies if digital signature of the data wrapped inside a {@link ByteArray} is
	 * correct.
	 * @param signature Signature wrapped as a byte buffer that should be verified, can't
	 * be {@literal null}.
	 * @param data Original data wrapped as a byte buffer from which the signature is
	 * created, can't be {@literal null}.
	 * @return {@code true} if the signature is valid, {@code false} otherwise.
	 */
	boolean verify(@NonNull ByteArray signature, @NonNull ByteArray data);

	/**
	 * Lifecycle method that is used to rotate cryptographic keys within the
	 * {@link Keyset}.
	 * @return new keyset with the rotated keys, never {@literal null}
	 */
	@NonNull
	Keyset rotate();

	/**
	 * Returns the number of {@link Key keys} that are present in this {@link Keyset}.
	 * @return the keyset size.
	 */
	default int size() {
		return getKeys().size();
	}

	@NonNull
	@Override
	default Iterator<Key> iterator() {
		return getKeys().iterator();
	}

	/**
	 * Returns a sequential stream of {@link Key keys} from this {@link Keyset}.
	 * @return key stream, never {@literal null}
	 */
	@NonNull
	default Stream<Key> stream() {
		return getKeys().stream();
	}

}
