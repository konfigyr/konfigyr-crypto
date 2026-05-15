package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Keyset, or also known as a Data Encryption Key, represents a non-empty list of
 * {@link Key cryptographic keys}, with one designated primary key which can be rotated.
 * <p>
 * Keys in a {@link Keyset} get a unique identifier and, depending on the implementation,
 * a key status which allows disabling keys without removing them from a {@link Keyset}.
 * <p>
 * The designated primary key within the {@link Keyset} is used to perform the active
 * cryptographic operation (sign or encrypt). Non-primary keys are used only for
 * the corresponding passive operation (verify or decrypt) when they are not
 * in a disabled state.
 * <p>
 * Which operations a keyset supports is determined by its {@link Algorithm#purpose()}:
 * <ul>
 *     <li>{@link KeysetPurpose#SIGNING} supports {@link #sign(ByteArray)} and
 *         {@link #verify(ByteArray, ByteArray)}.</li>
 *     <li>{@link KeysetPurpose#ENCRYPTION} supports {@link #encrypt(ByteArray)} and
 *         {@link #decrypt(ByteArray)}.</li>
 * </ul>
 * All other operations throw {@link CryptoException.UnsupportedKeysetOperationException}.
 * <p>
 * Rotating cryptographic keys is a recommended security practice. Some industry
 * standards, such as Payment Card Industry Data Security Standard (PCI DSS), require a
 * regular rotation of keys.
 * <p>
 * Key lifetime recommendations depend on the key's {@link Algorithm}, as well as either
 * the number of ciphers produced or the total number of bytes encrypted with the same key
 * version. For example, the recommended key lifetime for symmetric encryption keys in
 * Galois/Counter Mode (GCM) is based on the number of messages encrypted, as noted
 * <a href= "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">here</a>.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see Key
 * @see KeysetFactory
 **/
@NullMarked
public interface Keyset extends KeysetDefinition, Iterable<Key> {

	/**
	 * @return key encryption key, or {@code KEK} that generated this keyset, never {@literal null}.
	 */
	KeyEncryptionKey getKeyEncryptionKey();

	/**
	 * @return collection of {@link Key keys} contained within this {@link Keyset}, never {@literal null}.
	 */
	List<Key> getKeys();

	/**
	 * Retrieves a single {@link Key} by its identifier from this {@link Keyset}.
	 *
	 * @param id key identifier, can't be {@literal null}
	 * @return matching key or an empty {@link Optional}
	 */
	default Optional<Key> getKey(String id) {
		return getKeys().stream().filter(key -> id.equals(key.getId())).findFirst();
	}

	/**
	 * Encrypts the given byte buffer wrapped inside a {@link ByteArray}. Only supported when
	 * {@link Algorithm#purpose()} is {@link KeysetPurpose#ENCRYPTION}.
	 *
	 * @param data Data wrapped as a byte buffer that should be encrypted, can't be {@literal null}.
	 * @return Encrypted data wrapped inside a byte buffer.
	 * @throws CryptoException.UnsupportedKeysetOperationException when the algorithm does not
	 * support {@link KeysetOperation#ENCRYPT}.
	 */
	default ByteArray encrypt(ByteArray data) {
		return encrypt(data, null);
	}

	/**
	 * Encrypt the byte buffer with additional data to be used as authentication context when
	 * performing encryption. Only supported when {@link Algorithm#purpose()} is
	 * {@link KeysetPurpose#ENCRYPTION}.
	 *
	 * @param data Data wrapped as a byte buffer that should be encrypted, can't be {@literal null}.
	 * @param context Authentication context byte buffer, can be {@literal null}.
	 * @return Encrypted data wrapped inside a byte buffer.
	 * @throws CryptoException.UnsupportedKeysetOperationException when the algorithm does not
	 * support {@link KeysetOperation#ENCRYPT}.
	 */
	default ByteArray encrypt(ByteArray data, @Nullable ByteArray context) {
		throw new CryptoException.UnsupportedKeysetOperationException(
				getName(), KeysetOperation.ENCRYPT, getAlgorithm().operations());
	}

	/**
	 * Decrypt the given byte buffer wrapped inside a {@link ByteArray}. Only supported when
	 * {@link Algorithm#purpose()} is {@link KeysetPurpose#ENCRYPTION}.
	 *
	 * @param cipher Data wrapped as a byte buffer that should be decrypted, can't be {@literal null}.
	 * @return Decrypted data wrapped inside a byte buffer.
	 * @throws CryptoException.UnsupportedKeysetOperationException when the algorithm does not
	 * support {@link KeysetOperation#DECRYPT}.
	 */
	default ByteArray decrypt(ByteArray cipher) {
		return decrypt(cipher, null);
	}

	/**
	 * Decrypt the byte buffer with additional data that was used during encryption as
	 * authentication context. Only supported when {@link Algorithm#purpose()} is
	 * {@link KeysetPurpose#ENCRYPTION}.
	 *
	 * @param cipher Data wrapped as a byte buffer that should be decrypted, can't be {@literal null}.
	 * @param context Authentication context byte buffer, can be {@literal null}.
	 * @return Decrypted data wrapped inside a byte buffer.
	 * @throws CryptoException.UnsupportedKeysetOperationException when the algorithm does not
	 * support {@link KeysetOperation#DECRYPT}.
	 */
	default ByteArray decrypt(ByteArray cipher, @Nullable ByteArray context) {
		throw new CryptoException.UnsupportedKeysetOperationException(
				getName(), KeysetOperation.DECRYPT, getAlgorithm().operations());
	}

	/**
	 * Signs the data wrapped inside a {@link ByteArray}. Only supported when
	 * {@link Algorithm#purpose()} is {@link KeysetPurpose#SIGNING}.
	 *
	 * @param data Data wrapped as a byte buffer that should be signed, can't be {@literal null}.
	 * @return digital signature wrapped inside a byte buffer.
	 * @throws CryptoException.UnsupportedKeysetOperationException when the algorithm does not
	 * support {@link KeysetOperation#SIGN}.
	 */
	default ByteArray sign(ByteArray data) {
		throw new CryptoException.UnsupportedKeysetOperationException(
				getName(), KeysetOperation.SIGN, getAlgorithm().operations());
	}

	/**
	 * Verifies if the digital signature of the data wrapped inside a {@link ByteArray} is
	 * correct. Only supported when {@link Algorithm#purpose()} is {@link KeysetPurpose#SIGNING}.
	 *
	 * @param signature Signature wrapped as a byte buffer that should be verified, can't be {@literal null}.
	 * @param data Original data wrapped as a byte buffer from which the signature is created, can't be {@literal null}.
	 * @return {@code true} if the signature is valid, {@code false} otherwise.
	 * @throws CryptoException.UnsupportedKeysetOperationException when the algorithm does not
	 * support {@link KeysetOperation#VERIFY}.
	 */
	default boolean verify(ByteArray signature, ByteArray data) {
		throw new CryptoException.UnsupportedKeysetOperationException(
				getName(), KeysetOperation.VERIFY, getAlgorithm().operations());
	}

	/**
	 * Lifecycle method that is used to rotate cryptographic keys within the {@link Keyset}.
	 *
	 * @return new keyset with the rotated keys, never {@literal null}
	 */
	Keyset rotate();

	/**
	 * Returns the number of {@link Key keys} that are present in this {@link Keyset}.
	 * @return the keyset size.
	 */
	default int size() {
		return getKeys().size();
	}

	@Override
	default Iterator<Key> iterator() {
		return getKeys().iterator();
	}

	/**
	 * Returns a sequential stream of {@link Key keys} from this {@link Keyset}.
	 * @return key stream, never {@literal null}
	 */
	default Stream<Key> stream() {
		return getKeys().stream();
	}

}
