package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
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
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Key
 * @see KeysetFactory
 **/
@NullMarked
public interface Keyset extends Iterable<Key> {

	/**
	 * Name that uniquely identifies the {@link Keyset}.
	 *
	 * @return keyset name, never {@literal null}.
	 */
	String getName();

	/**
	 * The optimistic-locking version of this keyset as it was last read from the
	 * {@link KeysetRepository}. Zero for keysets that have not yet been persisted.
	 *
	 * @return non-negative version counter
	 */
	long getVersion();

	/**
	 * The name of the {@link KeysetFactory} that is responsible for creating the {@link Keyset} and it's
	 * underlying {@link Key keys}.
	 *
	 * @return keyset factory name, never {@literal null}.
	 */
	String getFactory();

	/**
	 * The purpose of the key material that describes the cryptographic capabilities of this {@link Keyset}.
	 *
	 * @return the purpose for this {@link Keyset}, never {@literal null}.
	 * @see KeysetPurpose
	 */
	KeysetPurpose getPurpose();

	/**
	 * Retrieves the {@link KeyEncryptionKey} that is used to encrypt the {@link Keyset} metadata.
	 *
	 * @return key encryption key, or {@code KEK} that generated this keyset, never {@literal null}.
	 */
	KeyEncryptionKey getKeyEncryptionKey();

	/**
	 * Retrieves all {@link Key keys} contained within this {@link Keyset}.
	 *
	 * @return collection of {@link Key keys} contained within this {@link Keyset}, never {@literal null}.
	 */
	List<? extends Key> getKeys();

	/**
	 * Retrieves the primary {@link Key} from this {@link Keyset}.
	 *
	 * @return primary key, never {@literal null}.
	 */
	Key getPrimary();

	/**
	 * Retrieves a single {@link Key} by its identifier from this {@link Keyset}.
	 *
	 * @param id key identifier, can't be {@literal null}
	 * @return matching key or an empty {@link Optional}
	 */
	default Optional<? extends Key> getKey(String id) {
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
				getName(), KeysetOperation.ENCRYPT, getPurpose().operations());
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
				getName(), KeysetOperation.DECRYPT, getPurpose().operations());
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
				getName(), KeysetOperation.SIGN, getPurpose().operations());
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
				getName(), KeysetOperation.VERIFY, getPurpose().operations());
	}

	/**
	 * Rotates the cryptographic keys within this {@link Keyset} using the algorithm and
	 * expiry interval from the given {@link KeyDefinition}.
	 * <p>
	 * Implementations must:
	 * <ol>
	 *     <li>Reject definitions whose {@link Algorithm#purpose()} differs from this
	 *         keyset's {@link #getPurpose()} by throwing
	 *         {@link CryptoException.UnsupportedAlgorithmException}.</li>
	 *     <li>Generate a key identifier that is unique within this keyset.</li>
	 *     <li>Create a new key, promote it to primary when
	 *         {@link KeyDefinition#isPrimary()} is {@literal true}, and demote or
	 *         retain existing keys as appropriate.</li>
	 *     <li>Return a new immutable keyset containing the updated key set.</li>
	 * </ol>
	 *
	 * @param definition parameters for the new key, can't be {@literal null}
	 * @return new keyset with the rotated keys, never {@literal null}
	 * @throws CryptoException.UnsupportedAlgorithmException when the definition's
	 *         algorithm purpose does not match this keyset's purpose
	 */
	Keyset rotate(KeyDefinition definition);

	/**
	 * Rotates the cryptographic keys within this {@link Keyset} using the same algorithm
	 * as the current primary key and the keyset's configured rotation interval.
	 * <p>
	 * This is a convenience method equivalent to:
	 * <pre>{@code
	 * keyset.rotate(KeyDefinition.builder()
	 *     .algorithm(keyset.getPrimary().getAlgorithm())
	 *     .rotationInterval(keyset.getRotationInterval().orElse(null))
	 *     .build());
	 * }</pre>
	 *
	 * @return new keyset with the rotated keys, never {@literal null}
	 */
	default Keyset rotate() {
		return rotate(KeyDefinition.builder()
			.algorithm(getPrimary().getAlgorithm())
			.rotationInterval(getRotationInterval().orElse(null))
			.build());
	}

	/**
	 * Retrieves the currently configured interval for automatic key material rotation.
	 * <p>
	 * This value determines the lifespan of a specific version of key material before the system automatically
	 * generates a new version to mitigate cryptographic wear-out.
	 * <p>
	 * <b>Security Note:</b> If this returns a value greater than 365 days, the key may be out of compliance
	 * with standard security frameworks (e.g., NIST SP 800-57). If automatic rotation is disabled, this may
	 * return an empty {@link Optional}.
	 *
	 * @return rotation frequency, it may return an {@link Optional#empty()} if automatic key rotation is
	 * not enabled for this {@link Keyset}.
	 * @see Keyset#rotate()
	 */
	Optional<Duration> getRotationInterval();

	/**
	 * Retrieves the grace period duration that will be applied if the {@link Key} is scheduled for destruction.
	 * <p>
	 * This represents the safety buffer or cooling-off period. Once a key is marked for deletion, it will remain
	 * in a {@link KeyStatus#PENDING_DESTRUCTION} state for this duration before the key material is permanently
	 * purged from the system.
	 * <p>
	 * <b>Audit Requirement:</b> Security auditors use this value to verify that the organization has enough
	 * time to recover from accidental or unauthorized deletion requests. A value of 30 days is the recommended
	 * industry default.
	 * <p>
	 * <b>Security Note:</b> If this returns a value greater than 120 or less than 7 days, the key may be out
	 * of compliance with standard security frameworks (e.g., NIST SP 800-57). If the destruction grace period
	 * is disabled, this may return an empty {@link Optional}.
	 *
	 * @return destruction grace period, may be an {@link Optional#empty()} if cryptograhic key material should
	 * be destroyed immediately when the key is marked for deletion.
	 * @see KeyStatus#PENDING_DESTRUCTION
	 */
	Optional<Duration> getDestructionGracePeriod();

	/**
	 * Returns the number of {@link Key keys} that are present in this {@link Keyset}.
	 * @return the keyset size.
	 */
	default int size() {
		return getKeys().size();
	}

	@Override
	default Iterator<Key> iterator() {
		return stream().map(Key.class::cast).iterator();
	}

	/**
	 * Returns a sequential stream of {@link Key keys} from this {@link Keyset}.
	 * @return key stream, never {@literal null}
	 */
	default Stream<? extends Key> stream() {
		return getKeys().stream();
	}

}
