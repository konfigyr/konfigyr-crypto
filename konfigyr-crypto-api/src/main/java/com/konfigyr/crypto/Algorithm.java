package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

import java.io.Serializable;
import java.util.Set;

/**
 * Algorithm interface that defines which {@link KeysetOperation operations} are supported
 * by a {@link Keyset}, what {@link KeysetPurpose purpose} it serves, and the
 * {@link KeyType type} of key material it uses.
 * <p>
 * Implementations should be immutable value objects. Each cryptographic library module
 * (e.g. {@code konfigyr-crypto-tink}, {@code konfigyr-crypto-jose}) provides a set of
 * pre-built constants for the algorithms it supports.
 * <p>
 * Custom algorithms can be created by implementing this interface and registering the
 * instance with the {@link AlgorithmRegistry} via an {@link AlgorithmRegistrar} bean.
 * <p>
 * The algorithm {@link #name()} is used as a stable, persistent identifier. It is stored
 * alongside the {@link EncryptedKeyset} and used by the {@link AlgorithmRegistry} and
 * {@link KeysetFactory} to resolve the correct implementation at runtime. It must
 * therefore be unique across all registered algorithms and must not change once
 * key material has been encrypted with it.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see KeysetPurpose
 * @see AlgorithmRegistry
 **/
@NullMarked
public interface Algorithm extends Serializable {

	/**
	 * Returns the stable, unique name of this algorithm. This value is persisted in the
	 * {@link EncryptedKeyset} and used to resolve the algorithm at load time via the
	 * {@link AlgorithmRegistry}. It must not change once key material has been created
	 * with this algorithm.
	 *
	 * @return algorithm name, never {@literal null}.
	 */
	String name();

	/**
	 * Returns the intended cryptographic purpose of this algorithm. Purpose determines
	 * which {@link Keyset keysets} this algorithm may be used with and constrains the
	 * set of valid {@link #operations()}.
	 *
	 * @return keyset purpose, never {@literal null}.
	 */
	KeysetPurpose purpose();

	/**
	 * The type of the key material that is used by the algorithm.
	 *
	 * @return key type used by the algorithm, never {@literal null}.
	 */
	KeyType type();

	/**
	 * Collection of {@link KeysetOperation operations} this {@link Algorithm} can perform.
	 * <p>
	 * The returned set of operations must match the operations from the specified keyset
	 * purpose.
	 *
	 * @return supported operations, never {@literal null} or empty.
	 */
	default Set<KeysetOperation> operations() {
		return purpose().operations();
	}

	/**
	 * Checks if the algorithm supports the given operation.
	 *
	 * @param operation operation to be checked, never {@literal null}.
	 * @return {@code true} if the algorithm supports the operation, {@code false} otherwise.
	 */
	default boolean supports(KeysetOperation operation) {
		return purpose().isOperationSupported(operation);
	}

}
