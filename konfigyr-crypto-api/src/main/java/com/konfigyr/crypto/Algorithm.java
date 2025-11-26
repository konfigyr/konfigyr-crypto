package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

import java.io.Serializable;
import java.util.Set;

/**
 * Algorithm interface that defines which {@link KeysetOperation} are supported by the
 * {@link Keyset keysets}, the {@link KeyType type of private key material}.
 * <p>
 * It is recommended that the implementation of this interface are a simple {@link Enum
 * Java enumerations} for easier serialization and deserialization of the
 * {@link Algorithm} values.
 * <p>
 * How an {@link Algorithm} is serialized and deserialized is usually defined by the
 * {@link KeysetFactory}, as this is the interface that defines how keysets are created,
 * wrapped and unwrapped.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 **/
@NullMarked
public interface Algorithm extends Serializable {

	/**
	 * Returns the name of the algorithm that is used to perform cryptographic operations.
	 *
	 * @return algorithm name, never {@literal null}.
	 */
	String name();

	/**
	 * The type of the key material that is used by the algorithm.
	 *
	 * @return key type used by the algorithm, never {@literal null}.
	 */
	KeyType type();

	/**
	 * Collection of {@link KeysetOperation operations} this {@link Algorithm} can perform.
	 *
	 * @return supported operations, never {@literal null}.
	 */
	Set<KeysetOperation> operations();

	/**
	 * Checks if the algorithm supports the given operation.
	 *
	 * @param operation operation to be checked, never {@literal null}.
	 * @return {@code true} if the algorithm supports the operation, {@code false} otherwise.
	 */
	default boolean supports(KeysetOperation operation) {
		return operations().contains(operation);
	}

}
