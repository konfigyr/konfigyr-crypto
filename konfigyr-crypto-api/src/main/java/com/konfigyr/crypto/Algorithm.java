package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

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
public interface Algorithm extends Serializable {

	/**
	 * @return algorithm name, never {@link null}.
	 */
	@NonNull
	String name();

	/**
	 * @return key type used by the algorithm, never {@link null}.
	 */
	@NonNull
	KeyType type();

	/**
	 * Collection of {@link KeysetOperation operations} this {@link Algorithm} can
	 * perform.
	 * @return supported operations, never {@link null}.
	 */
	@NonNull
	Set<KeysetOperation> operations();

}
