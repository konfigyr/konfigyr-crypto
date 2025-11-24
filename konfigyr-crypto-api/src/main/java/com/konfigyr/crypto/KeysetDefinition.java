package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

import java.time.Duration;
import java.time.Instant;

/**
 * Interface used to provide a simple definition of a cryptographic key set.
 * <p>
 * The definition of a key set is defined by the following:
 * <ul>
 * 		<li>Name - unique key set name</li>
 * 		<li>Algorithm - instructs which {@link KeysetOperation} are supported and how they are performed</li>
 * 		<li>Rotation - how often should this key set be rotated</li>
 * </ul>
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
@NullMarked
public interface KeysetDefinition {

	/**
	 * Name that uniquely identifies the {@link KeysetDefinition}.
	 *
	 * @return keyset name, never {@literal null}.
	 */
	String getName();

	/**
	 * Cryptographic algorithm that is used by this key set to perform
	 * {@link KeysetOperation operations}.
	 *
	 * @return algorithm that is used by this {@link KeysetDefinition}, never {@literal null}.
	 * @see Algorithm
	 */
	Algorithm getAlgorithm();

	/**
	 * Interval that defines the key rotation frequency.
	 *
	 * @return rotation frequency, never {@literal null}.
	 * @see Keyset#rotate()
	 */
	Duration getRotationInterval();

	/**
	 * Time when this keyset should be rotated. This would mean that the current primary
	 * key would be exchanged with a new one.
	 *
	 * @return next rotation time, never {@literal null}.
	 * @see Keyset#rotate()
	 */
	Instant getNextRotationTime();

	/**
	 * Creates a new definition of the {@link Keyset} that should be created. The
	 * definition would use a default value of 90 days for a rotation frequency.
	 *
	 * @param name      name of the keyset, can't be {@literal null}
	 * @param algorithm algorithm that should be used by the keyset, can't be {@literal null}
	 * @return keyset definition with a 90-day rotation frequency
	 */
	static KeysetDefinition of(String name, Algorithm algorithm) {
		return of(name, algorithm, Duration.ofDays(90));
	}

	/**
	 * Creates a new definition of the {@link Keyset} that should be created with a custom
	 * rotation frequency.
	 *
	 * @param name             name of the keyset, can't be {@literal null}
	 * @param algorithm        algorithm that should be used by the keyset, can't be {@literal null}
	 * @param rotationInterval rotation frequency of the keyset, can't be {@literal null}
	 * @return keyset definition with a custom rotation frequency
	 */
	static KeysetDefinition of(String name, Algorithm algorithm, Duration rotationInterval) {
		return of(name, algorithm, rotationInterval, Instant.now().plus(rotationInterval));
	}

	/**
	 * Creates a new definition of the {@link Keyset} that should be created with a custom
	 * rotation frequency and next rotation time.
	 *
	 * @param name             name of the keyset, can't be {@literal null}
	 * @param algorithm        algorithm that should be used by the keyset, can't be {@literal null}
	 * @param rotationInterval rotation frequency of the keyset, can't be {@literal null}
	 * @param nextRotationTime timestamp when this keyset should be rotated, can't be {@literal null}
	 * @return keyset definition with a custom rotation frequency and time
	 */
	static KeysetDefinition of(String name, Algorithm algorithm, Duration rotationInterval, Instant nextRotationTime) {
		return new SimpleKeysetDefinition(name, algorithm, rotationInterval, nextRotationTime);
	}

}
