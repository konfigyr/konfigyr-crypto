package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

import java.time.Duration;
import java.time.Instant;

/**
 * Interface used to provide a simple definition of a cryptographic key set.
 * <p>
 * Definition of a key set is defined by the following:
 * <ul>
 * <li>Name - unique key set name</li>
 * <li>Algorithm - instructs which {@link KeysetOperation} are supported and how they are
 * performed</li>
 * <li>Rotation - how often should this key set be rotated</li>
 * </ul>
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
public interface KeysetDefinition {

	/**
	 * Name that uniquely identifies the {@link KeysetDefinition}.
	 * @return keyset name, never {@link null}.
	 */
	@NonNull
	String getName();

	/**
	 * Cryptographic algorithm that is used by this key set to perform
	 * {@link KeysetOperation operations}.
	 * @return algorithm that is used by this {@link KeysetDefinition}, never
	 * {@link null}.
	 * @see Algorithm
	 */
	@NonNull
	Algorithm getAlgorithm();

	/**
	 * Interval that defines the key rotation frequency.
	 * @return rotation frequency, never {@link null}.
	 * @see Keyset#rotate()
	 */
	@NonNull
	Duration getRotationInterval();

	/**
	 * Time when this keyset should be rotated. This would mean that the current primary
	 * key would be exchanged with a new one.
	 * @return next rotation time, never {@link null}.
	 * @see Keyset#rotate()
	 */
	@NonNull
	Instant getNextRotationTime();

	static KeysetDefinition of(@NonNull String name, @NonNull Algorithm algorithm) {
		return of(name, algorithm, Duration.ofDays(90));
	}

	static KeysetDefinition of(@NonNull String name, @NonNull Algorithm algorithm, @NonNull Duration rotationInterval) {
		return of(name, algorithm, rotationInterval, Instant.now().plus(rotationInterval));
	}

	static KeysetDefinition of(@NonNull String name, @NonNull Algorithm algorithm, @NonNull Duration rotationInterval,
			@NonNull Instant nextRotationTime) {
		return new SimpleKeysetDefinition(name, algorithm, rotationInterval, nextRotationTime);
	}

}
