package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.Optional;

/**
 * Defines the parameters used to generate a new cryptographic {@link Key} during a
 * {@link Keyset} rotation.
 * <p>
 * Unlike {@link KeysetDefinition}, which describes the full keyset lifecycle and storage
 * configuration, a {@link KeyDefinition} carries only what is needed to produce a single
 * replacement key: the {@link Algorithm}, the primary flag, and an optional expiry interval.
 * The unique key identifier is not part of the definition — it is generated and
 * guaranteed unique by the {@link Keyset} implementation at rotation time.
 * <p>
 * Use {@link KeysetStore#rotate(String, KeyDefinition)} to trigger a custom rotation via
 * the store, or call {@link Keyset#rotate(KeyDefinition)} directly when working with a
 * keyset instance.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Keyset#rotate(KeyDefinition)
 * @see KeysetStore#rotate(String, KeyDefinition)
 */
@NullMarked
public interface KeyDefinition {

	/**
	 * Returns the {@link Algorithm} to be used when generating the new {@link Key}.
	 * <p>
	 * The algorithm's {@link Algorithm#purpose()} must match the target {@link Keyset}'s
	 * purpose, otherwise the rotation will be rejected with an
	 * {@link CryptoException.UnsupportedAlgorithmException}.
	 *
	 * @return algorithm for the new key, never {@literal null}
	 */
	Algorithm getAlgorithm();

	/**
	 * Returns whether the newly generated key should become the primary key in the keyset.
	 * <p>
	 * A primary key is used for active cryptographic operations (encrypt, sign). Passing
	 * {@literal true} will demote the current primary key to a non-primary status.
	 *
	 * @return {@literal true} if the new key should be primary
	 */
	boolean isPrimary();

	/**
	 * Returns the duration after which the new key should expire and be eligible for
	 * rotation. When empty, no expiry is set on the key.
	 *
	 * @return key rotation interval, or empty if the key should not expire automatically
	 */
	Optional<Duration> getRotationInterval();

	/**
	 * Creates a new {@link KeyDefinition} for a primary key using the {@link Algorithm}
	 * and the rotation interval specified in the given {@link KeysetDefinition}.
	 *
	 * @param definition keyset definition to use for the new key, can't be {@literal null}
	 * @return key definition, never {@literal null}
	 */
	static KeyDefinition of(KeysetDefinition definition) {
		return builder()
			.algorithm(definition.getAlgorithm())
			.rotationInterval(definition.getRotationInterval().orElse(null))
			.build();
	}

	/**
	 * Creates a new {@link KeyDefinition} for a primary key using the given algorithm
	 * with no fixed rotation interval.
	 *
	 * @param algorithm algorithm to use for the new key, can't be {@literal null}
	 * @return key definition, never {@literal null}
	 */
	static KeyDefinition of(Algorithm algorithm) {
		return builder().algorithm(algorithm).build();
	}

	/**
	 * Creates a new fluent builder for {@link KeyDefinition}.
	 *
	 * @return key definition builder, never {@literal null}
	 */
	static Builder builder() {
		return new Builder();
	}

	/**
	 * Fluent builder used to create a {@link KeyDefinition}.
	 */
	class Builder {

		protected boolean primary = true;
		protected @Nullable Algorithm algorithm;
		protected @Nullable Duration rotationInterval;

		protected Builder() {
		}

		/**
		 * Sets the algorithm for the new key.
		 *
		 * @param algorithm the algorithm to use, can't be {@literal null}
		 * @return this builder
		 */
		public Builder algorithm(Algorithm algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		/**
		 * Sets whether the new key should become the primary key in the keyset.
		 *
		 * @param primary {@literal true} to make the key primary
		 * @return this builder
		 */
		public Builder primary(boolean primary) {
			this.primary = primary;
			return this;
		}

		/**
		 * Sets the duration after which the new key should expire.
		 *
		 * @param rotationInterval key expiry duration, can be {@literal null} to disable expiry
		 * @return this builder
		 */
		public Builder rotationInterval(@Nullable Duration rotationInterval) {
			this.rotationInterval = rotationInterval;
			return this;
		}

		/**
		 * Builds the {@link KeyDefinition}.
		 *
		 * @return key definition, never {@literal null}
		 * @throws IllegalArgumentException when the algorithm is not set
		 */
		public KeyDefinition build() {
			Assert.notNull(algorithm, "Key definition algorithm can't be null");
			return new SimpleKeyDefinition(algorithm, primary, rotationInterval);
		}

	}

}
