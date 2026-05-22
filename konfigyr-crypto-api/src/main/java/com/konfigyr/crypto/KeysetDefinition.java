package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.Optional;

/**
 * Interface used to provide a definition of a cryptographic key set that should be created
 * by the {@link KeysetStore}.
 * <p>
 * The definition of a key set is defined by the following:
 * <ul>
 * 		<li>
 * 		    Name - unique key set name, please make sure that within the same {@link KeysetStore}
 * 		    there are no two key sets with the same name.
 * 		</li>
 * 		<li>
 * 		    Purpose - which cryptographic capabilities of the {@link Keyset} are permitted. The purpose
 * 		    also specifies which {@link Algorithm algorithms} can be used to generate the key material.
 * 		</li>
 * 		<li>
 * 		    Algorithm - defines how the cryptographic material is generated for a {@link Key},
 * 		    how and which {@link KeysetOperation cryptographic operations} are performed.
 * 		</li>
 * 		<li>
 * 		    Rotation duration - how often should this key set be rotated. This is used to
 * 		    schedule the automatic key rotation by the {@link KeysetStore}.
 * 		</li>
 * 		<li>
 * 		    Destruction grace duration - the "grace period" between a deletion request and the
 * 		    permanent destruction of the key material.
 * 		</li>
 * </ul>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
public interface KeysetDefinition {

	/**
	 * The recommended minimum value for the key rotation interval, according to NIST SP 800-57,
	 * is set <strong>30 days</strong>.
	 */
	Duration MINIMUM_ROTATION_INTERVAL = Duration.ofDays(30);

	/**
	 * The recommended maximum value for the key rotation interval, according to NIST SP 800-57,
	 * is set <strong>365 days or 1 year</strong>.
	 * <p>
	 * We strongly advise the developers of this library to use this period as the default
	 * rotation interval when creating new keys.
	 */
	Duration MAXIMUM_ROTATION_INTERVAL = Duration.ofDays(365);

	/**
	 * The recommended minimum value for the key material destruction grace period, according to
	 * NIST SP 800-57, is <strong>7 days</strong>. Most enterprise systems do not allow periods shorter
	 * than a week to ensure at least one full business cycle for detecting errors within their system logs.
	 */
	Duration MINIMUM_DESTRUCTION_GRACE_INTERVAL = Duration.ofDays(7);

	/**
	 * The recommended maximum value for the key material destruction grace period is <strong>120 days</strong>.
	 */
	Duration MAXIMUM_DESTRUCTION_GRACE_INTERVAL = Duration.ofDays(120);

	/**
	 * Name that uniquely identifies the {@link KeysetDefinition}.
	 *
	 * @return keyset name, never {@literal null}.
	 */
	String getName();

	/**
	 * The purpose of the key material that describes the cryptographic capabilities of this {@code Keyset}.
	 *
	 * @return the purpose for this {@link KeysetDefinition}, never {@literal null}.
	 * @see Algorithm
	 */
	KeysetPurpose getPurpose();

	/**
	 * Cryptographic algorithm that is used by this key set to perform {@link KeysetOperation operations}.
	 *
	 * @return algorithm that is used by this {@link KeysetDefinition}, never {@literal null}.
	 * @see Algorithm
	 */
	Algorithm getAlgorithm();

	/**
	 * Interval that defines the key rotation frequency. Leaving this unspecified will prevent
	 * automatic key rotation by the {@link KeysetStore}.
	 * <p>
	 * You are still allowed to perform manual primary key rotation by calling {@link Keyset#rotate()} method.
	 *
	 * @return rotation frequency, may be {@literal null}.
	 * @see Keyset#rotate()
	 */
	Optional<@Nullable Duration> getRotationInterval();

	/**
	 * This duration interval defines the mandatory waiting period between the moment a user initiates a
	 * deletion request for a {@link Key} within the {@link Keyset}, and the permanent, irrevocable destruction
	 * of the cryptographic key material.
	 * <p>
	 * Leaving this unspecified is not advised, as immediate destruction is irreversible. This grace period allows
	 * administrators to verify that no systems are still reliant on the keyset and provides a window to reverse
	 * the operation if it was performed in error or by an unauthorized actor.
	 *
	 * @return destruction grace period, may be {@literal null}.
	 */
	Optional<@Nullable Duration> getDestructionGracePeriod();

	/**
	 * Creates a new builder used to create a {@link KeysetDefinition}.
	 *
	 * @return the keyset definition builder, never {@literal null}
	 */
	static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new definition of the {@link Keyset} that should be created for the given name
	 * and algorithm. The following default values are used when creating this keyset:
	 * <ul>
	 *     <li>Purpose is extracted from the algorithm</li>
	 *     <li>Key rotation interval - 90 days</li>
	 *     <li>Destruction grace period - 30 days</li>
	 *  </ul>
	 *
	 * @param name      name of the keyset, can't be {@literal null}
	 * @param algorithm algorithm that should be used by the keyset, can't be {@literal null}
	 * @return keyset definition with a 90-day rotation frequency
	 */
	static KeysetDefinition of(String name, Algorithm algorithm) {
		return of(name, algorithm.purpose(), algorithm);
	}

	/**
	 * Creates a new definition of the {@link Keyset} that should be created for the given name, purpose,
	 * and algorithm. The following default values are used when creating this keyset:
	 * <ul>
	 *     <li>Key rotation interval - 90 days</li>
	 *     <li>Destruction grace period - 30 days</li>
	 * </ul>
	 *
	 * @param name      name of the keyset, can't be {@literal null}
	 * @param purpose   purpose of the keyset, can't be {@literal null}
	 * @param algorithm algorithm that should be used by the keyset, can't be {@literal null}
	 * @return keyset definition with a 90-day rotation frequency
	 */
	static KeysetDefinition of(String name, KeysetPurpose purpose, Algorithm algorithm) {
		return builder()
			.name(name)
			.purpose(purpose)
			.algorithm(algorithm)
			.build();
	}

	/**
	 * Creates a new definition of the existing {@link Keyset}. The following values are used
	 * when creating this keyset definition:
	 * <ul>
	 *     <li>Name</li>
	 *     <li>Keyset purpose</li>
	 *     <li>Key rotation interval</li>
	 *     <li>Destruction grace period</li>
	 * </ul>
	 *
	 * @param keyset existing keyset, can't be {@literal null}
	 * @return keyset definition with a 90-day rotation frequency
	 */
	static Builder builder(Keyset keyset) {
		final Builder builder = builder()
			.name(keyset.getName())
			.purpose(keyset.getPurpose());

		keyset.getRotationInterval().ifPresentOrElse(
			builder::rotationInterval, builder::disableAutomaticKeyRotation
		);
		keyset.getDestructionGracePeriod().ifPresentOrElse(
			builder::destructionGracePeriod, builder::disableDestructionGracePeriod
		);

		return builder;
	}

	/**
	 * Fluent builder used to create a {@link KeysetDefinition}.
	 */
	class Builder {

		@Nullable
		protected String name;

		@Nullable
		protected KeysetPurpose purpose;

		@Nullable
		protected Algorithm algorithm;

		@Nullable
		protected Duration rotationInterval = Duration.ofDays(90);

		@Nullable
		protected Duration destructionGracePeriod = Duration.ofDays(30);

		protected Builder() {
		}

		/**
		 * Specifies the name of the {@link Keyset} that should be created. The name of the keyset must
		 * be unique within the {@link KeysetStore}.
		 *
		 * @param name keyset name
		 * @return the definition builder
		 */
		public Builder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Specifies the purpose of the {@link Keyset} that should be created.
		 *
		 * @param purpose keyset purpose
		 * @return the definition builder
		 */
		public Builder purpose(KeysetPurpose purpose) {
			this.purpose = purpose;
			return this;
		}

		/**
		 * Specifies the algorithm that should be used by the {@link Keyset} to generate the
		 * cryptographic material for the {@link Key}s.
		 *
		 * @param algorithm the algorithm
		 * @return the definition builder
		 */
		public Builder algorithm(Algorithm algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		/**
		 * Sets the automatic rotation interval for the key material within the {@link Keyset}.
		 * <p>
		 * We recommended setting this to 365 days (1 year) if you are using it for performing
		 * cryptographic operations against standard data; 90 days for sensitive data.
		 * <p>
		 * Regular rotation limits the cryptographic period: the amount of data protected by a single key.
		 * This minimizes the blast radius if a key is ever compromised and ensures compliance with standards
		 * like PCI DSS 4.0 and NIST SP 800-57.
		 * <p>
		 * You can choose any interval between 30 days and 365 days
		 *
		 * @param rotationInterval the duration between automatic key rotations.
		 * @return the definition builder
		 */
		public Builder rotationInterval(Duration rotationInterval) {
			this.rotationInterval = rotationInterval;
			return this;
		}

		/**
		 * Disables the automatic rotation of the key material within the {@link Keyset}.
		 * <p>
		 * Bypassing automatic rotation is a violation of NIST SP 800-57 and PCI DSS 4.0 security standards.
		 * It increases the amount of data encrypted under a single key, expanding the blast radius in the
		 * event of a key compromise.
		 * <p>
		 * Security best practice tells us to enable automatic rotation with a maximum interval of 365 days.
		 * For sensitive PII or financial data, an interval of 90 days is recommended to ensure high
		 * cryptographic hygiene.
		 *
		 * @return the definition builder
		 * @see #rotationInterval(Duration)
		 */
		public Builder disableAutomaticKeyRotation() {
			this.rotationInterval = null;
			return this;
		}

		/**
		 * Sets the safety window between a deletion request and the permanent destruction of the key.
		 * <p>
		 * We recommended setting this to 30 days, that is an industry standard.
		 * <p>
		 * This period acts as a critical safeguard against accidental or malicious deletion. Because key
		 * destruction is irreversible and renders all associated encrypted data unrecoverable, this window
		 * allows administrators to detect service disruptions and cancel the destruction before data loss occurs.
		 * <p>
		 * You can choose any interval between 7 days and 120 days.
		 *
		 * @param destructionGracePeriod duration how long the key remains in a scheduled for deletion state.
		 * @return the definition builder
		 */
		public Builder destructionGracePeriod(Duration destructionGracePeriod) {
			this.destructionGracePeriod = destructionGracePeriod;
			return this;
		}

		/**
		 * Explicitly disables the destruction grace period for cryptographic key material.
		 * <p>
		 * Using this method is <b>strongly discouraged</b> in production environments. Not setting a grace period
		 * significantly increases the risk of permanent, unrecoverable data loss due to accidental or malicious
		 * deletion requests.
		 * <p>
		 * According to security best practices, you should maintain a minimum grace period of 30 days. This
		 * gives the system enough time to detect system failures and cancel pending cryptographic key
		 * material destruction.
		 *
		 * @return the definition builder
		 * @see #destructionGracePeriod(Duration)
		 */
		public Builder disableDestructionGracePeriod() {
			this.destructionGracePeriod = null;
			return this;
		}

		public KeysetDefinition build() {
			Assert.hasText(name, "Keyset name can not be blank");
			Assert.notNull(algorithm, "Keyset algorithm can not be null");

			if (purpose == null) {
				purpose = algorithm.purpose();
			}

			if (algorithm.purpose() != purpose) {
				throw new IllegalArgumentException(
					"Can not create keyset definition for algorithm " + algorithm + " with keyset purpose " +
						purpose + ". Please make sure that the algorithm purpose matches the keyset purpose.");
			}

			if (rotationInterval != null) {
				if (KeysetDefinition.MINIMUM_ROTATION_INTERVAL.compareTo(rotationInterval) > 0) {
					throw new IllegalArgumentException("Keyset rotation interval can not be less than "
						+ KeysetDefinition.MINIMUM_ROTATION_INTERVAL.toDays() + " days");
				}
				if (KeysetDefinition.MAXIMUM_ROTATION_INTERVAL.compareTo(rotationInterval) < 0) {
					throw new IllegalArgumentException("Keyset rotation interval can not be greater than "
						+ KeysetDefinition.MAXIMUM_ROTATION_INTERVAL.toDays() + " days");
				}
			}

			if (destructionGracePeriod != null) {
				if (KeysetDefinition.MINIMUM_DESTRUCTION_GRACE_INTERVAL.compareTo(destructionGracePeriod) > 0) {
					throw new IllegalArgumentException("Keyset destruction grace interval can not be less than "
						+ KeysetDefinition.MINIMUM_DESTRUCTION_GRACE_INTERVAL.toDays() + " days");
				}
				if (KeysetDefinition.MAXIMUM_DESTRUCTION_GRACE_INTERVAL.compareTo(destructionGracePeriod) < 0) {
					throw new IllegalArgumentException("Keyset destruction grace interval can not be greater than "
						+ KeysetDefinition.MAXIMUM_DESTRUCTION_GRACE_INTERVAL.toDays() + " days");
				}
			}

			return new SimpleKeysetDefinition(name, purpose, algorithm, rotationInterval, destructionGracePeriod);
		}

	}

}
