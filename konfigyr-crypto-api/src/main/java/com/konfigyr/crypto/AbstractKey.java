package com.konfigyr.crypto;

import lombok.Getter;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.StringJoiner;

/**
 * Abstract implementation of the {@link Key} interface that can be used to create specific
 * cryptographic key implementations by the {@link KeysetFactory}.
 *
 * @param <A> the type of the cryptographic algorithm used by the key.
 * @author Vladimir Spasic
 * @since 1.0.0
 */
@Getter
@NullMarked
public abstract class AbstractKey<A extends Algorithm> implements Key {

	/**
	 * The unique identifier for the key.
	 */
	protected final String id;

	/**
	 * The cryptographic algorithm used by the key.
	 */
	protected final A algorithm;

	/**
	 * The status of the key indicating its usability for cryptographic operations.
	 */
	protected final KeyStatus status;

	/**
	 * Flag indicating whether this key is the primary key for encryption, signing,
	 * or key encapsulation operations.
	 */
	protected final boolean primary;

	/**
	 * The timestamp when the key was created.
	 */
	protected final Instant createdAt;

	/**
	 * The timestamp when the cryptographic material was initialized for the key.
	 */
	@Nullable
	protected final Instant initializedAt;

	/**
	 * The timestamp when the key should expire and be rotated.
	 */
	@Nullable
	protected final Instant expiresAt;

	/**
	 * The timestamp when the key is scheduled for destruction.
	 */
	@Nullable
	protected final Instant destructionScheduledAt;

	/**
	 * The timestamp when the cryptographic material was destroyed for the key.
	 */
	@Nullable
	protected final Instant destroyedAt;

	/**
	 * Internal constructor used by the {@link AbstractKey} implementations to create the {@link Key} instances.
	 *
	 * @param builder the builder instance used to create the {@link Key} instance.
	 */
	protected AbstractKey(Builder<A, ?, ?> builder) {
		Assert.notNull(builder.id, "Key identifier can't be null");
		Assert.notNull(builder.algorithm, "Key algorithm can't be null");
		Assert.notNull(builder.status, "Key status can't be null");
		Assert.notNull(builder.createdAt, "Key creation time can't be null");

		this.id = builder.id;
		this.algorithm = builder.algorithm;
		this.status = builder.status;
		this.primary = builder.primary;
		this.createdAt = builder.createdAt;
		this.initializedAt = builder.initializedAt;
		this.expiresAt = builder.expiresAt;
		this.destructionScheduledAt = builder.destructionScheduledAt;
		this.destroyedAt = builder.destroyedAt;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof AbstractKey<?> that)) return false;
		return primary == that.primary
			&& status == that.status
			&& Objects.equals(id, that.id)
			&& Objects.equals(algorithm, that.algorithm)
			&& Objects.equals(createdAt, that.createdAt)
			&& Objects.equals(initializedAt, that.initializedAt)
			&& Objects.equals(expiresAt, that.expiresAt)
			&& Objects.equals(destructionScheduledAt, that.destructionScheduledAt)
			&& Objects.equals(destroyedAt, that.destroyedAt);
	}

	@Override
	public int hashCode() {
		int result = id.hashCode();
		result = 31 * result + Objects.hashCode(algorithm);
		result = 31 * result + status.hashCode();
		result = 31 * result + Boolean.hashCode(primary);
		result = 31 * result + createdAt.hashCode();
		result = 31 * result + Objects.hashCode(initializedAt);
		result = 31 * result + Objects.hashCode(expiresAt);
		result = 31 * result + Objects.hashCode(destructionScheduledAt);
		result = 31 * result + Objects.hashCode(destroyedAt);
		return result;
	}

	@Override
	public String toString() {
		return new StringJoiner(", ", getClass().getSimpleName() + "(", ")")
			.add("id='" + id + "'")
			.add("algorithm=" + algorithm)
			.add("status=" + status)
			.add("primary=" + primary)
			.add("createdAt=" + createdAt)
			.add("initializedAt=" + initializedAt)
			.add("expiresAt=" + expiresAt)
			.add("destructionScheduledAt=" + destructionScheduledAt)
			.add("destroyedAt=" + destroyedAt)
			.toString();
	}

	/**
	 * Abstract builder type that can be used by the {@link AbstractKey} implementations to create instances
	 * of the {@link AbstractKey}.
	 *
	 * @param <A> the type of the cryptographic algorithm used by the key.
	 * @param <K> the type of the {@link AbstractKey} implementation.
	 * @param <B> the type of the builder implementation.
	 * @author Vladimir Spasic
	 * @since 1.0.0
	 */
	public static abstract class Builder<A extends Algorithm, K extends AbstractKey<A>, B extends Builder<A, K, B>> {

		/**
		 * The unique identifier for the key.
		 */
		@Nullable
		protected String id;

		/**
		 * The cryptographic algorithm used by the key.
		 */
		@Nullable
		protected A algorithm;

		/**
		 * The status of the key indicating its usability for cryptographic operations.
		 */
		@Nullable
		protected KeyStatus status;

		/**
		 * Flag indicating whether this key is the primary key for encryption, signing, or key encapsulation operations.
		 */
		protected boolean primary;

		/**
		 * The timestamp when the key was created.
		 */
		@Nullable
		protected Instant createdAt;

		/**
		 * The timestamp when the cryptographic material was initialized for the key.
		 */
		@Nullable
		protected Instant initializedAt;

		/**
		 * The timestamp when the key should expire and be rotated.
		 */
		@Nullable
		protected Instant expiresAt;

		/**
		 * The timestamp when the key is scheduled for destruction.
		 */
		@Nullable
		protected Instant destructionScheduledAt;

		/**
		 * The timestamp when the cryptographic material was destroyed for the key.
		 */
		@Nullable
		protected Instant destroyedAt;

		protected Builder() {
			this.createdAt = Instant.now();
		}

		@SuppressWarnings("unchecked")
		protected Builder(KeyDefinition definition) {
			this.algorithm = (A) definition.getAlgorithm();
			this.primary = definition.isPrimary();
			this.createdAt = Instant.now();
			this.expiresAt = definition.getRotationInterval()
				.map(this.createdAt::plus)
				.orElse(null);
		}

		protected Builder(K key) {
			this.id = key.id;
			this.algorithm = key.algorithm;
			this.status = key.status;
			this.primary = key.primary;
			this.createdAt = key.createdAt;
			this.initializedAt = key.initializedAt;
			this.expiresAt = key.expiresAt;
			this.destructionScheduledAt = key.destructionScheduledAt;
			this.destroyedAt = key.destroyedAt;
		}

		/**
		 * Method used by the builder implementations to return the type-safe builder instance.
		 *
		 * @return the type-safe builder instance.
		 */
		@SuppressWarnings("unchecked")
		protected B self() {
			return (B) this;
		}

		/**
		 * Specifies the key identifier. The identifier of the key must be unique within the {@link Keyset}.
		 *
		 * @param id the key identifier.
		 * @return the key builder instance.
		 */
		public B id(String id) {
			this.id = id;
			return self();
		}

		/**
		 * Specifies the key algorithm that would be used by the key. The {@link Algorithm} defines the
		 * which {@link KeysetOperation} are supported by the key and the type of the cryptographic material.
		 *
		 * @param algorithm the key algorithm.
		 * @return the key builder instance.
		 */
		public B algorithm(A algorithm) {
			this.algorithm = algorithm;
			return self();
		}

		/**
		 * Sets the status of the key. The key status is used to determine if this key can be used for
		 * performing cryptographic operations defined by the algorithm.
		 *
		 * @param status the key status.
		 * @return the key builder instance.
		 */
		public B status(KeyStatus status) {
			this.status = status;
			return self();
		}

		/**
		 * Sets the status of the key to {@link KeyStatus#ENABLED}.
		 *
		 * @return the key builder instance.
		 */
		public B enabled() {
			return status(KeyStatus.ENABLED);
		}

		/**
		 * Keys that are marked as primary are the ones that would perform the encryption, key encapsulation,
		 * or signing operations.
		 *
		 * @param primary the primary flag for the key.
		 * @return the key builder instance.
		 */
		public B primary(boolean primary) {
			this.primary = primary;
			return self();
		}

		/**
		 * Sets this key as primary.
		 *
		 * @return the key builder instance.
		 */
		public B primary() {
			return primary(true);
		}

		/**
		 * Specify the timestamp when the {@link Key} was created.
		 *
		 * @param createdAt the timestamp when the key was created
		 * @return builder
		 */
		public B createdAt(@Nullable Instant createdAt) {
			this.createdAt = createdAt;
			return self();
		}

		/**
		 * Specify the timestamp when cryptographic material was initialized for this {@link Key}.
		 *
		 * @param initializedAt the timestamp when cryptographic material was initialized
		 * @return builder
		 */
		public B initializedAt(@Nullable Instant initializedAt) {
			this.initializedAt = initializedAt;
			return self();
		}

		/**
		 * Calculates the expiration time for this {@link Key} using the specified rotation interval.
		 *
		 * @param rotationInterval the key rotation interval
		 * @return builder
		 */
		public B expiresIn(@Nullable Duration rotationInterval) {
			return expiresAt(rotationInterval != null ? Instant.now().plus(rotationInterval) : null);
		}

		/**
		 * Specify the time when this {@link Key} should expire and be rotated.
		 *
		 * @param expiresAt the expiry time
		 * @return builder
		 */
		public B expiresAt(@Nullable Instant expiresAt) {
			this.expiresAt = expiresAt;
			return self();
		}

		/**
		 * Calculates the time when this {@link Key} should be scheduled for destruction using the specified
		 * rotation interval.
		 *
		 * @param destructionGracePeriod the destruction grace period
		 * @return builder
		 */
		public B scheduleDestructionIn(@Nullable Duration destructionGracePeriod) {
			return this.destructionScheduledAt(destructionGracePeriod != null ?
				Instant.now().plus(destructionGracePeriod) : null);
		}

		/**
		 * Specify the time when cryptographic material associated with this {@link Key} is scheduled
		 * to be destroyed.
		 *
		 * @param destructionScheduledAt the scheduled destruction time
		 * @return builder
		 */
		public B destructionScheduledAt(@Nullable Instant destructionScheduledAt) {
			this.destructionScheduledAt = destructionScheduledAt;
			return self();
		}

		/**
		 * Specify the time when the cryptographic material was destroyed for the {@link Key}.
		 *
		 * @param destroyedAt the destruction time
		 * @return builder
		 */
		public B destroyedAt(@Nullable Instant destroyedAt) {
			this.destroyedAt = destroyedAt;
			return self();
		}

		/**
		 * Creates the {@link Key} instance based on the builder configuration.
		 *
		 * @return the {@link Key} instance.
		 * @throws IllegalArgumentException when required arguments are not set.
		 */
		public abstract K build();

	}
}
