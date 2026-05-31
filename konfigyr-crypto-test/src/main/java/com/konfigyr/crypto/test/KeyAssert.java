package com.konfigyr.crypto.test;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstantAssert;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.description.Description;
import org.assertj.core.description.TextDescription;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * AssertJ assertions for verifying the state of a {@link Key} instance.
 * <p>
 * Use {@link #assertThat(Key)} as the primary entry point, or {@link #factory()} when
 * working with {@link AbstractObjectAssert#asInstanceOf(InstanceOfAssertFactory)}.
 * All assertion methods return {@code this} to support fluent method chaining.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Key
 */
@NullMarked
public class KeyAssert extends AbstractObjectAssert<KeyAssert, @Nullable Key> {

	/**
	 * Returns an {@link InstanceOfAssertFactory} that creates {@link KeyAssert} instances,
	 * for use with {@link AbstractObjectAssert#asInstanceOf(InstanceOfAssertFactory)}.
	 *
	 * @return the instance-of assert factory, never {@literal null}
	 */
	public static InstanceOfAssertFactory<Key, KeyAssert> factory() {
		return new InstanceOfAssertFactory<>(Key.class, KeyAssert::new);
	}

	/**
	 * Creates a new {@link KeyAssert} for the given {@link Key}.
	 *
	 * @param key the key to assert on, can be {@literal null}
	 * @return the assertion, never {@literal null}
	 */
	public static KeyAssert assertThat(@Nullable Key key) {
		return new KeyAssert(key);
	}

	private KeyAssert(@Nullable Key actual) {
		super(actual, KeyAssert.class);
	}

	/**
	 * Verifies that the key has the expected identifier.
	 *
	 * @param id the expected identifier, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert hasId(@Nullable String id) {
		isNotNull();
		if (!Objects.equals(actual.getId(), id)) {
			failWithMessage("Expected key to have an identifier <%s> but was <%s>", id, actual.getId());
		}
		return myself;
	}

	/**
	 * Verifies that the key uses the expected {@link Algorithm}.
	 *
	 * @param algorithm the expected algorithm, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert hasAlgorithm(@Nullable Algorithm algorithm) {
		isNotNull();
		if (!Objects.equals(actual.getAlgorithm(), algorithm)) {
			failWithMessage("Expected key to have an algorithm <%s> but was <%s>",
				algorithm, actual.getAlgorithm());
		}
		return myself;
	}

	/**
	 * Verifies that the key has the expected {@link KeyType}.
	 *
	 * @param type the expected key type, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert hasType(@Nullable KeyType type) {
		isNotNull();
		if (!Objects.equals(actual.getType(), type)) {
			failWithMessage("Expected key to be type of <%s> but was <%s>", type, actual.getType());
		}
		return myself;
	}

	/**
	 * Verifies that the key is in {@link KeyStatus#ENABLED} status.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isEnabled() {
		return hasStatus(KeyStatus.ENABLED);
	}

	/**
	 * Verifies that the key has the expected {@link KeyStatus}.
	 *
	 * @param status the expected status, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert hasStatus(@Nullable KeyStatus status) {
		isNotNull();
		if (!Objects.equals(actual.getStatus(), status)) {
			failWithMessage("Expected key to be in status <%s> but was <%s>", status, actual.getStatus());
		}
		return myself;
	}

	/**
	 * Verifies that the key is the primary key in its keyset.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isPrimary() {
		return isPrimary(true);
	}

	/**
	 * Verifies that the key is not the primary key in its keyset.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isNotPrimary() {
		return isPrimary(false);
	}

	/**
	 * Verifies that the key's primary flag matches the expected value.
	 *
	 * @param primary the expected primary flag value
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isPrimary(boolean primary) {
		isNotNull();
		if (primary != actual.isPrimary()) {
			failWithMessage("Expected key to have primary state of <%s> but was <%s>",
				primary, actual.isPrimary());
		}
		return myself;
	}

	/**
	 * Verifies that the key was created at exactly the expected timestamp.
	 *
	 * @param createdAt the expected creation timestamp, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isCreatedAt(@Nullable Instant createdAt) {
		return isCreatedAt(createdAt, Duration.ZERO);
	}

	/**
	 * Verifies that the key was created within {@code tolerance} of the expected timestamp.
	 *
	 * @param createdAt the expected creation timestamp, can be {@literal null}
	 * @param tolerance maximum acceptable difference, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isCreatedAt(@Nullable Instant createdAt, Duration tolerance) {
		return assertInstant(actual.getCreatedAt(), createdAt, tolerance, new TextDescription(
			"Expected key to be created at <%s> but was <%s>", createdAt, actual.getCreatedAt()
		));
	}

	/**
	 * Verifies that the key was initialized at exactly the expected timestamp.
	 *
	 * @param initializedAt the expected initialization timestamp, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isInitializedAt(@Nullable Instant initializedAt) {
		return isInitializedAt(initializedAt, Duration.ZERO);
	}

	/**
	 * Verifies that the key was initialized within {@code tolerance} of the expected timestamp.
	 *
	 * @param initializedAt the expected initialization timestamp, can be {@literal null}
	 * @param tolerance maximum acceptable difference, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isInitializedAt(@Nullable Instant initializedAt, Duration tolerance) {
		return assertInstant(actual.getInitializedAt(), initializedAt, tolerance, new TextDescription(
			"Expected key to be initialized at <%s> but was <%s>", initializedAt, actual.getInitializedAt()
		));
	}

	/**
	 * Verifies that the key expires at exactly the expected timestamp.
	 *
	 * @param expiresAt the expected expiry timestamp, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert expiresAt(@Nullable Instant expiresAt) {
		return expiresAt(expiresAt, Duration.ZERO);
	}

	/**
	 * Verifies that the key expires within {@code tolerance} of the expected timestamp.
	 *
	 * @param expiresAt the expected expiry timestamp, can be {@literal null}
	 * @param tolerance maximum acceptable difference, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert expiresAt(@Nullable Instant expiresAt, Duration tolerance) {
		return assertInstant(actual.getExpiresAt(), expiresAt, tolerance, new TextDescription(
			"Expected key to expire at <%s> but was <%s>", expiresAt, actual.getExpiresAt()
		));
	}

	/**
	 * Verifies that key destruction is scheduled at exactly the expected timestamp.
	 *
	 * @param destructionScheduledAt the expected scheduled destruction timestamp, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert destructionScheduledAt(@Nullable Instant destructionScheduledAt) {
		return destructionScheduledAt(destructionScheduledAt, Duration.ZERO);
	}

	/**
	 * Verifies that key destruction is scheduled within {@code tolerance} of the expected timestamp.
	 *
	 * @param destructionScheduledAt the expected scheduled destruction timestamp, can be {@literal null}
	 * @param tolerance maximum acceptable difference, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert destructionScheduledAt(@Nullable Instant destructionScheduledAt, Duration tolerance) {
		return assertInstant(actual.getDestructionScheduledAt(), destructionScheduledAt, tolerance, new TextDescription(
			"Expected key to be scheduled for destruction at <%s> but was <%s>", destructionScheduledAt,
			actual.getDestructionScheduledAt()
		));
	}

	/**
	 * Verifies that the key was destroyed at exactly the expected timestamp.
	 *
	 * @param destroyedAt the expected destruction timestamp, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isDestroyedAt(@Nullable Instant destroyedAt) {
		return isDestroyedAt(destroyedAt, Duration.ZERO);
	}

	/**
	 * Verifies that the key was destroyed within {@code tolerance} of the expected timestamp.
	 *
	 * @param destroyedAt the expected destruction timestamp, can be {@literal null}
	 * @param tolerance maximum acceptable difference, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeyAssert isDestroyedAt(@Nullable Instant destroyedAt, Duration tolerance) {
		return assertInstant(actual.getDestroyedAt(), destroyedAt, tolerance, new TextDescription(
			"Expected key to be destroyed at <%s> but was <%s>", destroyedAt, actual.getDestroyedAt()
		));
	}

	private KeyAssert assertInstant(@Nullable Instant value, @Nullable Instant expected, Duration tolerance, Description description) {
		isNotNull();

		final InstantAssert assertion = new InstantAssert(value).as(description);

		if (expected == null) {
			assertion.isNull();
		} else {
			assertion.isCloseTo(expected, Assertions.within(tolerance));
		}

		return myself;
	}
}
