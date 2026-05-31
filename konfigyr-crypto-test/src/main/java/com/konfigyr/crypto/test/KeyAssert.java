package com.konfigyr.crypto.test;

import com.konfigyr.crypto.*;
import org.assertj.core.api.*;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

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
		assertThatKey()
			.extracting(Key::getId, InstanceOfAssertFactories.STRING)
			.as("key identifier")
			.isEqualTo(id);
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
		assertThatKey()
			.extracting(Key::getAlgorithm)
			.as("key algorithm")
			.isEqualTo(algorithm);
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
		assertThatKey()
			.extracting(Key::getType)
			.as("key type")
			.isEqualTo(type);
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
		assertThatKey()
			.extracting(Key::getStatus)
			.as("key status")
			.isEqualTo(status);
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
		assertThatKey()
			.extracting(Key::isPrimary, InstanceOfAssertFactories.BOOLEAN)
			.as("key primary flag")
			.isEqualTo(primary);
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
		return assertInstant(Key::getCreatedAt, createdAt, tolerance, "key creation timestamp");
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
		return assertInstant(Key::getInitializedAt, initializedAt, tolerance, "key initialization timestamp");
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
		return assertInstant(Key::getExpiresAt, expiresAt, tolerance, "key expiry timestamp");
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
		return assertInstant(Key::getDestructionScheduledAt, destructionScheduledAt, tolerance,
			"key scheduled destruction timestamp");
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
		return assertInstant(Key::getDestroyedAt, destroyedAt, tolerance, "key destruction timestamp");
	}

	private ObjectAssert<Key> assertThatKey() {
		return Assertions.assertThatObject(actual).isNotNull();
	}

	private KeyAssert assertInstant(
		Function<Key, @Nullable Instant> supplier,
		@Nullable Instant expected,
		Duration tolerance,
		String description
	) {
		if (expected == null) {
			assertThatKey()
				.extracting(supplier)
				.as(description)
				.isNull();
		} else {
			assertThatKey()
				.extracting(supplier)
				.asInstanceOf(InstanceOfAssertFactories.INSTANT)
				.as(description)
				.isCloseTo(expected, Assertions.within(tolerance));
		}

		return myself;
	}

}
