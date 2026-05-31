package com.konfigyr.crypto.test;

import com.konfigyr.crypto.*;
import org.assertj.core.api.*;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * AssertJ assertions for verifying the state of a {@link Keyset} instance.
 * <p>
 * Use {@link #assertThat(Keyset)} as the primary entry point, or {@link #factory()} when
 * working with {@link AbstractObjectAssert#asInstanceOf(InstanceOfAssertFactory)}.
 * All assertion methods return {@code this} to support fluent method chaining.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Keyset
 */
@NullMarked
public class KeysetAssert extends AbstractObjectAssert<KeysetAssert, @Nullable Keyset> {

	/**
	 * Returns an {@link InstanceOfAssertFactory} that creates {@link KeysetAssert} instances,
	 * for use with {@link AbstractObjectAssert#asInstanceOf(InstanceOfAssertFactory)}.
	 *
	 * @return the instance-of assert factory, never {@literal null}
	 */
	public static InstanceOfAssertFactory<Keyset, KeysetAssert> factory() {
		return new InstanceOfAssertFactory<>(Keyset.class, KeysetAssert::new);
	}

	/**
	 * Creates a new {@link KeysetAssert} for the given {@link Keyset}.
	 *
	 * @param keyset the keyset to assert on, can be {@literal null}
	 * @return the assertion, never {@literal null}
	 */
	public static KeysetAssert assertThat(@Nullable Keyset keyset) {
		return new KeysetAssert(keyset);
	}

	private KeysetAssert(@Nullable Keyset actual) {
		super(actual, KeysetAssert.class);
	}

	/**
	 * Returns an {@link IterableAssert} over the keyset's {@link Key keys}, allowing further
	 * assertions to be chained on the key collection.
	 *
	 * @return iterable assertion over the keyset's keys, never {@literal null}
	 */
	public IterableAssert<Key> assertThatKeys() {
		return assertThatKeyset()
			.as("encrypted keys")
			.extracting(Keyset::getKeys, InstanceOfAssertFactories.iterable(Key.class));
	}

	/**
	 * Verifies that the keyset's name, purpose, rotation interval, and destruction grace period
	 * all match the corresponding values of the given {@link KeysetDefinition}.
	 *
	 * @param definition the definition to match against, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert matchesDefinition(KeysetDefinition definition) {
		return hasName(definition.getName())
			.hasPurpose(definition.getPurpose())
			.hasRotationInterval(definition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(definition.getDestructionGracePeriod().orElse(null));
	}

	/**
	 * Verifies that the keyset has the expected name.
	 *
	 * @param name the expected name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasName(@Nullable String name) {
		assertThatKeyset()
			.extracting(Keyset::getName, InstanceOfAssertFactories.STRING)
			.as("keyset name")
			.isEqualTo(name);
		return myself;
	}

	/**
	 * Verifies that the keyset was created by the factory with the expected name.
	 *
	 * @param name the expected factory name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert createdByFactory(@Nullable String name) {
		assertThatKeyset()
			.extracting(Keyset::getFactory, InstanceOfAssertFactories.STRING)
			.as("keyset factory")
			.isEqualTo(name);
		return myself;
	}

	/**
	 * Verifies that the keyset has the expected {@link KeysetPurpose}.
	 *
	 * @param purpose the expected purpose, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasPurpose(@Nullable KeysetPurpose purpose) {
		assertThatKeyset()
			.extracting(Keyset::getPurpose)
			.as("keyset purpose")
			.isEqualTo(purpose);
		return myself;
	}

	/**
	 * Verifies that the keyset is wrapped by the expected {@link KeyEncryptionKey}.
	 *
	 * @param kek the expected key encryption key, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasKeyEncryptionKey(@Nullable KeyEncryptionKey kek) {
		assertThatKeyset()
			.extracting(Keyset::getKeyEncryptionKey)
			.as("key encryption key")
			.isEqualTo(kek);
		return myself;
	}

	/**
	 * Verifies that the keyset is wrapped by a {@link KeyEncryptionKey} with the expected provider
	 * and identifier.
	 *
	 * @param provider the expected KEK provider name, can be {@literal null}
	 * @param id the expected KEK identifier, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasKeyEncryptionKey(@Nullable String provider, @Nullable String id) {
		assertThatKeyset()
			.extracting(k -> k.getKeyEncryptionKey().getProvider(), InstanceOfAssertFactories.STRING)
			.as("KEK provider")
			.isEqualTo(provider);
		assertThatKeyset()
			.extracting(k -> k.getKeyEncryptionKey().getId(), InstanceOfAssertFactories.STRING)
			.as("KEK identifier")
			.isEqualTo(id);
		return myself;
	}

	/**
	 * Verifies that the keyset contains the expected number of keys.
	 *
	 * @param size the expected number of keys
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasSize(int size) {
		assertThatKeyset()
			.extracting(Keyset::size, InstanceOfAssertFactories.INTEGER)
			.as("keyset size")
			.isEqualTo(size);
		return myself;
	}

	/**
	 * Verifies that the keyset has no rotation interval configured.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasNoRotationInterval() {
		assertThatKeyset()
			.extracting(Keyset::getRotationInterval, InstanceOfAssertFactories.optional(Duration.class))
			.as("keyset rotation interval")
			.isEmpty();
		return myself;
	}

	/**
	 * Verifies that the keyset has the expected rotation interval. Pass {@literal null} to assert
	 * that no rotation interval is configured.
	 *
	 * @param interval the expected rotation interval, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasRotationInterval(@Nullable Duration interval) {
		if (interval == null) {
			return hasNoRotationInterval();
		}
		assertThatKeyset()
			.extracting(Keyset::getRotationInterval, InstanceOfAssertFactories.optional(Duration.class))
			.as("keyset rotation interval")
			.hasValue(interval);
		return myself;
	}

	/**
	 * Verifies that the keyset has no destruction grace period configured.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasNoDestructionGracePeriod() {
		assertThatKeyset()
			.extracting(Keyset::getDestructionGracePeriod, InstanceOfAssertFactories.optional(Duration.class))
			.as("keyset destruction grace period")
			.isEmpty();
		return myself;
	}

	/**
	 * Verifies that the keyset has the expected destruction grace period. Pass {@literal null}
	 * to assert that no destruction grace period is configured.
	 *
	 * @param interval the expected destruction grace period, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasDestructionGracePeriod(@Nullable Duration interval) {
		if (interval == null) {
			return hasNoDestructionGracePeriod();
		}
		assertThatKeyset()
			.extracting(Keyset::getDestructionGracePeriod, InstanceOfAssertFactories.optional(Duration.class))
			.as("keyset destruction grace period")
			.hasValue(interval);
		return myself;
	}

	private ObjectAssert<Keyset> assertThatKeyset() {
		return Assertions.assertThatObject(actual).isNotNull();
	}

}
