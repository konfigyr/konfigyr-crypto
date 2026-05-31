package com.konfigyr.crypto.test;

import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetPurpose;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.IterableAssert;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Objects;

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
		return IterableAssert.assertThatIterable(actual.getKeys());
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
		isNotNull();
		if (!Objects.equals(actual.getName(), name)) {
			failWithMessage("Expected keyset to have a name of <%s> but was <%s>", name, actual.getName());
		}
		return myself;
	}

	/**
	 * Verifies that the keyset was created by the factory with the expected name.
	 *
	 * @param name the expected factory name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert createdByFactory(@Nullable String name) {
		isNotNull();
		if (!Objects.equals(actual.getFactory(), name)) {
			failWithMessage("Expected keyset to be managed by a <%s> keyset factory but was <%s>",
				name, actual.getFactory());
		}
		return myself;
	}

	/**
	 * Verifies that the keyset has the expected {@link KeysetPurpose}.
	 *
	 * @param purpose the expected purpose, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasPurpose(@Nullable KeysetPurpose purpose) {
		isNotNull();
		if (!Objects.equals(actual.getPurpose(), purpose)) {
			failWithMessage("Expected keyset to have a purpose of <%s> but was <%s>",
				purpose, actual.getPurpose());
		}
		return myself;
	}

	/**
	 * Verifies that the keyset is wrapped by the expected {@link KeyEncryptionKey}.
	 *
	 * @param kek the expected key encryption key, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasKeyEncryptionKey(@Nullable KeyEncryptionKey kek) {
		isNotNull();
		if (!Objects.equals(actual.getKeyEncryptionKey(), kek)) {
			failWithMessage("Expected keyset to have a Key Encryption Key of <%s> but was <%s>",
				kek, actual.getKeyEncryptionKey());
		}
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
		isNotNull();

		final KeyEncryptionKey kek = actual.getKeyEncryptionKey();

		Assertions.assertThat(kek)
			.as("Expected keyset to have a Key Encryption Key with provider of <%s> but was <%s>", provider, kek.getProvider())
			.returns(provider, KeyEncryptionKey::getProvider);

		Assertions.assertThat(kek)
			.as("Expected keyset to have a Key Encryption Key with identifier of <%s> but was <%s>", id, kek.getId())
			.returns(id, KeyEncryptionKey::getId);

		return myself;
	}

	/**
	 * Verifies that the keyset contains the expected number of keys.
	 *
	 * @param size the expected number of keys
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasSize(int size) {
		isNotNull();
		if (!Objects.equals(actual.size(), size)) {
			failWithMessage("Expected keyset to have a size of <%s> but was <%s>", size, actual.size());
		}
		return myself;
	}

	/**
	 * Verifies that the keyset has no rotation interval configured.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasNoRotationInterval() {
		isNotNull();

		Assertions.assertThat(actual.getRotationInterval())
			.as("Keyset should not have no rotation interval defined, but was <%s>", actual.getRotationInterval())
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
		isNotNull();

		final Duration duration = actual.getRotationInterval().orElse(null);

		if (!Objects.equals(duration, interval)) {
			failWithMessage("Expected keyset to have a rotation interval of <%s> but was <%s>",
				interval, duration);
		}

		return myself;
	}

	/**
	 * Verifies that the keyset has no destruction grace period configured.
	 *
	 * @return this assertion for chaining, never {@literal null}
	 */
	public KeysetAssert hasNoDestructionGracePeriod() {
		isNotNull();

		Assertions.assertThat(actual.getDestructionGracePeriod())
			.as("Keyset should not have no destruction grace defined, but was <%s>", actual.getDestructionGracePeriod())
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
		isNotNull();

		final Duration duration = actual.getDestructionGracePeriod().orElse(null);

		if (!Objects.equals(duration, interval)) {
			failWithMessage("Expected keyset to have a destruction grace period of <%s> but was <%s>",
				interval, duration);
		}

		return myself;
	}

}
