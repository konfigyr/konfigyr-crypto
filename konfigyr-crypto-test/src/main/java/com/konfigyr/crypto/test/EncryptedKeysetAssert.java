package com.konfigyr.crypto.test;

import com.konfigyr.crypto.EncryptedKey;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetPurpose;
import org.assertj.core.api.*;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * AssertJ assertions for verifying the state of an {@link EncryptedKeyset} instance.
 * <p>
 * Use {@link #assertThat(EncryptedKeyset)} as the primary entry point, or {@link #factory()} when
 * working with {@link AbstractObjectAssert#asInstanceOf(InstanceOfAssertFactory)}.
 * All assertion methods return {@code this} to support fluent method chaining.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see EncryptedKeyset
 */
@NullMarked
public class EncryptedKeysetAssert extends AbstractObjectAssert<EncryptedKeysetAssert, @Nullable EncryptedKeyset> {

	/**
	 * Returns an {@link InstanceOfAssertFactory} that creates {@link EncryptedKeysetAssert} instances,
	 * for use with {@link AbstractObjectAssert#asInstanceOf(InstanceOfAssertFactory)}.
	 *
	 * @return the instance-of assert factory, never {@literal null}
	 */
	public static InstanceOfAssertFactory<EncryptedKeyset, EncryptedKeysetAssert> factory() {
		return new InstanceOfAssertFactory<>(EncryptedKeyset.class, EncryptedKeysetAssert::new);
	}

	/**
	 * Creates a new {@link EncryptedKeysetAssert} for the given {@link EncryptedKeyset}.
	 *
	 * @param keyset the encrypted keyset to assert on, can be {@literal null}
	 * @return the assertion, never {@literal null}
	 */
	public static EncryptedKeysetAssert assertThat(@Nullable EncryptedKeyset keyset) {
		return new EncryptedKeysetAssert(keyset);
	}

	private EncryptedKeysetAssert(@Nullable EncryptedKeyset actual) {
		super(actual, EncryptedKeysetAssert.class);
	}

	/**
	 * Returns an {@link IterableAssert} over the keyset's {@link EncryptedKey encrypted keys},
	 * allowing further assertions to be chained on the key collection.
	 *
	 * @return iterable assertion over the encrypted keys, never {@literal null}
	 */
	public IterableAssert<EncryptedKey> assertThatKeys() {
		return assertThatKeyset()
			.as("encrypted keys")
			.extracting(EncryptedKeyset::getKeys, InstanceOfAssertFactories.iterable(EncryptedKey.class));
	}

	/**
	 * Verifies that the encrypted keyset's name, purpose, factory, KEK provider and identifier,
	 * rotation interval, and destruction grace period all match the corresponding values of the
	 * given {@link Keyset}.
	 *
	 * @param keyset the keyset to match against, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert matchesKeyset(Keyset keyset) {
		return hasName(keyset.getName())
			.hasPurpose(keyset.getPurpose())
			.createdByFactory(keyset.getFactory())
			.hasKeyEncryptionKey(keyset.getKeyEncryptionKey())
			.hasRotationInterval(keyset.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(keyset.getDestructionGracePeriod().orElse(null));
	}

	/**
	 * Verifies that the encrypted keyset's name, purpose, factory, rotation interval, and
	 * destruction grace period all match the corresponding values of the given
	 * {@link KeysetDefinition}.
	 *
	 * @param definition the definition to match against, can't be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert matchesDefinition(KeysetDefinition definition) {
		return hasName(definition.getName())
			.hasPurpose(definition.getPurpose())
			.createdByFactory(definition.getAlgorithm().factory())
			.hasRotationInterval(definition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(definition.getDestructionGracePeriod().orElse(null));
	}

	/**
	 * Verifies that the encrypted keyset has the expected name.
	 *
	 * @param name the expected name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasName(@Nullable String name) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::getName, InstanceOfAssertFactories.STRING)
			.as("keyset name")
			.isEqualTo(name);
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset was created by the factory with the expected name.
	 *
	 * @param name the expected factory name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert createdByFactory(@Nullable String name) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::getFactory, InstanceOfAssertFactories.STRING)
			.as("keyset factory")
			.isEqualTo(name);
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset has the expected purpose.
	 *
	 * @param purpose the expected purpose, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasPurpose(@Nullable KeysetPurpose purpose) {
		return hasPurpose(purpose == null ? null : purpose.name());
	}

	/**
	 * Verifies that the encrypted keyset has the expected purpose, compared by name.
	 *
	 * @param purpose the expected purpose name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasPurpose(@Nullable String purpose) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::getPurpose, InstanceOfAssertFactories.STRING)
			.as("keyset purpose")
			.isEqualTo(purpose);
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset was wrapped by the given {@link KeyEncryptionKey},
	 * compared by provider and identifier.
	 *
	 * @param kek the expected key encryption key, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasKeyEncryptionKey(@Nullable KeyEncryptionKey kek) {
		return hasKeyEncryptionKey(
			kek == null ? null : kek.getProvider(),
			kek == null ? null : kek.getId()
		);
	}

	/**
	 * Verifies that the encrypted keyset was wrapped by a {@link KeyEncryptionKey} with the
	 * expected provider and identifier.
	 *
	 * @param provider the expected KEK provider name, can be {@literal null}
	 * @param id the expected KEK identifier, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasKeyEncryptionKey(@Nullable String provider, @Nullable String id) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::getProvider, InstanceOfAssertFactories.STRING)
			.as("KEK provider")
			.isEqualTo(provider);
		assertThatKeyset()
			.extracting(EncryptedKeyset::getKeyEncryptionKey, InstanceOfAssertFactories.STRING)
			.as("KEK identifier")
			.isEqualTo(id);
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset contains the expected number of keys.
	 *
	 * @param size the expected number of keys
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasSize(int size) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::size, InstanceOfAssertFactories.INTEGER)
			.as("keyset size")
			.isEqualTo(size);
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset has the expected rotation interval. Pass {@literal null}
	 * to assert that no rotation interval is configured.
	 *
	 * @param interval the expected rotation interval, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasRotationInterval(@Nullable Duration interval) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::getRotationInterval)
			.as("keyset rotation interval")
			.isEqualTo(interval);
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset has the expected destruction grace period. Pass
	 * {@literal null} to assert that no destruction grace period is configured.
	 *
	 * @param interval the expected destruction grace period, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasDestructionGracePeriod(@Nullable Duration interval) {
		assertThatKeyset()
			.extracting(EncryptedKeyset::getDestructionGracePeriod)
			.as("keyset destruction grace period")
			.isEqualTo(interval);
		return myself;
	}

	private ObjectAssert<EncryptedKeyset> assertThatKeyset() {
		return Assertions.assertThatObject(actual).isNotNull();
	}

}
