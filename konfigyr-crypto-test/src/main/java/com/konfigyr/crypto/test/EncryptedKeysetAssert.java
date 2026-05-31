package com.konfigyr.crypto.test;

import com.konfigyr.crypto.EncryptedKey;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetPurpose;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.IterableAssert;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Objects;

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
public class EncryptedKeysetAssert extends AbstractObjectAssert<EncryptedKeysetAssert, EncryptedKeyset> {

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
		return IterableAssert.assertThatIterable(actual.getKeys());
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
		isNotNull();
		if (!Objects.equals(actual.getName(), name)) {
			failWithMessage("Expected keyset to have a name of <%s> but was <%s>", name, actual.getName());
		}
		return myself;
	}

	/**
	 * Verifies that the encrypted keyset was created by the factory with the expected name.
	 *
	 * @param name the expected factory name, can be {@literal null}
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert createdByFactory(@Nullable String name) {
		isNotNull();
		if (!Objects.equals(actual.getFactory(), name)) {
			failWithMessage("Expected keyset to be managed by a <%s> keyset factory but was <%s>",
				name, actual.getFactory());
		}
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
		isNotNull();
		if (!Objects.equals(actual.getPurpose(), purpose)) {
			failWithMessage("Expected keyset to have a purpose of <%s> but was <%s>",
				purpose, actual.getPurpose());
		}
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
		isNotNull();

		if (!Objects.equals(actual.getProvider(), provider)) {
			failWithMessage("Expected keyset to have a Key Encryption Key with provider of <%s> but was <%s>",
				provider, actual.getProvider());
		}

		if (!Objects.equals(actual.getKeyEncryptionKey(), id)) {
			failWithMessage("Expected keyset to have a Key Encryption Key with identifier of <%s> but was <%s>",
				id, actual.getKeyEncryptionKey());
		}

		return myself;
	}

	/**
	 * Verifies that the encrypted keyset contains the expected number of keys.
	 *
	 * @param size the expected number of keys
	 * @return this assertion for chaining, never {@literal null}
	 */
	public EncryptedKeysetAssert hasSize(int size) {
		isNotNull();
		if (!Objects.equals(actual.size(), size)) {
			failWithMessage("Expected keyset to have a size of <%s> but was <%s>", size, actual.size());
		}
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
		isNotNull();

		if (!Objects.equals(actual.getRotationInterval(), interval)) {
			failWithMessage("Expected keyset to have a rotation interval of <%s> but was <%s>",
				interval, actual.getRotationInterval());
		}

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
		isNotNull();

		if (!Objects.equals(actual.getDestructionGracePeriod(), interval)) {
			failWithMessage("Expected keyset to have a destruction grace period of <%s> but was <%s>",
				interval, actual.getDestructionGracePeriod());
		}

		return myself;
	}

}
