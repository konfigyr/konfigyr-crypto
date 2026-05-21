package com.konfigyr.crypto.test;

import com.konfigyr.crypto.*;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.IterableAssert;

import java.time.Duration;
import java.util.Objects;

public class KeysetAssert extends AbstractObjectAssert<KeysetAssert, Keyset> {

	public static InstanceOfAssertFactory<Keyset, KeysetAssert> factory() {
		return new InstanceOfAssertFactory<>(Keyset.class, KeysetAssert::new);
	}

	public static KeysetAssert assertThat(Keyset keyset) {
		return new KeysetAssert(keyset);
	}

	private KeysetAssert(Keyset actual) {
		super(actual, KeysetAssert.class);
	}

	public IterableAssert<Key> assertThatKeys() {
		return IterableAssert.assertThatIterable(actual.getKeys());
	}

	public KeysetAssert matchesDefinition(KeysetDefinition definition) {
		return hasName(definition.getName())
			.hasPurpose(definition.getPurpose())
			.hasRotationInterval(definition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(definition.getDestructionGracePeriod().orElse(null));
	}

	public KeysetAssert hasName(String name) {
		isNotNull();
		if (!Objects.equals(actual.getName(), name)) {
			failWithMessage("Expected keyset to have a name of <%s> but was <%s>", name, actual.getName());
		}
		return myself;
	}

	public KeysetAssert createdByFactory(String name) {
		isNotNull();
		if (!Objects.equals(actual.getFactory(), name)) {
			failWithMessage("Expected keyset to be managed by a <%s> keyset factory but was <%s>",
				name, actual.getFactory());
		}
		return myself;
	}

	public KeysetAssert hasPurpose(KeysetPurpose purpose) {
		isNotNull();
		if (!Objects.equals(actual.getPurpose(), purpose)) {
			failWithMessage("Expected keyset to have a purpose of <%s> but was <%s>",
				purpose, actual.getPurpose());
		}
		return myself;
	}

	public KeysetAssert hasKeyEncryptionKey(KeyEncryptionKey kek) {
		isNotNull();
		if (!Objects.equals(actual.getKeyEncryptionKey(), kek)) {
			failWithMessage("Expected keyset to have a Key Encryption Key of <%s> but was <%s>",
				kek, actual.getKeyEncryptionKey());
		}
		return myself;
	}

	public KeysetAssert hasKeyEncryptionKey(String provider, String id) {
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

	public KeysetAssert hasSize(int size) {
		isNotNull();
		if (!Objects.equals(actual.size(), size)) {
			failWithMessage("Expected keyset to have a size of <%s> but was <%s>", size, actual.size());
		}
		return myself;
	}

	public KeysetAssert hasNoRotationInterval() {
		isNotNull();

		Assertions.assertThat(actual.getRotationInterval())
			.as("Keyset should not have no rotation interval defined, but was <%s>", actual.getRotationInterval())
			.isEmpty();

		return myself;
	}

	public KeysetAssert hasRotationInterval(Duration interval) {
		isNotNull();

		final Duration duration = actual.getRotationInterval().orElse(null);

		if (!Objects.equals(duration, interval)) {
			failWithMessage("Expected keyset to have a rotation interval of <%s> but was <%s>",
				interval, duration);
		}

		return myself;
	}

	public KeysetAssert hasNoDestructionGracePeriod() {
		isNotNull();

		Assertions.assertThat(actual.getDestructionGracePeriod())
			.as("Keyset should not have no destruction grace defined, but was <%s>", actual.getDestructionGracePeriod())
			.isEmpty();

		return myself;
	}

	public KeysetAssert hasDestructionGracePeriod(Duration interval) {
		isNotNull();

		final Duration duration = actual.getDestructionGracePeriod().orElse(null);

		if (!Objects.equals(duration, interval)) {
			failWithMessage("Expected keyset to have a destruction grace period of <%s> but was <%s>",
				interval, duration);
		}

		return myself;
	}

}
