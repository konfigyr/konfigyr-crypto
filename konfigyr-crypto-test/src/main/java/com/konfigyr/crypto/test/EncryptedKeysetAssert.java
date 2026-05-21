package com.konfigyr.crypto.test;

import com.konfigyr.crypto.*;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.IterableAssert;

import java.time.Duration;
import java.util.Objects;

public class EncryptedKeysetAssert extends AbstractObjectAssert<EncryptedKeysetAssert, EncryptedKeyset> {

	public static InstanceOfAssertFactory<EncryptedKeyset, EncryptedKeysetAssert> factory() {
		return new InstanceOfAssertFactory<>(EncryptedKeyset.class, EncryptedKeysetAssert::new);
	}

	public static EncryptedKeysetAssert assertThat(EncryptedKeyset keyset) {
		return new EncryptedKeysetAssert(keyset);
	}

	private EncryptedKeysetAssert(EncryptedKeyset actual) {
		super(actual, EncryptedKeysetAssert.class);
	}

	public IterableAssert<EncryptedKey> assertThatKeys() {
		return IterableAssert.assertThatIterable(actual.getKeys());
	}

	public EncryptedKeysetAssert matchesKeyset(Keyset keyset) {
		return hasName(keyset.getName())
			.hasPurpose(keyset.getPurpose())
			.createdByFactory(keyset.getFactory())
			.hasKeyEncryptionKey(keyset.getKeyEncryptionKey())
			.hasRotationInterval(keyset.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(keyset.getDestructionGracePeriod().orElse(null));
	}

	public EncryptedKeysetAssert matchesDefinition(KeysetDefinition definition) {
		return hasName(definition.getName())
			.hasPurpose(definition.getPurpose())
			.createdByFactory(definition.getAlgorithm().factory())
			.hasRotationInterval(definition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(definition.getDestructionGracePeriod().orElse(null));
	}

	public EncryptedKeysetAssert hasName(String name) {
		isNotNull();
		if (!Objects.equals(actual.getName(), name)) {
			failWithMessage("Expected keyset to have a name of <%s> but was <%s>", name, actual.getName());
		}
		return myself;
	}

	public EncryptedKeysetAssert createdByFactory(String name) {
		isNotNull();
		if (!Objects.equals(actual.getFactory(), name)) {
			failWithMessage("Expected keyset to be managed by a <%s> keyset factory but was <%s>",
				name, actual.getFactory());
		}
		return myself;
	}

	public EncryptedKeysetAssert hasPurpose(KeysetPurpose purpose) {
		return hasPurpose(purpose == null ? null : purpose.name());
	}

	public EncryptedKeysetAssert hasPurpose(String purpose) {
		isNotNull();
		if (!Objects.equals(actual.getPurpose(), purpose)) {
			failWithMessage("Expected keyset to have a purpose of <%s> but was <%s>",
				purpose, actual.getPurpose());
		}
		return myself;
	}

	public EncryptedKeysetAssert hasKeyEncryptionKey(KeyEncryptionKey kek) {
		return hasKeyEncryptionKey(
			kek == null ? null : kek.getProvider(),
			kek == null ? null : kek.getId()
		);
	}

	public EncryptedKeysetAssert hasKeyEncryptionKey(String provider, String id) {
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

	public EncryptedKeysetAssert hasSize(int size) {
		isNotNull();
		if (!Objects.equals(actual.size(), size)) {
			failWithMessage("Expected keyset to have a size of <%s> but was <%s>", size, actual.size());
		}
		return myself;
	}

	public EncryptedKeysetAssert hasRotationInterval(Duration interval) {
		isNotNull();

		if (!Objects.equals(actual.getRotationInterval(), interval)) {
			failWithMessage("Expected keyset to have a rotation interval of <%s> but was <%s>",
				interval, actual.getRotationInterval());
		}

		return myself;
	}

	public EncryptedKeysetAssert hasDestructionGracePeriod(Duration interval) {
		isNotNull();

		if (!Objects.equals(actual.getDestructionGracePeriod(), interval)) {
			failWithMessage("Expected keyset to have a destruction grace period of <%s> but was <%s>",
				interval, actual.getDestructionGracePeriod());
		}

		return myself;
	}

}
