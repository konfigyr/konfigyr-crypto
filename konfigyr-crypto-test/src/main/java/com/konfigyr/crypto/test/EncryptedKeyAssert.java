package com.konfigyr.crypto.test;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.InstantAssert;
import org.assertj.core.description.Description;
import org.assertj.core.description.TextDescription;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public class EncryptedKeyAssert extends AbstractObjectAssert<EncryptedKeyAssert, EncryptedKey> {

	public static InstanceOfAssertFactory<EncryptedKey, EncryptedKeyAssert> factory() {
		return new InstanceOfAssertFactory<>(EncryptedKey.class, EncryptedKeyAssert::new);
	}

	public static EncryptedKeyAssert assertThat(EncryptedKey key) {
		return new EncryptedKeyAssert(key);
	}

	private EncryptedKeyAssert(EncryptedKey actual) {
		super(actual, EncryptedKeyAssert.class);
	}

	public EncryptedKeyAssert matchesKey(Key key) {
		return hasId(key.getId())
			.hasAlgorithm(key.getAlgorithm())
			.hasType(key.getType())
			.hasStatus(key.getStatus())
			.isPrimary(key.isPrimary())
			.isCreatedAt(key.getCreatedAt())
			.isInitializedAt(key.getInitializedAt())
			.expiresAt(key.getExpiresAt())
			.destructionScheduledAt(key.getDestructionScheduledAt())
			.isDestroyedAt(key.getDestroyedAt());
	}

	public EncryptedKeyAssert hasId(String id) {
		isNotNull();
		if (!Objects.equals(actual.getId(), id)) {
			failWithMessage("Expected key to have an identifier <%s> but was <%s>", id, actual.getId());
		}
		return myself;
	}

	public EncryptedKeyAssert hasAlgorithm(Algorithm algorithm) {
		return hasAlgorithm(algorithm == null ? null : algorithm.name());
	}

	public EncryptedKeyAssert hasAlgorithm(String algorithm) {
		isNotNull();
		if (!Objects.equals(actual.getAlgorithm(), algorithm)) {
			failWithMessage("Expected key to have an algorithm <%s> but was <%s>",
				algorithm, actual.getAlgorithm());
		}
		return myself;
	}

	public EncryptedKeyAssert hasType(KeyType type) {
		isNotNull();
		if (!Objects.equals(actual.getType(), type)) {
			failWithMessage("Expected key to be type of <%s> but was <%s>", type, actual.getType());
		}
		return myself;
	}

	public EncryptedKeyAssert isEnabled() {
		return hasStatus(KeyStatus.ENABLED);
	}

	public EncryptedKeyAssert hasStatus(KeyStatus status) {
		isNotNull();
		if (!Objects.equals(actual.getStatus(), status)) {
			failWithMessage("Expected key to be in status <%s> but was <%s>", status, actual.getStatus());
		}
		return myself;
	}

	public EncryptedKeyAssert isPrimary() {
		return isPrimary(true);
	}

	public EncryptedKeyAssert isNotPrimary() {
		return isPrimary(false);
	}

	public EncryptedKeyAssert isPrimary(boolean primary) {
		isNotNull();
		if (primary != actual.isPrimary()) {
			failWithMessage("Expected key to have primary state of <%s> but was <%s>",
				primary, actual.isPrimary());
		}
		return myself;
	}

	public EncryptedKeyAssert hasMaterial(String material) {
		return hasMaterial(material == null ? null : ByteArray.fromString(material));
	}

	public EncryptedKeyAssert hasMaterial(ByteArray material) {
		isNotNull();
		if (!Objects.equals(actual.getData(), material)) {
			failWithMessage("Expected key to have key material of <%s> but was <%s>",
				material, actual.getData());
		}
		return myself;
	}

	public EncryptedKeyAssert isCreatedAt(Instant createdAt) {
		return isCreatedAt(createdAt, Duration.ZERO);
	}

	public EncryptedKeyAssert isCreatedAt(Instant createdAt, Duration tolerance) {
		return assertInstant(actual.getCreatedAt(), createdAt, tolerance, new TextDescription(
			"Expected key to be created at <%s> but was <%s>", createdAt, actual.getCreatedAt()
		));
	}

	public EncryptedKeyAssert isInitializedAt(Instant initializedAt) {
		return isInitializedAt(initializedAt, Duration.ZERO);
	}

	public EncryptedKeyAssert isInitializedAt(Instant initializedAt, Duration tolerance) {
		return assertInstant(actual.getInitializedAt(), initializedAt, tolerance, new TextDescription(
			"Expected key to be initialized at <%s> but was <%s>", initializedAt, actual.getInitializedAt()
		));
	}

	public EncryptedKeyAssert expiresAt(Instant expiresAt) {
		return expiresAt(expiresAt, Duration.ZERO);
	}

	public EncryptedKeyAssert expiresAt(Instant expiresAt, Duration tolerance) {
		return assertInstant(actual.getExpiresAt(), expiresAt, tolerance, new TextDescription(
			"Expected key to expire at <%s> but was <%s>", expiresAt, actual.getExpiresAt()
		));
	}

	public EncryptedKeyAssert destructionScheduledAt(Instant destructionScheduledAt) {
		return destructionScheduledAt(destructionScheduledAt, Duration.ZERO);
	}

	public EncryptedKeyAssert destructionScheduledAt(Instant destructionScheduledAt, Duration tolerance) {
		return assertInstant(actual.getDestructionScheduledAt(), destructionScheduledAt, tolerance, new TextDescription(
			"Expected key to be destroyed at <%s> but was <%s>", destructionScheduledAt,
			actual.getDestructionScheduledAt()
		));
	}

	public EncryptedKeyAssert isDestroyedAt(Instant destroyedAt) {
		return isDestroyedAt(destroyedAt, Duration.ZERO);
	}

	public EncryptedKeyAssert isDestroyedAt(Instant destroyedAt, Duration tolerance) {
		return assertInstant(actual.getDestroyedAt(), destroyedAt, tolerance, new TextDescription(
			"Expected key to be destroyed at <%s> but was <%s>", destroyedAt, actual.getDestroyedAt()
		));
	}

	private EncryptedKeyAssert assertInstant(Instant actual, Instant expected, Duration tolerance, Description description) {
		isNotNull();

		final InstantAssert assertion = new InstantAssert(actual)
			.as(description);

		if (expected == null) {
			assertion.isNull();
		} else {
			assertion.isCloseTo(actual, Assertions.within(tolerance));
		}

		return myself;
	}

}
