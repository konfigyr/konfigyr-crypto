package com.konfigyr.crypto.test;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.InstantAssert;
import org.assertj.core.description.Description;
import org.assertj.core.description.TextDescription;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public class KeyAssert extends AbstractObjectAssert<KeyAssert, Key> {

	public static InstanceOfAssertFactory<Key, KeyAssert> factory() {
		return new InstanceOfAssertFactory<>(Key.class, KeyAssert::new);
	}

	public static KeyAssert assertThat(Key key) {
		return new KeyAssert(key);
	}

	private KeyAssert(Key actual) {
		super(actual, KeyAssert.class);
	}

	public KeyAssert hasId(String id) {
		isNotNull();
		if (!Objects.equals(actual.getId(), id)) {
			failWithMessage("Expected key to have an identifier <%s> but was <%s>", id, actual.getId());
		}
		return myself;
	}

	public KeyAssert hasAlgorithm(Algorithm algorithm) {
		isNotNull();
		if (!Objects.equals(actual.getAlgorithm(), algorithm)) {
			failWithMessage("Expected key to have an algorithm <%s> but was <%s>",
				algorithm, actual.getAlgorithm());
		}
		return myself;
	}

	public KeyAssert hasType(KeyType type) {
		isNotNull();
		if (!Objects.equals(actual.getType(), type)) {
			failWithMessage("Expected key to be type of <%s> but was <%s>", type, actual.getType());
		}
		return myself;
	}

	public KeyAssert isEnabled() {
		return hasStatus(KeyStatus.ENABLED);
	}

	public KeyAssert hasStatus(KeyStatus status) {
		isNotNull();
		if (!Objects.equals(actual.getStatus(), status)) {
			failWithMessage("Expected key to be in status <%s> but was <%s>", status, actual.getStatus());
		}
		return myself;
	}

	public KeyAssert isPrimary() {
		return isPrimary(true);
	}

	public KeyAssert isNotPrimary() {
		return isPrimary(false);
	}

	public KeyAssert isPrimary(boolean primary) {
		isNotNull();
		if (primary != actual.isPrimary()) {
			failWithMessage("Expected key to have primary state of <%s> but was <%s>",
				primary, actual.isPrimary());
		}
		return myself;
	}

	public KeyAssert isCreatedAt(Instant createdAt) {
		return isCreatedAt(createdAt, Duration.ZERO);
	}

	public KeyAssert isCreatedAt(Instant createdAt, Duration tolerance) {
		return assertInstant(actual.getCreatedAt(), createdAt, tolerance, new TextDescription(
			"Expected key to be created at <%s> but was <%s>", createdAt, actual.getCreatedAt()
		));
	}

	public KeyAssert isInitializedAt(Instant initializedAt) {
		return isInitializedAt(initializedAt, Duration.ZERO);
	}

	public KeyAssert isInitializedAt(Instant initializedAt, Duration tolerance) {
		return assertInstant(actual.getInitializedAt(), initializedAt, tolerance, new TextDescription(
			"Expected key to be initialized at <%s> but was <%s>", initializedAt, actual.getInitializedAt()
		));
	}

	public KeyAssert expiresAt(Instant expiresAt) {
		return expiresAt(expiresAt, Duration.ZERO);
	}

	public KeyAssert expiresAt(Instant expiresAt, Duration tolerance) {
		return assertInstant(actual.getExpiresAt(), expiresAt, tolerance, new TextDescription(
			"Expected key to expire at <%s> but was <%s>", expiresAt, actual.getExpiresAt()
		));
	}

	public KeyAssert destructionScheduledAt(Instant destructionScheduledAt) {
		return destructionScheduledAt(destructionScheduledAt, Duration.ZERO);
	}

	public KeyAssert destructionScheduledAt(Instant destructionScheduledAt, Duration tolerance) {
		return assertInstant(actual.getDestructionScheduledAt(), destructionScheduledAt, tolerance, new TextDescription(
			"Expected key to be destroyed at <%s> but was <%s>", destructionScheduledAt,
			actual.getDestructionScheduledAt()
		));
	}

	public KeyAssert isDestroyedAt(Instant destroyedAt) {
		return isDestroyedAt(destroyedAt, Duration.ZERO);
	}

	public KeyAssert isDestroyedAt(Instant destroyedAt, Duration tolerance) {
		return assertInstant(actual.getDestroyedAt(), destroyedAt, tolerance, new TextDescription(
			"Expected key to be destroyed at <%s> but was <%s>", destroyedAt, actual.getDestroyedAt()
		));
	}

	private KeyAssert assertInstant(Instant actual, Instant expected, Duration tolerance, Description description) {
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
