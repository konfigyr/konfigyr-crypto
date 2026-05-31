package com.konfigyr.crypto.test;

import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetPurpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("KeysetAssert")
class KeysetAssertTest {

	static final KeyEncryptionKey KEK = TestKeyEncryptionKey.INSTANCE;

	TestKey key;
	TestKeyset keyset;

	@BeforeEach
	void setup() {
		key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.primary()
			.enabled()
			.build();

		keyset = TestKeyset.builder()
			.name("my-keyset")
			.factory("my-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(KEK)
			.key(key)
			.build();
	}

	@Test
	@DisplayName("hasName passes when name matches")
	void hasNamePassesWhenNameMatches() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).hasName("my-keyset"));
	}

	@Test
	@DisplayName("hasName fails when name does not match")
	void hasNameFailsWhenNameDoesNotMatch() {
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).hasName("other-keyset"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("createdByFactory passes when factory name matches")
	void createdByFactoryPassesWhenFactoryNameMatches() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).createdByFactory("my-factory"));
	}

	@Test
	@DisplayName("createdByFactory fails when factory name does not match")
	void createdByFactoryFailsWhenFactoryNameDoesNotMatch() {
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).createdByFactory("other-factory"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasPurpose passes when purpose matches")
	void hasPurposePassesWhenPurposeMatches() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).hasPurpose(KeysetPurpose.ENCRYPTION));
	}

	@Test
	@DisplayName("hasPurpose fails when purpose does not match")
	void hasPurposeFailsWhenPurposeDoesNotMatch() {
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).hasPurpose(KeysetPurpose.SIGNING))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasKeyEncryptionKey passes when KEK instance matches")
	void hasKeyEncryptionKeyPassesWhenKekInstanceMatches() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).hasKeyEncryptionKey(KEK));
	}

	@Test
	@DisplayName("hasKeyEncryptionKey fails when KEK instance does not match")
	void hasKeyEncryptionKeyFailsWhenKekInstanceDoesNotMatch() {
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).hasKeyEncryptionKey(new TestKeyEncryptionKey("other", "other")))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasKeyEncryptionKey(provider, id) passes when provider and id match")
	void hasKeyEncryptionKeyByProviderAndIdPasses() {
		assertThatNoException().isThrownBy(() ->
			KeysetAssert.assertThat(keyset).hasKeyEncryptionKey(KEK.getProvider(), KEK.getId()));
	}

	@Test
	@DisplayName("hasKeyEncryptionKey(provider, id) fails when provider does not match")
	void hasKeyEncryptionKeyByProviderAndIdFailsWhenProviderDoesNotMatch() {
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).hasKeyEncryptionKey("wrong-provider", KEK.getId()))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasSize passes when key count matches")
	void hasSizePassesWhenKeyCountMatches() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).hasSize(1));
	}

	@Test
	@DisplayName("hasSize fails when key count does not match")
	void hasSizeFailsWhenKeyCountDoesNotMatch() {
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).hasSize(2))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasNoRotationInterval passes when no interval is configured")
	void hasNoRotationIntervalPassesWhenNoneConfigured() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).hasNoRotationInterval());
	}

	@Test
	@DisplayName("hasNoRotationInterval fails when an interval is configured")
	void hasNoRotationIntervalFailsWhenIntervalIsConfigured() {
		final TestKeyset withInterval = TestKeyset.builder(keyset).key(key).rotationInterval(Duration.ofDays(30)).build();
		assertThatThrownBy(() -> KeysetAssert.assertThat(withInterval).hasNoRotationInterval())
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasRotationInterval passes when interval matches")
	void hasRotationIntervalPassesWhenIntervalMatches() {
		final TestKeyset withInterval = TestKeyset.builder(keyset).key(key).rotationInterval(Duration.ofDays(30)).build();
		assertThatNoException().isThrownBy(() ->
			KeysetAssert.assertThat(withInterval).hasRotationInterval(Duration.ofDays(30)));
	}

	@Test
	@DisplayName("hasRotationInterval fails when interval does not match")
	void hasRotationIntervalFailsWhenIntervalDoesNotMatch() {
		final TestKeyset withInterval = TestKeyset.builder(keyset).key(key).rotationInterval(Duration.ofDays(30)).build();
		assertThatThrownBy(() -> KeysetAssert.assertThat(withInterval).hasRotationInterval(Duration.ofDays(7)))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasNoDestructionGracePeriod passes when no grace period is configured")
	void hasNoDestructionGracePeriodPassesWhenNoneConfigured() {
		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(keyset).hasNoDestructionGracePeriod());
	}

	@Test
	@DisplayName("hasDestructionGracePeriod passes when grace period matches")
	void hasDestructionGracePeriodPassesWhenGracePeriodMatches() {
		final TestKeyset withGrace = TestKeyset.builder(keyset).key(key).destructionGracePeriod(Duration.ofDays(7)).build();
		assertThatNoException().isThrownBy(() ->
			KeysetAssert.assertThat(withGrace).hasDestructionGracePeriod(Duration.ofDays(7)));
	}

	@Test
	@DisplayName("matchesDefinition passes when all definition fields match")
	void matchesDefinitionPassesWhenAllFieldsMatch() {
		final KeysetDefinition definition = KeysetDefinition.of("my-keyset", TestAlgorithm.INSTANCE);
		final TestKeyset matched = TestKeyset.builder(definition)
			.keyEncryptionKey(KEK)
			.key(key)
			.build();

		assertThatNoException().isThrownBy(() -> KeysetAssert.assertThat(matched).matchesDefinition(definition));
	}

	@Test
	@DisplayName("matchesDefinition fails when name does not match the definition")
	void matchesDefinitionFailsWhenNameDoesNotMatch() {
		final KeysetDefinition definition = KeysetDefinition.of("other-name", TestAlgorithm.INSTANCE);
		assertThatThrownBy(() -> KeysetAssert.assertThat(keyset).matchesDefinition(definition))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("assertThatKeys allows chaining assertions on the key collection")
	void assertThatKeysChainsToKeyCollection() {
		assertThatNoException().isThrownBy(() ->
			KeysetAssert.assertThat(keyset).assertThatKeys().hasSize(1).first().isEqualTo(key));
	}

}
