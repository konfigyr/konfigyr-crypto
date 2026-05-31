package com.konfigyr.crypto.test;

import com.konfigyr.crypto.EncryptedKey;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetPurpose;
import com.konfigyr.crypto.WrappedKeyMaterial;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EncryptedKeysetAssert")
class EncryptedKeysetAssertTest {

	static final KeyEncryptionKey KEK = TestKeyEncryptionKey.INSTANCE;

	TestKey key;
	TestKeyset keyset;
	EncryptedKey encryptedKey;
	EncryptedKeyset encryptedKeyset;

	@BeforeEach
	void setup() {
		key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.primary()
			.enabled()
			.createdAt(Instant.EPOCH)
			.initializedAt(Instant.EPOCH)
			.build();

		keyset = TestKeyset.builder()
			.name("my-keyset")
			.factory("my-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(KEK)
			.key(key)
			.build();

		encryptedKey = EncryptedKey.from(key, WrappedKeyMaterial.of("material"));

		encryptedKeyset = EncryptedKeyset.builder()
			.name("my-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("my-factory")
			.provider(KEK.getProvider())
			.keyEncryptionKey(KEK.getId())
			.build(List.of(encryptedKey));
	}

	@Test
	@DisplayName("hasName passes when name matches")
	void hasNamePassesWhenNameMatches() {
		assertThatNoException().isThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).hasName("my-keyset"));
	}

	@Test
	@DisplayName("hasName fails when name does not match")
	void hasNameFailsWhenNameDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).hasName("other-keyset"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("createdByFactory passes when factory name matches")
	void createdByFactoryPassesWhenFactoryNameMatches() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).createdByFactory("my-factory"));
	}

	@Test
	@DisplayName("createdByFactory fails when factory name does not match")
	void createdByFactoryFailsWhenFactoryNameDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).createdByFactory("other-factory"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasPurpose(KeysetPurpose) passes when purpose matches")
	void hasPurposeByEnumPassesWhenPurposeMatches() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasPurpose(KeysetPurpose.ENCRYPTION));
	}

	@Test
	@DisplayName("hasPurpose(String) passes when purpose name matches")
	void hasPurposeByStringPassesWhenPurposeMatches() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasPurpose("ENCRYPTION"));
	}

	@Test
	@DisplayName("hasPurpose fails when purpose does not match")
	void hasPurposeFailsWhenPurposeDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).hasPurpose(KeysetPurpose.SIGNING))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasKeyEncryptionKey(KeyEncryptionKey) passes when provider and id match")
	void hasKeyEncryptionKeyByInstancePasses() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasKeyEncryptionKey(KEK));
	}

	@Test
	@DisplayName("hasKeyEncryptionKey(provider, id) passes when provider and id match")
	void hasKeyEncryptionKeyByProviderAndIdPasses() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasKeyEncryptionKey(KEK.getProvider(), KEK.getId()));
	}

	@Test
	@DisplayName("hasKeyEncryptionKey fails when provider does not match")
	void hasKeyEncryptionKeyFailsWhenProviderDoesNotMatch() {
		assertThatThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasKeyEncryptionKey("wrong-provider", KEK.getId()))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasSize passes when key count matches")
	void hasSizePassesWhenKeyCountMatches() {
		assertThatNoException().isThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).hasSize(1));
	}

	@Test
	@DisplayName("hasSize fails when key count does not match")
	void hasSizeFailsWhenKeyCountDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).hasSize(2))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasRotationInterval passes when null and no interval is configured")
	void hasRotationIntervalPassesWhenNullAndNoneConfigured() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasRotationInterval(null));
	}

	@Test
	@DisplayName("hasRotationInterval passes when interval matches")
	void hasRotationIntervalPassesWhenIntervalMatches() {
		final EncryptedKeyset withInterval = EncryptedKeyset.builder(encryptedKeyset)
			.rotationInterval(Duration.ofDays(30))
			.build(List.of(encryptedKey));
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(withInterval).hasRotationInterval(Duration.ofDays(30)));
	}

	@Test
	@DisplayName("hasRotationInterval fails when interval does not match")
	void hasRotationIntervalFailsWhenIntervalDoesNotMatch() {
		assertThatThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).hasRotationInterval(Duration.ofDays(30)))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("matchesKeyset passes when all fields match the given Keyset")
	void matchesKeysetPassesWhenAllFieldsMatch() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).matchesKeyset(keyset));
	}

	@Test
	@DisplayName("matchesKeyset fails when name does not match the keyset")
	void matchesKeysetFailsWhenNameDoesNotMatch() {
		final TestKeyset otherKeyset = TestKeyset.builder(keyset).key(key).name("other-name").build();
		assertThatThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).matchesKeyset(otherKeyset))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("matchesDefinition passes when all definition fields match")
	void matchesDefinitionPassesWhenAllFieldsMatch() {
		final KeysetDefinition definition = KeysetDefinition.of("my-keyset", TestAlgorithm.INSTANCE);
		final EncryptedKeyset matchingKeyset = EncryptedKeyset.builder(definition)
			.provider(KEK.getProvider())
			.keyEncryptionKey(KEK.getId())
			.build(List.of(encryptedKey));
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(matchingKeyset).matchesDefinition(definition));
	}

	@Test
	@DisplayName("matchesDefinition fails when name does not match the definition")
	void matchesDefinitionFailsWhenNameDoesNotMatch() {
		final KeysetDefinition definition = KeysetDefinition.of("other-name", TestAlgorithm.INSTANCE);
		assertThatThrownBy(() -> EncryptedKeysetAssert.assertThat(encryptedKeyset).matchesDefinition(definition))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("assertThatKeys allows chaining assertions on the encrypted key collection")
	void assertThatKeysChainsToEncryptedKeyCollection() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeysetAssert.assertThat(encryptedKeyset).assertThatKeys().hasSize(1));
	}

}
