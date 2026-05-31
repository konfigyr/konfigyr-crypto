package com.konfigyr.crypto.test;

import com.konfigyr.crypto.EncryptedKey;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.WrappedKeyMaterial;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EncryptedKeyAssert")
class EncryptedKeyAssertTest {

	static final WrappedKeyMaterial MATERIAL = WrappedKeyMaterial.of("test-material");

	EncryptedKey encryptedKey;
	TestKey key;

	@BeforeEach
	void setup() {
		encryptedKey = EncryptedKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.type(KeyType.OCTET)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(Instant.EPOCH)
			.initializedAt(Instant.EPOCH)
			.build(MATERIAL);

		key = TestKey.builder()
			.id("key-id")
			.algorithm(TestAlgorithm.INSTANCE)
			.status(KeyStatus.ENABLED)
			.primary()
			.createdAt(Instant.EPOCH)
			.initializedAt(Instant.EPOCH)
			.build();
	}

	@Test
	@DisplayName("hasId passes when identifier matches")
	void hasIdPassesWhenIdentifierMatches() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasId("key-id"));
	}

	@Test
	@DisplayName("hasId fails when identifier does not match")
	void hasIdFailsWhenIdentifierDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasId("other-id"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasAlgorithm(Algorithm) passes when algorithm matches by name")
	void hasAlgorithmByInstancePassesWhenMatches() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeyAssert.assertThat(encryptedKey).hasAlgorithm(TestAlgorithm.INSTANCE));
	}

	@Test
	@DisplayName("hasAlgorithm(String) passes when algorithm name matches")
	void hasAlgorithmByNamePassesWhenMatches() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeyAssert.assertThat(encryptedKey).hasAlgorithm(TestAlgorithm.INSTANCE.name()));
	}

	@Test
	@DisplayName("hasAlgorithm fails when algorithm name does not match")
	void hasAlgorithmFailsWhenNameDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasAlgorithm("wrong:algorithm"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasType passes when key type matches")
	void hasTypePassesWhenKeyTypeMatches() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasType(KeyType.OCTET));
	}

	@Test
	@DisplayName("hasType fails when key type does not match")
	void hasTypeFailsWhenKeyTypeDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasType(KeyType.EC))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isEnabled passes when key is ENABLED")
	void isEnabledPassesWhenKeyIsEnabled() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).isEnabled());
	}

	@Test
	@DisplayName("isEnabled fails when key is not ENABLED")
	void isEnabledFailsWhenKeyIsNotEnabled() {
		final EncryptedKey disabled = EncryptedKey.builder(encryptedKey).status(KeyStatus.DISABLED).build(MATERIAL);
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(disabled).isEnabled())
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isPrimary passes when key is primary")
	void isPrimaryPassesWhenKeyIsPrimary() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).isPrimary());
	}

	@Test
	@DisplayName("isNotPrimary fails when key is primary")
	void isNotPrimaryFailsWhenKeyIsPrimary() {
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).isNotPrimary())
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("hasMaterial(WrappedKeyMaterial) passes when material matches")
	void hasMaterialPassesWhenMaterialMatches() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasMaterial(MATERIAL));
	}

	@Test
	@DisplayName("hasMaterial(String) passes when material matches")
	void hasMaterialByStringPassesWhenMaterialMatches() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasMaterial("test-material"));
	}

	@Test
	@DisplayName("hasMaterial(ByteArray) passes when material matches")
	void hasMaterialByByteArrayPassesWhenMaterialMatches() {
		assertThatNoException().isThrownBy(() ->
			EncryptedKeyAssert.assertThat(encryptedKey).hasMaterial(ByteArray.fromString("test-material")));
	}

	@Test
	@DisplayName("hasMaterial fails when material does not match")
	void hasMaterialFailsWhenMaterialDoesNotMatch() {
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).hasMaterial("wrong-material"))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("isCreatedAt passes when timestamp matches exactly")
	void isCreatedAtPassesWhenTimestampMatchesExactly() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).isCreatedAt(Instant.EPOCH));
	}

	@Test
	@DisplayName("isCreatedAt passes when timestamp is within tolerance")
	void isCreatedAtPassesWhenTimestampIsWithinTolerance() {
		final EncryptedKey recent = EncryptedKey.builder(encryptedKey).createdAt(Instant.now()).build(MATERIAL);
		assertThatNoException().isThrownBy(() ->
			EncryptedKeyAssert.assertThat(recent).isCreatedAt(Instant.now(), Duration.ofSeconds(1)));
	}

	@Test
	@DisplayName("isCreatedAt fails when timestamp differs from expected")
	void isCreatedAtFailsWhenTimestampDiffersFromExpected() {
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).isCreatedAt(Instant.now()))
			.isInstanceOf(AssertionError.class);
	}

	@Test
	@DisplayName("matchesKey passes when all fields match the given Key")
	void matchesKeyPassesWhenAllFieldsMatch() {
		assertThatNoException().isThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).matchesKey(key));
	}

	@Test
	@DisplayName("matchesKey fails when identifier does not match")
	void matchesKeyFailsWhenIdDoesNotMatch() {
		final TestKey otherKey = TestKey.builder(key).id("other-id").build();
		assertThatThrownBy(() -> EncryptedKeyAssert.assertThat(encryptedKey).matchesKey(otherKey))
			.isInstanceOf(AssertionError.class);
	}

}
