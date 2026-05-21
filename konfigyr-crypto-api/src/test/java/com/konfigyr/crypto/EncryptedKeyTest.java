package com.konfigyr.crypto;

import com.konfigyr.crypto.test.EncryptedKeyAssert;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class EncryptedKeyTest {

	static final Algorithm algorithm = TestAlgorithm.INSTANCE;
	static final ByteArray data = ByteArray.fromString("encrypted-key-material");
	static final Instant now = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	@DisplayName("should build an encrypted key with all fields populated")
	void shouldBuildEncryptedKeyWithAllFields() {
		final var key = EncryptedKey.builder()
			.id("key-id")
			.algorithm(algorithm)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(now)
			.initializedAt(now)
			.expiresAt(now.plusSeconds(3600))
			.destructionScheduledAt(null)
			.destroyedAt(null)
			.build(data);

		EncryptedKeyAssert.assertThat(key)
			.hasId("key-id")
			.hasAlgorithm(algorithm)
			.hasType(algorithm.type())
			.hasStatus(KeyStatus.ENABLED)
			.isPrimary()
			.hasMaterial(data)
			.isCreatedAt(now)
			.isInitializedAt(now)
			.expiresAt(now.plusSeconds(3600))
			.destructionScheduledAt(null)
			.isDestroyedAt(null);
	}

	@Test
	@DisplayName("should build an encrypted key with null data for a destroyed key")
	void shouldBuildEncryptedKeyWithNullData() {
		final var key = EncryptedKey.builder()
			.id("key-id")
			.algorithm(algorithm)
			.status(KeyStatus.DESTROYED)
			.primary(false)
			.createdAt(now)
			.destroyedAt(now)
			.build(null);

		EncryptedKeyAssert.assertThat(key)
			.hasStatus(KeyStatus.DESTROYED)
			.hasMaterial((ByteArray) null)
			.isDestroyedAt(now);
	}

	@Test
	@DisplayName("should set algorithm name and key type when an Algorithm is supplied")
	void shouldSetAlgorithmNameAndTypeFromAlgorithm() {
		final var key = EncryptedKey.builder()
			.id("key-id")
			.algorithm(algorithm)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build(data);

		EncryptedKeyAssert.assertThat(key)
			.hasAlgorithm(algorithm)
			.hasType(algorithm.type());
	}

	@Test
	@DisplayName("should create an encrypted key from an existing Key and wrapped key material")
	void shouldCreateFromKey() {
		final var source = mock(Key.class);
		doReturn("key-id").when(source).getId();
		doReturn(algorithm).when(source).getAlgorithm();
		doReturn(algorithm.type()).when(source).getType();
		doReturn(KeyStatus.ENABLED).when(source).getStatus();
		doReturn(true).when(source).isPrimary();
		doReturn(now).when(source).getCreatedAt();
		doReturn(now).when(source).getInitializedAt();
		doReturn(now.plusSeconds(3600)).when(source).getExpiresAt();
		doReturn(null).when(source).getDestructionScheduledAt();
		doReturn(null).when(source).getDestroyedAt();

		EncryptedKeyAssert.assertThat(EncryptedKey.from(source, data))
			.matchesKey(source)
			.hasMaterial(data);
	}

	@Test
	@DisplayName("should return an input stream backed by the encrypted key data")
	void shouldReturnInputStreamFromData() {
		final var key = EncryptedKey.builder()
			.id("key-id")
			.algorithm(algorithm)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build(data);

		assertThat(key.getInputStream())
			.hasBinaryContent(data.array());
	}

	@Test
	@DisplayName("should return an empty input stream when key data is absent")
	void shouldReturnEmptyInputStreamWhenDataIsAbsent() {
		final var key = EncryptedKey.builder()
			.id("key-id")
			.algorithm(algorithm)
			.status(KeyStatus.DESTROYED)
			.createdAt(now)
			.build(null);

		assertThat(key.getInputStream())
			.hasBinaryContent(new byte[0]);
	}

	@Test
	@DisplayName("should order encrypted keys by their identifier")
	void shouldOrderByIdentifier() {
		final var first = EncryptedKey.builder()
			.id("aaa")
			.algorithm(algorithm)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build(data);

		final var second = EncryptedKey.builder()
			.id("bbb")
			.algorithm(algorithm)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build(data);

		assertThat(first)
			.isLessThan(second);
		assertThat(second)
			.isGreaterThan(first);
		assertThat(first)
			.isEqualByComparingTo(first);
	}

	@Test
	@DisplayName("should fail to build when key identifier is blank")
	void shouldFailToBuildWithBlankId() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKey.builder()
				.algorithm(algorithm)
				.status(KeyStatus.ENABLED)
				.createdAt(now)
				.build(data))
			.withMessage("Key identifier can not be blank");
	}

	@Test
	@DisplayName("should fail to build when algorithm name is blank")
	void shouldFailToBuildWithBlankAlgorithm() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKey.builder()
				.id("key-id")
				.status(KeyStatus.ENABLED)
				.createdAt(now)
				.build(data))
			.withMessage("Key algorithm can not be blank");
	}

	@Test
	@DisplayName("should fail to build when key type is null")
	void shouldFailToBuildWithNullType() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKey.builder()
				.id("key-id")
				.algorithm("test-algorithm")
				.status(KeyStatus.ENABLED)
				.createdAt(now)
				.build(data))
			.withMessage("Key type can not be null");
	}

	@Test
	@DisplayName("should fail to build when status is null")
	void shouldFailToBuildWithNullStatus() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKey.builder()
				.id("key-id")
				.algorithm(algorithm)
				.createdAt(now)
				.build(data))
			.withMessage("Key status can not be null");
	}

	@Test
	@DisplayName("should fail to build when creation timestamp is null")
	void shouldFailToBuildWithNullCreatedAt() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKey.builder()
				.id("key-id")
				.algorithm(algorithm)
				.status(KeyStatus.ENABLED)
				.build(data))
			.withMessage("Key creation time can not be null");
	}

}
