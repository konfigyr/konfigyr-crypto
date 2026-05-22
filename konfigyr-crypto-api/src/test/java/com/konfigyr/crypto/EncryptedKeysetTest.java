package com.konfigyr.crypto;

import com.konfigyr.crypto.test.EncryptedKeysetAssert;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class EncryptedKeysetTest {

	static final Algorithm algorithm = TestAlgorithm.INSTANCE;
	static final KeyEncryptionKey kek = new TestKeyEncryptionKey("test-kek", "test-provider");
	static final Instant now = Instant.parse("2026-01-01T00:00:00Z");
	static final EncryptedKey key = EncryptedKey.builder()
		.id("key-id")
		.algorithm(algorithm)
		.status(KeyStatus.ENABLED)
		.primary(true)
		.createdAt(now)
		.build(ByteArray.fromString("key-material"));

	@Test
	@DisplayName("should build an encrypted keyset with all fields populated")
	void shouldBuildEncryptedKeysetWithAllFields() {
		final var keyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.destructionGracePeriod(Duration.ofDays(30))
			.build(List.of(key));

		EncryptedKeysetAssert.assertThat(keyset)
			.hasName("test-keyset")
			.hasPurpose(KeysetPurpose.ENCRYPTION)
			.createdByFactory("test-factory")
			.hasKeyEncryptionKey("test-provider", "test-kek")
			.hasRotationInterval(Duration.ofDays(90))
			.hasDestructionGracePeriod(Duration.ofDays(30))
			.hasSize(1);

		EncryptedKeysetAssert.assertThat(keyset)
			.assertThatKeys()
			.containsExactly(key);
	}

	@Test
	@DisplayName("should copy all metadata fields using the builder copy constructor")
	void shouldCopyAllFieldsUsingBuilderCopyConstructor() {
		final var original = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.destructionGracePeriod(Duration.ofDays(30))
			.build(List.of(key));

		final var copy = EncryptedKeyset.builder(original).build(original.getKeys());

		assertThat(copy).isEqualTo(original);
	}

	@Test
	@DisplayName("should build an encrypted keyset with rotation and grace period disabled")
	void shouldBuildEncryptedKeysetWithDisabledOptionals() {
		final var keyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(List.of());

		EncryptedKeysetAssert.assertThat(keyset)
			.hasRotationInterval(null)
			.hasDestructionGracePeriod(null)
			.hasSize(0);

		EncryptedKeysetAssert.assertThat(keyset)
			.assertThatKeys()
			.isEmpty();
	}

	@Test
	@DisplayName("should set provider and KEK identifier from a key encryption key")
	void shouldSetProviderAndKekFromKeyEncryptionKey() {
		final var keyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.keyEncryptionKey(kek)
			.build();

		EncryptedKeysetAssert.assertThat(keyset)
			.hasKeyEncryptionKey(kek);
	}

	@Test
	@DisplayName("should set rotation interval from milliseconds")
	void shouldSetRotationIntervalFromMilliseconds() {
		final var keyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90).toMillis())
			.build();

		EncryptedKeysetAssert.assertThat(keyset)
			.hasRotationInterval(Duration.ofDays(90));
	}

	@Test
	@DisplayName("should set destruction grace period from milliseconds")
	void shouldSetDestructionGracePeriodFromMilliseconds() {
		final var keyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.destructionGracePeriod(Duration.ofDays(30).toMillis())
			.build();

		EncryptedKeysetAssert.assertThat(keyset)
			.hasDestructionGracePeriod(Duration.ofDays(30));
	}

	@Test
	@DisplayName("should build from a keyset definition with rotation interval and grace period")
	void shouldBuildFromDefinitionWithRotationAndGracePeriod() {
		final var definition = KeysetDefinition.of("test-keyset", algorithm);

		final var keyset = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build();

		EncryptedKeysetAssert.assertThat(keyset)
			.matchesDefinition(definition)
			.hasKeyEncryptionKey("test-provider", "test-kek");
	}

	@Test
	@DisplayName("should build from a keyset definition with rotation interval and grace period disabled")
	void shouldBuildFromDefinitionWithOptionalFieldsDisabled() {
		final var definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(algorithm)
			.disableAutomaticKeyRotation()
			.disableDestructionGracePeriod()
			.build();

		final var keyset = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build();

		EncryptedKeysetAssert.assertThat(keyset)
			.matchesDefinition(definition);
	}

	@Test
	@DisplayName("should create an encrypted keyset from an existing keyset with rotation and grace period")
	void shouldCreateFromKeysetWithRotationAndGracePeriod() {
		final var source = mock(Keyset.class);
		doReturn("test-keyset").when(source).getName();
		doReturn(KeysetPurpose.ENCRYPTION).when(source).getPurpose();
		doReturn("test-factory").when(source).getFactory();
		doReturn(kek).when(source).getKeyEncryptionKey();
		doReturn(Optional.of(Duration.ofDays(90))).when(source).getRotationInterval();
		doReturn(Optional.of(Duration.ofDays(30))).when(source).getDestructionGracePeriod();

		final var keyset = EncryptedKeyset.from(source, List.of(key));

		EncryptedKeysetAssert.assertThat(keyset)
			.matchesKeyset(source)
			.assertThatKeys()
			.containsExactly(key);
	}

	@Test
	@DisplayName("should create an encrypted keyset from an existing keyset with disabled optionals")
	void shouldCreateFromKeysetWithDisabledOptionals() {
		final var source = mock(Keyset.class);
		doReturn("test-keyset").when(source).getName();
		doReturn(KeysetPurpose.ENCRYPTION).when(source).getPurpose();
		doReturn("test-factory").when(source).getFactory();
		doReturn(kek).when(source).getKeyEncryptionKey();
		doReturn(Optional.empty()).when(source).getRotationInterval();
		doReturn(Optional.empty()).when(source).getDestructionGracePeriod();

		EncryptedKeysetAssert.assertThat(EncryptedKeyset.from(source, List.of()))
			.matchesKeyset(source)
			.hasSize(0);
	}

	@Test
	@DisplayName("should return the number of encrypted keys and iterate over them")
	void shouldIterateOverKeys() {
		final var secondKey = EncryptedKey.builder()
			.id("key-id-2")
			.algorithm(algorithm)
			.status(KeyStatus.ENABLED)
			.createdAt(now)
			.build(ByteArray.fromString("other-material"));

		final var keyset = EncryptedKeyset.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(key, secondKey);

		EncryptedKeysetAssert.assertThat(keyset)
			.assertThatKeys()
			.hasSize(2)
			.containsExactly(key, secondKey);
	}

	@Test
	@DisplayName("should fail to build when keyset name is blank")
	void shouldFailToBuildWithBlankName() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKeyset.builder()
				.purpose(KeysetPurpose.ENCRYPTION)
				.provider("test-provider")
				.keyEncryptionKey("test-kek")
				.build())
			.withMessage("Keyset name can not be blank");
	}

	@Test
	@DisplayName("should fail to build when keyset purpose is blank")
	void shouldFailToBuildWithBlankPurpose() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKeyset.builder()
				.name("test-keyset")
				.provider("test-provider")
				.keyEncryptionKey("test-kek")
				.build())
			.withMessage("Keyset purpose can not be blank");
	}

	@Test
	@DisplayName("should fail to build when factory name is blank")
	void shouldDefaultFactoryToEmptyString() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKeyset.builder()
				.name("test-keyset")
				.purpose(KeysetPurpose.ENCRYPTION)
				.build())
			.withMessage("Keyset factory name can not be blank");
	}

	@Test
	@DisplayName("should fail to build when KEK provider name is blank")
	void shouldFailToBuildWithBlankProvider() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKeyset.builder()
				.name("test-keyset")
				.purpose(KeysetPurpose.ENCRYPTION)
				.factory("test-factory")
				.keyEncryptionKey("test-kek")
				.build())
			.withMessage("KEK provider name can not be blank");
	}

	@Test
	@DisplayName("should fail to build when KEK identifier is blank")
	void shouldFailToBuildWithBlankKek() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> EncryptedKeyset.builder()
				.name("test-keyset")
				.purpose(KeysetPurpose.ENCRYPTION)
				.factory("test-factory")
				.provider("test-provider")
				.build())
			.withMessage("KEK identifier can not be blank");
	}

}
