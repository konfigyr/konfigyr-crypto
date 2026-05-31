package com.konfigyr.crypto.test;

import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetPurpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("TestKeyset")
class TestKeysetTest {

	TestKey primaryKey;
	TestKeyset keyset;

	@BeforeEach
	void setup() {
		primaryKey = TestKey.builder()
			.id("primary-key")
			.algorithm(TestAlgorithm.INSTANCE)
			.primary()
			.enabled()
			.build();

		keyset = TestKeyset.builder()
			.name("my-keyset")
			.factory("my-factory")
			.purpose(KeysetPurpose.ENCRYPTION)
			.keyEncryptionKey(TestKeyEncryptionKey.INSTANCE)
			.key(primaryKey)
			.build();
	}

	@Test
	@DisplayName("rotate adds a new primary key and demotes the existing primary key")
	void rotateAddsPrimaryKeyAndDemotesExistingPrimary() {
		final KeyDefinition definition = KeyDefinition.of(TestAlgorithm.INSTANCE);
		final Keyset rotated = keyset.rotate(definition);

		KeysetAssert.assertThat(rotated)
			.isInstanceOf(TestKeyset.class)
			.hasSize(2);

		assertThat(rotated.getPrimary())
			.isNotEqualTo(primaryKey);

		assertThat(rotated.getKey(primaryKey.getId()))
			.isPresent()
			.hasValueSatisfying(key -> assertThat(key.isPrimary()).isFalse());

		assertThat(rotated.rotate())
			.hasSize(3);
	}

}
