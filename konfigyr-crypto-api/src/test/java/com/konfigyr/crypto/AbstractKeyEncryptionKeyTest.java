package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class AbstractKeyEncryptionKeyTest {

	KeyEncryptionKey kek;

	@BeforeEach
	void setup() {
		kek = new TestKeyEncryptionKey("test-kek", "test-provider");
	}

	@Test
	@DisplayName("should define a basic information about a key encryption key")
	void shouldDefineKek() {
		assertThat(kek)
			.returns("test-kek", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek", KeyEncryptionKey::toString)
			.isEqualTo(new TestKeyEncryptionKey("test-kek", "test-provider"))
			.hasSameHashCodeAs(new TestKeyEncryptionKey("test-kek", "test-provider"))
			.hasToString("test-provider@test-kek");
	}

}
