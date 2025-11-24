package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.jspecify.annotations.NonNull;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class AbstractKeyEncryptionKeyTest {

	KeyEncryptionKey kek;

	@BeforeEach
	void setup() {
		kek = new AbstractKeyEncryptionKey("test-kek", "test-provider") {
			@NonNull
			@Override
			public ByteArray wrap(@NonNull ByteArray data) {
				return data;
			}

			@NonNull
			@Override
			public ByteArray unwrap(@NonNull ByteArray data) {
				return data;
			}
		};
	}

	@Test
	void shouldDefineKek() {
		assertThat(kek).returns("test-kek", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek", KeyEncryptionKey::toString)
			.isEqualTo(kek);
	}

}
