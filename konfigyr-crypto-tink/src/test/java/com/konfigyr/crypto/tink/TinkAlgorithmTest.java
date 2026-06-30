package com.konfigyr.crypto.tink;

import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class TinkAlgorithmTest {

	@Test
	@DisplayName("should fail to create algorithm without a valid `tink:` prefix")
	void shouldAssertTinkPrefix() {
		assertThatIllegalArgumentException().isThrownBy(() -> new TinkAlgorithm(
			"AES128_GCM", KeysetPurpose.ENCRYPTION, KeyType.OCTET, AesGcmKeyManager.aes128GcmTemplate()
		)).withMessage("Tink algorithm names must start with 'tink:' prefix");
	}

	@Test
	@DisplayName("should consider two algorithms with the same name equal")
	void shouldBeEqualByName() {
		final var algorithm = new TinkAlgorithm(
			"tink:AES128_GCM", KeysetPurpose.ENCRYPTION, KeyType.OCTET, AesGcmKeyManager.aes128GcmTemplate()
		);

		assertThat(algorithm)
			.isEqualTo(TinkAlgorithm.AES128_GCM)
			.hasSameHashCodeAs(TinkAlgorithm.AES128_GCM);

		assertThat(algorithm)
			.isNotEqualTo(TinkAlgorithm.AES256_GCM);
	}

	@Test
	@DisplayName("should produce a non-blank toString")
	void shouldProduceNonBlankToString() {
		assertThat(TinkAlgorithm.AES128_GCM)
			.hasToString("tink:AES128_GCM");
		assertThat(TinkAlgorithm.AES256_GCM)
			.hasToString("tink:AES256_GCM");
	}

}
