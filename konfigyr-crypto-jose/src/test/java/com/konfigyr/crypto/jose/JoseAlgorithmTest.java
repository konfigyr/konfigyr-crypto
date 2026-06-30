package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class JoseAlgorithmTest {

	@Test
	@DisplayName("should fail to create algorithm without a valid `jose:` prefix")
	void shouldAssertJosePrefix() {
		assertThatIllegalArgumentException().isThrownBy(() ->new JoseAlgorithm(
			"RS256", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.RS256,
			() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS)
		)).withMessage("JOSE algorithm names must start with 'jose:' prefix");
	}

	@Test
	@DisplayName("should consider two algorithms with the same name equal")
	void shouldBeEqualByName() {
		final var algorithm = new JoseAlgorithm(
			"jose:RS256", KeyType.RSA, KeysetPurpose.SIGNING, JWSAlgorithm.RS256,
			() -> new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS)
		);

		assertThat(algorithm)
			.isEqualTo(JoseAlgorithm.RS256)
			.hasSameHashCodeAs(JoseAlgorithm.RS256);

		assertThat(algorithm)
			.isNotEqualTo(JoseAlgorithm.ES256);
	}

	@Test
	@DisplayName("should produce a non-blank toString")
	void shouldProduceNonBlankToString() {
		assertThat(JoseAlgorithm.RS256)
			.hasToString("jose:RS256");
		assertThat(JoseAlgorithm.ES256)
			.hasToString("jose:ES256");
	}

}
