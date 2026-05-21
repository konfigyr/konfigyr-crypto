package com.konfigyr.crypto.jose;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyOperation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonWebKeysetSelectorTest extends AbstractCryptoTest {

	@Test
	@DisplayName("should select JWK from keyset")
	void shouldSelectKey() throws IOException {
		final var keyset = (JsonWebKeyset) generate("selecting-keyset", JoseAlgorithm.RS256).rotate();

		final var selector = new JWKSelector(
			new JWKMatcher.Builder()
				.algorithm(JWSAlgorithm.RS256)
				.keyID(keyset.getKeys().getFirst().getId())
				.build()
		);

		assertThat(keyset.get(selector, null))
			.isNotNull()
			.hasSize(1);
	}

	@Test
	@DisplayName("should fail to select any JWK from keyset")
	void shouldNotSelectAnyKey() throws IOException {
		final var keyset = (JsonWebKeyset) generate("selecting-keyset", JoseAlgorithm.HS256);

		final var selector = new JWKSelector(
			new JWKMatcher.Builder()
				.keyOperation(KeyOperation.ENCRYPT)
				.build()
		);

		assertThat(keyset.get(selector, null))
			.isNotNull()
			.isEmpty();
	}

}
