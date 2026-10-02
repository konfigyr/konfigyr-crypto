package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

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

	@Test
	@DisplayName("should only expose enabled keys through the JWK source")
	void shouldOnlySelectEnabledKeys() throws IOException {
		final var keyset = (JsonWebKeyset) generate("selecting-keyset", JoseAlgorithm.ES256).rotate();
		final var primary = keyset.getPrimary().getId();
		final var previous = keyset.stream().filter(key -> !key.isPrimary()).findFirst().orElseThrow().getId();

		final var compromised = withStatus(keyset, previous, KeyStatus.COMPROMISED);

		assertThat(compromised.get(new JWKSelector(new JWKMatcher.Builder().build()), null))
			.as("JWK source must only expose enabled keys")
			.extracting(JWK::getKeyID)
			.containsExactly(primary);

		assertThat(compromised.getKeys())
			.as("keyset must still list every key, regardless of its status")
			.hasSize(2);
	}

	@Test
	@DisplayName("should reject JWT signed by a compromised key when using a Nimbus JWT processor")
	void shouldRejectJwtSignedByCompromisedKey() throws Exception {
		final var keyset = (JsonWebKeyset) generate("selecting-keyset", JoseAlgorithm.ES256);
		final var previous = keyset.getPrimary().getId();

		final var claims = new JWTClaimsSet.Builder().subject("konfigyr").build();
		final var token = keyset.sign(ByteArray.fromString(claims.toString()))
			.toString(StandardCharsets.UTF_8);

		final var rotated = (JsonWebKeyset) keyset.rotate();

		assertThat(processor(rotated).process(token, null).getSubject())
			.as("JWT signed by an enabled key must be accepted")
			.isEqualTo("konfigyr");

		final var processor = processor(withStatus(rotated, previous, KeyStatus.COMPROMISED));

		assertThatExceptionOfType(BadJOSEException.class)
			.as("JWT signed by a compromised key must be rejected")
			.isThrownBy(() -> processor.process(token, null));
	}

	static DefaultJWTProcessor<SecurityContext> processor(JsonWebKeyset keyset) {
		final var processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, keyset));
		return processor;
	}

	static JsonWebKeyset withStatus(JsonWebKeyset keyset, String keyId, KeyStatus status) {
		return new JsonWebKeyset.Builder(keyset)
			.keys(keyset.stream()
				.map(JsonWebKey.class::cast)
				.map(key -> key.getId().equals(keyId)
					? new JsonWebKey.Builder(key, key.getValue()).status(status).build()
					: key)
				.toList())
			.build();
	}

}
