package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.AbstractKey;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyStatus;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import lombok.Getter;
import org.jspecify.annotations.NullMarked;

@Getter
@NullMarked
class JsonWebKey extends AbstractKey<JoseAlgorithm> {

	JWK value;

	JsonWebKey(JWK value, Builder builder) {
		super(builder);
		this.value = value;
	}

	static JsonWebKey generate(KeyDefinition definition, String id) {
		if (!(definition.getAlgorithm() instanceof JoseAlgorithm joseAlgorithm)) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm());
		}

		final JWK value;

		try {
			value = joseAlgorithm.generator()
				.keyID(id)
				.generate();
		} catch (JOSEException ex) {
			throw new CryptoException.KeysetException(
				definition.getAlgorithm().name(), "Failed to create JWK with id '" + id + "'", ex);
		}

		return new Builder(definition, value)
			.id(value.getKeyID())
			.status(KeyStatus.ENABLED)
			.build();
	}

	static class Builder extends AbstractKey.Builder<JoseAlgorithm, JsonWebKey, Builder> {

		private final JWK value;

		Builder(JWK value) {
			super();
			this.value = value;
			this.initializedAt = this.createdAt;
		}

		Builder(KeyDefinition definition, JWK value) {
			super(definition);
			this.value = value;
			this.initializedAt = this.createdAt;
		}

		Builder(JsonWebKey key, JWK value) {
			super(key);
			this.value = value;
		}

		@Override
		public JsonWebKey build() {
			return new JsonWebKey(value, this);
		}
	}
}
