package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class JsonWebKeyTest {

	static OctetSequenceKey jwk;

	@BeforeAll
	static void setup() throws Exception {
		jwk = new OctetSequenceKeyGenerator(128).keyID("kid").generate();
	}

	@Test
	@DisplayName("JSON web key can be created from a JSON Object")
	void createFromJson() throws Exception {
		final var map = new HashMap<>(jwk.toJSONObject());
		map.put("status", "ENABLED");
		map.put("primary", false);

		assertThat(new JsonWebKey(map))
			.returns(jwk.getKeyID(), JsonWebKey::getId)
			.returns(KeyType.OCTET, JsonWebKey::getType)
			.returns(KeyStatus.ENABLED, JsonWebKey::getStatus)
			.returns(false, JsonWebKey::isPrimary)
			.returns(jwk, JsonWebKey::getValue)
			.returns(map, JsonWebKey::toJSON);
	}

	@Test
	@DisplayName("JSON web key should be unique")
	void shouldCheckKeyEquality() {
		final var primary = new JsonWebKey(jwk, KeyStatus.ENABLED, true);

		assertThat(primary)
			.isEqualTo(new JsonWebKey(jwk, KeyStatus.ENABLED, true))
			.hasSameHashCodeAs(new JsonWebKey(jwk, KeyStatus.ENABLED, true));

		assertThat(primary)
			.isNotEqualTo(new JsonWebKey(jwk, KeyStatus.ENABLED, false))
			.doesNotHaveSameHashCodeAs(new JsonWebKey(jwk, KeyStatus.ENABLED, false))
			.isNotEqualTo(new JsonWebKey(jwk, KeyStatus.DISABLED, false))
			.doesNotHaveSameHashCodeAs(new JsonWebKey(jwk, KeyStatus.DISABLED, false));
	}

	@Test
	@DisplayName("JSON web key can not be created without a status")
	void parseKeyWithoutStatus() {
		assertThatExceptionOfType(ParseException.class)
			.isThrownBy(() -> new JsonWebKey(jwk.toJSONObject()))
			.withMessageContaining("Missing key status \"status\" parameter");
	}

	@Test
	@DisplayName("JSON web key can not be created without a valid status")
	void parseKeyWithInvalidStatus() {
		final var map = new HashMap<>(jwk.toJSONObject());
		map.put("status", "invalid");
		map.put("primary", "true");

		assertThatExceptionOfType(ParseException.class)
			.isThrownBy(() -> new JsonWebKey(map))
			.withMessageContaining("Invalid key status \"status\" parameter: invalid");
	}

	@Test
	@DisplayName("JSON web key can not be created without a primary state")
	void parseKeyWithoutPrimaryState() {
		final var map = new HashMap<>(jwk.toJSONObject());
		map.put("status", "ENABLED");

		assertThatExceptionOfType(ParseException.class)
			.isThrownBy(() -> new JsonWebKey(map))
			.withMessageContaining("Missing key primary state \"primary\" parameter");
	}

}
