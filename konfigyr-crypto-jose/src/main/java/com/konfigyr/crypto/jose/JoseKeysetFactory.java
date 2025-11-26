package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jose.shaded.gson.JsonParseException;
import com.nimbusds.jose.shaded.gson.reflect.TypeToken;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Implementation of the {@link KeysetFactory} that integrates
 * <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE SDK</a> in the Konfigyr {@link KeysetStore}.
 * <p>
 * It produces the {@link JsonWebKeyset} implementation that would be using the set of {@link JWK JWKs} as the
 * underlying store of cryptographic keys. To generate a new {@link JsonWebKeyset} it is required to use a
 * {@link JoseAlgorithm} when defining which type of keys should be generated to perform specified
 * {@link KeysetOperation key operations}.
 * <p>
 * You can use the {@link JsonWebKeyset} as a {@link com.nimbusds.jose.jwk.source.JWKSource} to retrieve
 * JSON Web cryptographic keys from keyset. This makes it easier to integrate the keysets in the Nimbus SDK
 * API, like {@link com.nimbusds.jose.proc.JWEKeySelector JWEKeySelector} and
 * {@link com.nimbusds.jose.proc.JWSKeySelector JWSKeySelector}.
 * <p>
 * Keep in mind that the {@link JsonWebKeyset} would generate {@link com.nimbusds.jose.JWEObject JWE}
 * when encrypting the data, and {@link com.nimbusds.jose.JWSObject JWS} when signing it.
 *
 * @author : Vladimir Spasic
 * @since : 24.11.25, Mon
 * @see JoseAlgorithm
 * @see JsonWebKeyset
 **/
@NullMarked
public class JoseKeysetFactory implements KeysetFactory {

	private static final TypeToken<?> JSON_KEY_TYPE = TypeToken.getParameterized(Map.class, String.class, Object.class);
	private static final TypeToken<?> JSON_KEYS_TYPE = TypeToken.getArray(JSON_KEY_TYPE.getType());

	private final Gson gson = new GsonBuilder()
		.create();

	@Override
	public boolean supports(EncryptedKeyset encryptedKeyset) {
		for (JoseAlgorithm algorithm : JoseAlgorithm.values()) {
			if (algorithm.name().equals(encryptedKeyset.getAlgorithm())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean supports(KeysetDefinition definition) {
		return definition.getAlgorithm() instanceof JoseAlgorithm;
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
		final JWKGenerator<?> generator = JoseUtils.generatorForDefinition(definition);
		final JWK key;

		try {
			key = generator.generate();
		} catch (JOSEException ex) {
			throw new CryptoException.KeysetException(definition, "Failed to create JWK", ex);
		}

		return JsonWebKeyset.builder(new JsonWebKey(key, KeyStatus.ENABLED, true))
			.keyEncryptionKey(kek)
			.name(definition.getName())
			.algorithm((JoseAlgorithm) definition.getAlgorithm())
			.rotationInterval(definition.getRotationInterval())
			.nextRotationTime(definition.getNextRotationTime())
			.build();
	}

	@Override
	public EncryptedKeyset create(Keyset keyset) {
		final KeyEncryptionKey kek = keyset.getKeyEncryptionKey();
		final ByteArray encrypted;

		try {
			final List<Map<String, Object>> keys = keyset.getKeys()
				.stream()
				.map(JsonWebKey.class::cast)
				.map(JsonWebKey::toJSON)
				.toList();

			encrypted = kek.wrap(ByteArray.fromString(gson.toJson(keys)));
		} catch (Exception e) {
			throw new CryptoException.WrappingException(keyset.getName(), kek, e);
		}

		return EncryptedKeyset.from(keyset, encrypted);
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) throws IOException {
		final ByteArray unwrapped = kek.unwrap(encryptedKeyset.getData());
		final InputStreamReader reader = new InputStreamReader(unwrapped.getInputStream());
		final Map<String, Object>[] json;

		try {
			json = gson.fromJson(reader, JSON_KEYS_TYPE.getType());
		} catch (JsonParseException ex) {
			throw new IOException("Fail to read encrypted JOSE keyset: " + encryptedKeyset.getName(), ex);
		}

		final List<JsonWebKey> keys = new ArrayList<>(json.length);

		for (Map<String, Object> key : json) {
			try {
				keys.add(new JsonWebKey(key));
			} catch (ParseException ex) {
				throw new IOException("Fail to read encrypted JOSE keyset: " + encryptedKeyset.getName(), ex);
			}
		}

		return JsonWebKeyset.builder(keys)
			.keyEncryptionKey(kek)
			.name(encryptedKeyset.getName())
			.algorithm(JoseAlgorithm.valueOf(encryptedKeyset.getAlgorithm()))
			.rotationInterval(encryptedKeyset.getRotationInterval())
			.nextRotationTime(encryptedKeyset.getNextRotationTime())
			.build();
	}
}
