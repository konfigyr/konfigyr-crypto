package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.produce.JWSSignerFactory;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.function.ThrowingFunction;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Implementation of a {@link Keyset} that is backed by the
 * <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE SDK</a>.
 * <p>
 * Internally, it wraps a {@link JWKSet} to manage the JSON Web Key (JWK) representation and
 * facilitates key selection via a {@link JWKSource}.
 *
 * @author : Vladimir Spasic
 * @since : 24.11.25, Mon
 * @see JWKSource
 */
@Value
@NullMarked
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
class JsonWebKeyset implements Keyset, JWKSource<SecurityContext> {

	String name;
	JoseAlgorithm algorithm;
	KeyEncryptionKey keyEncryptionKey;
	List<Key> keys;
	Duration rotationInterval;
	Instant nextRotationTime;

	@Override
	public List<JWK> get(JWKSelector selector, @Nullable SecurityContext context) {
		final List<JWK> keys = stream()
			.map(JsonWebKey.class::cast)
			.map(JsonWebKey::getValue)
			.toList();

		return selector.select(new JWKSet(keys));
	}

	@Override
	public ByteArray encrypt(ByteArray data, @Nullable ByteArray context) {
		assertKeysetOperation(KeysetOperation.ENCRYPT);

		final JWK key = getPrimaryKey().orElseThrow(() -> new CryptoException.KeysetOperationException(
			name, KeysetOperation.ENCRYPT, "No primary key for encryption found for Keyset: " + name
		));

		try {
			final JWEHeader header = new JWEHeader.Builder(
				(JWEAlgorithm) algorithm.algorithm(),
				EncryptionMethod.A256GCM
			).keyID(key.getKeyID()).build();

			final JWEObject object = new JWEObject(header, new Payload(data.array()));

			object.encrypt(createEncrypter(key));

			return ByteArray.fromString(object.serialize(), StandardCharsets.UTF_8);
		} catch (JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.ENCRYPT, e);
		}
	}

	@Override
	public ByteArray decrypt(ByteArray cipher, @Nullable ByteArray context) {
		assertKeysetOperation(KeysetOperation.DECRYPT);

		try {
			final JWEObject object = JWEObject.parse(new String(cipher.array(), StandardCharsets.UTF_8));
			object.decrypt(createDecrypter(object.getHeader()));

			return new ByteArray(object.getPayload().toBytes());
		} catch (ParseException | JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.DECRYPT, e);
		}
	}

	@Override
	public ByteArray sign(ByteArray data) {
		assertKeysetOperation(KeysetOperation.SIGN);

		final JWK key = getPrimaryKey().orElseThrow(() -> new CryptoException.KeysetOperationException(
			name, KeysetOperation.SIGN, "No primary key for signing found for Keyset: " + name
		));

		try {
			final JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) algorithm.algorithm())
				.keyID(key.getKeyID())
				.build();

			final JWSObject object = new JWSObject(header, new Payload(data.array()));
			object.sign(createSigner(key));

			return ByteArray.fromString(object.serialize(), StandardCharsets.UTF_8);
		} catch (JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.SIGN, e);
		}
	}

	@Override
	public boolean verify(ByteArray signature, ByteArray data) {
		assertKeysetOperation(KeysetOperation.VERIFY);

		try {
			final JWSObject object = JWSObject.parse(new String(signature.array(), StandardCharsets.UTF_8));

			if (!object.verify(createVerifier(object.getHeader()))) {
				return false;
			}

			return Arrays.equals(object.getPayload().toBytes(), data.array());
		} catch (ParseException | JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.VERIFY, e);
		}
	}

	@Override
	public Keyset rotate() {
		final JWKGenerator<?> generator = JoseUtils.generatorForDefinition(this);
		final JWK key;

		try {
			key = generator.generate();
		} catch (JOSEException ex) {
			throw new CryptoException.KeysetException(this, "Failed to create JWK", ex);
		}

		final List<JsonWebKey> keys = new ArrayList<>(size());
		keys.add(new JsonWebKey(key, KeyStatus.ENABLED, true));

		stream().map(JsonWebKey.class::cast).forEach(existing -> keys.add(
			new JsonWebKey(existing.getValue(), existing.getStatus(), false))
		);

		return JsonWebKeyset.builder(keys)
				.name(name)
				.algorithm(algorithm)
				.keyEncryptionKey(keyEncryptionKey)
				.rotationInterval(rotationInterval)
				.nextRotationTime(Instant.now().plus(rotationInterval))
				.build();
	}

	private JWEEncrypter createEncrypter(JWK key) throws JOSEException {
		if (key instanceof RSAKey rsa) {
			return new RSAEncrypter(rsa);
		}

		if (key instanceof ECKey ec) {
			return new ECDHEncrypter(ec);
		}

		if (key instanceof OctetSequenceKey secret) {
			return new AESEncrypter(secret);
		}

		throw new CryptoException.UnsupportedAlgorithmException(algorithm);
	}

	private JWEDecrypter createDecrypter(JWEHeader header) throws JOSEException {
		final JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
		final java.security.Key key = resolveMatchingKey(JWKMatcher.forJWEHeader(header), AsymmetricJWK::toPrivateKey);

		try {
			return factory.createJWEDecrypter(header, key);
		} catch (JOSEException e) {
			throw new CryptoException.UnsupportedAlgorithmException(algorithm, e);
		}
	}

	private JWSSigner createSigner(JWK key) throws JOSEException {
		final JWSSignerFactory factory = new DefaultJWSSignerFactory();

		try {
			return factory.createJWSSigner(key, (JWSAlgorithm) algorithm.algorithm());
		} catch (JOSEException e) {
			throw new CryptoException.UnsupportedAlgorithmException(algorithm, e);
		}
	}

	private JWSVerifier createVerifier(JWSHeader header) throws JOSEException {
		final JWSVerifierFactory factory = new DefaultJWSVerifierFactory();
		final java.security.Key key = resolveMatchingKey(JWKMatcher.forJWSHeader(header), AsymmetricJWK::toPublicKey);

		try {
			return factory.createJWSVerifier(header, key);
		} catch (JOSEException e) {
			throw new CryptoException.UnsupportedAlgorithmException(algorithm, e);
		}
	}

	private Optional<JWK> getPrimaryKey() {
		return stream()
			.map(JsonWebKey.class::cast)
			.filter(JsonWebKey::isPrimary)
			.map(JsonWebKey::getValue)
			.findFirst();
	}

	private java.security.Key resolveMatchingKey(
		JWKMatcher matcher,
		ThrowingFunction<AsymmetricJWK, java.security.Key> resolver
	) throws JOSEException {
		final List<JWK> keys = get(new JWKSelector(matcher), null);

		if (keys.isEmpty()) {
			throw new KeySourceException("No matching key found for JWK matcher: " + matcher);
		}

		if (keys.size() > 1) {
			throw new KeySourceException("Found multiple keys for JWK matcher: " + matcher);
		}

		final JWK key = keys.get(0);

		if (KeyType.RSA.equals(key.getKeyType())) {
			return resolver.apply(key.toRSAKey());
		}

		if (KeyType.EC.equals(key.getKeyType())) {
			return resolver.apply(key.toECKey());
		}

		if (KeyType.OCT.equals(key.getKeyType())) {
			return key.toOctetSequenceKey().toSecretKey();
		}

		throw new IllegalArgumentException("Unsupported JWK key type: " + key.getKeyType());
	}

	private void assertKeysetOperation(KeysetOperation operation) {
		if (!algorithm.supports(operation)) {
			throw new CryptoException.UnsupportedKeysetOperationException(name, operation, algorithm.operations());
		}
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		JsonWebKeyset that = (JsonWebKeyset) o;
		return name.equals(that.name)
				&& algorithm.equals(that.algorithm)
				&& keyEncryptionKey.equals(that.keyEncryptionKey)
				&& keys.equals(that.keys)
				&& rotationInterval.equals(that.rotationInterval)
				&& nextRotationTime.equals(that.nextRotationTime);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name, algorithm, keyEncryptionKey, keys, rotationInterval, nextRotationTime);
	}

	@Override
	public String toString() {
		return "JsonWebKeyset[name='" + name + "', algorithm=" + algorithm + ", keys=" + keys
			+ ", keyEncryptionKey=" + keyEncryptionKey + ", rotationInterval=" + rotationInterval
			+ ", nextRotationTime=" + nextRotationTime + ']';
	}

	static Builder builder(JsonWebKey... keys) {
		return new Builder(Arrays.asList(keys));
	}

	static Builder builder(Collection<JsonWebKey> keys) {
		return new Builder(keys);
	}

	@NullUnmarked
	static final class Builder {

		private final List<Key> keys;

		private String name;

		private JoseAlgorithm algorithm;

		private KeyEncryptionKey keyEncryptionKey;

		private Duration rotationInterval;

		private Instant nextRotationTime;

		private Builder(Collection<JsonWebKey> keys) {
			Assert.notNull(keys, "JWK set can not be null");
			Assert.state(!keys.isEmpty(), "Can not create JSON Web Keyset with an empty key set");

			this.keys = List.copyOf(keys);
		}

		Builder name(String name) {
			this.name = name;
			return this;
		}

		Builder algorithm(JoseAlgorithm algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		Builder keyEncryptionKey(KeyEncryptionKey keyEncryptionKey) {
			this.keyEncryptionKey = keyEncryptionKey;
			return this;
		}

		Builder rotationInterval(Duration rotationInterval) {
			this.rotationInterval = rotationInterval;
			return this;
		}

		Builder nextRotationTime(Instant nextRotationTime) {
			this.nextRotationTime = nextRotationTime;
			return this;
		}

		JsonWebKeyset build() {
			Assert.hasText(name, "Keyset name can not be blank");
			Assert.notNull(algorithm, "Keyset algorithm can not be null");
			Assert.notNull(keyEncryptionKey, "Keyset key encryption key can not be null");
			Assert.notNull(rotationInterval, "Keyset rotation interval can not be null");
			Assert.notNull(nextRotationTime, "Keyset next rotation time can not be null");

			return new JsonWebKeyset(name, algorithm, keyEncryptionKey, keys, rotationInterval, nextRotationTime);
		}

	}
}
