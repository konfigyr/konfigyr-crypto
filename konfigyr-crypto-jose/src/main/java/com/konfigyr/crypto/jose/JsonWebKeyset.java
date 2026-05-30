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
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.produce.JWSSignerFactory;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.function.ThrowingFunction;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Implementation of a {@link Keyset} that is backed by the
 * <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE SDK</a>.
 * <p>
 * Internally, it wraps a {@link JWKSet} to manage the JSON Web Key (JWK) representation and
 * facilitates key selection via a {@link JWKSource}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see JWKSource
 */
@NullMarked
class JsonWebKeyset extends AbstractKeyset<JsonWebKey> implements JWKSource<SecurityContext> {

	private JsonWebKeyset(Builder builder) {
		super(builder);
	}

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
		Assert.isTrue(!data.isEmpty(), "Cannot encrypt an empty byte array");
		assertKeysetOperation(KeysetOperation.ENCRYPT);

		final JsonWebKey key = requireActivePrimary();

		try {
			final JWEHeader header = JoseUtils.createEncryptionHeader(key, context);
			final JWEObject object = new JWEObject(header, new Payload(data.array()));
			object.encrypt(createEncrypter(key));

			return ByteArray.fromString(object.serialize(), StandardCharsets.UTF_8);
		} catch (JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.ENCRYPT, e);
		}
	}

	@Override
	public ByteArray decrypt(ByteArray cipher, @Nullable ByteArray context) {
		Assert.isTrue(!cipher.isEmpty(), "Cannot decrypt an empty byte array");
		assertKeysetOperation(KeysetOperation.DECRYPT);

		try {
			final JWEObject object = JWEObject.parse(new String(cipher.array(), StandardCharsets.UTF_8));
			final ByteArray aad = JoseUtils.resolveAdditionalAuthenticationData(object.getHeader());

			if (!((context == null || context.isEmpty()) ? aad == null : context.constantTimeEquals(aad))) {
				throw new CryptoException.KeysetOperationException(name, KeysetOperation.DECRYPT,
					"AAD does not match the expected value");
			}

			object.decrypt(createDecrypter(object.getHeader()));

			return new ByteArray(object.getPayload().toBytes());
		} catch (ParseException | JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.DECRYPT, e);
		}
	}

	@Override
	public ByteArray sign(ByteArray data) {
		Assert.isTrue(!data.isEmpty(), "Cannot sign an empty byte array");
		assertKeysetOperation(KeysetOperation.SIGN);

		final JsonWebKey key = requireActivePrimary();

		try {
			final JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) key.getAlgorithm().algorithm())
				.keyID(key.getId())
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
		Assert.isTrue(!signature.isEmpty(), "Cannot verify an empty signature");
		Assert.isTrue(!data.isEmpty(), "Cannot verify a signature against an empty byte array");
		assertKeysetOperation(KeysetOperation.VERIFY);

		try {
			final JWSObject object = JWSObject.parse(new String(signature.array(), StandardCharsets.UTF_8));

			if (!object.verify(createVerifier(object.getHeader()))) {
				return false;
			}

			return data.constantTimeEquals(object.getPayload().toBytes());
		} catch (ParseException e) {
			return false;
		} catch (JOSEException e) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.VERIFY, e);
		}
	}

	@Override
	protected String generateId() {
		return JoseUtils.generateKeyId();
	}

	@Override
	protected Keyset doRotate(KeyDefinition definition, String uniqueId) {
		final JsonWebKeyset.Builder builder = new JsonWebKeyset.Builder(this)
			.key(JsonWebKey.generate(definition, uniqueId));

		stream().map(JsonWebKey.class::cast).forEach(existing -> {
			if (existing.isPrimary() && definition.isPrimary()) {
				builder.key(rotateKey(existing));
			} else {
				builder.key(existing);
			}
		});

		return builder.build();
	}

	private JWEEncrypter createEncrypter(JsonWebKey key) throws JOSEException {
		return switch (key.getValue()) {
			case RSAKey rsa -> new RSAEncrypter(rsa);
			case ECKey ec -> new ECDHEncrypter(ec);
			case OctetSequenceKey secret -> new AESEncrypter(secret);
			default -> throw new CryptoException.UnsupportedAlgorithmException(key.getAlgorithm());
		};
	}

	private JWEDecrypter createDecrypter(JWEHeader header) throws JOSEException {
		final JsonWebKey key = resolveMatchingKey(JWKMatcher.forJWEHeader(header));
		final java.security.Key cryptographicKey = resolveCryptographicKey(key, AsymmetricJWK::toPrivateKey);

		try {
			final JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
			return factory.createJWEDecrypter(header, cryptographicKey);
		} catch (JOSEException e) {
			throw new CryptoException.UnsupportedAlgorithmException(key.getAlgorithm(), e);
		}
	}

	private JWSSigner createSigner(JsonWebKey key) throws JOSEException {
		final JWSSignerFactory factory = new DefaultJWSSignerFactory();

		try {
			return factory.createJWSSigner(key.getValue(), (JWSAlgorithm) key.getAlgorithm().algorithm());
		} catch (JOSEException e) {
			throw new CryptoException.UnsupportedAlgorithmException(key.getAlgorithm(), e);
		}
	}

	private JWSVerifier createVerifier(JWSHeader header) throws JOSEException {
		final JsonWebKey key = resolveMatchingKey(JWKMatcher.forJWSHeader(header));
		final java.security.Key cryptographicKey = resolveCryptographicKey(key, AsymmetricJWK::toPublicKey);

		try {
			final JWSVerifierFactory factory = new DefaultJWSVerifierFactory();
			return factory.createJWSVerifier(header, cryptographicKey);
		} catch (JOSEException e) {
			throw new CryptoException.UnsupportedAlgorithmException(key.getAlgorithm(), e);
		}
	}

	private JsonWebKey resolveMatchingKey(JWKMatcher matcher) throws JOSEException {
		final List<JWK> keys = get(new JWKSelector(matcher), new SimpleSecurityContext());

		if (keys.isEmpty()) {
			throw new KeySourceException("No matching key found for JWK matcher: " + matcher);
		}

		if (keys.size() > 1) {
			throw new KeySourceException("Found multiple keys for JWK matcher: " + matcher);
		}

		final JWK key = keys.getFirst();

		return getKey(key.getKeyID()).orElseThrow(() -> new IllegalStateException(
			"Failed to find JSON Web key with identifier: " + key.getKeyID()
		));
	}

	private java.security.Key resolveCryptographicKey(
		JsonWebKey key,
		ThrowingFunction<AsymmetricJWK, java.security.Key> resolver
	) {
		if (KeyType.RSA.equals(key.getValue().getKeyType())) {
			return resolver.apply(key.getValue().toRSAKey());
		}

		if (KeyType.EC.equals(key.getValue().getKeyType())) {
			return resolver.apply(key.getValue().toECKey());
		}

		if (KeyType.OCT.equals(key.getValue().getKeyType())) {
			return key.getValue().toOctetSequenceKey().toSecretKey();
		}

		throw new IllegalArgumentException("Unsupported JWK key type: " + key.getValue().getKeyType());
	}

	/**
	 * Rotates the previously generated key that was part of the keyset. The key should not be marked
	 * as primary anymore and should not perform encryption or signing operations.
	 *
	 * @param key the existing key to be rotated
	 * @return the rotated key
	 */
	private JsonWebKey rotateKey(JsonWebKey key) {
		final Set<KeyOperation> operations = key.getValue()
			.getKeyOperations()
			.stream()
			.filter(operation -> operation == KeyOperation.VERIFY || operation == KeyOperation.DECRYPT)
			.collect(Collectors.toUnmodifiableSet());

		final JWK jwk = switch (key.getValue()) {
			case RSAKey rsa -> new RSAKey.Builder(rsa)
				.keyOperations(operations)
				.build();
			case ECKey ec -> new ECKey.Builder(ec)
				.keyOperations(operations)
				.build();
			case OctetSequenceKey secret -> new OctetSequenceKey.Builder(secret)
				.keyOperations(operations)
				.build();
			default -> throw new IllegalStateException("Unsupported JWK type: " + key.getValue().getKeyType());
		};

		return new JsonWebKey.Builder(key, jwk)
			.primary(false)
			.build();
	}

	private void assertKeysetOperation(KeysetOperation operation) {
		if (!purpose.isOperationSupported(operation)) {
			throw new CryptoException.UnsupportedKeysetOperationException(name, operation, purpose.operations());
		}
	}

	static final class Builder extends AbstractKeyset.Builder<JsonWebKey, JsonWebKeyset, Builder> {

		Builder(KeysetDefinition definition) {
			super(definition);
		}

		Builder(JsonWebKeyset keyset) {
			super(keyset);
		}

		Builder(EncryptedKeyset keyset) {
			super(keyset);
		}

		Builder(Collection<JsonWebKey> keys) {
			Assert.notNull(keys, "JWK set can not be null");
			Assert.state(!keys.isEmpty(), "Can not create JSON Web Keyset with an empty key set");
			factory(JoseKeysetFactory.NAME).keys(keys);
		}

		@Override
		public JsonWebKeyset build() {
			return new JsonWebKeyset(this);
		}

	}
}
