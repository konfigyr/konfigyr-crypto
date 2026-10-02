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

import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Implementation of a {@link Keyset} that is backed by the
 * <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE SDK</a>.
 * <p>
 * Internally, it wraps a {@link JWKSet} to manage the JSON Web Key (JWK) representation and
 * facilitates key selection via a {@link JWKSource}.
 * <p>
 * Only {@link Key#isEnabled() enabled} keys take part in cryptographic operations. This applies
 * to the {@link JWKSource#get(JWKSelector, SecurityContext)} method as well, which only exposes
 * enabled keys. This prevents disabled or compromised keys from being used by Nimbus processors,
 * such as the {@code DefaultJWTProcessor}, or from being published as part of a public JWK set.
 * The {@link #getKeys()} method still lists every key in this keyset, regardless of its status.
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

	/**
	 * Selects the matching JSON Web Keys that are {@link Key#isEnabled() enabled}. Keys in any other
	 * {@link KeyStatus} are never returned by this method, regardless of the given selector.
	 *
	 * @param selector the JWK selector, can't be {@literal null}
	 * @param context the optional security context, can be {@literal null}
	 * @return the matching enabled keys, never {@literal null}
	 */
	@Override
	public List<JWK> get(JWKSelector selector, @Nullable SecurityContext context) {
		return select(selector, Key::isEnabled);
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
			final JWEObject object = JWEObject.parse(cipher.toString(StandardCharsets.UTF_8));
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
			final JWSObject object = JWSObject.parse(signature.toString(StandardCharsets.UTF_8));

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
				builder.key(demote(existing));
			} else {
				builder.key(existing);
			}
		});

		return builder.build();
	}

	@Override
	protected Keyset doPromote(JsonWebKey key, @Nullable Instant expiresAt) {
		final Builder builder = new Builder(this);

		stream().map(JsonWebKey.class::cast).forEach(existing -> {
			if (existing.getId().equals(key.getId())) {
				builder.key(promote(existing, expiresAt));
			} else if (existing.isPrimary()) {
				builder.key(demote(existing));
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

	private List<JWK> select(JWKSelector selector, Predicate<Key> filter) {
		final List<JWK> keys = stream()
			.filter(filter)
			.map(JsonWebKey.class::cast)
			.map(JsonWebKey::getValue)
			.toList();

		return selector.select(new JWKSet(keys));
	}

	private JsonWebKey resolveMatchingKey(JWKMatcher matcher) throws JOSEException {
		// select over all keys so that a key that is not usable fails with a status-specific exception
		final List<JWK> keys = select(new JWKSelector(matcher), key -> true);

		if (keys.isEmpty()) {
			throw new KeySourceException("No matching key found for JWK matcher: " + matcher);
		}

		if (keys.size() > 1) {
			throw new KeySourceException("Found multiple keys for JWK matcher: " + matcher);
		}

		return requireUsableKey(keys.getFirst().getKeyID());
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

	private void assertKeysetOperation(KeysetOperation operation) {
		if (!purpose.isOperationSupported(operation)) {
			throw new CryptoException.UnsupportedKeysetOperationException(name, operation, purpose.operations());
		}
	}

	/**
	 * Promotes the given key to be the primary key, restoring all the key operations permitted by the
	 * purpose of its algorithm, as these are removed when a key is {@link #demote(JsonWebKey) demoted}.
	 *
	 * @param key       the key to be promoted
	 * @param expiresAt the new expiration time of the promoted key
	 * @return the promoted key
	 */
	private static JsonWebKey promote(JsonWebKey key, @Nullable Instant expiresAt) {
		final Set<KeyOperation> operations = JoseUtils.resolveKeyOperations(key.getAlgorithm().purpose());

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

		return new JsonWebKey.Builder(key, jwk).promote(expiresAt).build();
	}

	/**
	 * Demotes the primary key of the keyset when it is rotated or when another key is promoted. The key
	 * should not be marked as primary anymore and should not perform encryption or signing operations.
	 *
	 * @param key the existing primary key to be demoted
	 * @return the demoted key
	 */
	private static JsonWebKey demote(JsonWebKey key) {
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

		return new JsonWebKey.Builder(key, jwk).demote().build();
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
