package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.AbstractKey;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyStatus;
import org.bouncycastle.operator.OperatorCreationException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

/**
 * Implementation of the {@link com.konfigyr.crypto.Key} that holds an asymmetric key pair that is bound
 * to an X.509 certificate.
 * <p>
 * The certificate chain is public information and is exposed by this key. The private key is
 * intentionally not exposed through a getter, so it cannot be picked up by serializers, template
 * engines, or bean introspection by accident, it can only be handed over using the
 * {@link #convert(Converter)} method.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 */
@NullMarked
final class X509Key extends AbstractKey<X509Algorithm> implements X509Material {

	/**
	 * The key identifier as a {@link UUID}, written in the header of ciphertexts and signatures.
	 */
	private final UUID uuid;

	/**
	 * The private key material, never exposed outside of this package.
	 */
	private final PrivateKey privateKey;

	/**
	 * The certificate chain, starting with the certificate of this key.
	 */
	private final List<X509Certificate> certificateChain;

	private X509Key(UUID uuid, Builder builder) {
		super(builder);
		this.uuid = uuid;
		this.privateKey = Objects.requireNonNull(builder.privateKey, "X509 private key can't be null");
		this.certificateChain = Objects.requireNonNull(builder.certificateChain, "X509 certificate chain can't be null");
	}

	UUID uuid() {
		return uuid;
	}

	/**
	 * Returns the X.509 certificate bound to this key.
	 *
	 * @return the certificate, never {@literal null}
	 */
	@Override
	public X509Certificate getCertificate() {
		return certificateChain.getFirst();
	}

	/**
	 * Returns the X.509 certificate chain, starting with the {@link #getCertificate() certificate}
	 * of this key, followed by the issuer certificates, if any.
	 *
	 * @return the immutable certificate chain, never {@literal null} or empty
	 */
	@Override
	public List<X509Certificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Returns the public key that is certified by the {@link #getCertificate() certificate}.
	 *
	 * @return the public key, never {@literal null}
	 */
	@Override
	public PublicKey getPublicKey() {
		return getCertificate().getPublicKey();
	}

	@Override
	public <T extends @Nullable Object> T convert(Converter<PrivateKey, T> converter) {
		Assert.notNull(converter, "Private key converter can't be null");

		if (isEnabled()) {
			return converter.convert(privateKey);
		}

		throw new CryptoException.KeysetException(id, "X509 key '" + id + "' is " + status
			+ " and its private key material can not be used.");
	}

	PrivateKey privateKey() {
		return privateKey;
	}

	/**
	 * Generates a new key pair for the algorithm defined in the {@link KeyDefinition} and issues a
	 * self-signed certificate for it.
	 * <p>
	 * The certificate is valid from the key creation time until the key expiration time, or for
	 * {@link X509Utils#DEFAULT_CERTIFICATE_VALIDITY} when the key does not expire.
	 *
	 * @param definition the key definition, can't be {@literal null}
	 * @param id         the key identifier, can't be {@literal null}
	 * @param subject    common name of the certificate subject, usually the keyset name, can't be {@literal null}
	 * @return the generated key, never {@literal null}
	 * @throws CryptoException.UnsupportedAlgorithmException when the algorithm is not a {@link X509Algorithm}
	 * @throws CryptoException.KeysetException when the key pair or the certificate can not be generated
	 */
	static X509Key generate(KeyDefinition definition, String id, String subject) {
		if (!(definition.getAlgorithm() instanceof X509Algorithm algorithm)) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm());
		}

		final Builder builder = new Builder(definition).id(id).status(KeyStatus.ENABLED);
		final Instant notBefore = Objects.requireNonNull(builder.createdAt(), "Key creation time can't be null");
		final Instant expiresAt = builder.expiresAt();
		final Instant notAfter = expiresAt == null ? notBefore.plus(X509Utils.DEFAULT_CERTIFICATE_VALIDITY) : expiresAt;

		try {
			final KeyPair pair = algorithm.keyPairGenerator(X509Utils.random()).generateKeyPair();
			final X509Certificate certificate = X509Utils.issueSelfSignedCertificate(
				subject, pair, algorithm, notBefore, notAfter);

			return builder.material(pair.getPrivate(), List.of(certificate))
				.initializedAt(Instant.now())
				.build();
		} catch (GeneralSecurityException | IOException | OperatorCreationException ex) {
			throw new CryptoException.KeysetException(algorithm.name(),
				"Failed to create X509 key with id '" + id + "'", ex);
		}
	}

	static final class Builder extends AbstractKey.Builder<X509Algorithm, X509Key, Builder> {

		private @Nullable PrivateKey privateKey;
		private @Nullable List<X509Certificate> certificateChain;

		Builder() {
			super();
		}

		Builder(KeyDefinition definition) {
			super(definition);
		}

		Builder(X509Key key) {
			super(key);
			this.privateKey = key.privateKey;
			this.certificateChain = key.certificateChain;
		}

		Builder material(PrivateKey privateKey, List<X509Certificate> certificateChain) {
			this.privateKey = privateKey;
			this.certificateChain = certificateChain;
			return self();
		}

		@Nullable
		Instant createdAt() {
			return createdAt;
		}

		@Nullable
		Instant expiresAt() {
			return expiresAt;
		}

		@Override
		public X509Key build() {
			final UUID uuid = parseIdentifier(id);
			Assert.notNull(privateKey, "X509 private key can't be null");
			Assert.notEmpty(certificateChain, "X509 certificate chain can't be empty");
			Assert.noNullElements(certificateChain, "X509 certificate chain can't contain null certificates");
			Assert.isTrue(privateKey.getAlgorithm().equals(certificateChain.getFirst().getPublicKey().getAlgorithm()),
				"X509 private key algorithm does not match the algorithm of the certificate public key");
			this.certificateChain = List.copyOf(certificateChain);
			return new X509Key(uuid, this);
		}

		/**
		 * Key identifiers must be UUIDs in their canonical form, as they are written as UUID bits in the
		 * header of ciphertexts and signatures and are resolved back to the canonical form when parsed.
		 */
		private static UUID parseIdentifier(@Nullable String id) {
			Assert.hasText(id, "X509 key identifier can't be blank");

			final UUID uuid;

			try {
				uuid = UUID.fromString(id);
			} catch (IllegalArgumentException ex) {
				throw new IllegalArgumentException("X509 key identifier must be a UUID, got: " + id, ex);
			}

			Assert.isTrue(uuid.toString().equals(id), () -> "X509 key identifier must be a UUID in its "
				+ "canonical lower case form, got: " + id);
			return uuid;
		}

	}
}
