package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.AbstractKeyset;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetOperation;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.time.Instant;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Implementation of the {@link Keyset} that manages {@link X509Key X.509 keys} and performs the
 * cryptographic operations using the default JCA providers.
 * <p>
 * Signing keysets use the {@link X509Algorithm#signatureAlgorithm() signature algorithm} of the key.
 * Encryption keysets use RSA-OAEP with SHA-256 and MGF1 with SHA-256, where the optional context is
 * used as the OAEP label. As RSA-OAEP encrypts a single block, the size of the data that can be
 * encrypted is limited by the key size, for example {@literal 318} bytes for 3072-bit keys. This
 * keyset is therefore intended for key transport, not for the encryption of arbitrary application data.
 * <p>
 * Ciphertexts and signatures are prefixed with the {@link java.util.UUID} identifier of the key that
 * produced them, so they remain verifiable or decryptable after the keyset is rotated. The identifier is
 * written as its most and least significant bits, in big-endian byte order:
 * <pre>
 * [ 0x01 version ][ 16 bytes key identifier UUID ][ ciphertext | signature ]
 * </pre>
 *
 * @author Vladimir Spasic
 * @since 1.1.0
 */
@NullMarked
final class X509Keyset extends AbstractKeyset<X509Key> implements X509MaterialSelector {

	private static final byte FORMAT_VERSION = 0x01;

	// version byte followed by the most and least significant bits of the key identifier UUID
	private static final int HEADER_LENGTH = 1 + 2 * Long.BYTES;

	// "ECB" is a JCA naming artifact: RSA encrypts a single block, no block cipher mode is involved
	private static final String OAEP_TRANSFORMATION = "RSA/ECB/OAEPPadding";

	private static final int OAEP_HASH_LENGTH = 32;

	// primary key first, followed by the remaining keys from the most recently created one
	private static final Comparator<X509Key> SELECTION_ORDER = Comparator.comparing((X509Key key) -> !key.isPrimary())
		.thenComparing(X509Key::getCreatedAt, Comparator.reverseOrder())
		.thenComparing(X509Key::getId);

	private X509Keyset(Builder builder) {
		super(builder);
	}

	@Override
	public ByteArray encrypt(ByteArray data, @Nullable ByteArray context) {
		Assert.isTrue(!data.isEmpty(), "Cannot encrypt an empty byte array");
		assertKeysetOperation(KeysetOperation.ENCRYPT);

		final X509Key key = requireActivePrimary();
		final int limit = maximumPlaintextSize(key);

		Assert.isTrue(data.size() <= limit, () -> "Cannot encrypt more than " + limit
			+ " bytes with RSA-OAEP and a " + key.getAlgorithm().keySize() + "-bit key, got: " + data.size());

		try {
			final Cipher cipher = Cipher.getInstance(OAEP_TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey(), oaep(context), X509Utils.random());

			return prefix(key, cipher.doFinal(data.array()));
		} catch (GeneralSecurityException ex) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.ENCRYPT, ex);
		}
	}

	@Override
	public ByteArray decrypt(ByteArray cipher, @Nullable ByteArray context) {
		Assert.isTrue(!cipher.isEmpty(), "Cannot decrypt an empty byte array");
		assertKeysetOperation(KeysetOperation.DECRYPT);

		final Prefixed prefixed = parse(cipher).orElseThrow(() -> new CryptoException.KeysetOperationException(
			name, KeysetOperation.DECRYPT, "Invalid cipher text format"));

		final X509Key key = resolveKey(prefixed).orElseThrow(() -> new CryptoException.KeysetOperationException(
			name, KeysetOperation.DECRYPT, "No key found for the cipher text"));

		try {
			final Cipher decrypter = Cipher.getInstance(OAEP_TRANSFORMATION);
			decrypter.init(Cipher.DECRYPT_MODE, key.privateKey(), oaep(context));

			return new ByteArray(decrypter.doFinal(prefixed.payload()));
		} catch (GeneralSecurityException ex) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.DECRYPT, ex);
		}
	}

	@Override
	public ByteArray sign(ByteArray data) {
		Assert.isTrue(!data.isEmpty(), "Cannot sign an empty byte array");
		assertKeysetOperation(KeysetOperation.SIGN);

		final X509Key key = requireActivePrimary();

		try {
			final Signature signature = Signature.getInstance(key.getAlgorithm().signatureAlgorithm());
			signature.initSign(key.privateKey(), X509Utils.random());
			signature.update(data.array());

			return prefix(key, signature.sign());
		} catch (GeneralSecurityException ex) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.SIGN, ex);
		}
	}

	@Override
	public boolean verify(ByteArray signature, ByteArray data) {
		Assert.isTrue(!signature.isEmpty(), "Cannot verify an empty signature");
		Assert.isTrue(!data.isEmpty(), "Cannot verify a signature against an empty byte array");
		assertKeysetOperation(KeysetOperation.VERIFY);

		final Optional<Prefixed> prefixed = parse(signature);
		final Optional<X509Key> key = prefixed.flatMap(this::resolveKey);

		// malformed signatures, or signatures referencing an unknown key, are simply not valid
		if (prefixed.isEmpty() || key.isEmpty()) {
			return false;
		}

		try {
			final Signature verifier = Signature.getInstance(key.get().getAlgorithm().signatureAlgorithm());
			verifier.initVerify(key.get().getPublicKey());
			verifier.update(data.array());

			return verifier.verify(prefixed.get().payload());
		} catch (SignatureException ex) {
			return false;
		} catch (GeneralSecurityException ex) {
			throw new CryptoException.KeysetOperationException(name, KeysetOperation.VERIFY, ex);
		}
	}

	@Override
	public List<X509Material> select(X509Matcher matcher) {
		Assert.notNull(matcher, "X509 matcher can't be null");

		return stream()
			.map(X509Key.class::cast)
			.filter(AbstractKeyset::isReadable)
			.filter(matcher::matches)
			.sorted(SELECTION_ORDER)
			.map(X509Material.class::cast)
			.toList();
	}

	@Override
	protected String generateId() {
		return X509Utils.generateKeyId();
	}

	@Override
	protected Keyset doRotate(KeyDefinition definition, String uniqueId) {
		final Instant notAfter = X509Utils.certificateNotAfter(resolveCertificateActivatesAt(definition),
			definition.getRotationInterval().orElse(null), destructionGracePeriod);

		final Builder builder = new Builder(this)
			.key(X509Key.generate(definition, uniqueId, name, notAfter));

		stream().map(X509Key.class::cast).forEach(existing -> {
			if (existing.isPrimary() && definition.isPrimary()) {
				builder.key(demote(existing, new X509Key.Builder(existing)).build());
			} else {
				builder.key(existing);
			}
		});

		return builder.build();
	}

	@Override
	protected Keyset doPromote(X509Key key, @Nullable Instant expiresAt) {
		final Builder builder = new Builder(this);

		stream().map(X509Key.class::cast).forEach(existing -> {
			if (existing.getId().equals(key.getId())) {
				builder.key(new X509Key.Builder(existing).promote(resolveCertificateExpiration(key, expiresAt)).build());
			} else if (existing.isPrimary()) {
				builder.key(demote(existing, new X509Key.Builder(existing)).build());
			} else {
				builder.key(existing);
			}
		});

		return builder.build();
	}

	/**
	 * Resolves the time when a key generated from the given definition becomes the primary key. A primary
	 * key becomes the primary key right away, while the next key takes over once the current primary key
	 * expires, or right away when the current primary key does not expire or has already expired.
	 */
	private Instant resolveCertificateActivatesAt(KeyDefinition definition) {
		final Instant now = Instant.now();

		if (definition.isPrimary()) {
			return now;
		}

		final Instant primaryExpiresAt = getPrimary().getExpiresAt();
		return primaryExpiresAt == null || primaryExpiresAt.isBefore(now) ? now : primaryExpiresAt;
	}

	/**
	 * Caps the expiration time of a promoted key, so that the key, including the destruction grace period
	 * during which it is retired afterward, never outlives its certificate. This is the case when the key is
	 * promoted later than planned, for instance, when the scheduled maintenance tasks could not run in time.
	 */
	private @Nullable Instant resolveCertificateExpiration(X509Key key, @Nullable Instant expiresAt) {
		if (expiresAt == null) {
			return null;
		}

		final Instant latest = X509Utils.latestExpiration(key.getCertificate().getNotAfter().toInstant(),
			destructionGracePeriod);

		return expiresAt.isAfter(latest) ? latest : expiresAt;
	}

	/**
	 * Resolves the key that produced the cipher text or signature. Only enabled and retired keys are used
	 * to decrypt or verify, a key in any other status fails with a status-specific exception.
	 */
	private Optional<X509Key> resolveKey(Prefixed prefixed) {
		return getKey(prefixed.keyId())
			.map(X509Key.class::cast)
			.map(this::requireReadableKey);
	}

	private void assertKeysetOperation(KeysetOperation operation) {
		if (!purpose.isOperationSupported(operation)) {
			throw new CryptoException.UnsupportedKeysetOperationException(name, operation, purpose.operations());
		}
	}

	private static int maximumPlaintextSize(X509Key key) {
		return key.getAlgorithm().keySize() / Byte.SIZE - 2 * OAEP_HASH_LENGTH - 2;
	}

	private static OAEPParameterSpec oaep(@Nullable ByteArray context) {
		final PSource source = context == null || context.isEmpty()
			? PSource.PSpecified.DEFAULT
			: new PSource.PSpecified(context.array());

		return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, source);
	}

	private static ByteArray prefix(X509Key key, byte[] payload) {
		final UUID id = key.uuid();

		return new ByteArray(ByteBuffer.allocate(HEADER_LENGTH + payload.length)
			.put(FORMAT_VERSION)
			.putLong(id.getMostSignificantBits())
			.putLong(id.getLeastSignificantBits())
			.put(payload)
			.array());
	}

	private static Optional<Prefixed> parse(ByteArray value) {
		final ByteBuffer buffer = ByteBuffer.wrap(value.array());

		if (buffer.remaining() <= HEADER_LENGTH || buffer.get() != FORMAT_VERSION) {
			return Optional.empty();
		}

		final UUID keyId = new UUID(buffer.getLong(), buffer.getLong());
		final byte[] payload = new byte[buffer.remaining()];
		buffer.get(payload);

		return Optional.of(new Prefixed(keyId.toString(), payload));
	}

	private record Prefixed(String keyId, byte[] payload) {
	}

	static final class Builder extends AbstractKeyset.Builder<X509Key, X509Keyset, Builder> {

		Builder(KeysetDefinition definition) {
			super(definition);
		}

		Builder(X509Keyset keyset) {
			super(keyset);
		}

		Builder(EncryptedKeyset keyset) {
			super(keyset);
		}

		@Override
		public X509Keyset build() {
			return new X509Keyset(this);
		}

	}
}
