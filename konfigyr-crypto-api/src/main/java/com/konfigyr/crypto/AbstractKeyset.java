package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Abstract base implementation of the {@link Keyset} interface that provides common
 * functionality for managing cryptographic keysets (Data Encryption Keys).
 * <p>
 * This class implements the core metadata management aspects of a {@link Keyset}, including:
 * <ul>
 *     <li>Keyset identification via {@link #name}</li>
 *     <li>Factory association via {@link #factory}</li>
 *     <li>Cryptographic purpose definition via {@link #purpose}</li>
 *     <li>Key encryption key management via {@link #keyEncryptionKey}</li>
 *     <li>Automatic rotation scheduling via {@link #rotationInterval}</li>
 *     <li>Key destruction safety period via {@link #destructionGracePeriod}</li>
 * </ul>
 * <p>
 * Concrete implementations must provide:
 * <ul>
 *     <li>The collection of cryptographic keys via {@link #getKeys()}</li>
 *     <li>Primary key selection logic via {@link #getPrimary()}</li>
 *     <li>Key rotation implementation via {@link #rotate()}</li>
 *     <li>Cryptographic operations (encrypt, decrypt, sign, verify) as appropriate for the {@link KeysetPurpose}</li>
 * </ul>
 * <p>
 * <b>Thread Safety:</b> Implementations should be immutable and thread-safe.
 * <p>
 * <b>Security Considerations:</b>
 * <ul>
 *     <li>Rotation intervals should not exceed 365 days for compliance with NIST SP 800-57</li>
 *     <li>Destruction grace periods should be between 7 and 120 days for audit compliance</li>
 *     <li>All key material must be encrypted using the provided {@link KeyEncryptionKey}</li>
 * </ul>
 *
 * @param <T> the type of {@link Key} managed by this keyset
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Keyset
 * @see Key
 * @see KeysetFactory
 */
@NullMarked
public abstract class AbstractKeyset<T extends Key> implements Keyset {

	/**
	 * Unique identifier for this keyset. Used for lookup and audit logging.
	 */
	protected final String name;

	/**
	 * Name of the {@link KeysetFactory} responsible for creating and managing this keyset.
	 */
	protected final String factory;

	/**
	 * The cryptographic purpose (e.g., ENCRYPTION, SIGNING) that determines which operations
	 * this keyset supports.
	 */
	protected final KeysetPurpose purpose;

	/**
	 * The Key Encryption Key (KEK) used to encrypt the keyset metadata and key material.
	 * This provides an additional layer of security for key storage and transmission.
	 */
	protected final KeyEncryptionKey keyEncryptionKey;

	/**
	 * The collection of cryptographic keys managed by this keyset.
	 */
	protected final List<T> keys;

	/**
	 * The interval at which key material should be automatically rotated to mitigate
	 * cryptographic wear-out. May be {@literal null} if automatic rotation is disabled.
	 */
	protected final @Nullable Duration rotationInterval;

	/**
	 * How long before the scheduled rotation of the primary key the next key should be created.
	 * May be {@literal null} if the next key is created at the moment of rotation.
	 */
	protected final @Nullable Duration rotationLeadTime;

	/**
	 * The grace period before a key marked for destruction is permanently deleted.
	 * This provides a safety buffer for recovering from accidental deletions.
	 * May be {@literal null} if immediate destruction is configured.
	 */
	protected final @Nullable Duration destructionGracePeriod;

	/**
	 * The optimistic-locking version of this keyset as it was last read from the
	 * {@link KeysetRepository}. Zero for keysets that have not yet been persisted.
	 */
	protected final long version;

	/**
	 * Constructs a new {@link AbstractKeyset} with the specified configuration.
	 *
	 * @param builder the builder containing all keyset configuration parameters, can't be {@literal null}
	 */
	protected AbstractKeyset(Builder<T, ?, ?> builder) {
		Assert.hasText(builder.name, "Keyset name can't be blank");
		Assert.notNull(builder.factory, "Keyset factory can't be null");
		Assert.notNull(builder.purpose, "Keyset purpose can't be null");
		Assert.notNull(builder.kek, "Keyset key encryption key can't be null");
		Assert.notNull(builder.keys, "Keyset keys can't be null");
		Assert.isTrue(!builder.keys.isEmpty(), "Keyset must have at least one key");

		this.name = builder.name;
		this.factory = builder.factory;
		this.purpose = builder.purpose;
		this.keyEncryptionKey = builder.kek;
		this.keys = Collections.unmodifiableList(builder.keys);
		this.rotationInterval = builder.rotationInterval;
		this.rotationLeadTime = builder.rotationLeadTime;
		this.destructionGracePeriod = builder.destructionGracePeriod;
		this.version = builder.version;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public long getVersion() {
		return version;
	}

	@Override
	public String getFactory() {
		return factory;
	}

	@Override
	public KeysetPurpose getPurpose() {
		return purpose;
	}

	@Override
	public KeyEncryptionKey getKeyEncryptionKey() {
		return keyEncryptionKey;
	}

	@Override
	public List<T> getKeys() {
		return keys;
	}

	@Override
	public Key getPrimary() {
		return keys.stream()
			.filter(Key::isPrimary)
			.findFirst()
			.orElseThrow(() -> new CryptoException.KeysetException(
				name, "Keyset '" + name + "' has no primary key."
			));
	}

	/**
	 * Returns the primary {@link Key} of this keyset, asserting that it is in an operational
	 * state (i.e., its {@link KeyStatus} is {@link KeyStatus#ENABLED}).
	 * <p>
	 * This method is intended for use by cryptographic write operations ({@code encrypt},
	 * {@code sign}) that must use the primary key. It follows the same principle as major
	 * KMS providers (AWS, GCP, HashiCorp Vault): key metadata is always readable, but
	 * cryptographic operations are gated by key state.
	 * <p>
	 * For key inspection or rotation logic, use {@link #getPrimary()} instead.
	 *
	 * @return the primary key, never {@literal null}
	 * @throws CryptoException.KeysetCompromisedException       if the primary key status is {@link KeyStatus#COMPROMISED}
	 *                                                          or {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION}
	 * @throws CryptoException.KeysetDisabledException          if the primary key status is {@link KeyStatus#DISABLED}
	 * @throws CryptoException.KeysetPendingDestructionException if the primary key status is {@link KeyStatus#PENDING_DESTRUCTION}
	 * @throws CryptoException.KeysetDestroyedException         if the primary key status is {@link KeyStatus#DESTROYED}
	 * @throws CryptoException.KeysetUnavailableException       if the primary key status is {@link KeyStatus#INITIALIZING},
	 *                                                          {@link KeyStatus#INITIALIZATION_FAILED} or
	 *                                                          {@link KeyStatus#DESTRUCTION_FAILED}
	 * @see #requireUsableKey(Key)
	 */
	@SuppressWarnings("unchecked")
	protected final T requireActivePrimary() {
		return requireUsableKey((T) getPrimary());
	}

	/**
	 * Looks up the {@link Key} with the given identifier within this keyset and asserts that it can
	 * be used for cryptographic operations.
	 * <p>
	 * This method is intended for cryptographic read operations ({@code decrypt}, {@code verify})
	 * where the key is resolved from the identifier carried by the ciphertext or signature.
	 *
	 * @param keyId the identifier of the key to resolve, can't be {@literal null}
	 * @return the usable key, never {@literal null}
	 * @throws CryptoException.KeyNotFoundException if no key with the given identifier exists in this keyset
	 * @throws CryptoException.KeysetException      if the key is not usable, see {@link #requireUsableKey(Key)}
	 */
	protected final T requireUsableKey(String keyId) {
		final T key = getKey(keyId).orElseThrow(() -> new CryptoException.KeyNotFoundException(name, keyId));
		return requireUsableKey(key);
	}

	/**
	 * Asserts that the given {@link Key} is in a state where it can be used for cryptographic
	 * operations, as defined by {@link Key#isEnabled()}.
	 * <p>
	 * This method is the guard that every cryptographic operation must pass before key material
	 * is used, both write operations ({@code encrypt}, {@code sign}) and read operations
	 * ({@code decrypt}, {@code verify}). It deliberately evaluates the {@link KeyStatus} directly,
	 * instead of relying on {@link Key#isEnabled()}, so that a {@link Key} implementation can't
	 * weaken it and each blocked status results in its own exception type.
	 * <p>
	 * Exception messages only contain the keyset name, key identifier and status, never key material.
	 *
	 * @param key the key to check, can't be {@literal null}
	 * @return the same key when it is usable, never {@literal null}
	 * @throws CryptoException.KeysetCompromisedException       if the key status is {@link KeyStatus#COMPROMISED}
	 *                                                          or {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION}
	 * @throws CryptoException.KeysetDisabledException          if the key status is {@link KeyStatus#DISABLED}
	 * @throws CryptoException.KeysetPendingDestructionException if the key status is {@link KeyStatus#PENDING_DESTRUCTION}
	 * @throws CryptoException.KeysetDestroyedException         if the key status is {@link KeyStatus#DESTROYED}
	 * @throws CryptoException.KeysetUnavailableException       if the key status is {@link KeyStatus#INITIALIZING},
	 *                                                          {@link KeyStatus#INITIALIZATION_FAILED} or
	 *                                                          {@link KeyStatus#DESTRUCTION_FAILED}
	 */
	protected final T requireUsableKey(T key) {
		// exhaustive switch without a default branch, new statuses must be explicitly handled here
		return switch (key.getStatus()) {
			case ENABLED -> key;
			case COMPROMISED, COMPROMISED_PENDING_DESTRUCTION -> throw new CryptoException.KeysetCompromisedException(name, key);
			case DISABLED -> throw new CryptoException.KeysetDisabledException(name, key);
			case PENDING_DESTRUCTION -> throw new CryptoException.KeysetPendingDestructionException(name, key);
			case DESTROYED -> throw new CryptoException.KeysetDestroyedException(name, key);
			case INITIALIZING, INITIALIZATION_FAILED, DESTRUCTION_FAILED ->
				throw new CryptoException.KeysetUnavailableException(name, key);
		};
	}

	@Override
	public Optional<? extends T> getKey(String id) {
		return keys.stream().filter(key -> Objects.equals(key.getId(), id)).findFirst();
	}

	@Override
	public Optional<@Nullable Duration> getRotationInterval() {
		return Optional.ofNullable(rotationInterval);
	}

	@Override
	public Optional<@Nullable Duration> getRotationLeadTime() {
		return Optional.ofNullable(rotationLeadTime);
	}

	@Override
	public Optional<@Nullable Duration> getDestructionGracePeriod() {
		return Optional.ofNullable(destructionGracePeriod);
	}

	/**
	 * Generates a candidate key identifier using this implementation's ID scheme. The
	 * returned value is not guaranteed to be unique within the keyset, use the
	 * {@link #generateUniqueId} method which calls this in a retry loop guarded by
	 * {@link #isUniqueId(String)}.
	 * <p>
	 * Implementations must use a cryptographically strong random source. For example,
	 * Tink-backed keysets return a random 32-bit integer string; JOSE-backed keysets
	 * return a random UUID string.
	 *
	 * @return candidate key identifier, never {@literal null}
	 */
	protected abstract String generateId();

	/**
	 * Returns {@literal true} if {@code id} is not already used by any key currently
	 * in this keyset.
	 * <p>
	 * Subclasses may override to enforce additional format or range constraints beyond
	 * simple collision detection.
	 *
	 * @param id candidate identifier to check, can't be {@literal null}
	 * @return {@literal true} if the identifier is available
	 */
	protected boolean isUniqueId(String id) {
		return keys.stream().noneMatch(key -> key.getId().equals(id));
	}

	/**
	 * Generates a guaranteed unique identifier within this keyset by repeatedly
	 * calling {@link #generateId()} until {@link #isUniqueId(String)} returns
	 * {@literal true}.
	 */
	private String generateUniqueId() {
		String id;
		do {
			id = generateId();
		} while (!isUniqueId(id));
		return id;
	}

	/**
	 * Rotates the primary key of this keyset, or adds a new non-primary key when
	 * {@link KeyDefinition#isPrimary()} is {@literal false}.
	 * <p>
	 * When a primary key is requested and this keyset contains a {@link #findNextKey() next key}, the next
	 * key is promoted to be the primary key instead of generating a new one. The next key was created
	 * ahead of the rotation, as defined by the {@link #getRotationLeadTime() rotation lead time}, so third
	 * parties that cache the public key material could already obtain it. The promoted key expires after
	 * the {@link KeyDefinition#getRotationInterval() rotation interval} of the given definition, counted
	 * from the moment of promotion.
	 * <p>
	 * A new primary key is generated instead when:
	 * <ul>
	 *     <li>there is no next key,</li>
	 *     <li>the current primary key is not {@link KeyStatus#ENABLED}, for instance when it was compromised,
	 *     as the next key may have been exposed as well,</li>
	 *     <li>the next key uses a different {@link Algorithm} than the requested one.</li>
	 * </ul>
	 *
	 * @param definition parameters for the new key, can't be {@literal null}
	 * @return new keyset with the rotated keys, never {@literal null}
	 * @throws CryptoException.UnsupportedAlgorithmException when the definition's
	 *         algorithm purpose does not match this keyset's purpose
	 */
	@Override
	public final Keyset rotate(KeyDefinition definition) {
		if (purpose != definition.getAlgorithm().purpose()) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm());
		}

		if (definition.isPrimary()) {
			final Optional<T> next = findNextKey();

			if (next.isPresent() && isPromotable(next.get(), definition)) {
				final Instant expiresAt = definition.getRotationInterval()
					.map(Instant.now()::plus)
					.orElse(null);

				return doPromote(next.get(), expiresAt);
			}
		}

		return doRotate(definition, generateUniqueId());
	}

	/**
	 * Attempts to find the next key of this keyset, the key that would be promoted to be the primary key on
	 * the next {@link #rotate(KeyDefinition) rotation}.
	 * <p>
	 * The next key is a non-primary {@link KeyStatus#ENABLED} key that was created after the current primary
	 * key. Previous primary keys were all created before the current one, so they never match. When more than
	 * one key matches, which may happen when non-primary keys are added manually, the most recently created
	 * key is returned.
	 *
	 * @return the next key, or empty when there is none, never {@literal null}
	 */
	protected final Optional<T> findNextKey() {
		final Optional<T> primary = keys.stream().filter(Key::isPrimary).findFirst();

		if (primary.isEmpty()) {
			return Optional.empty();
		}

		final Instant primaryCreatedAt = primary.get().getCreatedAt();

		return keys.stream()
			.filter(key -> !key.isPrimary())
			.filter(key -> key.getStatus() == KeyStatus.ENABLED)
			.filter(key -> key.getCreatedAt().isAfter(primaryCreatedAt))
			.max(Comparator.comparing(Key::getCreatedAt).thenComparing(Key::getId));
	}

	private boolean isPromotable(T next, KeyDefinition definition) {
		return getPrimary().isEnabled() && next.isUsing(definition.getAlgorithm());
	}

	/**
	 * Performs the actual key rotation using a pre-validated, unique identifier.
	 * <p>
	 * Implementations should create a new key from the given {@link KeyDefinition} using
	 * {@code uniqueId} as the key identifier, promote it to primary (if
	 * {@link KeyDefinition#isPrimary()} is {@literal true}), demote or retain the
	 * existing keys as appropriate, and return a new keyset containing the updated key set.
	 *
	 * @param definition the parameters for the new key, can't be {@literal null}
	 * @param uniqueId   a key identifier guaranteed not to clash with any existing
	 *                   key in this keyset, can't be {@literal null}
	 * @return new keyset with the rotated keys, never {@literal null}
	 */
	protected abstract Keyset doRotate(KeyDefinition definition, String uniqueId);

	/**
	 * Promotes the given existing key to be the primary key of this keyset.
	 * <p>
	 * Implementations should make the given key the primary key, with the given expiration time, demote the
	 * current primary key exactly like {@link #doRotate(KeyDefinition, String)} does, retain all other keys,
	 * and return a new keyset containing the updated key set.
	 * <p>
	 * Implementations do not need to validate the key, it is selected by {@link #findNextKey()} and checked
	 * by the caller ({@link #rotate(KeyDefinition)}).
	 *
	 * @param key       the key of this keyset that should become the primary key, can't be {@literal null}
	 * @param expiresAt the new expiration time of the promoted key, can be {@literal null} when automatic
	 *                  key rotation is disabled
	 * @return new keyset with the promoted key, never {@literal null}
	 * @since 1.1.0
	 */
	protected abstract Keyset doPromote(T key, @Nullable Instant expiresAt);

	@Override
	public final boolean equals(Object object) {
		if (!(object instanceof AbstractKeyset<?> that)) return false;
		return Objects.equals(name, that.name)
			&& Objects.equals(factory, that.factory)
			&& Objects.equals(purpose, that.purpose)
			&& Objects.equals(keyEncryptionKey, that.keyEncryptionKey)
			&& Objects.equals(keys, that.keys)
			&& Objects.equals(rotationInterval, that.rotationInterval)
			&& Objects.equals(rotationLeadTime, that.rotationLeadTime)
			&& Objects.equals(destructionGracePeriod, that.destructionGracePeriod);
	}

	@Override
	public int hashCode() {
		int result = Objects.hashCode(name);
		result = 31 * result + Objects.hashCode(factory);
		result = 31 * result + Objects.hashCode(purpose);
		result = 31 * result + Objects.hashCode(keyEncryptionKey);
		result = 31 * result + Objects.hashCode(keys);
		result = 31 * result + Objects.hashCode(rotationInterval);
		result = 31 * result + Objects.hashCode(rotationLeadTime);
		result = 31 * result + Objects.hashCode(destructionGracePeriod);
		return result;
	}

	@Override
	public String toString() {
		return new StringJoiner(", ", getClass().getSimpleName() + "(", ")")
			.add("name='" + name + "'")
			.add("factory=" + factory)
			.add("purpose=" + purpose)
			.add("kek=" + KeyEncryptionKey.format(keyEncryptionKey))
			.add("keys=" + keys)
			.add("rotationInterval=" + rotationInterval)
			.add("rotationLeadTime=" + rotationLeadTime)
			.add("destructionGracePeriod=" + destructionGracePeriod)
			.toString();
	}

	/**
	 * Abstract builder for constructing {@link AbstractKeyset} instances.
	 * <p>
	 * This builder provides a fluent API for configuring keyset metadata and lifecycle policies.
	 * Concrete implementations should extend this builder to add keyset-specific configuration.
	 * <p>
	 * <b>Usage Example:</b>
	 * <pre>{@code
	 * MyKeyset keyset = MyKeyset.builder()
	 *     .name("my-encryption-keyset")
	 *     .factory("aws-kms")
	 *     .purpose(KeysetPurpose.ENCRYPTION)
	 *     .kek(myKek)
	 *     .rotationInterval(Duration.ofDays(90))
	 *     .destructionGracePeriod(Duration.ofDays(30))
	 *     .build();
	 * }</pre>
	 *
	 * @param <T> the type of {@link Key} managed by this keyset
	 * @param <K> the concrete keyset type for fluent chaining
	 * @param <B> the concrete builder type for fluent chaining
	 */
	@NullMarked
	public abstract static class Builder<T extends Key, K extends AbstractKeyset<T>, B extends Builder<T, K, B>> {

		private @Nullable String name;
		private @Nullable String factory;
		private @Nullable KeysetPurpose purpose;
		private @Nullable KeyEncryptionKey kek;
		private @Nullable Duration rotationInterval;
		private @Nullable Duration rotationLeadTime;
		private @Nullable Duration destructionGracePeriod;
		private long version = 0L;
		private final List<T> keys;

		/**
		 * Creates a new empty builder instance.
		 */
		protected Builder() {
			keys = new ArrayList<>();
		}

		/**
		 * Creates a new builder instance pre-populated from the given {@link KeysetDefinition}.
		 *
		 * @param definition the keyset definition to copy values from, can't be {@literal null}
		 */
		protected Builder(KeysetDefinition definition) {
			name = definition.getName();
			factory = definition.getAlgorithm().factory();
			purpose = definition.getPurpose();
			rotationInterval = definition.getRotationInterval().orElse(null);
			rotationLeadTime = definition.getRotationLeadTime().orElse(null);
			destructionGracePeriod = definition.getDestructionGracePeriod().orElse(null);
			keys = new ArrayList<>();
		}

		/**
		 * Creates a new builder instance pre-populated from an existing {@link Keyset}.
		 *
		 * @param keyset the existing keyset to copy values from, can't be {@literal null}
		 */
		protected Builder(K keyset) {
			name = keyset.getName();
			factory = keyset.getFactory();
			purpose = keyset.getPurpose();
			kek = keyset.getKeyEncryptionKey();
			rotationInterval = keyset.getRotationInterval().orElse(null);
			rotationLeadTime = keyset.getRotationLeadTime().orElse(null);
			destructionGracePeriod = keyset.getDestructionGracePeriod().orElse(null);
			version = keyset.getVersion();
			keys = new ArrayList<>(keyset.size());
		}

		/**
		 * Creates a new builder instance pre-populated from an existing {@link EncryptedKeyset}.
		 *
		 * @param keyset the encrypted keyset to copy metadata from, can't be {@literal null}
		 */
		protected Builder(EncryptedKeyset keyset) {
			name = keyset.name();
			factory = keyset.factory();
			purpose = KeysetPurpose.valueOf(keyset.purpose());
			rotationInterval = keyset.rotationInterval();
			rotationLeadTime = keyset.rotationLeadTime();
			destructionGracePeriod = keyset.destructionGracePeriod();
			version = keyset.version();
			keys = new ArrayList<>(keyset.size());
		}

		/**
		 * Sets the unique name for the keyset.
		 *
		 * @param name the keyset identifier, can't be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B name(String name) {
			this.name = name;
			return self();
		}

		/**
		 * Sets the factory name responsible for creating this keyset.
		 *
		 * @param factory the factory identifier, can't be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B factory(String factory) {
			this.factory = factory;
			return self();
		}

		/**
		 * Sets the cryptographic purpose for this keyset.
		 *
		 * @param purpose the keyset purpose (e.g., ENCRYPTION, SIGNING), can't be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B purpose(KeysetPurpose purpose) {
			this.purpose = purpose;
			return self();
		}

		/**
		 * Sets the Key Encryption Key (KEK) used to protect this keyset.
		 *
		 * @param kek the key encryption key, can't be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B keyEncryptionKey(KeyEncryptionKey kek) {
			this.kek = kek;
			return self();
		}

		/**
		 * Adds a single cryptographic key to this keyset.
		 * <p>
		 * Keys are added in the order specified, which may affect primary key selection
		 * in concrete implementations.
		 *
		 * @param key the key to add, can't be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B key(T key) {
			Assert.notNull(key, "Key can't be null");
			Assert.isTrue(
				keys.stream().noneMatch(k -> k.getId().equals(key.getId())),
				() -> "Key with id '" + key.getId() + "' already exists in this keyset"
			);
			this.keys.add(key);
			return self();
		}

		/**
		 * Sets the complete collection of cryptographic keys for this keyset.
		 * <p>
		 * This method replaces any previously added keys. To add keys incrementally,
		 * use {@link #key(Key)} instead.
		 *
		 * @param keys the collection of keys to set, can't be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B keys(Iterable<? extends T> keys) {
			Assert.notNull(keys, "Keys can't be null");
			this.keys.clear();
			keys.forEach(this::key);
			return self();
		}

		/**
		 * Sets the automatic rotation interval for key material.
		 * <p>
		 * <b>Security Note:</b> Values greater than 365 days may violate compliance requirements.
		 *
		 * @param rotationInterval the duration between automatic key rotations, can be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B rotationInterval(@Nullable Duration rotationInterval) {
			this.rotationInterval = rotationInterval;
			return self();
		}

		/**
		 * Sets how long before the scheduled rotation of the primary key the next key should be created.
		 *
		 * @param rotationLeadTime the duration before the scheduled rotation, can be {@literal null}
		 * @return this builder instance for method chaining
		 * @since 1.1.0
		 */
		public B rotationLeadTime(@Nullable Duration rotationLeadTime) {
			this.rotationLeadTime = rotationLeadTime;
			return self();
		}

		/**
		 * Sets the grace period before key material is permanently destroyed.
		 * <p>
		 * <b>Security Note:</b> Values outside the 7-120 day range may violate compliance requirements.
		 *
		 * @param destructionGracePeriod the safety buffer duration, can be {@literal null}
		 * @return this builder instance for method chaining
		 */
		public B destructionGracePeriod(@Nullable Duration destructionGracePeriod) {
			this.destructionGracePeriod = destructionGracePeriod;
			return self();
		}

		/**
		 * Sets the optimistic-locking version for this keyset.
		 *
		 * @param version non-negative version counter
		 * @return this builder instance for method chaining
		 */
		public B version(long version) {
			this.version = version;
			return self();
		}

		/**
		 * Returns this builder instance cast to the concrete builder type.
		 * <p>
		 * This method enables fluent method chaining in subclasses by returning the
		 * actual builder type rather than the abstract base type.
		 *
		 * @return this builder instance as type {@code B}
		 */
		@SuppressWarnings("unchecked")
		protected B self() {
			return (B) this;
		}

		/**
		 * Constructs the keyset instance from this builder's configuration.
		 * <p>
		 * Implementations should validate all required fields and throw appropriate
		 * exceptions if the configuration is invalid.
		 *
		 * @return the constructed keyset instance, never {@literal null}
		 */
		public abstract K build();
	}
}
