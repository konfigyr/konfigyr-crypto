package com.konfigyr.crypto;

import lombok.Getter;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.time.Duration;
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
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see Keyset
 * @see Key
 * @see KeysetFactory
 */
@Getter
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
	 * The grace period before a key marked for destruction is permanently deleted.
	 * This provides a safety buffer for recovering from accidental deletions.
	 * May be {@literal null} if immediate destruction is configured.
	 */
	protected final @Nullable Duration destructionGracePeriod;

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
		this.destructionGracePeriod = builder.destructionGracePeriod;
	}

	@Override
	public T getPrimary() {
		return keys.stream().filter(Key::isPrimary).findFirst().orElseThrow();
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

	@Override
	public final Keyset rotate(KeyDefinition definition) {
		if (purpose != definition.getAlgorithm().purpose()) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm());
		}
		return doRotate(definition, generateUniqueId());
	}

	/**
	 * Performs the actual key rotation using a pre-validated, unique identifier.
	 * <p>
	 * Implementations should create a new key from the given {@link KeyDefinition} using
	 * {@code uniqueId} as the key identifier, promote it to primary (if
	 * {@link KeyDefinition#isPrimary()} is {@literal true}), demote or retain the
	 * existing keys as appropriate, and return a new keyset containing the updated key set.
	 * <p>
	 * Implementations do not need to check purpose compatibility or identifier uniqueness —
	 * both are guaranteed by the caller ({@link #rotate(KeyDefinition)}).
	 *
	 * @param definition the parameters for the new key, can't be {@literal null}
	 * @param uniqueId   a key identifier guaranteed not to clash with any existing
	 *                   key in this keyset, can't be {@literal null}
	 * @return new keyset with the rotated keys, never {@literal null}
	 */
	protected abstract Keyset doRotate(KeyDefinition definition, String uniqueId);

	@Override
	public final boolean equals(Object object) {
		if (!(object instanceof AbstractKeyset<?> that)) return false;
		return Objects.equals(name, that.name)
			&& Objects.equals(factory, that.factory)
			&& Objects.equals(purpose, that.purpose)
			&& Objects.equals(keyEncryptionKey, that.keyEncryptionKey)
			&& Objects.equals(keys, that.keys)
			&& Objects.equals(rotationInterval, that.rotationInterval)
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
		result = 31 * result + Objects.hashCode(destructionGracePeriod);
		return result;
	}

	@Override
	public String toString() {
		return new StringJoiner(", ", getClass().getSimpleName() + "(", ")")
			.add("name='" + name + "'")
			.add("factory=" + factory)
			.add("purpose=" + purpose)
			.add("kek=" + keyEncryptionKey)
			.add("keys=" + keys)
			.add("rotationInterval=" + rotationInterval)
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
	 * @param <B> the concrete builder type for fluent chaining
	 */
	@NullMarked
	public abstract static class Builder<T extends Key, K extends AbstractKeyset<T>, B extends Builder<T, K, B>> {

		private @Nullable String name;
		private @Nullable String factory;
		private @Nullable KeysetPurpose purpose;
		private @Nullable KeyEncryptionKey kek;
		private @Nullable Duration rotationInterval;
		private @Nullable Duration destructionGracePeriod;
		private final List<T> keys;

		protected Builder() {
			keys = new ArrayList<>();
		}

		protected Builder(KeysetDefinition definition) {
			name = definition.getName();
			factory = definition.getAlgorithm().factory();
			purpose = definition.getPurpose();
			rotationInterval = definition.getRotationInterval().orElse(null);
			destructionGracePeriod = definition.getDestructionGracePeriod().orElse(null);
			keys = new ArrayList<>();
		}

		protected Builder(K keyset) {
			name = keyset.getName();
			factory = keyset.getFactory();
			purpose = keyset.getPurpose();
			kek = keyset.getKeyEncryptionKey();
			rotationInterval = keyset.getRotationInterval().orElse(null);
			destructionGracePeriod = keyset.getDestructionGracePeriod().orElse(null);
			keys = new ArrayList<>(keyset.size());
		}

		protected Builder(EncryptedKeyset keyset) {
			name = keyset.getName();
			factory = keyset.getFactory();
			purpose = KeysetPurpose.valueOf(keyset.getPurpose());
			rotationInterval = keyset.getRotationInterval();
			destructionGracePeriod = keyset.getDestructionGracePeriod();
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
