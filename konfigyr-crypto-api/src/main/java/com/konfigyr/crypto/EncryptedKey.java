package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.io.InputStreamSource;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * The class that contains the actual encrypted key material and its attributes that is
 * derived from the {@link Key} that is part of the {@link Keyset}
 * <p>
 * Each {@link EncryptedKey} stores the per-key lifecycle metadata alongside the
 * encrypted key material ({@link #getData()}). The metadata fields (status, timestamps)
 * are stored in plaintext because they are not sensitive; only the cryptographic key
 * bytes are encrypted by the {@link KeyEncryptionKey}.
 * <p>
 * When a key is in {@link KeyStatus#DESTROYED} or {@link KeyStatus#INITIALIZING} state,
 * {@link #getData()} will be {@literal null} because the key material either has not yet
 * been generated or has been permanently erased.
 *
 * @author : Vladimir Spasic
 * @since : 15.05.26, Fri
 * @see EncryptedKeyset
 * @see Key
 **/
@Value
@NullMarked
public class EncryptedKey implements Comparable<EncryptedKey>, InputStreamSource, Serializable {

	@Serial
	private static final long serialVersionUID = -7568519341937720112L;

	/**
	 * Unique identifier of this key within the encrypted keyset.
	 */
	String id;

	/**
	 * The name of the {@link Algorithm} that defines the usage, or supported operations, of the encrypted key.
	 */
	String algorithm;

	/**
	 * Defines the {@link KeyType} of the encrypted key.
	 */
	KeyType type;

	/**
	 * Returns the status of the encrypted key.
	 */
	KeyStatus status;

	/**
	 * Returns {@literal true} if this key is the primary key within the keyset.
	 */
	boolean primary;

	/**
	 * Encrypted cryptographic key material that was wrapped by the {@link KeyEncryptionKey}.
	 */
	@Nullable
	ByteArray data;

	/**
	 * Timestamp that tells the time when this key was created.
	 */
	Instant createdAt;

	/**
	 * Timestamp when cryptographic material was initialized for this key.
	 */
	@Nullable
	Instant initializedAt;

	/**
	 * The time when this key should expire and be rotated.
	 */
	@Nullable
	Instant expiresAt;

	/**
	 * The time when the cryptographic material should be destroyed for this key.
	 */
	@Nullable
	Instant destructionScheduledAt;

	/**
	 * The time when the cryptographic material was destroyed for this key.
	 */
	@Nullable
	Instant destroyedAt;

	@Override
	public InputStream getInputStream() {
		return data == null ? InputStream.nullInputStream() : data.getInputStream();
	}

	@Override
	public int compareTo(EncryptedKey o) {
		return id.compareTo(o.id);
	}

	/**
	 * Creates a new empty instance of the {@link Builder}.
	 *
	 * @return encrypted key builder, never {@literal  null}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new instance of the {@link Builder} pre-populated from an existing {@link EncryptedKey}.
	 * <p>
	 * All fields are copied as-is. Callers can then override individual fields (e.g. {@code status},
	 * {@code destructionScheduledAt}) before calling {@link Builder#build(ByteArray)}.
	 *
	 * @param existing the source {@link EncryptedKey} to copy, can't be {@literal null}
	 * @return a pre-populated builder, never {@literal null}
	 */
	public static Builder builder(EncryptedKey existing) {
		return builder()
			.id(existing.getId())
			.algorithm(existing.getAlgorithm())
			.type(existing.getType())
			.status(existing.getStatus())
			.primary(existing.isPrimary())
			.createdAt(existing.getCreatedAt())
			.initializedAt(existing.getInitializedAt())
			.expiresAt(existing.getExpiresAt())
			.destructionScheduledAt(existing.getDestructionScheduledAt())
			.destroyedAt(existing.getDestroyedAt());
	}

	/**
	 * Creates a new instance of the {@link EncryptedKey} from the given {@link Key} and encrypted
	 * key material represented by the {@link ByteArray}.
	 *
	 * @param key key that is encrypted by the {@link KeyEncryptionKey}, can't be {@literal null}
	 * @param data encrypted private key material, if the key material is initialized
	 * @return encrypted key, never {@literal  null}
	 */
	public static EncryptedKey from(Key key, @Nullable ByteArray data) {
		return builder()
			.id(key.getId())
			.algorithm(key.getAlgorithm())
			.type(key.getType())
			.status(key.getStatus())
			.primary(key.isPrimary())
			.createdAt(key.getCreatedAt())
			.initializedAt(key.getInitializedAt())
			.expiresAt(key.getExpiresAt())
			.destructionScheduledAt(key.getDestructionScheduledAt())
			.destroyedAt(key.getDestroyedAt())
			.build(data);
	}

	/**
	 * Builder class used to create new instances of the {@link EncryptedKey}.
	 */
	@NullUnmarked
	@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
	public static final class Builder {

		private String id;
		private String algorithm;
		private KeyType type;
		private KeyStatus status;
		private boolean primary;
		private Instant createdAt;
		private Instant initializedAt;
		private Instant expiresAt;
		private Instant destructionScheduledAt;
		private Instant destroyedAt;

		/**
		 * Specify the identifier of the {@link EncryptedKey}.
		 *
		 * @param id key identifier, can't be {@literal null}
		 * @return builder
		 */
		public Builder id(String id) {
			this.id = id;
			return this;
		}

		/**
		 * Specify the {@link Algorithm} that is used by the {@link EncryptedKey}.
		 *
		 * @param algorithm algorithm name, can't be {@literal null}
		 * @return builder
		 */
		public Builder algorithm(Algorithm algorithm) {
			return algorithm(algorithm == null ? null : algorithm.name())
				.type(algorithm == null ? null : algorithm.type());
		}

		/**
		 * Specify the name of the {@link Algorithm} that is used by the {@link EncryptedKey}.
		 *
		 * @param algorithm algorithm name, can't be {@literal null}
		 * @return builder
		 */
		public Builder algorithm(String algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		/**
		 * Specify the type of the {@link EncryptedKey}.
		 *
		 * @param type key type, can't be {@literal null}
		 * @return builder
		 */
		public Builder type(KeyType type) {
			this.type = type;
			return this;
		}

		/**
		 * Specify the status of the {@link EncryptedKey}.
		 *
		 * @param status key status, can't be {@literal null}
		 * @return builder
		 */
		public Builder status(KeyStatus status) {
			this.status = status;
			return this;
		}

		/**
		 * Marks the {@link EncryptedKey} as primary or not.
		 *
		 * @param primary whether the key is primary or not
		 * @return builder
		 */
		public Builder primary(boolean primary) {
			this.primary = primary;
			return this;
		}

		/**
		 * Specify the timestamp when the {@link Key} was created.
		 *
		 * @param createdAt the timestamp when the key was created
		 * @return builder
		 */
		public Builder createdAt(Instant createdAt) {
			this.createdAt = createdAt;
			return this;
		}

		/**
		 * Specify the timestamp when cryptographic material was initialized.
		 *
		 * @param initializedAt the timestamp when cryptographic material was initialized
		 * @return builder
		 */
		public Builder initializedAt(Instant initializedAt) {
			this.initializedAt = initializedAt;
			return this;
		}

		/**
		 * Specify the time when this key should expire and be rotated.
		 *
		 * @param expiresAt the expiry time
		 * @return builder
		 */
		public Builder expiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
			return this;
		}

		/**
		 * Specify the time when this key should be destroyed.
		 *
		 * @param destructionScheduledAt the scheduled destruction time
		 * @return builder
		 */
		public Builder destructionScheduledAt(Instant destructionScheduledAt) {
			this.destructionScheduledAt = destructionScheduledAt;
			return this;
		}

		/**
		 * Specify the time when the cryptographic material was destroyed for the key.
		 *
		 * @param destroyedAt the destruction time
		 * @return builder
		 */
		public Builder destroyedAt(Instant destroyedAt) {
			this.destroyedAt = destroyedAt;
			return this;
		}

		/**
		 * Creates a new instance of the {@link EncryptedKey} using the given {@link ByteArray} as the
		 * encrypted key material from the matching {@link Key}.
		 *
		 * @param data encrypted key material, can be {@literal null} if the key is not yet initialized
		 * @return encrypted key
		 * @throws IllegalArgumentException when required information to create the encrypted key is missing
		 */
		public EncryptedKey build(@Nullable ByteArray data) {
			Assert.hasText(id, "Key identifier can not be blank");
			Assert.hasText(algorithm, "Key algorithm can not be blank");
			Assert.notNull(type, "Key type can not be null");
			Assert.notNull(status, "Key status can not be null");
			Assert.notNull(createdAt, "Key creation time can not be null");

			return new EncryptedKey(id, algorithm, type, status, primary, data,
				createdAt, initializedAt, expiresAt, destructionScheduledAt, destroyedAt);
		}

	}
}
