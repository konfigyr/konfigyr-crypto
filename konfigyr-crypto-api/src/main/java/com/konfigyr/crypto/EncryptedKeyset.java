package com.konfigyr.crypto;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.*;

/**
 * Record that represents the {@link Keyset} at rest whose private key material is
 * encrypted by the {@link KeyEncryptionKey Key Encryption Key (KEK)}. The
 * {@link EncryptedKeyset} are retrieved, stored or removed by the
 * {@link KeysetRepository}.
 * <p>
 * Where possible, {@link KeyEncryptionKey Key Encryption Keys} should be stored in a
 * separate location from {@link EncryptedKeyset encrypted keysets}. For example, if the
 * data is stored in a database, the keys should be stored in the filesystem. This means
 * that if an attacker only has access to one of these (for example through directory
 * traversal or SQL injection), they cannot access both the keys and the data.
 * <p>
 * Each individual {@link Key} has its own encrypted material stored as an {@link EncryptedKey},
 * which also carries the per-key lifecycle metadata (status, timestamps).
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetFactory
 * @see KeysetRepository
 **/
@Value
@NullMarked
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class EncryptedKeyset implements Iterable<EncryptedKey> {

	/**
	 * Unique keyset name.
	 */
	String name;

	/**
	 * The purpose of the key material in this keyset, stored as the enum name.
	 */
	String purpose;

	/**
	 * The name of the {@link KeysetFactory} that manages this keyset.
	 */
	String factory;

	/**
	 * {@link KeyEncryptionKeyProvider} name that supplied the {@link KeyEncryptionKey} to encrypt this keyset.
	 */
	String provider;

	/**
	 * The identifier of the {@link KeyEncryptionKey} used to wrap and unwrap this keyset.
	 */
	String keyEncryptionKey;

	/**
	 * Per-key encrypted material with lifecycle metadata.
	 */
	List<EncryptedKey> keys;

	/**
	 * Rotation frequency for the keyset. {@literal null} when automatic rotation is disabled.
	 */
	@Nullable
	Duration rotationInterval;

	/**
	 * Grace period between scheduling key destruction and the actual removal of key material.
	 * {@literal null} when the destruction grace period is disabled.
	 */
	@Nullable
	Duration destructionGracePeriod;

	/**
	 * Attempts to find the {@link EncryptedKey} with the given identifier.
	 *
	 * @param id the key identifier, can't be {@literal null}
	 * @return the matching {@link EncryptedKey} or empty if not found
	 */
	public Optional<EncryptedKey> getKey(String id) {
		return keys.stream()
			.filter(key -> Objects.equals(key.getId(), id))
			.findFirst();
	}

	/**
	 * Returns the number of {@link EncryptedKey keys} in this keyset.
	 *
	 * @return keyset size.
	 */
	public int size() {
		return keys.size();
	}

	@Override
	public Iterator<EncryptedKey> iterator() {
		return keys.iterator();
	}

	/**
	 * Creates a new empty instance of the {@link EncryptedKeyset.Builder}.
	 * @return encrypted keyset builder, never {@literal  null}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new instance of the {@link EncryptedKeyset.Builder} populated from the given
	 * {@link KeysetDefinition}.
	 *
	 * @param definition definition from which the builder would be populated, can't be {@literal null}
	 * @return encrypted keyset builder based on this definition, never {@literal  null}
	 */
	public static Builder builder(KeysetDefinition definition) {
		return builder()
			.name(definition.getName())
			.purpose(definition.getPurpose())
			.factory(definition.getAlgorithm().factory())
			.rotationInterval(definition.getRotationInterval().orElse(null))
			.destructionGracePeriod(definition.getDestructionGracePeriod().orElse(null));
	}

	/**
	 * Creates a new instance of the {@link EncryptedKeyset.Builder} pre-populated from an existing
	 * {@link EncryptedKeyset}. All metadata fields are copied; the key list is left empty and must
	 * be provided via {@link Builder#build(List)} or {@link Builder#build(EncryptedKey...)}.
	 * <p>
	 * Useful when reconstructing an {@link EncryptedKeyset} with a modified key list (e.g. after
	 * a key status update) without having to re-specify all metadata fields.
	 *
	 * @param existing the source {@link EncryptedKeyset} to copy metadata from, can't be {@literal null}
	 * @return a pre-populated builder, never {@literal null}
	 */
	public static Builder builder(EncryptedKeyset existing) {
		return builder()
			.name(existing.getName())
			.purpose(KeysetPurpose.valueOf(existing.getPurpose()))
			.factory(existing.getFactory())
			.provider(existing.getProvider())
			.keyEncryptionKey(existing.getKeyEncryptionKey())
			.rotationInterval(existing.getRotationInterval())
			.destructionGracePeriod(existing.getDestructionGracePeriod());
	}

	/**
	 * Creates a new instance of the {@link EncryptedKeyset} from the given {@link Keyset} and list of
	 * {@link EncryptedKey encrypted keys}.
	 *
	 * @param keyset keyset that is encrypted by the {@link KeyEncryptionKey}, can't be {@literal null}
	 * @param keys per-key encrypted material, can't be {@literal null}
	 * @return encrypted keyset, never {@literal  null}
	 */
	public static EncryptedKeyset from(Keyset keyset, List<EncryptedKey> keys) {
		final Builder builder = builder()
			.name(keyset.getName())
			.purpose(keyset.getPurpose())
			.factory(keyset.getFactory())
			.keyEncryptionKey(keyset.getKeyEncryptionKey());

		keyset.getRotationInterval().ifPresent(builder::rotationInterval);
		keyset.getDestructionGracePeriod().ifPresent(builder::destructionGracePeriod);

		return builder.build(keys);
	}

	/**
	 * Builder class used to create new instances of the {@link EncryptedKeyset}.
	 */
	@NullUnmarked
	@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
	public static final class Builder {

		private String name;
		private String purpose;
		private String factory;
		private String provider;
		private String kek;
		private Duration rotationInterval;
		private Duration destructionGracePeriod;

		/**
		 * Specify the name of the {@link EncryptedKeyset}.
		 *
		 * @param name keyset name, can't be {@literal null}
		 * @return builder
		 */
		public Builder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Specify the {@link KeysetPurpose} of the {@link Keyset}.
		 *
		 * @param purpose keyset purpose, can't be {@literal null}
		 * @return builder
		 */
		public Builder purpose(KeysetPurpose purpose) {
			Assert.notNull(purpose, "Keyset purpose can not be null");
			this.purpose = purpose.name();
			return this;
		}

		/**
		 * Specify the name of the {@link KeysetFactory} that manages this keyset.
		 *
		 * @param factory factory name, can't be {@literal null}
		 * @return builder
		 */
		public Builder factory(String factory) {
			this.factory = factory;
			return this;
		}

		/**
		 * Specify the name of the {@link KeyEncryptionKeyProvider} that owns the {@link KeyEncryptionKey}.
		 *
		 * @param provider KEK provider name, can't be {@literal null}
		 * @return builder
		 */
		public Builder provider(String provider) {
			this.provider = provider;
			return this;
		}

		/**
		 * Specify the identifier of the {@link KeyEncryptionKey} used to wrap and unwrap the {@link Keyset}.
		 *
		 * @param kekIdentifier KEK identifier, can't be {@literal null}
		 * @return builder
		 */
		public Builder keyEncryptionKey(String kekIdentifier) {
			this.kek = kekIdentifier;
			return this;
		}

		/**
		 * Specify the {@link KeyEncryptionKey} used to wrap and unwrap the {@link Keyset}.
		 *
		 * @param kek KEK, can't be {@literal null}
		 * @return builder
		 */
		public Builder keyEncryptionKey(KeyEncryptionKey kek) {
			Assert.notNull(kek, "Key Encryption Key can not be null");
			return provider(kek.getProvider()).keyEncryptionKey(kek.getId());
		}

		/**
		 * Specify the rotation frequency of the {@link EncryptedKeyset} in milliseconds.
		 *
		 * @param rotationInterval rotation frequency, can't be {@literal null}
		 * @return builder
		 */
		public Builder rotationInterval(long rotationInterval) {
			return rotationInterval(Duration.ofMillis(rotationInterval));
		}

		/**
		 * Specify the rotation frequency of the {@link EncryptedKeyset}.
		 *
		 * @param rotationInterval rotation frequency, can be {@literal null} to disable
		 * @return builder
		 */
		public Builder rotationInterval(@Nullable Duration rotationInterval) {
			this.rotationInterval = rotationInterval;
			return this;
		}

		/**
		 * Specify the destruction grace period of the {@link EncryptedKeyset} in milliseconds.
		 *
		 * @param destructionGracePeriod destruction grace period, can be {@literal null} to disable
		 * @return builder
		 */
		public Builder destructionGracePeriod(long destructionGracePeriod) {
			return destructionGracePeriod(Duration.ofMillis(destructionGracePeriod));
		}

		/**
		 * Specify the destruction grace period of the {@link EncryptedKeyset}.
		 *
		 * @param destructionGracePeriod destruction grace period, can be {@literal null} to disable
		 * @return builder
		 */
		public Builder destructionGracePeriod(@Nullable Duration destructionGracePeriod) {
			this.destructionGracePeriod = destructionGracePeriod;
			return this;
		}

		/**
		 * Convenience overload that builds with a varargs array of {@link EncryptedKey keys}.
		 *
		 * @param keys per-key encrypted material
		 * @return encrypted keyset
		 */
		public EncryptedKeyset build(EncryptedKey... keys) {
			return build(keys == null ? new ArrayList<>() : List.of(keys));
		}

		/**
		 * Creates a new instance of the {@link EncryptedKeyset} with the given list of {@link EncryptedKey keys}.
		 *
		 * @param keys per-key encrypted material, cannot be {@literal null}
		 * @return encrypted keyset
		 * @throws IllegalArgumentException when required data to create encrypted keyset is not set
		 */
		public EncryptedKeyset build(List<EncryptedKey> keys) {
			Assert.hasText(name, "Keyset name can not be blank");
			Assert.hasText(purpose, "Keyset purpose can not be blank");
			Assert.hasText(factory, "Keyset factory name can not be blank");
			Assert.hasText(provider, "KEK provider name can not be blank");
			Assert.hasText(kek, "KEK identifier can not be blank");
			Assert.notNull(keys, "Encrypted keys can not be null");

			return new EncryptedKeyset(name, purpose, factory, provider, kek,
				List.copyOf(keys), rotationInterval, destructionGracePeriod);
		}

	}

}
