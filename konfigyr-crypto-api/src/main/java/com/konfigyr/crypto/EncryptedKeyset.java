package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.core.io.InputStreamSource;
import org.springframework.lang.NonNull;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

/**
 * Record that represents the {@link Keyset} at rest which private key material is
 * encrypted by the {@link KeyEncryptionKey Key Encryption Key (KEK)}. The
 * {@link EncryptedKeyset} are retrieved, stored or removed by the
 * {@link KeysetRepository}.
 * <p>
 * Where possible, {@link KeyEncryptionKey Key Encryption Keys} should be stored in a
 * separate location from {@link EncryptedKeyset encrypted keysets}. For example, if the
 * data is stored in a database, the keys should be stored in the filesystem. This means
 * that if an attacker only has access to one of these (for example through directory
 * traversal or SQL injection), they cannot access both the keys and the data.
 *
 * @author : Vladimir Spasic
 * @since : 25.08.23, Fri
 * @see KeysetFactory
 * @see KeysetRepository
 **/
@Value
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class EncryptedKeyset implements InputStreamSource, Serializable {

	@Serial
	private static final long serialVersionUID = -5051833454368671211L;

	/**
	 * Unique keyset name.
	 */
	@NonNull
	String name;

	/**
	 * Algorithm name that is used by this keyset.
	 */
	@NonNull
	String algorithm;

	/**
	 * {@link KeyEncryptionKeyProvider} name that supplied the {@link KeyEncryptionKey} to
	 * encrypt this keyset.
	 */
	@NonNull
	String provider;

	/**
	 * The identifier of the {@link KeyEncryptionKey} used to wrap and unwrap this keyset.
	 */
	@NonNull
	String keyEncryptionKey;

	/**
	 * Encrypted key material that was wrapped by the {@link KeyEncryptionKey}.
	 */
	@NonNull
	ByteArray data;

	/**
	 * Rotation frequency for the keyset.
	 */
	@NonNull
	Duration rotationInterval;

	/**
	 * Timestamp when the next key rotation should occur.
	 */
	@NonNull
	Instant nextRotationTime;

	@NonNull
	@Override
	public InputStream getInputStream() {
		return data.getInputStream();
	}

	/**
	 * Creates a new empty instance of the {@link EncryptedKeyset.Builder}.
	 * @return encrypted keyset builder, never {@literal  null}
	 */
	public static @NonNull Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new instance of the {@link EncryptedKeyset.Builder} and populates the
	 * builder with the data from the given {@link KeysetDefinition}.
	 * @param definition definition from which the builder would be created, can't be
	 * {@literal null}
	 * @return encrypted keyset builder based on this definition, never {@literal  null}
	 */
	public static @NonNull Builder builder(@NonNull KeysetDefinition definition) {
		return builder().name(definition.getName())
			.algorithm(definition.getAlgorithm().name())
			.rotationInterval(definition.getRotationInterval())
			.nextRotationTime(definition.getNextRotationTime());
	}

	/**
	 * Creates a new instance of the {@link EncryptedKeyset} from the given {@link Keyset}
	 * and encrypted key material represented by the {@link ByteArray}.
	 * @param keyset keyset that is encrypted by the {@link KeyEncryptionKey}, can't be
	 * {@literal null}
	 * @param data encrypted private key material, can't be {@literal null}
	 * @return encrypted keyset, never {@literal  null}
	 */
	public static @NonNull EncryptedKeyset from(@NonNull Keyset keyset, @NonNull ByteArray data) {
		return builder(keyset).keyEncryptionKey(keyset.getKeyEncryptionKey()).build(data);
	}

	@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
	public static final class Builder {

		private String name;

		private String algorithm;

		private String provider;

		private String kek;

		private Duration rotationInterval;

		private Instant nextRotationTime;

		/**
		 * Specify the name of the {@link EncryptedKeyset}.
		 * @param name keyset name, can't be {@literal null}
		 * @return builder
		 */
		public Builder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Specify the {@link Algorithm} that is used by the {@link Keyset}.
		 * @param algorithm algorithm name, can't be {@literal null}
		 * @return builder
		 */
		public Builder algorithm(Algorithm algorithm) {
			Assert.notNull(kek, "Algorithm can not be null");
			return algorithm(algorithm.name());
		}

		/**
		 * Specify the name of the {@link Algorithm} that is used by the {@link Keyset}.
		 * @param algorithm algorithm name, can't be {@literal null}
		 * @return builder
		 */
		public Builder algorithm(String algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		/**
		 * Specify the name of the {@link KeyEncryptionKeyProvider} that owns the
		 * {@link KeyEncryptionKey}.
		 * @param provider KEK provider name, can't be {@literal null}
		 * @return builder
		 */
		public Builder provider(String provider) {
			this.provider = provider;
			return this;
		}

		/**
		 * Specify the identifier of the {@link KeyEncryptionKey} used to wrap and unwrap
		 * the {@link Keyset}.
		 * @param kekIdentifier KEK identifier, can't be {@literal null}
		 * @return builder
		 */
		public Builder keyEncryptionKey(String kekIdentifier) {
			this.kek = kekIdentifier;
			return this;
		}

		/**
		 * Specify the {@link KeyEncryptionKey} used to wrap and unwrap the
		 * {@link Keyset}. This method would extract the identifier of the KEK as well as
		 * the {@link KeyEncryptionKeyProvider} name.
		 * @param kek KEK, can't be {@literal null}
		 * @return builder
		 */
		public Builder keyEncryptionKey(KeyEncryptionKey kek) {
			Assert.notNull(kek, "Key Encryption Key can not be null");

			return provider(kek.getProvider()).keyEncryptionKey(kek.getId());
		}

		/**
		 * Specify the rotation frequency of the {@link EncryptedKeyset} in milliseconds.
		 * @param rotationInterval rotation frequency, can't be {@literal null}
		 * @return builder
		 */
		public Builder rotationInterval(long rotationInterval) {
			return rotationInterval(Duration.ofMillis(rotationInterval));
		}

		/**
		 * Specify the rotation frequency of the {@link EncryptedKeyset}.
		 * @param rotationInterval rotation frequency, can't be {@literal null}
		 * @return builder
		 */
		public Builder rotationInterval(Duration rotationInterval) {
			this.rotationInterval = rotationInterval;
			return this;
		}

		/**
		 * Specify the next rotation time of the {@link EncryptedKeyset}.
		 * @param nextRotationTime next rotation time of the keyset, can't be
		 * {@literal null}
		 * @return builder
		 */
		public Builder nextRotationTime(long nextRotationTime) {
			return nextRotationTime(Instant.ofEpochMilli(nextRotationTime));
		}

		/**
		 * Specify the next rotation time of the {@link EncryptedKeyset}.
		 * @param nextRotationTime next rotation time of the keyset, can't be
		 * {@literal null}
		 * @return builder
		 */
		public Builder nextRotationTime(Instant nextRotationTime) {
			this.nextRotationTime = nextRotationTime;
			return this;
		}

		/**
		 * Creates a new instance of the {@link EncryptedKeyset} using the given
		 * {@link ByteArray} as the encrypted key material from the {@link Keyset}.
		 * @param data encrypted key material, can not be {@literal null}
		 * @return encrypted keyset
		 * @throws IllegalArgumentException when encrypted keyset can not be built
		 */
		public @NonNull EncryptedKeyset build(ByteArray data) {
			Assert.hasText(name, "Keyset name can not be blank");
			Assert.hasText(algorithm, "Keyset algorithm can not be blank");
			Assert.hasText(provider, "KEK provider name can not be blank");
			Assert.hasText(kek, "KEK identifier can not be blank");
			Assert.notNull(rotationInterval, "Keyset rotation interval can not be blank");
			Assert.notNull(nextRotationTime, "Keyset next rotation time can not be blank");
			Assert.notNull(data, "Encrypted key material can not be null");

			return new EncryptedKeyset(name, algorithm, provider, kek, data, rotationInterval, nextRotationTime);
		}

	}

}
