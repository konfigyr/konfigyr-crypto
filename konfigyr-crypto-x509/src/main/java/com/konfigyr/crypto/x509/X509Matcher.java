package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.StringJoiner;

/**
 * Matcher used by the {@link X509MaterialSelector} to select {@link X509Material keys} based on
 * their attributes and their certificate validity.
 * <p>
 * Every criterion is optional, a criterion that is not specified matches any key. All the specified
 * criteria must match for a key to be selected:
 * <pre>{@code
 * X509Matcher matcher = X509Matcher.builder()
 *     .primary(true)
 *     .validAt(Instant.now())
 *     .build();
 * }</pre>
 * Matchers can only narrow down the selection. Keys that are neither {@link KeyStatus#ENABLED enabled} nor
 * {@link KeyStatus#RETIRED retired} are never selected, even when the matcher would match them.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see X509MaterialSelector
 */
@NullMarked
public final class X509Matcher {

	private static final X509Matcher ANY = new Builder().build();

	private final @Nullable Boolean primary;
	private final @Nullable Set<String> keyIds;
	private final @Nullable Set<KeyType> keyTypes;
	private final @Nullable Set<X509Algorithm> algorithms;
	private final @Nullable Instant validAt;

	private X509Matcher(Builder builder) {
		this.primary = builder.primary;
		this.keyIds = builder.keyIds;
		this.keyTypes = builder.keyTypes;
		this.algorithms = builder.algorithms;
		this.validAt = builder.validAt;
	}

	/**
	 * Returns a matcher that matches any key.
	 *
	 * @return the matcher, never {@literal null}
	 */
	public static X509Matcher any() {
		return ANY;
	}

	/**
	 * Creates a new builder used to create a {@link X509Matcher}.
	 *
	 * @return the matcher builder, never {@literal null}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Checks if the given key matches all the criteria of this matcher.
	 *
	 * @param key the key to match, can't be {@literal null}
	 * @return {@literal true} when the key matches this matcher
	 */
	public boolean matches(X509Material key) {
		if (primary != null && primary != key.isPrimary()) {
			return false;
		}
		if (keyIds != null && !keyIds.contains(key.getId())) {
			return false;
		}
		if (keyTypes != null && !keyTypes.contains(key.getType())) {
			return false;
		}
		if (algorithms != null && !algorithms.contains(key.getAlgorithm())) {
			return false;
		}
		return validAt == null || isValidAt(key, validAt);
	}

	private static boolean isValidAt(X509Material key, Instant instant) {
		try {
			key.getCertificate().checkValidity(Date.from(instant));
			return true;
		} catch (CertificateException ex) {
			return false;
		}
	}

	@Override
	public String toString() {
		return new StringJoiner(", ", "X509Matcher(", ")")
			.add("primary=" + primary)
			.add("keyIds=" + keyIds)
			.add("keyTypes=" + keyTypes)
			.add("algorithms=" + algorithms)
			.add("validAt=" + validAt)
			.toString();
	}

	/**
	 * Builder used to create a {@link X509Matcher}.
	 *
	 * @author Vladimir Spasic
	 * @since 1.0.0
	 */
	@NullMarked
	public static final class Builder {

		private @Nullable Boolean primary;
		private @Nullable Set<String> keyIds;
		private @Nullable Set<KeyType> keyTypes;
		private @Nullable Set<X509Algorithm> algorithms;
		private @Nullable Instant validAt;

		private Builder() {
		}

		/**
		 * Matches keys that are, or are not, the primary key of the keyset.
		 *
		 * @param primary {@literal true} to match the primary key, {@literal false} to match the
		 *                other keys, {@literal null} to match any key
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder primary(@Nullable Boolean primary) {
			this.primary = primary;
			return this;
		}

		/**
		 * Matches keys with one of the given identifiers.
		 *
		 * @param keyIds the key identifiers to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder keyIds(String... keyIds) {
			return keyIds(Arrays.asList(keyIds));
		}

		/**
		 * Matches keys with one of the given identifiers.
		 *
		 * @param keyIds the key identifiers to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder keyIds(Collection<String> keyIds) {
			this.keyIds = copyOf(keyIds, "Key identifiers");
			return this;
		}

		/**
		 * Matches keys with one of the given key types.
		 *
		 * @param keyTypes the key types to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder keyTypes(KeyType... keyTypes) {
			return keyTypes(Arrays.asList(keyTypes));
		}

		/**
		 * Matches keys with one of the given key types.
		 *
		 * @param keyTypes the key types to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder keyTypes(Collection<KeyType> keyTypes) {
			this.keyTypes = copyOf(keyTypes, "Key types");
			return this;
		}

		/**
		 * Matches keys that use one of the given algorithms.
		 *
		 * @param algorithms the algorithms to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder algorithms(X509Algorithm... algorithms) {
			return algorithms(Arrays.asList(algorithms));
		}

		/**
		 * Matches keys that use one of the given algorithms.
		 *
		 * @param algorithms the algorithms to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder algorithms(Collection<X509Algorithm> algorithms) {
			this.algorithms = copyOf(algorithms, "Algorithms");
			return this;
		}

		/**
		 * Matches keys whose certificate is valid at the given instant, as defined by the certificate
		 * {@code notBefore} and {@code notAfter} validity period.
		 * <p>
		 * The usability of a key is defined by its {@link com.konfigyr.crypto.KeyStatus status}, not by the
		 * validity of its certificate. The certificate covers the whole period during which the key is used,
		 * so it does not expire while the key is selected, unless the keyset retains its demoted keys or the
		 * scheduled keyset maintenance tasks could not run in time. Use this criterion when publishing
		 * certificates, for instance in SAML metadata, to make sure an expired certificate is never published.
		 *
		 * @param validAt the instant at which the certificate must be valid, {@literal null} to match
		 *                any certificate
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder validAt(@Nullable Instant validAt) {
			this.validAt = validAt;
			return this;
		}

		/**
		 * Creates the {@link X509Matcher} based on the builder configuration.
		 *
		 * @return the matcher, never {@literal null}
		 */
		public X509Matcher build() {
			return new X509Matcher(this);
		}

		private static <T> Set<T> copyOf(Collection<T> values, String name) {
			Assert.notNull(values, () -> name + " can't be null");
			Assert.noNullElements(values, () -> name + " can't contain null elements");
			return Set.copyOf(values);
		}

	}
}
