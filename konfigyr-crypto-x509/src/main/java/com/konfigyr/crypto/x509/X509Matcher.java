package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetOperation;
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
 * @since 1.1.0
 * @see X509MaterialSelector
 */
@NullMarked
public final class X509Matcher {

	private static final X509Matcher ANY = new Builder().build();

	private final @Nullable Boolean primary;
	private final @Nullable Boolean enabled;
	private final @Nullable Set<String> keyIds;
	private final @Nullable Set<KeyType> keyTypes;
	private final @Nullable Set<KeysetOperation> operations;
	private final @Nullable Set<X509Algorithm> algorithms;
	private final @Nullable Instant validAt;

	private X509Matcher(Builder builder) {
		this.primary = builder.primary;
		this.enabled = builder.enabled;
		this.keyIds = builder.keyIds;
		this.keyTypes = builder.keyTypes;
		this.operations = builder.operations;
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
		if (enabled != null && enabled != key.isEnabled()) {
			return false;
		}
		if (keyIds != null && !keyIds.contains(key.getId())) {
			return false;
		}
		if (keyTypes != null && !keyTypes.contains(key.getType())) {
			return false;
		}
		if (operations != null && operations.stream().noneMatch(operation -> X509Key.isPermitted(key, operation))) {
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
			.add("enabled=" + enabled)
			.add("keyIds=" + keyIds)
			.add("keyTypes=" + keyTypes)
			.add("operations=" + operations)
			.add("algorithms=" + algorithms)
			.add("validAt=" + validAt)
			.toString();
	}

	/**
	 * Builder used to create a {@link X509Matcher}.
	 *
	 * @author Vladimir Spasic
	 * @since 1.1.0
	 */
	@NullMarked
	public static final class Builder {

		private @Nullable Boolean primary;
		private @Nullable Boolean enabled;
		private @Nullable Set<String> keyIds;
		private @Nullable Set<KeyType> keyTypes;
		private @Nullable Set<KeysetOperation> operations;
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
		 * Matches keys that are, or are not, {@link KeyStatus#ENABLED enabled}.
		 * <p>
		 * As only enabled and {@link KeyStatus#RETIRED retired} keys are ever selected, {@literal false} matches
		 * the retired keys. Matching enabled keys selects the primary key and the next key that is created ahead
		 * of the rotation, but never the retired keys. Use it to select the certificates that third parties should
		 * use from now on, for instance the certificates that are published in SAML 2.0 metadata. Retired keys may
		 * still decrypt data that was encrypted for them, but must not be advertised, otherwise third parties keep
		 * encrypting data for keys that are about to be destroyed:
		 * <pre>{@code
		 * // all keys that may still decrypt assertions, used as the decryption credentials
		 * X509Matcher decryption = X509Matcher.builder()
		 *     .operations(KeysetOperation.DECRYPT)
		 *     .build();
		 *
		 * // only the primary and the next key, used for the certificates published in the metadata
		 * X509Matcher published = X509Matcher.builder()
		 *     .operations(KeysetOperation.DECRYPT)
		 *     .enabled(true)
		 *     .build();
		 * }</pre>
		 * Keep in mind that Spring Security publishes all the decryption credentials of a
		 * {@code RelyingPartyRegistration} in its metadata, customize the metadata to publish only the
		 * certificates of the enabled keys.
		 *
		 * @param enabled {@literal true} to match enabled keys, {@literal false} to match retired keys,
		 *                {@literal null} to match any key
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder enabled(@Nullable Boolean enabled) {
			this.enabled = enabled;
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
		 * Matches keys that may perform one of the given operations.
		 * <p>
		 * A key may perform an operation when it is supported by the {@link com.konfigyr.crypto.KeysetPurpose purpose}
		 * of its algorithm and allowed by its status, following the same rules as the cryptographic operations of
		 * the keyset:
		 * <ul>
		 *     <li>{@link KeysetOperation#SIGN} and {@link KeysetOperation#ENCRYPT}: only the
		 *         {@link KeyStatus#ENABLED enabled} primary key,</li>
		 *     <li>{@link KeysetOperation#VERIFY} and {@link KeysetOperation#DECRYPT}: {@link KeyStatus#ENABLED enabled}
		 *         and {@link KeyStatus#RETIRED retired} keys.</li>
		 * </ul>
		 * <pre>
		 * {@code
		 * // the primary key of the signing keyset, never a retired or next key
		 * X509Matcher signing = X509Matcher.builder()
		 *     .operations(KeysetOperation.SIGN)
		 *     .build();
		 *
		 * // all keys of the encryption keyset that may still decrypt assertions encrypted for them
		 * X509Matcher decryption = X509Matcher.builder()
		 *     .operations(KeysetOperation.DECRYPT)
		 *     .build();
		 * }</pre>
		 *
		 * @param operations the operations to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 */
		public Builder operations(KeysetOperation... operations) {
			return operations(Arrays.asList(operations));
		}

		/**
		 * Matches keys that may perform one of the given operations.
		 *
		 * @param operations the operations to match, can't be {@literal null}
		 * @return the matcher builder, never {@literal null}
		 * @see #operations(KeysetOperation...)
		 */
		public Builder operations(Collection<KeysetOperation> operations) {
			this.operations = copyOf(operations, "Operations");
			return this;
		}

		/**
		 * Matches keys whose certificate is valid at the given instant, as defined by the certificate
		 * {@code notBefore} and {@code notAfter} validity period.
		 * <p>
		 * The usability of a key is defined by its {@link com.konfigyr.crypto.KeyStatus status}, not by the
		 * validity of its certificate. The certificate covers the whole period during which the key is used,
		 * so it does not expire while the key is selected, unless the keyset retains its demoted keys or the
		 * scheduled keyset maintenance tasks could not run in time.
		 * <p>Use this criterion when publishing or exposing the certificates to 3rd parties, for instance,
		 * in SAML metadata.
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
