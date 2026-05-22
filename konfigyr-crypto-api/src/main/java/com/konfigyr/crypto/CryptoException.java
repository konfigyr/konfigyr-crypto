package com.konfigyr.crypto;

import lombok.Getter;
import org.jspecify.annotations.NonNull;

import java.io.Serial;
import java.util.Collection;

import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;

/**
 * Base exception type that is thrown when dealing with the services within the crypto
 * package.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
public abstract class CryptoException extends RuntimeException {

	private static final long SERIAL = 7034297140745766930L;

	@Serial
	private static final long serialVersionUID = SERIAL;

	/**
	 * Creates a new {@link CryptoException} with the given exception message.
	 *
	 * @param message exception message, can't be {@literal null}
	 */
	public CryptoException(String message) {
		super(message);
	}

	/**
	 * Creates a new {@link CryptoException} with the given exception message and cause.
	 *
	 * @param message exception message, can't be {@literal null}
	 * @param cause the cause of the exception, can be {@literal null}
	 */
	public CryptoException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown when the {@link AlgorithmRegistry} cannot resolve an algorithm
	 * for the given name. This typically means the algorithm was never registered or
	 * the stored {@link EncryptedKeyset} references an algorithm that is no longer
	 * available in the current application context.
	 */
	public static class UnknownAlgorithmException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		private final String algorithmName;

		/**
		 * Creates a new {@link UnknownAlgorithmException} for the given algorithm name.
		 *
		 * @param algorithmName the unresolvable algorithm name, can't be {@literal null}
		 */
		public UnknownAlgorithmException(String algorithmName) {
			super("No algorithm registered with name '" + algorithmName + "'. Make sure the "
					+ "algorithm is registered via an AlgorithmRegistrar bean.");
			this.algorithmName = algorithmName;
		}

		/**
		 * @return the algorithm name that could not be resolved, never {@literal null}
		 */
		public @NonNull String getAlgorithmName() {
			return algorithmName;
		}

	}

	/**
	 * Exception thrown when the algorithm is not supported by the {@link Keyset}
	 * implementation, or it can't be used by a specific {@link KeysetOperation}.
	 */
	public static class UnsupportedAlgorithmException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link UnsupportedAlgorithmException} for the given algorithm.
		 *
		 * @param algorithm unsupported algorithm, can't be {@literal null}
		 */
		public UnsupportedAlgorithmException(Algorithm algorithm) {
			super("Unsupported algorithm: " + algorithm.name());
		}

		/**
		 * Creates a new {@link UnsupportedAlgorithmException} for the given algorithm and cause.
		 *
		 * @param algorithm unsupported algorithm, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public UnsupportedAlgorithmException(Algorithm algorithm, Throwable cause) {
			super("Unsupported algorithm: " + algorithm.name(), cause);
		}

	}

	/**
	 * Exception that is thrown when working {@link KeyEncryptionKeyProvider providers}.
	 * It is better to use specific exception types for a better understanding of the
	 * problem.
	 * <p>
	 * This exception contains the name of the {@link KeyEncryptionKeyProvider} which can
	 * be used for debugging or auditing purposes.
	 */
	public static class ProviderException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The name of the {@link KeyEncryptionKeyProvider} for which the exception was thrown.
		 */
		private final String provider;

		/**
		 * Create a new {@link ProviderException} for the given provider name and message.
		 *
		 * @param provider name of the provider, can't be {@literal null}
		 * @param message exception message, can't be {@literal null}
		 */
		public ProviderException(String provider, String message) {
			super(message);
			this.provider = provider;
		}

		/**
		 * Create a new {@link ProviderException} for the given provider name, message and cause.
		 *
		 * @param provider name of the provider, can't be {@literal null}
		 * @param message exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public ProviderException(String provider, String message, Throwable cause) {
			super(message, cause);
			this.provider = provider;
		}

		/**
		 * @return name of the {@link KeyEncryptionKeyProvider} for which the exception
		 * was thrown, never {@literal null}
		 */
		public @NonNull String getProvider() {
			return provider;
		}

	}

	/**
	 * Exception thrown when the {@link KeysetStore} could not find a
	 * {@link KeyEncryptionKeyProvider} with a given provider name.
	 */
	public static class ProviderNotFoundException extends ProviderException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link ProviderNotFoundException} for the given provider name.
		 *
		 * @param provider name of the provider, can't be {@literal null}
		 */
		public ProviderNotFoundException(String provider) {
			super(provider, "Could not find any Key Encryption Key providers for name '" + provider + "'.");
		}

	}

	/**
	 * Exception thrown when the {@link KeyEncryptionKeyProvider} could not find a
	 * {@link KeyEncryptionKey} with a given identifier.
	 * <p>
	 * This exception contains both the names of the {@link KeyEncryptionKeyProvider} and
	 * the {@link KeyEncryptionKey} which can be used for debugging or auditing purposes.
	 */
	public static class KeyEncryptionKeyNotFoundException extends ProviderException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The identifier of the {@link KeyEncryptionKey} for which the exception was thrown.
		 */
		private final String id;

		/**
		 * Creates a new {@link KeyEncryptionKeyNotFoundException} for the given provider and key
		 * encryption key identifier.
		 *
		 * @param provider name of the provider, can't be {@literal null}
		 * @param id identifier of the key encryption key, can't be {@literal null}
		 */
		public KeyEncryptionKeyNotFoundException(String provider, String id) {
			super(provider, "Could not find any Key Encryption Key with identifier '" + id + "' in "
					+ "provider with name '" + provider + "'.");
			this.id = id;
		}

		/**
		 * @return identifier of the {@link KeyEncryptionKey} for which the exception was
		 * thrown, never {@literal null}
		 */
		public @NonNull String getId() {
			return this.id;
		}

	}

	/**
	 * Exception that is thrown when working {@link Keyset keysets}. It is better to use
	 * specific exception types for a better understanding of the problem.
	 * <p>
	 * This exception contains the name of the {@link Keyset} which can be used for
	 * debugging or auditing purposes.
	 */
	public static class KeysetException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The name of the {@link Keyset} for which the exception was thrown.
		 */
		private final String name;

		/**
		 * Creates a new {@link KeysetException} for the given {@link KeysetDefinition} and exception message.
		 *
		 * @param definition {@link KeysetDefinition} for which the exception was thrown, can't be {@literal null}
		 * @param message exception message, can't be {@literal null}
		 */
		public KeysetException(KeysetDefinition definition, String message) {
			this(definition.getName(), message);
		}

		/**
		 * Creates a new {@link KeysetException} for the given {@link KeysetDefinition} name and exception message.
		 *
		 * @param name keyset name for which the exception was thrown, can't be {@literal null}
		 * @param message exception message, can't be {@literal null}
		 */
		public KeysetException(String name, String message) {
			super(message);
			this.name = name;
		}

		/**
		 * Creates a new {@link KeysetException} for the given {@link KeysetDefinition},
		 * exception message and cause.
		 *
		 * @param definition {@link KeysetDefinition} for which the exception was thrown, can't be {@literal null}
		 * @param message exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public KeysetException(KeysetDefinition definition, String message, Throwable cause) {
			this(definition.getName(), message, cause);
		}

		/**
		 * Creates a new {@link KeysetException} for the given {@link KeysetDefinition} name,exception message
		 * and cause.
		 *
		 * @param name keyset name for which the exception was thrown, can't be {@literal null}
		 * @param message exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public KeysetException(String name, String message, Throwable cause) {
			super(message, cause);
			this.name = name;
		}

		/**
		 * @return name of the {@link Keyset} for which the exception was thrown, never
		 * {@literal null}
		 */
		public @NonNull String getName() {
			return name;
		}

	}

	/**
	 * Exception that is thrown by the {@link KeysetStore} when working with
	 * {@link Keyset} implementations that are not supported. Usually this exception means
	 * that there is no matching {@link KeysetFactory} defined that is responsible for
	 * handling such keyset types.
	 */
	public static class UnsupportedKeysetException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link UnsupportedKeysetException} for the given {@link KeysetDefinition}.
		 *
		 * @param definition {@link KeysetDefinition} for which the exception was thrown, can't be {@literal null}
		 */
		public UnsupportedKeysetException(KeysetDefinition definition) {
			super(definition.getName(),
					"Could not find any Keyset factory implementation that supports: " + definition
							+ ". Please register your Keyset factory as a Spring Bean that can create "
							+ "Keysets using this definition.");
		}

		/**
		 * Creates a new {@link UnsupportedKeysetException} for the given {@link Keyset}.
		 *
		 * @param keyset {@link Keyset} for which the exception was thrown, can't be {@literal null}
		 */
		public UnsupportedKeysetException(Keyset keyset) {
			super(keyset.getName(),
					"Could not find any Keyset factory implementation that supports: " + keyset.getClass()
							+ ". Please register your Keyset factory as a Spring Bean that can "
							+ "wrap and encrypt instances of these Keysets.");
		}

		/**
		 * Creates a new {@link UnsupportedKeysetException} for the given {@link EncryptedKeyset}.
		 *
		 * @param encryptedKeyset {@link EncryptedKeyset} for which the exception was thrown, can't be {@literal null}
		 */
		public UnsupportedKeysetException(EncryptedKeyset encryptedKeyset) {
			super(encryptedKeyset.getName(),
					"Could not find any Keyset factory implementation that supports: " + encryptedKeyset
							+ ". Please register your Keyset factory as a Spring Bean that can unwrap "
							+ "instances of these Encrypted Keysets.");
		}

	}

	/**
	 * Exception thrown before or during the execution of {@link KeysetOperation} upon a
	 * {@link Keyset}.
	 * <p>
	 * This exception contains the attempted {@link KeysetOperation} which can be used for
	 * debugging or auditing purposes.
	 */
	public static class KeysetOperationException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The attempted {@link KeysetOperation} that was performed upon a {@link Keyset}.
		 */
		private final KeysetOperation attemptedOperation;

		/**
		 * Creates a new {@link KeysetOperationException} for the given {@link Keyset}, operation
		 * and message.
		 *
		 * @param key the {@link Keyset} that was attempted to perform the operation upon, can't be {@literal null}
		 * @param operation the attempted {@link KeysetOperation}, can't be {@literal null}
		 * @param message the exception message, can't be {@literal null}
		 */
		public KeysetOperationException(String key, KeysetOperation operation, String message) {
			super(key, message);
			this.attemptedOperation = operation;
		}

		/**
		 * Creates a new {@link KeysetOperationException} for the given {@link Keyset}, operation and cause.
		 *
		 * @param key the {@link Keyset} that was attempted to perform the operation upon, can't be {@literal null}
		 * @param operation the attempted {@link KeysetOperation}, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public KeysetOperationException(String key, KeysetOperation operation, Throwable cause) {
			this(key, operation, "Failed to perform keyset operation '" + operation + "' upon a " + "keyset with name '"
					+ key + "'.", cause);
		}

		/**
		 * Creates a new {@link KeysetOperationException} for the given {@link Keyset}, operation,
		 * exception message and cause.
		 *
		 * @param key the {@link Keyset} that was attempted to perform the operation upon, can't be {@literal null}
		 * @param operation the attempted {@link KeysetOperation}, can't be {@literal null}
		 * @param message the exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public KeysetOperationException(String key, KeysetOperation operation, String message, Throwable cause) {
			super(key, message, cause);
			this.attemptedOperation = operation;
		}

		/**
		 * @return the {@link KeysetOperation} that was attempted by the {@link Keyset},
		 * never {@literal null}
		 */
		public @NonNull KeysetOperation attemptedOperation() {
			return attemptedOperation;
		}

	}

	/**
	 * Exception thrown when the {@link Keyset} attempts to perform a
	 * {@link KeysetOperation} that is not supported by the {@link Algorithm}.
	 * <p>
	 * This exception contains the attempted {@link KeysetOperation} and a collection of
	 * supported operations by the {@link Algorithm} along with the name of the
	 * {@link Keyset} that attempted it.
	 */
	public static class UnsupportedKeysetOperationException extends KeysetOperationException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The collection of supported {@link KeysetOperation operations} that are supported by the
		 * {@link Algorithm} defined in the {@link Keyset}.
		 */
		private final Collection<KeysetOperation> supportedOperations;

		/**
		 * Creates a new {@link UnsupportedKeysetOperationException} for the given {@link Keyset}, operation
		 * and a collection of supported operations.
		 *
		 * @param name the name of the {@link Keyset} that attempted to perform the operation, can't be {@literal null}
		 * @param operation the attempted {@link KeysetOperation}, can't be {@literal null}
		 * @param supportedOperations the collection of supported {@link KeysetOperation operations} by the
		 * {@link Algorithm} defined in the {@link Keyset}, can't be {@literal null}
		 */
		public UnsupportedKeysetOperationException(String name, KeysetOperation operation,
				Collection<KeysetOperation> supportedOperations) {
			super(name, operation, "Unsupported '" + operation + "' operation performed upon a '" + name
					+ "' keyset. Supported operations are: " + collectionToCommaDelimitedString(supportedOperations));
			this.supportedOperations = supportedOperations;
		}

		/**
		 * @return the {@link KeysetOperation operations} are supported by the
		 * {@link Keyset}, never {@literal null}
		 */
		public @NonNull Collection<KeysetOperation> supportedOperations() {
			return supportedOperations;
		}

	}

	/**
	 * Exception thrown when the {@link KeysetStore} could not find a {@link Keyset} with
	 * a given name.
	 */
	public static class KeysetNotFoundException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link KeysetNotFoundException} for the given name.
		 *
		 * @param name the name of the {@link Keyset} that was not found, can't be {@literal null}
		 */
		public KeysetNotFoundException(String name) {
			this(name, "Keyset with identifier '" + name + "' does not exist");
		}

		/**
		 * Creates a new {@link KeysetNotFoundException} for the given name and exception message.
		 *
		 * @param name the name of the {@link Keyset} that was not found, can't be {@literal null}
		 * @param message the exception message, can't be {@literal null}
		 */
		public KeysetNotFoundException(String name, String message) {
			super(name, message);
		}

		/**
		 * Creates a new {@link KeysetNotFoundException} for the given name, exception message and cause.
		 *
		 * @param name the name of the {@link Keyset} that was not found, can't be {@literal null}
		 * @param message the exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public KeysetNotFoundException(String name, String message, Throwable cause) {
			super(name, message, cause);
		}

	}

	/**
	 * Exception thrown when a {@link Keyset} is accessed but its primary {@link Key} is
	 * in {@link KeyStatus#DISABLED} state and cannot perform any cryptographic operations.
	 * <p>
	 * This exception is thrown by the keyset construction path (e.g. {@link AbstractKeyset})
	 * before any key material is unwrapped, ensuring no sensitive data is touched for
	 * disabled keysets.
	 */
	public static class KeysetDisabledException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link KeysetDisabledException} for the given keyset name.
		 *
		 * @param name the name of the disabled {@link Keyset}, can't be {@literal null}
		 */
		public KeysetDisabledException(String name) {
			super(name, "Keyset '" + name + "' is disabled and cannot perform cryptographic operations. "
					+ "Enable the primary key before attempting to use this keyset.");
		}

	}

	/**
	 * Exception thrown when a {@link Keyset} is accessed but its primary {@link Key} is
	 * in {@link KeyStatus#PENDING_DESTRUCTION} state.
	 * <p>
	 * A keyset in this state has been scheduled for destruction and is waiting for the
	 * configured grace period to elapse. No cryptographic operations are permitted.
	 * Call {@code KeysetStore.cancelDestruction} to restore the key to
	 * {@link KeyStatus#DISABLED} if the destruction was unintended.
	 */
	public static class KeysetPendingDestructionException extends KeysetDisabledException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link KeysetPendingDestructionException} for the given keyset name.
		 *
		 * @param name the name of the {@link Keyset} pending destruction, can't be {@literal null}
		 */
		public KeysetPendingDestructionException(String name) {
			super(name);
		}

		@Override
		public String getMessage() {
			return "Keyset '" + getName() + "' is pending destruction and cannot perform cryptographic "
					+ "operations. Call cancelDestruction to restore it to a disabled state.";
		}

	}

	/**
	 * Exception thrown when a {@link Keyset} is accessed but its primary {@link Key} has
	 * been permanently destroyed ({@link KeyStatus#DESTROYED}).
	 * <p>
	 * A destroyed key's material has been erased and cannot be recovered. If the keyset
	 * has no remaining {@link KeyStatus#ENABLED} key, it is permanently inoperable.
	 */
	public static class KeysetDestroyedException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * Creates a new {@link KeysetDestroyedException} for the given keyset name.
		 *
		 * @param name the name of the {@link Keyset} whose primary key has been destroyed,
		 *             can't be {@literal null}
		 */
		public KeysetDestroyedException(String name) {
			super(name, "Keyset '" + name + "' primary key has been permanently destroyed. "
					+ "The key material cannot be recovered.");
		}

	}

	/**
	 * Exception thrown when an attempt is made to transition a {@link Key} to an invalid
	 * {@link KeyStatus} from its current state.
	 * <p>
	 * For example, calling {@code scheduleDestruction} on a key that is still
	 * {@link KeyStatus#ENABLED} (rather than {@link KeyStatus#DISABLED}) will throw this
	 * exception because the required deactivation step was skipped.
	 * <p>
	 * This exception carries the keyset name, the key identifier, the current status,
	 * and the attempted (target) status for diagnostic purposes.
	 */
	public static class InvalidKeyStatusTransitionException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The identifier of the {@link Key} for which the transition was attempted.
		 */
		private final String keyId;

		/**
		 * The current {@link KeyStatus} of the {@link Key} when the transition was attempted.
		 */
		private final KeyStatus currentStatus;

		/**
		 * The {@link KeyStatus} that the caller attempted to transition the key into.
		 */
		private final KeyStatus attemptedStatus;

		/**
		 * Creates a new {@link InvalidKeyStatusTransitionException}.
		 *
		 * @param keysetName    the name of the keyset containing the key, can't be {@literal null}
		 * @param keyId         the identifier of the key, can't be {@literal null}
		 * @param currentStatus the current status of the key, can't be {@literal null}
		 * @param attemptedStatus the status the caller tried to set, can't be {@literal null}
		 */
		public InvalidKeyStatusTransitionException(
				String keysetName, String keyId,
				KeyStatus currentStatus, KeyStatus attemptedStatus) {
			super(keysetName, "Invalid key status transition for key '" + keyId + "' in keyset '"
					+ keysetName + "': cannot transition from " + currentStatus + " to " + attemptedStatus + ".");
			this.keyId = keyId;
			this.currentStatus = currentStatus;
			this.attemptedStatus = attemptedStatus;
		}

		/**
		 * @return the identifier of the {@link Key} for which the transition was attempted,
		 *         never {@literal null}
		 */
		public @NonNull String getKeyId() {
			return keyId;
		}

		/**
		 * @return the current {@link KeyStatus} of the key when the invalid transition was
		 *         attempted, never {@literal null}
		 */
		public @NonNull KeyStatus getCurrentStatus() {
			return currentStatus;
		}

		/**
		 * @return the {@link KeyStatus} that was attempted but is not a valid transition from
		 *         {@link #getCurrentStatus()}, never {@literal null}
		 */
		public @NonNull KeyStatus getAttemptedStatus() {
			return attemptedStatus;
		}

	}

	/**
	 * Exception thrown when the {@link Keyset} is being encrypted, or wrapped, by the
	 * responsible {@link KeyEncryptionKey}.
	 * <p>
	 * This exception contains both the name of {@link Keyset} and the actual
	 * {@link KeyEncryptionKey} values for which this exception has been thrown.
	 */
	@Getter
	public static class WrappingException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The {@link KeyEncryptionKey} that was responsible for the wrapping, can't be {@literal null}.
		 */
		private final KeyEncryptionKey kek;

		/**
		 * Creates a new {@link WrappingException} for the given {@link Keyset} and {@link KeyEncryptionKey}.
		 *
		 * @param key the name of the {@link Keyset} that was being encrypted or wrapped, can't be {@literal null}
		 * @param kek the {@link KeyEncryptionKey} that was responsible for the wrapping, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public WrappingException(String key, KeyEncryptionKey kek, Throwable cause) {
			this(key, kek, "Failed to wrap private key material for keyset '" + key + "' using key encryption key: "
					+ kek + ".", cause);
		}

		/**
		 * Creates a new {@link WrappingException} for the given {@link Keyset} and {@link KeyEncryptionKey}.
		 *
		 * @param key the name of the {@link Keyset} that was being encrypted or wrapped, can't be {@literal null}
		 * @param kek the {@link KeyEncryptionKey} that was responsible for the wrapping, can't be {@literal null}
		 * @param message the exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public WrappingException(String key, KeyEncryptionKey kek, String message, Throwable cause) {
			super(key, message, cause);
			this.kek = kek;
		}

	}

	/**
	 * Exception thrown when the {@link EncryptedKeyset} is being decrypted, or unwrapped,
	 * by the responsible {@link KeyEncryptionKey}.
	 * <p>
	 * This exception contains both the name of {@link EncryptedKeyset} and the actual
	 * {@link KeyEncryptionKey} values for which this exception has been thrown.
	 */
	@Getter
	public static class UnwrappingException extends KeysetException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		/**
		 * The {@link KeyEncryptionKey} that was responsible for the unwrapping, can't be {@literal null}.
		 */
		private final KeyEncryptionKey kek;

		/**
		 * Creates a new {@link UnwrappingException} for the given {@link EncryptedKeyset} and {@link KeyEncryptionKey}.
		 *
		 * @param key the name of the {@link EncryptedKeyset} that was being decrypted or unwrapped, can't be {@literal null}
		 * @param kek the {@link KeyEncryptionKey} that was responsible for the unwrapping, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public UnwrappingException(String key, KeyEncryptionKey kek, Throwable cause) {
			this(key, kek, "Failed to unwrap encrypted private key material for keyset '" + key
					+ "' using key encryption key: " + kek + ".", cause);
		}

		/**
		 * Creates a new {@link UnwrappingException} for the given {@link EncryptedKeyset} and {@link KeyEncryptionKey}.
		 *
		 * @param key the name of the {@link EncryptedKeyset} that was being decrypted or unwrapped, can't be {@literal null}
		 * @param kek the {@link KeyEncryptionKey} that was responsible for the unwrapping, can't be {@literal null}
		 * @param message the exception message, can't be {@literal null}
		 * @param cause the cause of the exception, can be {@literal null}
		 */
		public UnwrappingException(String key, KeyEncryptionKey kek, String message, Throwable cause) {
			super(key, message, cause);
			this.kek = kek;
		}

	}

}
