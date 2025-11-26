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
 * @author : Vladimir Spasic
 * @since : 01.09.22, Thu
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
