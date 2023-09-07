package com.konfigyr.crypto;

import lombok.Getter;
import org.springframework.lang.NonNull;

import java.io.Serial;
import java.util.Collection;

import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;

/**
 * Base exception type that is thrown when dealing with the services within the crypto
 * package.
 *
 * @author : vladimir.spasic.86@gmail.com
 * @since : 01.09.22, Thu
 **/
public abstract class CryptoException extends RuntimeException {

	private static final long SERIAL = 7034297140745766930L;

	@Serial
	private static final long serialVersionUID = SERIAL;

	public CryptoException(String message) {
		super(message);
	}

	public CryptoException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown when the algorithm is not supported by the {@link Keyset}
	 * implementation or it can not be used by a specific {@link KeysetOperation}.
	 */
	public static class UnsupportedAlgorithmException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		public UnsupportedAlgorithmException(Algorithm algorithm) {
			super("Unsupported algorithm: " + algorithm.name());
		}

		public UnsupportedAlgorithmException(Algorithm algorithm, Throwable cause) {
			super("Unsupported algorithm: " + algorithm.name(), cause);
		}

	}

	/**
	 * Exception that is thrown when working {@link KeyEncryptionKeyProvider providers}.
	 * It is better to use specific exception types for better understanding of the
	 * problem.
	 * <p>
	 * This exception contains the name of the {@link KeyEncryptionKeyProvider} which can
	 * be used for debugging or auditing purposes.
	 */
	public static class ProviderException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		private final String provider;

		public ProviderException(String provider, String message) {
			super(message);
			this.provider = provider;
		}

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

		private final String id;

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
	 * specific exception types for better understanding of the problem.
	 * <p>
	 * This exception contains the name of the {@link Keyset} which can be used for
	 * debugging or auditing purposes.
	 */
	public static class KeysetException extends CryptoException {

		@Serial
		private static final long serialVersionUID = SERIAL;

		private final String name;

		public KeysetException(KeysetDefinition definition, String message) {
			this(definition.getName(), message);
		}

		public KeysetException(String name, String message) {
			super(message);
			this.name = name;
		}

		public KeysetException(KeysetDefinition definition, String message, Throwable cause) {
			this(definition.getName(), message, cause);
		}

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

		public UnsupportedKeysetException(KeysetDefinition definition) {
			super(definition.getName(),
					"Could not find any Keyset factory implementation that supports: " + definition
							+ ". Please register your Keyset factory as a Spring Bean that can create "
							+ "Keysets using this definition.");
		}

		public UnsupportedKeysetException(Keyset keyset) {
			super(keyset.getName(),
					"Could not find any Keyset factory implementation that supports: " + keyset.getClass()
							+ ". Please register your Keyset factory as a Spring Bean that can "
							+ "wrap and encrypt instances of these Keysets.");
		}

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

		static final long serialVersionUID = SERIAL;

		private final KeysetOperation attemptedOperation;

		public KeysetOperationException(String key, KeysetOperation operation, String message) {
			super(key, message);
			this.attemptedOperation = operation;
		}

		public KeysetOperationException(String key, KeysetOperation operation, Throwable cause) {
			this(key, operation, "Failed to perform keyset operation '" + operation + "' upon a " + "keyset with name '"
					+ key + "'.", cause);
		}

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

		private final Collection<KeysetOperation> supportedOperations;

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

		public KeysetNotFoundException(String name) {
			this(name, "Keyset with identifier '" + name + "' does not exist");
		}

		public KeysetNotFoundException(String name, String message) {
			super(name, message);
		}

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

		private final KeyEncryptionKey kek;

		public WrappingException(String key, KeyEncryptionKey kek, Throwable cause) {
			this(key, kek, "Failed to wrap private key material for keyset '" + key + "' using key encryption key: "
					+ kek + ".", cause);
		}

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

		private final KeyEncryptionKey kek;

		public UnwrappingException(String key, KeyEncryptionKey kek, Throwable cause) {
			this(key, kek, "Failed to unwrap encrypted private key material for keyset '" + key
					+ "' using key encryption key: " + kek + ".", cause);
		}

		public UnwrappingException(String key, KeyEncryptionKey kek, String message, Throwable cause) {
			super(key, message, cause);
			this.kek = kek;
		}

	}

}
