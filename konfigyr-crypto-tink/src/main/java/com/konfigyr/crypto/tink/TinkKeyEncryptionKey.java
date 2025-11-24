package com.konfigyr.crypto.tink;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.KmsAeadKeyManager;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.AesGcmKeyFormatOrBuilder;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.konfigyr.crypto.AbstractKeyEncryptionKey;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NonNull;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Implementation of the {@link KeyEncryptionKey} that would use the {@link Aead Tink
 * AEAD} primitives to perform {@link Keyset} wrapping and unwrapping operations.
 * <p>
 * You may choose to define this {@link KeyEncryptionKey} with a {@link SecretKey} or
 * decide to perform the operations against a KMS service using the Tink
 * {@link com.google.crypto.tink.KmsClient}.
 *
 * @author : Vladimir Spasic
 * @since : 26.08.23, Sat
 **/
public class TinkKeyEncryptionKey extends AbstractKeyEncryptionKey {

	private final AeadFactory factory;

	TinkKeyEncryptionKey(String id, String provider, AeadFactory factory) {
		super(id, provider);
		this.factory = factory;
	}

	@NonNull
	@Override
	public ByteArray wrap(@NonNull ByteArray data) throws IOException {
		try {
			return new ByteArray(factory.get().encrypt(data.array(), null));
		}
		catch (GeneralSecurityException e) {
			throw new IOException("Failed to encrypt private key material", e);
		}
	}

	@NonNull
	@Override
	public ByteArray unwrap(@NonNull ByteArray data) throws IOException {
		try {
			return new ByteArray(factory.get().decrypt(data.array(), null));
		}
		catch (GeneralSecurityException e) {
			throw new IOException("Failed to decrypt private key material", e);
		}
	}

	/**
	 * Creates a new {@link Builder Tink KEK Builder} instance with the name of the
	 * {@link com.konfigyr.crypto.KeyEncryptionKeyProvider} that would own the
	 * {@link KeyEncryptionKey} that is being built.
	 * @param provider name of the {@link com.konfigyr.crypto.KeyEncryptionKeyProvider}.
	 * @return Tink KEK builder, never {@literal null}
	 */
	public static @NonNull Builder builder(String provider) {
		Assert.hasText(provider, "Key Encryption Key provider name can not be blank");
		return new Builder(provider);
	}

	@FunctionalInterface
	interface AeadFactory {

		Aead get() throws GeneralSecurityException;

	}

	/**
	 * Builder class used to construct a Tink based {@link KeyEncryptionKey}.
	 */
	public static final class Builder {

		private final String provider;

		/**
		 * Creates a new builder with the
		 * {@link com.konfigyr.crypto.KeyEncryptionKeyProvider} name.
		 * @param provider key provider name
		 */
		private Builder(String provider) {
			this.provider = provider;
		}

		/**
		 * Generates a new random {@link KeyEncryptionKey} using the
		 * <code>AES128_GCM</code> algorithm.
		 * @param id key identifier, can't be {@literal null}
		 * @return randomly generated <code>AES128_GCM</code> key encryption key
		 */
		@NonNull
		public KeyEncryptionKey generate(String id) {
			final AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(16).build();

			return generate(id, format);
		}

		/**
		 * Generates a new random {@link KeyEncryptionKey} using the specified AES GCM
		 * format.
		 * @param id key identifier, can't be {@literal null}
		 * @param format key format to be used, can't be {@literal null}
		 * @return randomly generated <code>AES</code> key encryption key
		 */
		@NonNull
		public KeyEncryptionKey generate(String id, AesGcmKeyFormatOrBuilder format) {
			final byte[] key = Random.randBytes(format.getKeySize());
			return from(id, new ByteArray(key));
		}

		/**
		 * Generates a new random {@link KeyEncryptionKey} using the specified
		 * {@link KeyTemplate}.
		 * @param id key identifier, can't be {@literal null}
		 * @param template key template to be used, can't be {@literal null}
		 * @return randomly generated <code>AES</code> key encryption key
		 */
		@NonNull
		public KeyEncryptionKey generate(String id, KeyTemplate template) {
			Assert.notNull(template, "Key Encryption Key template can not be null");

			final KeysetHandle handle;

			try {
				handle = KeysetHandle.generateNew(template);
			}
			catch (GeneralSecurityException e) {
				throw new IllegalArgumentException("Failed to generate KEK for Key template.", e);
			}

			return from(id, handle);
		}

		/**
		 * Generates a new {@link KeyEncryptionKey} using the specified {@link SecretKey}.
		 * @param id key identifier, can't be {@literal null}
		 * @param key the actual secret key encryption key, can't be {@literal null}
		 * @return the key encryption key backed by a {@link SecretKey}
		 */
		@NonNull
		public KeyEncryptionKey from(String id, SecretKey key) {
			Assert.notNull(key, "Secret key can't be null");
			return from(id, new ByteArray(key.getEncoded()));
		}

		/**
		 * Generates a new {@link KeyEncryptionKey} using the secret key private material.
		 * @param id key identifier, can't be {@literal null}
		 * @param key the actual secret key encryption key, can't be {@literal null}
		 * @return the key encryption key backed by a {@link SecretKey}
		 */
		@NonNull
		public KeyEncryptionKey from(String id, ByteArray key) {
			Assert.hasText(id, "Key encryption key identifier can't be blank");
			Assert.notNull(key, "Secret key can't be null");

			final Aead primitive;

			try {
				primitive = new AesGcmJce(key.array());
			}
			catch (GeneralSecurityException e) {
				throw new IllegalArgumentException("Failed to create AES Key Encryption Key with id: " + id, e);
			}

			return new TinkKeyEncryptionKey(id, provider, new SingletonAeadFactory(primitive));
		}

		/**
		 * Generates a new {@link KeyEncryptionKey} that would use a
		 * {@link com.google.crypto.tink.KmsClient} that is responsible for handling the
		 * given Key Encryption Key (KEK) URI.
		 * <p>
		 * The wrapping and unwrapping of private material key is executed remotely,
		 * usually via HTTPS. Keep in mind that entire payload of the private key material
		 * is sent over the wire which, if not using SSL, may load to leaks of your
		 * private keys. Apart from possible security risks, this way of wrapping your
		 * keys could introduce performance penalties when it comes to handling larger
		 * {@link Keyset keysets}.
		 * @param kekUri location where the remote KEK is located, can't be
		 * {@literal null}
		 * @return Remote KMS key encryption key
		 * @see <a href=
		 * "https://developers.google.com/tink/generate-encrypted-keyset#java">How to use
		 * KMS Clients</a>
		 */
		@NonNull
		public KeyEncryptionKey kms(String kekUri) {
			return generate(kekUri, KmsAeadKeyManager.createKeyTemplate(kekUri));
		}

		/**
		 * Generates a new {@link KeyEncryptionKey} that would use a
		 * {@link com.google.crypto.tink.KmsClient} that is responsible for handling the
		 * given Key Encryption Key (KEK) URI.
		 * <p>
		 * The wrapping and unwrapping of private material key is executed via a randomly
		 * generated data encryption key (DEK) which is then sent to a KMS to be encrypted
		 * or decrypted. The encrypted DEK is then stored with the encrypted key material.
		 * When the {@link com.google.crypto.tink.proto.EncryptedKeyset} should be
		 * unwrapped, the encrypted DEK is extracted and decrypted by the KMS and then
		 * used to decrypt the key material.
		 * <p>
		 * When creating this typo of {@link KeyEncryptionKey} you can must supply the DEK
		 * key template that would be generated, usually an AES key template is used.
		 * @param kekUri location where the remote KEK is located, can't be
		 * {@literal null}
		 * @param template the template name that should be used to generate the DEK,
		 * can't be {@literal null}
		 * @return Remote Envelope KMS key encryption key
		 * @see <a href=
		 * "https://developers.google.com/tink/generate-encrypted-keyset#java">How to use
		 * KMS Clients</a>
		 */
		@NonNull
		public KeyEncryptionKey kms(String kekUri, String template) {
			return kms(kekUri, TinkUtils.keyTemplateForName(template));
		}

		/**
		 * Generates a new {@link KeyEncryptionKey} that would use a
		 * {@link com.google.crypto.tink.KmsClient} that is responsible for handling the
		 * given Key Encryption Key (KEK) URI.
		 * <p>
		 * The wrapping and unwrapping of private material key is executed via a randomly
		 * generated data encryption key (DEK) which is then sent to a KMS to be encrypted
		 * or decrypted. The encrypted DEK is then stored with the encrypted key material.
		 * When the {@link com.google.crypto.tink.proto.EncryptedKeyset} should be
		 * unwrapped, the encrypted DEK is extracted and decrypted by the KMS and then
		 * used to decrypt the key material.
		 * <p>
		 * When creating this typo of {@link KeyEncryptionKey} you can must supply the DEK
		 * key template that would be generated, usually an AES key template is used.
		 * @param kekUri location where the remote KEK is located, can't be
		 * {@literal null}
		 * @param template the template that should be used to generate the DEK, can't be
		 * {@literal null}
		 * @return Remote Envelope KMS key encryption key
		 * @see <a href=
		 * "https://developers.google.com/tink/generate-encrypted-keyset#java">How to use
		 * KMS Clients</a>
		 */
		@NonNull
		public KeyEncryptionKey kms(String kekUri, KeyTemplate template) {
			return generate(kekUri, KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, template));
		}

		/**
		 * Generates a new {@link KeyEncryptionKey} using the specific Tink
		 * {@link KeysetHandle}.
		 * @param id key identifier, can't be {@literal null}
		 * @param handle keyset handle used to wrap and unwrap key material, can't be
		 * {@literal null}
		 * @return Key encryption key using the Tink keyset handle
		 */
		@NonNull
		public KeyEncryptionKey from(String id, KeysetHandle handle) {
			Assert.hasText(id, "Key encryption key identifier can't be blank");
			Assert.notNull(handle, "Keyset handle can't be null");

			return new TinkKeyEncryptionKey(id, provider, new KeysetHandleAeadFactory(handle));
		}

	}

	private record SingletonAeadFactory(Aead aead) implements AeadFactory {

		@Override
		public Aead get() {
			return aead;
		}

	}

	private record KeysetHandleAeadFactory(KeysetHandle handle) implements AeadFactory {

		@Override
		public Aead get() throws GeneralSecurityException {
			return handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
		}

	}

}
