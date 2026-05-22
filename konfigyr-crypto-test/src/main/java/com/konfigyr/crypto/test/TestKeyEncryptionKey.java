package com.konfigyr.crypto.test;

import com.konfigyr.crypto.AbstractKeyEncryptionKey;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.WrappedKeyMaterial;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * A test implementation of {@link KeyEncryptionKey} that uses AES-256-GCM to wrap and
 * unwrap key material. Each instance generates its own random AES key on construction,
 * so wrap and unwrap are only symmetric within the same instance.
 * <p>
 * This class is intended for testing purposes only.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeyEncryptionKey
 * @see AbstractKeyEncryptionKey
 */
@NullMarked
public class TestKeyEncryptionKey extends AbstractKeyEncryptionKey {

	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int IV_LENGTH = 12;
	private static final int TAG_LENGTH = 128;

	/**
	 * The default instance of {@link TestKeyEncryptionKey}.
	 */
	public static KeyEncryptionKey INSTANCE = new TestKeyEncryptionKey("test-provider", "test-kek");

	private final SecretKey secretKey;

	/**
	 * Creates a new test key encryption key with the specified identifier and provider.
	 * A fresh AES-256 key is generated for this instance.
	 *
	 * @param id       the unique identifier for this key encryption key, must not be {@code null}
	 * @param provider the provider name for this key encryption key, must not be {@code null}
	 */
	public TestKeyEncryptionKey(String id, String provider) {
		super(id, provider);

		try {
			final var generator = KeyGenerator.getInstance("AES");
			generator.init(256);
			this.secretKey = generator.generateKey();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Failed to generate AES-256 key for test KEK", e);
		}
	}

	/**
	 * Encrypts the key material using AES-256-GCM. The output format is a 12-byte random
	 * IV prepended to the GCM ciphertext (which includes the 128-bit authentication tag).
	 *
	 * @param data the key material to wrap, must not be {@code null}
	 * @return the IV-prefixed ciphertext, never {@code null}
	 * @throws IOException when encryption fails
	 */
	@Override
	public WrappedKeyMaterial wrap(ByteArray data) throws IOException {
		try {
			final byte[] iv = new byte[IV_LENGTH];
			new SecureRandom().nextBytes(iv);

			final var cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));

			final byte[] ciphertext = cipher.doFinal(data.array());
			final byte[] result = new byte[IV_LENGTH + ciphertext.length];
			System.arraycopy(iv, 0, result, 0, IV_LENGTH);
			System.arraycopy(ciphertext, 0, result, IV_LENGTH, ciphertext.length);

			return WrappedKeyMaterial.of(result);
		} catch (GeneralSecurityException e) {
			throw new IOException("Failed to wrap key material using AES-256-GCM", e);
		}
	}

	/**
	 * Decrypts the key material using AES-256-GCM. Expects the input to be an IV-prefixed
	 * ciphertext as produced by {@link #wrap(ByteArray)}.
	 *
	 * @param data the IV-prefixed ciphertext to unwrap, must not be {@code null}
	 * @return the decrypted key material, never {@code null}
	 * @throws IOException when decryption or authentication fails
	 */
	@Override
	public ByteArray unwrap(WrappedKeyMaterial data) throws IOException {
		try {
			final byte[] raw = data.toByteArray();
			final byte[] iv = Arrays.copyOfRange(raw, 0, IV_LENGTH);
			final byte[] ciphertext = Arrays.copyOfRange(raw, IV_LENGTH, raw.length);

			final var cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));

			return new ByteArray(cipher.doFinal(ciphertext));
		} catch (GeneralSecurityException e) {
			throw new IOException("Failed to unwrap key material using AES-256-GCM", e);
		}
	}

}
