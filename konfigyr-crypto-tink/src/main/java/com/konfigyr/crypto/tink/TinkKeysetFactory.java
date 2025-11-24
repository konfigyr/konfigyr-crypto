package com.konfigyr.crypto.tink;

import com.google.crypto.tink.*;
import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.util.Assert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Implementation of the {@link KeysetFactory} that integrates
 * <a href="https://developers.google.com/tink/">Google Tink</a> library in the Konfigyr {@link KeysetStore}.
 * <p>
 * It produces the {@link TinkKeyset} implementation that would be using the {@link KeysetHandle} as the underlying
 * store of cryptographic keys. To generate a new {@link TinkKeyset} it is required to use a {@link TinkAlgorithm}
 * when defining which type of keys should be generated and which Tink Primitives can be used to perform
 * specified {@link KeysetOperation key operations}.
 * <p>
 * When encrypting or decrypting the {@link KeysetHandle} a {@link BinaryKeysetReader} and
 * {@link BinaryKeysetWriter} would be used to manage sensitive key material.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see TinkAlgorithm
 * @see TinkKeyset
 **/
@NullMarked
public class TinkKeysetFactory implements KeysetFactory {

	@Override
	public boolean supports(EncryptedKeyset encryptedKeyset) {
		for (TinkAlgorithm algorithm : TinkAlgorithm.values()) {
			if (algorithm.name().equals(encryptedKeyset.getAlgorithm())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean supports(KeysetDefinition definition) {
		return TinkUtils.isSupportedAlgorithm(definition.getAlgorithm());
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
		final KeyTemplate template = TinkUtils.keyTemplateForAlgorithm(definition.getAlgorithm());

		final KeysetHandle handle;

		try {
			handle = KeysetHandle.generateNew(template);
		}
		catch (GeneralSecurityException e) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm(), e);
		}

		return TinkKeyset.builder(handle)
			.name(definition.getName())
			.algorithm((TinkAlgorithm) definition.getAlgorithm())
			.keyEncryptionKey(kek)
			.rotationInterval(definition.getRotationInterval())
			.nextRotationTime(definition.getNextRotationTime())
			.build();
	}

	@Override
	public EncryptedKeyset create(Keyset keyset) throws IOException {
		Assert.isInstanceOf(TinkKeyset.class, keyset,
				"This keyset factory only supports Tink keysets," + "you have passed: " + keyset.getClass());

		final KeyEncryptionKey kek = keyset.getKeyEncryptionKey();
		final ByteArrayOutputStream os = new ByteArrayOutputStream();

		try {
			((TinkKeyset) keyset).getHandle()
				.write(BinaryKeysetWriter.withOutputStream(os), KeyEncryptionKeyAdapter.adapt(keyset.getName(), kek));
		}
		catch (GeneralSecurityException e) {
			throw new CryptoException.WrappingException(keyset.getName(), kek, e);
		}

		return EncryptedKeyset.from(keyset, new ByteArray(os.toByteArray()));
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) throws IOException {
		final KeysetHandle handle;

		final String name = encryptedKeyset.getName();
		final InputStream cipher = encryptedKeyset.getInputStream();

		try {
			handle = KeysetHandle.read(BinaryKeysetReader.withInputStream(cipher),
					KeyEncryptionKeyAdapter.adapt(name, kek));
		}
		catch (GeneralSecurityException e) {
			throw new CryptoException.UnwrappingException(name, kek, e);
		}

		return TinkKeyset.builder(handle)
			.name(name)
			.algorithm(TinkAlgorithm.valueOf(encryptedKeyset.getAlgorithm()))
			.keyEncryptionKey(kek)
			.rotationInterval(encryptedKeyset.getRotationInterval())
			.nextRotationTime(encryptedKeyset.getNextRotationTime())
			.build();
	}

	@RequiredArgsConstructor(staticName = "adapt")
	private static class KeyEncryptionKeyAdapter implements Aead {

		private final String keyset;

		private final KeyEncryptionKey kek;

		@Override
		public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
			try {
				return kek.wrap(new ByteArray(plaintext)).array();
			}
			catch (IOException e) {
				throw new CryptoException.WrappingException(keyset, kek, e);
			}
		}

		@Override
		public byte[] decrypt(byte[] ciphertext, byte[] associatedData) {
			try {
				return kek.unwrap(new ByteArray(ciphertext)).array();
			}
			catch (IOException e) {
				throw new CryptoException.UnwrappingException(keyset, kek, e);
			}
		}

	}

}
