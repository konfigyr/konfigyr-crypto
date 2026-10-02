package com.konfigyr.crypto.x509;

import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Internal codec for the plaintext key material of a {@link X509Material}, which is wrapped by the
 * {@link com.konfigyr.crypto.KeyEncryptionKey} before it is stored.
 * <p>
 * The material uses the following binary layout, where all lengths are big-endian:
 * <pre>
 * [ 0x01 version ]
 * [ 4 bytes length ][ PKCS#8 DER encoded private key ]
 * [ 1 byte certificate count ]
 * ([ 4 bytes length ][ X.509 DER encoded certificate ])+
 * </pre>
 * The certificate chain starts with the certificate of the key, followed by the issuer certificates.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 */
@NullMarked
final class X509MaterialCodec {

	private static final byte FORMAT_VERSION = 0x01;

	// guards the decoder against allocating large buffers for corrupted or malicious lengths
	private static final int MAXIMUM_ENTRY_LENGTH = 64 * 1024;

	private static final int MAXIMUM_CHAIN_LENGTH = 10;

	/**
	 * Encodes the private key and the certificate chain of the given key.
	 *
	 * @param material the X509 material to encode
	 * @return the encoded plaintext key material
	 * @throws GeneralSecurityException when the private key or a certificate can not be encoded
	 */
	static ByteArray encode(X509Material material) throws GeneralSecurityException {
		final List<X509Certificate> chain = material.getCertificateChain();
		final byte[] encodedPrivateKey = material.convert(Key::getEncoded);

		if (encodedPrivateKey == null) {
			throw new GeneralSecurityException("Private key of X509 key '" + material.getId() + "' does not support encoding");
		}

		final ByteArrayOutputStream buffer = new ByteArrayOutputStream(encodedPrivateKey.length + 1024 * chain.size());

		try (DataOutputStream output = new DataOutputStream(buffer)) {
			output.writeByte(FORMAT_VERSION);
			writeEntry(output, encodedPrivateKey);
			output.writeByte(chain.size());

			for (X509Certificate certificate : chain) {
				writeEntry(output, certificate.getEncoded());
			}

			output.flush();
			return new ByteArray(buffer.toByteArray());
		} catch (IOException ex) {
			throw new GeneralSecurityException("Failed to encode X509 key material for key: " + material.getId(), ex);
		} finally {
			Arrays.fill(encodedPrivateKey, (byte) 0);
		}
	}

	/**
	 * Decodes the plaintext key material for a key that uses the given algorithm.
	 *
	 * @param material  the plaintext key material
	 * @param algorithm the algorithm of the key, used to parse the private key
	 * @return the X509 Key builder populated with the decoded key material
	 * @throws IOException when the key material does not use the expected layout
	 * @throws GeneralSecurityException when the private key or a certificate cannot be parsed
	 */
	static X509Key.Builder decode(ByteArray material, X509Algorithm algorithm) throws IOException, GeneralSecurityException {
		final byte[] bytes = material.array();

		try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
			if (input.readByte() != FORMAT_VERSION) {
				throw new IOException("Unsupported X509 key material format version");
			}

			final byte[] encodedPrivateKey = readEntry(input);
			final PrivateKey privateKey;

			try {
				privateKey = KeyFactory.getInstance(algorithm.type().name())
					.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
			} finally {
				Arrays.fill(encodedPrivateKey, (byte) 0);
			}

			final int count = input.readUnsignedByte();

			if (count == 0 || count > MAXIMUM_CHAIN_LENGTH) {
				throw new IOException("Invalid X509 certificate chain length: " + count);
			}

			final CertificateFactory factory = CertificateFactory.getInstance("X.509");
			final List<X509Certificate> chain = new ArrayList<>(count);

			for (int i = 0; i < count; i++) {
				chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(readEntry(input))));
			}

			if (input.available() > 0) {
				throw new IOException("Unexpected trailing bytes in X509 key material");
			}

			return new X509Key.Builder()
				.algorithm(algorithm)
				.material(privateKey, chain);
		} finally {
			Arrays.fill(bytes, (byte) 0);
		}
	}

	private static void writeEntry(DataOutputStream output, byte[] value) throws IOException {
		output.writeInt(value.length);
		output.write(value);
	}

	private static byte[] readEntry(DataInputStream input) throws IOException {
		final int length = input.readInt();

		if (length <= 0 || length > MAXIMUM_ENTRY_LENGTH) {
			throw new IOException("Invalid X509 key material entry length: " + length);
		}

		final byte[] value = new byte[length];
		input.readFully(value);
		return value;
	}

}
