package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.InMemoryKeysetRepository;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeysetRepository;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

@NullMarked
@EnableAutoConfiguration
public class JoseIntegrationConfiguration {

	static final ByteArray AES_KEY = ByteArray.fromBase64String("eal1ugRPdfdWpEe6fmi6RA==");
	static final String KEK_PROVIDER = "test-provider";
	static final String KEK_IDENTIFIER = "test-kek";

	@Bean
	KeysetRepository testKeysetRepository() {
		return new InMemoryKeysetRepository();
	}

	@Bean
	KeyEncryptionKeyProvider testProviderProvider() throws Exception {
		return KeyEncryptionKeyProvider.of(KEK_PROVIDER, new TestKeyEncryptionKey());
	}

	private static final class TestKeyEncryptionKey implements KeyEncryptionKey {

		JWEEncrypter encrypter;
		JWEDecrypter decrypter;

		TestKeyEncryptionKey() throws Exception {
			this(AES_KEY);
		}

		TestKeyEncryptionKey(ByteArray key) throws Exception {
			this.encrypter = new DirectEncrypter(key.array());
			this.decrypter = new DirectDecrypter(key.array());
		}

		@Override
		public String getId() {
			return KEK_IDENTIFIER;
		}

		@Override
		public String getProvider() {
			return KEK_PROVIDER;
		}

		@Override
		public ByteArray wrap(ByteArray data) throws IOException {
			try {
				final var jwe = new JWEObject(
					new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM).build(),
					new Payload(data.array())
				);
				jwe.encrypt(encrypter);

				return ByteArray.fromString(jwe.serialize(), StandardCharsets.UTF_8);
			} catch (JOSEException ex) {
				throw new IOException("Failed to wrap keyset", ex);
			}
		}

		@Override
		public ByteArray unwrap(ByteArray data) throws IOException {
			try {
				final var jwe = JWEObject.parse(new String(data.array(), StandardCharsets.UTF_8));
				jwe.decrypt(decrypter);

				return new ByteArray(jwe.getPayload().toBytes());
			} catch (ParseException | JOSEException ex) {
				throw new IOException("Failed to unwrap keyset", ex);
			}
		}
	}

}
