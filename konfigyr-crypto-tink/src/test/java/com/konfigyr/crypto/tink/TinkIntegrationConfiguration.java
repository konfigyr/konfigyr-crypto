package com.konfigyr.crypto.tink;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.konfigyr.crypto.InMemoryKeysetRepository;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeysetRepository;
import com.konfigyr.io.ByteArray;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.util.Assert;

import java.security.GeneralSecurityException;

@EnableAutoConfiguration
public class TinkIntegrationConfiguration implements InitializingBean {

	static final String KMS_KEY_URI = "https://konfigyr.com/kms/kek";
	static final String ENVELOPE_KMS_KEY_URI = "https://konfigyr.com/kms/envelope";

	static final ByteArray AES_KEY = ByteArray.fromBase64String("eal1ugRPdfdWpEe6fmi6RA==");

	@Override
	public void afterPropertiesSet() {
		KmsClients.add(new TestKmsClient());
	}

	@Bean
	KeysetRepository testKeysetRepository() {
		return new InMemoryKeysetRepository();
	}

	@Bean
	KeyEncryptionKeyProvider randomKekProvider() {
		return KeyEncryptionKeyProvider.of("aes-provider",
				TinkKeyEncryptionKey.builder("aes-provider").generate("random-kek"),
				TinkKeyEncryptionKey.builder("aes-provider").from("aes-kek", AES_KEY));
	}

	@Bean
	KeyEncryptionKeyProvider kmsKekProvider() {
		return KeyEncryptionKeyProvider.of("kms-provider",
				TinkKeyEncryptionKey.builder("kms-provider").kms(KMS_KEY_URI),
				TinkKeyEncryptionKey.builder("kms-provider").kms(ENVELOPE_KMS_KEY_URI, "AES128_GCM"));
	}

	private static final class TestKmsClient implements KmsClient {

		static final ByteArray KEY = new ByteArray(Random.randBytes(16));

		@Override
		public boolean doesSupport(String keyUri) {
			return keyUri.equals(KMS_KEY_URI) || keyUri.equals(ENVELOPE_KMS_KEY_URI);
		}

		@Override
		public KmsClient withCredentials(String credentialPath) {
			return this;
		}

		@Override
		public KmsClient withDefaultCredentials() {
			return this;
		}

		@Override
		public Aead getAead(String keyUri) throws GeneralSecurityException {
			Assert.state(doesSupport(keyUri), "Unsupported KMS key URI: " + keyUri);
			return new AesGcmJce(KEY.array());
		}

	}

}
